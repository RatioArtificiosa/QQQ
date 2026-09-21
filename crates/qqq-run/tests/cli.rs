// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests that run the **real `qqqai` binary** and inspect its output.
//!
//! # Why these exist, and why they are separate from the unit tests
//!
//! Three defects reached a built binary this project despite hundreds of unit
//! tests passing around them:
//!
//! 1. `[dependencies]` was parsed **successfully** and silently discarded.
//! 2. `version = "1.2"` — the spelling Proposal §5.3 itself writes — was
//!    rejected by the requirement parser.
//! 3. `qqqai doctor` exited `0` when a check failed, and its human output never
//!    named the checks.
//!
//! Every one of them was invisible to the unit tests for the same reason: **the
//! tests were written from the same mental model as the code**, so they asserted
//! what the code did rather than what a user needs. A unit test can confirm that
//! `DoctorOutput` contains a failing check; only running the binary reveals that
//! the process still exits `0`.
//!
//! These tests therefore make no use of the library's internals. They spawn the
//! binary, read stdout/stderr and the exit code, and assert on the *user-facing*
//! contract — the same contract a script or CI job depends on. Where a bug is
//! found by running the program, the regression test belongs here.
//!
//! # Why `Home` is redirected
//!
//! The binary reads nothing outside the directories passed to it today, but a
//! test that inherits the developer's environment is a test that passes on one
//! machine and fails on another. `HOME`/`USERPROFILE` are pointed at the temp
//! directory so any future cache or config lookup is isolated.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The binary under test, located through Cargo's own variable.
///
/// `CARGO_BIN_EXE_<name>` is set by Cargo for integration tests and points at
/// the freshly built artifact, so the test can never accidentally run a stale
/// binary from a different target directory.
fn qqqai() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_qqqai"));
    let home = std::env::temp_dir().join("qqq-cli-test-home");
    let _ = std::fs::create_dir_all(&home);
    cmd.env("HOME", &home);
    cmd.env("USERPROFILE", &home);
    cmd
}

/// A per-sandbox cargo target directory.
///
/// # Why every sandbox needs its own
///
/// The sandboxes that run `qqqai test` each invoke `cargo`, and cargo takes an
/// exclusive lock on its target directory. Sharing one — the repository's by
/// default — makes concurrent tests contend, and the loser reports a failure
/// that has nothing to do with the code under test.
///
/// Measured: `test_trials_runs_each_test_repeatedly` passed in isolation and
/// failed roughly every other full-suite run. A test that fails one time in two
/// on identical input is worse than a failing test — it is indistinguishable
/// from a real intermittent bug until someone spends an hour on it, and the
/// usual response is to mark it ignored.
///
/// A per-sandbox directory also keeps the tests from polluting the repository's
/// own build cache with four extra copies of a scaffolded project.
fn target_dir_for(sandbox: &Path) -> PathBuf {
    sandbox.join(".cargo-target")
}

/// A scratch directory that is removed on drop.
struct Sandbox {
    path: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("qqq-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create sandbox");
        Self { path }
    }

    /// Write a file relative to the sandbox root.
    fn write(&self, name: &str, content: &str) {
        let target = self.path.join(name);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(&target, content).expect("write file");
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.path.join(name)).expect("read file")
    }

    fn exists(&self, name: &str) -> bool {
        self.path.join(name).exists()
    }

    /// Run `qqqai <args>` with the sandbox as the working directory.
    fn run(&self, args: &[&str]) -> Run {
        let out = qqqai()
            .args(args)
            .current_dir(&self.path)
            .env("CARGO_TARGET_DIR", target_dir_for(&self.path))
            .output()
            .expect("the binary must be runnable");
        Run::from(out)
    }

    /// Run an arbitrary program in the sandbox, for building test fixtures.
    ///
    /// Separate from [`Sandbox::run`] because that one is always `qqqai` — the
    /// binary under test — and a fixture builder must never be confused with it.
    ///
    /// A program that cannot be spawned yields a failing `Run` rather than a
    /// panic, so a caller that treats "no encoder" as a reason to skip can do
    /// so. Panicking here would turn a missing optional tool into a test
    /// failure, which is the opposite of the intent.
    fn run_raw(&self, args: &[&str]) -> Run {
        match Command::new(args[0])
            .args(&args[1..])
            .current_dir(&self.path)
            .output()
        {
            Ok(out) => Run::from(out),
            Err(e) => Run {
                code: -1,
                stdout: String::new(),
                stderr: format!("could not run `{}`: {e}", args[0]),
            },
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The result of one invocation, decoded.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl From<Output> for Run {
    fn from(o: Output) -> Self {
        Self {
            // A process killed by a signal has no code; `-1` makes that
            // distinguishable from a real exit rather than aliasing it to 0.
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }
}

impl Run {
    /// Everything the user would see, for assertions that do not care which
    /// stream a message went to.
    fn all(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }

    fn assert_ok(&self) -> &Self {
        assert_eq!(
            self.code, 0,
            "expected success, got exit {}\nstdout:\n{}\nstderr:\n{}",
            self.code, self.stdout, self.stderr
        );
        self
    }

    fn assert_failed(&self) -> &Self {
        assert_ne!(
            self.code, 0,
            "expected failure, got exit 0\nstdout:\n{}\nstderr:\n{}",
            self.stdout, self.stderr
        );
        self
    }

    fn assert_contains(&self, needle: &str) -> &Self {
        let all = self.all();
        assert!(
            all.contains(needle),
            "output must contain {needle:?}\nstdout:\n{}\nstderr:\n{}",
            self.stdout,
            self.stderr
        );
        self
    }
}

const MINIMAL: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n";

// ---------------------------------------------------------------------------
// doctor — the diagnostic must be able to fail
// ---------------------------------------------------------------------------

/// A failing check must fail the **process**, not merely print a complaint.
///
/// This is the regression test for a real defect. `qqqai doctor` printed "1 of
/// 3 checks need attention" and exited `0`, so `qqqai doctor || exit 1` in CI
/// treated a broken environment as healthy. A diagnostic that cannot fail
/// manufactures the false confidence it exists to remove (`§M-006`).
#[test]
fn doctor_exits_non_zero_when_a_check_fails() {
    let s = Sandbox::new("doctor-fail");
    // No qqq.toml, so the manifest check must fail.
    let run = s.run(&["doctor"]);

    run.assert_failed().assert_contains("need attention");
    assert_eq!(
        run.code, 69,
        "a failing check should exit UNAVAILABLE (69), not a generic failure: \
         nothing is broken inside qqqai, the environment is not ready"
    );
}

/// A passing run exits zero, so the code is a genuine signal in both directions.
///
/// Without this the previous test would also pass if `doctor` always failed.
#[test]
fn doctor_exits_zero_when_every_check_passes() {
    let s = Sandbox::new("doctor-ok");
    s.write("qqq.toml", MINIMAL);
    s.run(&["doctor"]).assert_ok();
}

/// The failing check must be **named**, with its detail and its fix.
///
/// "1 of 3 checks need attention" is a riddle, not a diagnosis: the user cannot
/// act on it without knowing which check. The unit test asserted the struct
/// contained the names; only running the binary shows whether the human output
/// ever prints them.
#[test]
fn doctor_names_the_failing_check_and_its_fix() {
    let s = Sandbox::new("doctor-names");
    let run = s.run(&["doctor"]);

    run.assert_failed()
        .assert_contains("manifest")
        .assert_contains("no qqq.toml")
        .assert_contains("fix:");
}

/// The passing checks are listed too.
///
/// A bare "all 3 checks passed" is a claim the reader cannot audit; naming the
/// checks is what shows the tool actually looked.
#[test]
fn doctor_lists_the_passing_checks() {
    let s = Sandbox::new("doctor-passes");
    s.write("qqq.toml", MINIMAL);
    let run = s.run(&["doctor"]);

    run.assert_ok()
        .assert_contains("all 3 checks passed")
        .assert_contains("manifest")
        .assert_contains("binary-name");
}

// ---------------------------------------------------------------------------
// caps and inspect — the listing commands must list
// ---------------------------------------------------------------------------

/// `caps` must name the capabilities, not only count them.
///
/// The command's entire purpose is telling the user *which* capabilities a
/// project holds. It printed "2 capabilities across 2 namespaces" and the names
/// were reachable only through `--json`.
#[test]
fn caps_names_the_capabilities_in_human_output() {
    let s = Sandbox::new("caps-names");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [capabilities.crypto]\nhash = [\"sha256\"]\n",
    );

    s.run(&["caps"])
        .assert_ok()
        .assert_contains("crypto.hash")
        .assert_contains("crypto");
}

/// A deny-all project is explained rather than summarised.
#[test]
fn caps_explains_a_deny_all_project() {
    let s = Sandbox::new("caps-deny");
    s.write("qqq.toml", MINIMAL);

    s.run(&["caps"])
        .assert_ok()
        .assert_contains("no capabilities granted")
        .assert_contains("denied");
}

/// `inspect` must show the interfaces and limits it counted.
#[test]
fn inspect_shows_interfaces_and_limits() {
    let s = Sandbox::new("inspect");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [capabilities.http]\nserver = true\n",
    );

    let run = s.run(&["inspect"]);
    run.assert_ok()
        .assert_contains("posture:")
        .assert_contains("http.server");

    assert_eq!(
        run.all().matches("Interfaces").count(),
        1,
        "the interfaces section must appear exactly once:\n{}",
        run.all()
    );
}

// ---------------------------------------------------------------------------
// why — the answer, not the verdict
// ---------------------------------------------------------------------------

/// A denial must print the exact stanza that would grant the capability.
///
/// This is the command's whole reason for existing: it is run at the moment a
/// capability is refused. It printed `fs.read DENIED` and dropped the stanza,
/// which the scaffolded `qqq.toml` explicitly promises it prints.
#[test]
fn why_prints_the_stanza_for_a_denied_capability() {
    let s = Sandbox::new("why-denied");
    s.write("qqq.toml", MINIMAL);

    s.run(&["why", "fs.read"])
        .assert_ok()
        .assert_contains("DENIED")
        .assert_contains("capabilities.fs")
        .assert_contains("qqq.toml");
}

/// The stanza is not wrapped a second time.
///
/// `fix_stanza_for` already emits its own `add to qqq.toml:` preamble. An
/// earlier version of the human renderer added another, so the terminal showed
/// the phrase twice — a defect no test that merely checks for presence can see.
#[test]
fn why_does_not_repeat_the_stanza_preamble() {
    let s = Sandbox::new("why-preamble");
    s.write("qqq.toml", MINIMAL);

    let run = s.run(&["why", "fs.read"]);
    run.assert_ok();
    assert_eq!(
        run.all().matches("add to qqq.toml:").count(),
        1,
        "the preamble must appear exactly once:\n{}",
        run.all()
    );
}

/// A granted capability names the deciding layer.
#[test]
fn why_names_the_deciding_layer_for_a_grant() {
    let s = Sandbox::new("why-granted");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [capabilities.crypto]\nhash = [\"sha256\"]\n",
    );

    s.run(&["why", "crypto.hash"])
        .assert_ok()
        .assert_contains("GRANTED")
        .assert_contains("manifest");
}

/// A typo gets a suggestion, because a typo is why the command is run.
#[test]
fn why_suggests_a_correction_for_a_typo() {
    let s = Sandbox::new("why-typo");
    s.write("qqq.toml", MINIMAL);

    s.run(&["why", "crypto.hassh"])
        .assert_failed()
        .assert_contains("crypto.hash");
}

// ---------------------------------------------------------------------------
// add / remove — the manifest round trip
// ---------------------------------------------------------------------------

/// `add` writes a dependency the parser can read back.
#[test]
fn add_writes_a_dependency_that_parses() {
    let s = Sandbox::new("add");
    s.write("qqq.toml", MINIMAL);

    s.run(&["add", "qqqai/json@1.2"])
        .assert_ok()
        .assert_contains("qqqai/json");

    let text = s.read("qqq.toml");
    assert!(text.contains("[dependencies]"), "{text}");
    assert!(text.contains("\"qqqai/json\" = \"1.2\""), "{text}");

    // The strongest check available without linking the library: the binary's
    // own parser must accept the file it just wrote.
    s.run(&["caps"]).assert_ok();
}

/// A two-component version is accepted.
///
/// `1.2` is the spelling Proposal §5.3 writes, and it was rejected outright by
/// the first end-to-end run of this command (`§O-034a`).
#[test]
fn add_accepts_the_version_form_the_proposal_writes() {
    let s = Sandbox::new("add-partial");
    s.write("qqq.toml", MINIMAL);

    for version in ["1", "1.2", "1.2.3", "^1.2", "~1.2.3", ">=1.0, <2.0", "*"] {
        let spec = format!("qqqai/json@{version}");
        s.run(&["add", &spec])
            .assert_ok()
            .assert_contains("qqqai/json");
    }
}

/// Comments survive an edit.
///
/// `qqq.toml` is human-owned and its comments record the reasoning behind
/// security decisions. A round-tripping implementation would delete them.
#[test]
fn add_preserves_comments_in_the_manifest() {
    let s = Sandbox::new("add-comments");
    let original = "[package]\nname = \"app\"\nversion = \"0.1.0\"  # the name\n\
                    \n[limits]\n# reasoned about in TICKET-4021\nfuel = 1000\n";
    s.write("qqq.toml", original);

    s.run(&["add", "qqqai/json@1.2"]).assert_ok();

    let text = s.read("qqq.toml");
    assert!(text.contains("# the name"), "inline comment lost:\n{text}");
    assert!(
        text.contains("# reasoned about in TICKET-4021"),
        "standalone comment lost:\n{text}"
    );
    assert!(
        text.contains("fuel = 1000"),
        "the limits table was disturbed"
    );
}

/// `remove` deletes exactly one entry.
#[test]
fn remove_deletes_only_the_named_dependency() {
    let s = Sandbox::new("remove");
    s.write("qqq.toml", MINIMAL);
    s.run(&["add", "qqqai/json@1.2"]).assert_ok();
    s.run(&["add", "qqqai/validate@2.0"]).assert_ok();

    s.run(&["remove", "qqqai/json"]).assert_ok();

    let text = s.read("qqq.toml");
    assert!(!text.contains("qqqai/json"), "the entry survived:\n{text}");
    assert!(
        text.contains("qqqai/validate"),
        "the wrong entry went:\n{text}"
    );
}

/// Removing something absent fails rather than silently succeeding.
#[test]
fn removing_an_absent_dependency_fails() {
    let s = Sandbox::new("remove-absent");
    s.write("qqq.toml", MINIMAL);

    s.run(&["remove", "qqqai/nope"])
        .assert_failed()
        .assert_contains("qqqai/nope");
}

/// A malformed requirement is refused **before** anything is written.
#[test]
fn add_refuses_a_malformed_requirement_without_writing() {
    let s = Sandbox::new("add-bad");
    s.write("qqq.toml", MINIMAL);
    let before = s.read("qqq.toml");

    s.run(&["add", "qqqai/json@1.2.3.4"])
        .assert_failed()
        .assert_contains("1.2.3.4");

    assert_eq!(
        s.read("qqq.toml"),
        before,
        "a refused add must not touch the manifest"
    );
}

// ---------------------------------------------------------------------------
// install — the lockfile contract
// ---------------------------------------------------------------------------

/// `--locked` with no lockfile fails and names the file.
#[test]
fn install_locked_without_a_lockfile_fails() {
    let s = Sandbox::new("install-locked");
    s.write("qqq.toml", MINIMAL);

    s.run(&["install", "--locked"])
        .assert_failed()
        .assert_contains("qqq.lock");
}

/// With no registry, an unpinned dependency fails instead of being invented.
///
/// The alternative — writing a lockfile listing packages never fetched — would
/// make the next command trust a promise about bytes nobody has.
#[test]
fn install_reports_the_registry_gap_rather_than_inventing_versions() {
    let s = Sandbox::new("install-registry");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [dependencies]\n\"qqqai/json\" = \"1.2\"\n",
    );

    s.run(&["install"])
        .assert_failed()
        .assert_contains("qqqai/json")
        .assert_contains("PKG-006");
}

/// A pinned dependency installs, and `--locked` then agrees.
#[test]
fn a_pinned_dependency_installs_and_locks() {
    let s = Sandbox::new("install-ok");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [dependencies]\n\"qqqai/json\" = \"1.2\"\n",
    );
    s.write(
        "qqq.lock",
        "version = 1\n\n[[package]]\nname = \"qqqai/json\"\nversion = \"1.2.3\"\n",
    );

    s.run(&["install"]).assert_ok();
    assert!(s.exists("qqq.lock"), "the lockfile must exist");

    // The written lockfile must be readable by the next run, and `--locked`
    // must accept it — which is the actual CI contract.
    s.run(&["install", "--locked"]).assert_ok();
}

/// **`SEC-015`: an authority change is DISPLAYED at install time.**
///
/// # Why this test exists, and the gap it closes
///
/// The library test `an_authority_change_between_lockfiles_is_visible` proves
/// that `LockDiff::compute` *finds* an escalation. It proves nothing about
/// whether `qqqai install` ever **prints** it — and `SEC-015` says *"`qqqai
/// install` prints a capability diff"*, which is a claim about a user-visible
/// surface. Until this test, that claim was unverified at the level it is made.
///
/// This is the same class of gap this project has now hit three times (§O-066,
/// §O-071, §O-073): a mechanism that exists, is correct, and is not reached. A
/// supply-chain signal an operator never sees is not a supply-chain signal.
///
/// # Why the lockfile is hand-written rather than produced by an install
///
/// Because the registry does not exist yet (`PKG-006`), so a second install
/// cannot fetch a *new* version whose caps differ. Hand-writing both sides is
/// what makes the diff reachable today. When the registry lands, this test keeps
/// working — it asserts the display, not how the lockfiles came to be.
///
/// The manifest uses the **long form** with an explicit `caps` declaration.
///
/// That is not incidental: under the corrected semantics a bare `name = "1.0"`
/// declares *nothing*, and "declares nothing" preserves whatever the lockfile
/// recorded. So a bare-form dependency can never produce an escalation, and an
/// earlier version of this test used the bare form and failed — correctly. The
/// declaration is what the diff compares the record against.
#[test]
fn an_authority_change_is_displayed_at_install_time() {
    let s = Sandbox::new("install-escalation");

    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
         \"qqqai/telemetry\" = { version = \"1.0\", caps = [\"http.client\"] }\n",
    );

    // The previous resolution recorded **no** authority for the dependency. The
    // manifest now declares `http.client`, which is the exact supply-chain event
    // §5.4 says must be visible in the diff.
    s.write(
        "qqq.lock",
        "version = 1\n\n[[package]]\nname = \"qqqai/telemetry\"\nversion = \"1.0.0\"\n\
         caps = [\"none\"]\n",
    );

    // The `--json` form is asserted first because it is the machine-readable
    // contract a CI gate branches on, and an `escalation` boolean that never
    // became true would let every such gate pass silently.
    let json = s.run(&["install", "--json"]);
    json.assert_ok();
    let out = json.stdout.clone();
    assert!(
        out.contains("\"escalation\":true") || out.contains("\"escalation\": true"),
        "`qqqai install --json` must report `escalation: true` when a dependency \
         gains authority; a CI gate reads this field, so a false negative here is a \
         supply-chain event that passes unnoticed. Output:\n{out}"
    );

    // **The human form needs a FRESH sandbox.**
    //
    // The `--json` run above *wrote* `qqq.lock` with the new declaration, so a
    // second run in the same sandbox finds nothing to change and — correctly —
    // reports no escalation. An earlier version of this test re-used the sandbox
    // and failed on its own ordering rather than on the code. The two surfaces
    // must therefore each start from the same pre-change state, which is also
    // what makes the human assertion mean anything: it proves the *display*,
    // independent of whether a previous command already applied the change.
    let s2 = Sandbox::new("install-escalation-human");
    s2.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
         \"qqqai/telemetry\" = { version = \"1.0\", caps = [\"http.client\"] }\n",
    );
    s2.write(
        "qqq.lock",
        "version = 1\n\n[[package]]\nname = \"qqqai/telemetry\"\nversion = \"1.0.0\"\n\
         caps = [\"none\"]\n",
    );

    let human = s2.run(&["install"]);
    human.assert_ok();
    let text = human.all();
    assert!(
        text.contains("AUTHORITY ESCALATION"),
        "the human-readable install output must lead with the escalation; burying \
         the supply-chain signal is what §5.4's diff exists to prevent. Output:\n{text}"
    );
    assert!(
        text.contains("telemetry"),
        "the escalation summary must NAME the package that gained authority. \
         Output:\n{text}"
    );
    assert!(
        text.contains("http.client"),
        "the escalation must say WHAT was gained, not merely that something was. \
         Output:\n{text}"
    );
}

/// A tampered lockfile is refused, not silently rewritten.
///
/// The covering hash exists so a hand-edited lockfile is *detected*. A command
/// that ignored the failure and overwrote the file would destroy the evidence
/// of what changed.
#[test]
fn install_refuses_a_tampered_lockfile() {
    let s = Sandbox::new("install-tampered");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [dependencies]\n\"qqqai/json\" = \"1.2\"\n",
    );
    // A lockfile whose recorded hash cannot match its contents.
    s.write(
        "qqq.lock",
        "version = 1\n\n[[package]]\nname = \"qqqai/json\"\nversion = \"1.2.3\"\n\n\
         [metadata]\n\"lockfile-hash\" = \"deadbeef\"\n",
    );

    s.run(&["install"])
        .assert_failed()
        .assert_contains("qqq.lock");
}

// ---------------------------------------------------------------------------
// update — the two axes
// ---------------------------------------------------------------------------

/// A lockfile with one pinned package.
const PINNED: &str = "version = 1\n\n[[package]]\nname = \"qqqai/json\"\nversion = \"1.2.3\"\n";

/// `update` reports what it considered, and why each package stayed.
///
/// With no registry nothing can move — and that is not a stub, it is the honest
/// answer. The value is the explanation: `--dry-run` tells the user that
/// `^1.2.3` is what is holding the version, which is a real answer to a real
/// question.
#[test]
fn update_explains_why_a_package_did_not_move() {
    let s = Sandbox::new("update-kept");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [dependencies]\n\"qqqai/json\" = \"^1.2.3\"\n",
    );
    s.write("qqq.lock", PINNED);

    s.run(&["update", "--dry-run"])
        .assert_ok()
        .assert_contains("qqqai/json")
        .assert_contains("^1.2.3");
}

/// A package is named in the human output, not merely counted.
///
/// This is the `§O-036a` contract applied to a new command: in human format the
/// summary is the whole output, so "0 updated, 1 kept" alone would leave the
/// user unable to tell which package was kept.
#[test]
fn update_names_the_packages_it_considered() {
    let s = Sandbox::new("update-names");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [dependencies]\n\"qqqai/json\" = \"^1.2.3\"\n",
    );
    s.write("qqq.lock", PINNED);

    let run = s.run(&["update", "--dry-run"]);
    run.assert_ok();
    assert!(
        run.all().contains("qqqai/json"),
        "the package must be named:\n{}",
        run.all()
    );
    assert!(
        run.all().contains("1.2.3"),
        "the version must be shown:\n{}",
        run.all()
    );
}

/// `--latest` with an exact pin is refused, not resolved by precedence.
///
/// The two state opposite intents, and silently letting one win is how a user
/// ends up with a major upgrade they did not ask for.
#[test]
fn update_refuses_latest_with_an_exact_pin() {
    let s = Sandbox::new("update-exact");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [dependencies]\n\"qqqai/json\" = { version = \"1.2.3\", exact = true }\n",
    );
    s.write("qqq.lock", PINNED);

    s.run(&["update", "--latest"])
        .assert_failed()
        .assert_contains("exact");
}

/// Updating with no lockfile fails and says what to run first.
#[test]
fn update_without_a_lockfile_says_what_to_run_first() {
    let s = Sandbox::new("update-nolock");
    s.write("qqq.toml", MINIMAL);

    s.run(&["update"])
        .assert_failed()
        .assert_contains("qqq.lock")
        .assert_contains("install");
}

/// `install --dry-run` writes nothing, and a real install does.
///
/// The rehearsal is only useful if it is genuinely non-mutating.
#[test]
fn install_dry_run_does_not_write_a_lockfile() {
    let s = Sandbox::new("install-dry");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [dependencies]\n\"qqqai/json\" = \"1.2\"\n",
    );
    s.write("qqq.lock", PINNED);

    s.run(&["install", "--dry-run"]).assert_ok();
    assert_eq!(
        s.read("qqq.lock"),
        PINNED,
        "a rehearsal must not rewrite the lockfile"
    );
}

// ---------------------------------------------------------------------------
// inspect <artifact> — the security property
// ---------------------------------------------------------------------------

/// A minimal component importing `qqq:clock/wall-clock`.
///
/// Hand-written WAT rather than a compiled guest: the test is about what the
/// *inspector* reads, and depending on a language toolchain to produce the input
/// would make this test fail for reasons that have nothing to do with
/// inspection.
const IMPORTS_WALL_CLOCK: &str = r#"(component
  (import "qqq:clock/wall-clock@1.0.0" (instance $c
    (export "now" (func (result u64)))
    (export "resolution" (func (result u64)))
    (export "timezone" (func (result string)))
  ))
  (core module $m)
  (core instance $i (instantiate $m))
)"#;

/// A component importing the filesystem interface.
const IMPORTS_FILESYSTEM: &str = r#"(component
  (import "qqq:fs/filesystem@1.0.0" (instance $c
    (export "read" (func (result u64)))
  ))
  (core module $m)
  (core instance $i (instantiate $m))
)"#;

/// A component importing nothing.
const IMPORTS_NOTHING: &str = r"(component
  (core module $m)
  (core instance $i (instantiate $m))
)";

/// Compile WAT to a component, or `None` when no encoder is available.
///
/// `wasm-tools` is present in CI but not necessarily on a developer's machine.
/// Returning `None` skips the test rather than failing it, because a missing
/// optional tool is not a defect in `qqqai` — but the tests that *can* run
/// without it still do.
fn encode(dir: &Sandbox, name: &str, wat: &str) -> Option<String> {
    dir.write(&format!("{name}.wat"), wat);
    // `wasm-tools parse` takes no `--features` flag: component support is
    // always on in the parser. An earlier version passed one and every fixture
    // silently failed to build, which made all five tests skip while appearing
    // to pass.
    let out = dir.run_raw(&[
        "wasm-tools",
        "parse",
        &format!("{name}.wat"),
        "-o",
        &format!("{name}.wasm"),
    ]);
    if out.code == 0 && dir.exists(&format!("{name}.wasm")) {
        Some(format!("{name}.wasm"))
    } else {
        None
    }
}

/// Inspecting an artifact reports what **it** requires, not what the manifest
/// grants.
///
/// This is the regression test for a real defect. `inspect` ignored its path
/// argument entirely and reported the project's manifest capabilities, so a user
/// inspecting an untrusted `.wasm` received a confident answer about their own
/// `qqq.toml` with nothing indicating the answer was to a different question.
/// On the surface that exists to make a grant auditable *before execution*
/// (Proposal §7), that is worse than not answering.
#[test]
fn inspect_reports_the_artifacts_requirements_not_the_manifests_grants() {
    let s = Sandbox::new("inspect-artifact");
    // A manifest granting something quite different from what the artifact
    // wants. If the command reports the manifest, this is what it will say.
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [capabilities.http]\nclient = [\"api.example.com:443\"]\n",
    );

    let Some(wasm) = encode(&s, "wall", IMPORTS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    let run = s.run(&["inspect", &wasm]);
    run.assert_ok()
        .assert_contains("clock.wall")
        .assert_contains("qqq:clock/wall-clock");

    assert!(
        !run.all().contains("http.client"),
        "the manifest's grants leaked into an artifact report:\n{}",
        run.all()
    );
}

/// The two halves of one WIT package map to different capabilities.
///
/// `qqq:clock` contains both `wall-clock` and `monotonic-clock`, so a
/// package-level search returns whichever the registry lists first. An artifact
/// importing the wall clock was reported as requiring the monotonic clock —
/// a wrong answer on the surface that exists to give the right one.
#[test]
fn inspect_distinguishes_two_interfaces_in_one_package() {
    let s = Sandbox::new("inspect-clock-split");
    s.write("qqq.toml", MINIMAL);

    let Some(wall) = encode(&s, "wall", IMPORTS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    let run = s.run(&["inspect", &wall]);
    run.assert_ok().assert_contains("clock.wall");
    assert!(
        !run.all().contains("clock.monotonic"),
        "the wrong half of the package was reported:\n{}",
        run.all()
    );
}

/// An artifact importing nothing is reported as reaching nothing.
#[test]
fn inspect_reports_an_artifact_that_imports_nothing() {
    let s = Sandbox::new("inspect-empty");
    s.write("qqq.toml", MINIMAL);

    let Some(wasm) = encode(&s, "bare", IMPORTS_NOTHING) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    s.run(&["inspect", &wasm])
        .assert_ok()
        .assert_contains("imports nothing");
}

/// An artifact that can write is reported as `exposed`.
///
/// `qqq:fs/filesystem` is unlocked by `fs.read`, `fs.write` and `fs.watch`, so
/// the report must name the strongest — understating an artifact's authority is
/// the one failure an audit surface must not have.
#[test]
fn inspect_reports_the_strongest_capability_an_interface_implies() {
    let s = Sandbox::new("inspect-strongest");
    s.write("qqq.toml", MINIMAL);

    let Some(wasm) = encode(&s, "fs", IMPORTS_FILESYSTEM) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    let run = s.run(&["inspect", &wasm]);
    run.assert_ok()
        .assert_contains("fs.write")
        .assert_contains("exposed");
}

/// A file that is not a component is an error, never a fallback to the manifest.
///
/// Silently answering a *different* question is the failure this command was
/// fixed for, so an unreadable artifact must fail rather than degrade.
#[test]
fn inspect_refuses_a_file_that_is_not_a_component() {
    let s = Sandbox::new("inspect-not-wasm");
    s.write("qqq.toml", MINIMAL);
    s.write("garbage.wasm", "this is not webassembly at all");

    s.run(&["inspect", "garbage.wasm"])
        .assert_failed()
        .assert_contains("garbage.wasm");
}

/// Inspecting a missing file fails and names the path.
#[test]
fn inspect_refuses_a_missing_artifact() {
    let s = Sandbox::new("inspect-missing");
    s.write("qqq.toml", MINIMAL);

    s.run(&["inspect", "not-here.wasm"])
        .assert_failed()
        .assert_contains("not-here.wasm");
}

/// Inspecting an artifact works with **no project at all**.
///
/// The primary use is a file someone handed you. Requiring a `qqq.toml` in the
/// directory would make the command unusable in exactly that situation.
#[test]
fn inspect_an_artifact_needs_no_manifest() {
    let s = Sandbox::new("inspect-no-manifest");

    let Some(wasm) = encode(&s, "wall", IMPORTS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    s.run(&["inspect", &wasm])
        .assert_ok()
        .assert_contains("clock.wall");
}

/// Without an argument, `inspect` still reports the project's manifest.
///
/// The two modes must both keep working: fixing the artifact path must not break
/// the manifest report it was originally built for.
#[test]
fn inspect_without_an_argument_reports_the_project() {
    let s = Sandbox::new("inspect-project");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [capabilities.crypto]\nhash = [\"sha256\"]\n",
    );

    s.run(&["inspect"])
        .assert_ok()
        .assert_contains("app")
        .assert_contains("crypto.hash");
}

/// A component importing the monotonic clock.
const IMPORTS_MONO_CLOCK: &str = r#"(component
  (import "qqq:clock/monotonic-clock@1.0.0" (instance $c
    (export "now" (func (result u64)))
    (export "resolution" (func (result u64)))
  ))
  (core module $m)
  (core instance $i (instantiate $m))
)"#;

/// Two artifacts with the same authority report no change, and exit zero.
///
/// The exit code matters: if this returned non-zero, `--diff` could not be used
/// as a CI gate, because a clean comparison would fail the build.
#[test]
fn a_diff_of_identical_artifacts_reports_no_change_and_succeeds() {
    let s = Sandbox::new("diff-same");
    let Some(wasm) = encode(&s, "wall", IMPORTS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    s.run(&["inspect", &wasm, "--diff", &wasm])
        .assert_ok()
        .assert_contains("no authority change");
}

/// Gaining authority is reported as an escalation **and exits non-zero**.
///
/// This is the whole point of the flag: an artifact that grew its authority must
/// be gateable in CI without parsing output. A report that named the gain but
/// exited `0` would be unusable as a gate, which is how the `doctor` defect
/// (`§O-036b`) presented.
#[test]
fn a_diff_that_gains_authority_exits_non_zero() {
    let s = Sandbox::new("diff-escalate");
    let Some(clock_only) = encode(&s, "clock", IMPORTS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };
    let Some(with_fs) = encode(&s, "fs", IMPORTS_FILESYSTEM) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    let run = s.run(&["inspect", &with_fs, "--diff", &clock_only]);
    run.assert_failed()
        .assert_contains("ESCALATION")
        .assert_contains("fs.write")
        .assert_contains("exposed");
}

/// Losing authority is reported but does **not** fail.
///
/// A reduction cannot hurt anyone, and failing CI on it would train people to
/// bypass the check — which costs more than the check is worth.
///
/// Direction matters: `inspect A --diff B` reads as **B → A**, so `A` is the
/// "after". Here the after-artifact is the clock-only component, which is the
/// reduction from the filesystem one.
#[test]
fn a_diff_that_loses_authority_reports_but_succeeds() {
    let s = Sandbox::new("diff-reduce");
    let Some(clock_only) = encode(&s, "clock", IMPORTS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };
    // Two imports, one of them `fs.write`, so the *before* state has more
    // authority than the *after* state.
    let Some(double) = encode(&s, "double", DOUBLE_IMPORT) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    // after = clock_only, before = double: authority was given up.
    s.run(&["inspect", &clock_only, "--diff", &double])
        .assert_ok()
        .assert_contains("fs.write");
}

/// A component importing both a benign and an exposing capability.
const DOUBLE_IMPORT: &str = r#"(component
  (import "qqq:clock/wall-clock@1.0.0" (instance $w
    (export "now" (func (result u64)))
  ))
  (import "qqq:fs/filesystem@1.0.0" (instance $f
    (export "read" (func (result u64)))
  ))
  (core module $m)
  (core instance $i (instantiate $m))
)"#;

/// Gaining a **covert channel** escalates even when the posture band holds.
///
/// `clock.wall` is `Ambient`, so it can never lift a component out of
/// `Contained` — but Proposal §10.5 singles it out as an information channel the
/// audit stream cannot see. A diff that only compared posture bands would let
/// such a gain through silently.
#[test]
fn gaining_a_covert_channel_escalates_within_the_same_posture() {
    let s = Sandbox::new("diff-covert");
    let Some(wall) = encode(&s, "wall", IMPORTS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };
    let Some(mono) = encode(&s, "mono", IMPORTS_MONO_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    let run = s.run(&["inspect", &wall, "--diff", &mono]);
    run.assert_failed()
        .assert_contains("ESCALATION")
        .assert_contains("covert channel");

    // The posture band is unchanged, which is exactly why the covert-channel
    // rule has to exist separately.
    assert!(
        run.all().contains("contained → contained"),
        "posture should not have moved: {}",
        run.all()
    );
}

/// `--diff` reports the digest of both artifacts.
///
/// A diff that does not name the bytes is not evidence: "this artifact is safe"
/// without saying *which* artifact cannot be reviewed later.
#[test]
fn a_diff_ties_itself_to_both_digests() {
    let s = Sandbox::new("diff-digests");
    s.write("qqq.toml", MINIMAL);
    let Some(a) = encode(&s, "a", IMPORTS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };
    let Some(b) = encode(&s, "b", IMPORTS_FILESYSTEM) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    // The comparison gains `fs.write`, so it exits non-zero — that is asserted
    // elsewhere. What matters here is the JSON, which `Run` captures either way.
    let run = s.run(&["inspect", &a, "--diff", &b, "--json"]);
    let line = run.stdout.lines().next().unwrap_or("");
    assert!(
        line.matches("sha256:").count() >= 2,
        "both digests must appear: {line}"
    );
    assert!(
        line.contains("before_digest") && line.contains("after_digest"),
        "the digests must be named fields, not prose: {line}"
    );
}

/// `--diff` without an artifact is refused with the reason.
#[test]
fn a_diff_without_an_artifact_is_refused() {
    let s = Sandbox::new("diff-noarg");
    s.write("qqq.toml", MINIMAL);

    s.run(&["inspect", "--diff", "other.wasm"])
        .assert_failed()
        .assert_contains("--diff");
}

// ---------------------------------------------------------------------------
// test — the runner must be able to fail
// ---------------------------------------------------------------------------

/// A Rust project with a passing and a failing test.
///
/// Built by hand rather than by `qqqai new`, because the runner's behaviour
/// under a failure is the thing under test and a scaffold has no failing test to
/// offer.
fn project_with_tests(dir: &Sandbox) {
    dir.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [build]\nlanguage = \"rust\"\ntarget = \"wasm32-wasip2\"\n",
    );
    dir.write(
        "Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n",
    );
    dir.write(
        "src/lib.rs",
        "pub fn add(a: i32, b: i32) -> i32 { a + b }\n\
         \n#[cfg(test)]\nmod tests {\n\
         \x20   #[test]\n    fn adding_works() { assert_eq!(super::add(1, 2), 3); }\n\
         }\n",
    );
    dir.write("tests/smoke.rs", "#[test]\nfn smoke() { assert!(true); }\n");
}

/// A passing project exits zero and reports the tests.
///
/// File attribution is asserted through `--dry-run`, which lists what would run
/// and where each test lives. A passing run names only the counts — printing
/// every test that succeeded would bury the failures, which is the reason
/// someone runs the command.
#[test]
fn test_runs_a_passing_project_and_exits_zero() {
    let s = Sandbox::new("test-pass");
    project_with_tests(&s);

    s.run(&["test"]).assert_ok().assert_contains("2 passed");

    let listed = s.run(&["test", "--dry-run"]);
    listed
        .assert_ok()
        .assert_contains("src/lib.rs")
        .assert_contains("tests/smoke.rs");
}

/// **A failing test exits non-zero.**
///
/// This is the contract a CI job branches on. A runner that reports a failure
/// and exits `0` is unusable in the one place it matters — the same defect
/// `qqqai doctor` had (`§O-036b`).
#[test]
fn a_failing_test_exits_non_zero() {
    let s = Sandbox::new("test-fail");
    project_with_tests(&s);
    // Append a failing test to the library.
    let mut lib = s.read("src/lib.rs");
    lib.push_str(
        "\n#[cfg(test)]\nmod failing {\n    #[test]\n    fn nope() { assert_eq!(1, 2); }\n}\n",
    );
    s.write("src/lib.rs", &lib);

    let run = s.run(&["test"]);
    run.assert_failed()
        .assert_contains("Failures")
        .assert_contains("nope");
}

/// `--filter` selects by test name.
#[test]
fn test_filters_by_name() {
    let s = Sandbox::new("test-filter");
    project_with_tests(&s);

    let run = s.run(&["test", "--filter", "adding"]);
    run.assert_ok().assert_contains("1 passed");
    assert!(
        !run.all().contains("smoke"),
        "the unselected test must not run: {}",
        run.all()
    );
}

/// A filter matching nothing runs nothing, and succeeds.
///
/// Not a failure: the user asked for a selection that is empty, which is a
/// different situation from asking for tests that then failed.
#[test]
fn a_filter_matching_nothing_runs_nothing() {
    let s = Sandbox::new("test-nomatch");
    project_with_tests(&s);

    let run = s.run(&["test", "--filter", "no_such_test_name"]);
    run.assert_ok().assert_contains("0 passed");
}

/// `--dry-run` runs nothing and says what it would run.
///
/// The regression test for a real defect: a rehearsal left every outcome
/// un-run, and the summary rendered that as a "Failures" section listing every
/// test — the opposite of what happened, under the flag a cautious user runs
/// first.
#[test]
fn test_dry_run_runs_nothing_and_reports_no_failures() {
    let s = Sandbox::new("test-dry");
    project_with_tests(&s);

    let run = s.run(&["test", "--dry-run"]);
    run.assert_ok()
        .assert_contains("would run")
        .assert_contains("Would run");
    assert!(
        !run.all().contains("Failures"),
        "a rehearsal ran nothing, so nothing failed: {}",
        run.all()
    );
}

/// `--trials N` runs each test N times and reports the count.
#[test]
fn test_trials_runs_each_test_repeatedly() {
    let s = Sandbox::new("test-trials");
    project_with_tests(&s);

    s.run(&["test", "--trials", "3"])
        .assert_ok()
        .assert_contains("3 trials each");
}

/// A project whose language has no runner is refused by name.
///
/// The error must name the language and the tracking item, not fail with an
/// opaque "command not found" — the user needs to know this is a known gap
/// rather than a broken install.
#[test]
fn test_refuses_a_language_with_no_runner() {
    let s = Sandbox::new("test-nolang");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [build]\nlanguage = \"python\"\ntarget = \"wasm32-wasip2\"\n",
    );

    s.run(&["test"])
        .assert_failed()
        .assert_contains("python")
        .assert_contains("TEST-001");
}

/// `--trials` with a non-number is a usage error.
#[test]
fn a_non_numeric_trial_count_is_a_usage_error() {
    let s = Sandbox::new("test-badtrials");
    project_with_tests(&s);

    s.run(&["test", "--trials", "many"])
        .assert_failed()
        .assert_contains("--trials");
}

// ---------------------------------------------------------------------------
// run — the capability enforcement path
// ---------------------------------------------------------------------------

/// A component importing `qqq:clock/wall-clock`, as WAT.
const NEEDS_WALL_CLOCK: &str = r#"(component
  (import "qqq:clock/wall-clock@1.0.0" (instance $c
    (export "now" (func (result u64)))
    (export "resolution" (func (result u64)))
    (export "timezone" (func (result string)))
  ))
  (core module $m)
  (core instance $i (instantiate $m))
)"#;

/// An ungranted import is **refused**, and the error names the right capability.
///
/// This is the runtime half of the project's central claim. `inspect` reports
/// what an artifact needs; `run` is what enforces it, and an enforcement path
/// with no test is a claim rather than a guarantee.
///
/// The capability assertion is the regression test for a real defect: `run` used
/// the *package-level* mapping, so a component importing
/// `qqq:clock/wall-clock` was told to grant `clock.monotonic` — the other half
/// of the same package. That advice would have left the component still
/// failing, on the one error whose entire purpose is saying what to add.
#[test]
fn run_refuses_an_ungranted_import_and_names_the_right_capability() {
    let s = Sandbox::new("run-ungranted");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
    );
    let Some(wasm) = encode(&s, "wall", NEEDS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    let run = s.run(&["run", &wasm]);
    run.assert_failed()
        .assert_contains("qqq:clock/wall-clock")
        .assert_contains("capability: clock.wall");

    // The stanza lists both options for the package, which is correct — the
    // user may want either. What must **not** happen is the diagnostic naming
    // the wrong capability as the one implicated, which is what the defect did.
    //
    // Asserted on the `capability:` line specifically, not on the whole output:
    // a blunt `!contains("clock.monotonic")` failed on the legitimate stanza and
    // would have hidden the real check in a screen of text.
    // Bound first: `all()` builds a `String`, and the iterator would borrow a
    // temporary.
    let output = run.all();
    let implicated: Vec<&str> = output
        .lines()
        .filter(|l| l.trim_start().starts_with("capability:"))
        .collect();
    assert_eq!(implicated.len(), 1, "exactly one implicated capability");
    assert!(
        implicated[0].contains("clock.wall"),
        "the implicated capability must be the interface's own, not its package-mate: {}",
        implicated[0]
    );
}

/// The same component **runs** once the capability is granted.
///
/// The positive control. Without it, a `run` that refused everything would pass
/// the test above and the enforcement would look correct while being useless.
#[test]
fn run_executes_when_the_capability_is_granted() {
    let s = Sandbox::new("run-granted");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [capabilities.clock]\nwall = true\n",
    );
    let Some(wasm) = encode(&s, "wall", NEEDS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    s.run(&["run", &wasm]).assert_ok().assert_contains("ran in");
}

/// `--cap` **cannot widen** what the manifest granted.
///
/// The narrowing-only invariant, asserted at the command line rather than only
/// in the resolver's unit tests. A flag that could add authority would be a way
/// to defeat the manifest, which is the one thing the design forbids — and the
/// place to prove it is the interface a user actually types.
#[test]
fn a_cap_flag_cannot_widen_the_manifest() {
    let s = Sandbox::new("run-widen");
    // The manifest grants nothing at all.
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
    );
    let Some(wasm) = encode(&s, "wall", NEEDS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    s.run(&["run", &wasm, "--cap", "clock.wall"])
        .assert_failed()
        .assert_contains("no grant provides");
}

/// A bare positional names the **artifact**, not a component argument.
///
/// The regression test for a real defect: the positional was appended to the
/// component's arguments, so `qqqai run ./needs-clock.wasm` silently ran the
/// project's built component instead and reported success. The user got a
/// confident answer about something they had not asked for — the same class as
/// `qqqai inspect` discarding its path (`§O-038a`).
#[test]
fn a_positional_names_the_artifact() {
    let s = Sandbox::new("run-positional");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
    );
    let Some(wasm) = encode(&s, "wall", NEEDS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    // If the positional were still treated as a component argument, this would
    // succeed by running the (absent) built artifact and the import check would
    // never see the file.
    s.run(&["run", &wasm])
        .assert_failed()
        .assert_contains("qqq:clock/wall-clock");
}

/// `--dry-run` rehearses the whole pre-flight and runs nothing.
#[test]
fn run_dry_run_checks_grants_without_executing() {
    let s = Sandbox::new("run-dry");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [capabilities.clock]\nwall = true\n",
    );
    let Some(wasm) = encode(&s, "wall", NEEDS_WALL_CLOCK) else {
        eprintln!("SKIPPED: no wasm-tools available - this test did not run");
        return;
    };

    let run = s.run(&["run", "--dry-run", &wasm]);
    run.assert_ok().assert_contains("would run");
}

// ---------------------------------------------------------------------------
// global contracts
// ---------------------------------------------------------------------------

/// Every command emits valid JSON with the stable envelope under `--json`.
///
/// An agent branches on these fields, so their presence is a contract rather
/// than a formatting choice.
#[test]
fn every_command_emits_the_json_envelope() {
    let s = Sandbox::new("json-envelope");
    s.write("qqq.toml", MINIMAL);

    for args in [
        vec!["caps", "--json"],
        vec!["inspect", "--json"],
        vec!["doctor", "--json"],
        vec!["why", "crypto.hash", "--json"],
        vec!["schema", "--json"],
    ] {
        let run = s.run(&args);
        let line = run.stdout.lines().next().unwrap_or("");
        assert!(
            line.starts_with('{') && line.ends_with('}'),
            "`{}` did not emit a JSON object: {line:?}",
            args.join(" ")
        );
        for field in ["producer", "schema_version", "command", "ok"] {
            assert!(
                line.contains(&format!("\"{field}\"")),
                "`{}` is missing `{field}`: {line}",
                args.join(" ")
            );
        }
    }
}

/// The producer name is `qqqai`, never `qqq`.
///
/// The naming is settled: the brand is QQQ, the binary and every identifier a
/// machine sees are `qqqai`. A build producing `qqq` is a defect.
#[test]
fn the_binary_reports_itself_as_qqqai() {
    let s = Sandbox::new("naming");
    s.write("qqq.toml", MINIMAL);

    let run = s.run(&["caps", "--json"]);
    run.assert_ok().assert_contains("\"producer\":\"qqqai\"");
    assert!(
        !run.all().contains("\"producer\":\"qqq\""),
        "the producer must never be `qqq`:\n{}",
        run.all()
    );
}

/// An unknown capability is rejected with a code, not a panic.
#[test]
fn an_unknown_capability_is_an_error_not_a_crash() {
    let s = Sandbox::new("unknown-cap");
    s.write("qqq.toml", MINIMAL);

    let run = s.run(&["why", "not.a.capability"]);
    run.assert_failed().assert_contains("QQQ-");
}
