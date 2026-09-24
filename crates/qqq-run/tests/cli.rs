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
        self.write_bytes(name, content.as_bytes());
    }

    /// Write raw bytes.
    ///
    /// # Why `write` delegates here rather than the reverse
    ///
    /// Because a signature is bytes, and a byte with the high bit set is not a `char` — so a
    /// fixture routed through `&str` would have to be encoded and decoded, and any asymmetry
    /// between the two would change the bytes being signed. One path, taking bytes, with the
    /// text convenience on top.
    fn write_bytes(&self, name: &str, content: &[u8]) {
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

/// `caps --explain` shows the reasoning, and plain `caps` does not.
///
/// # What this catches
///
/// Measured defect: `qqqai caps --explain` produced **byte-identical output** to
/// `qqqai caps`. The flag was parsed as unknown and dropped, so `§5.2`'s documented
/// `--explain` and `audit.rs`'s own instruction to run it both reached a command that did
/// nothing.
///
/// The two assertions are deliberate and different. "They differ" catches the flag being
/// ignored. "The explanation names the layer" catches it printing anything at all --
/// a test that only compared the strings would pass on a flag that emitted noise.
#[test]
fn caps_explain_adds_the_reasoning() {
    let s = Sandbox::new("caps-explain");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [capabilities.crypto]\nhash = [\"sha256\"]\n",
    );

    let plain = s.run(&["caps"]);
    plain.assert_ok();

    let explained = s.run(&["caps", "--explain"]);
    explained.assert_ok();

    assert_ne!(
        plain.stdout, explained.stdout,
        "`--explain` must change the human output; identical output is the defect this \
         test exists for"
    );
    explained
        .assert_contains("crypto.hash")
        .assert_contains("manifest")
        .assert_contains("declared in qqq.toml");
}

/// The reasoning appears in the envelope only when it was asked for.
///
/// `skip_serializing_if` rather than an always-present empty array: a consumer must be able
/// to tell "the caller did not ask" from "there were no decisions", and an empty array
/// conflates them.
#[test]
fn caps_json_grows_explained_only_when_asked() {
    let s = Sandbox::new("caps-explain-json");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [capabilities.crypto]\nhash = [\"sha256\"]\n",
    );

    let plain = s.run(&["caps", "--json"]);
    plain.assert_ok();
    assert!(
        !plain.stdout.contains("\"explained\""),
        "a plain `caps` must not carry the field:\n{}",
        plain.stdout
    );

    let explained = s.run(&["caps", "--explain", "--json"]);
    explained.assert_ok();
    assert!(
        explained.stdout.contains("\"explained\""),
        "`--explain --json` must carry the reasoning:\n{}",
        explained.stdout
    );
    assert!(
        explained.stdout.contains("\"layer\":\"manifest\""),
        "the explanation must name the layer that decided:\n{}",
        explained.stdout
    );
}

/// An unknown flag is refused, not ignored.
///
/// `caps --explan` previously exited 0 having printed the ordinary listing. A typo that
/// succeeds is worse than one that fails: there is nothing to notice. Same QQQ-7001 class
/// and same `exit::USAGE` as `build`'s and `run`'s unknown-flag refusals, so a script has
/// one behaviour to handle.
#[test]
fn caps_refuses_an_unknown_flag() {
    let s = Sandbox::new("caps-unknown-flag");
    s.write("qqq.toml", MINIMAL);

    let typo = s.run(&["caps", "--explan"]);
    typo.assert_failed()
        .assert_contains("unknown flag `--explan` for `caps`")
        .assert_contains("--explain");

    // The remediation is a single sentence. A stray line-continuation once left twenty-two
    // spaces in the middle of it, which only the JSON path made visible.
    let json = s.run(&["caps", "--explan", "--json"]);
    json.assert_failed();
    assert!(
        !json.stdout.contains("capability)  "),
        "the remediation must not carry a run of spaces:\n{}",
        json.stdout
    );
}

/// The signing seed every `verify` test uses, so a failure is reproducible.
const VERIFY_SEED: [u8; 32] = [0x42; 32];

/// Write a signed artifact and its `.sig` into the sandbox, and return the public key in hex.
///
/// Signing through `qqq_pkg::signature` rather than embedding a fixture: a stored `.sig` would
/// be a second copy of the format that drifts the moment either side changes, and a test that
/// asserts against a drifted fixture passes for the wrong reason.
fn signed_artifact(s: &Sandbox, name: &str, bytes: &[u8]) -> String {
    let sig = qqq_pkg::signature::sign(bytes, &VERIFY_SEED).expect("sign the fixture");
    s.write_bytes(name, bytes);
    s.write_bytes(&format!("{name}.sig"), &sig.to_bytes());

    let public = ed25519_dalek::SigningKey::from_bytes(&VERIFY_SEED)
        .verifying_key()
        .to_bytes();
    public.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// A signed artifact verifies, and the answer names the key and the digest.
///
/// # What this catches
///
/// `CLI-017` was an unimplemented command answering QQQ-6004. The assertions are the promises
/// §5.2 makes for `qqqai verify <artifact>`: it verifies, it says **which** key, and — since a
/// verification is about specific bytes — it reports the digest those bytes produced.
#[test]
fn verify_accepts_a_real_signature_and_names_the_key() {
    let s = Sandbox::new("verify-ok");
    s.write("qqq.toml", MINIMAL);
    let public = signed_artifact(&s, "app.wasm", b"the artifact bytes");

    let run = s.run(&["verify", "app.wasm", "--key", &public]);
    run.assert_ok()
        .assert_contains("signature verified against key")
        .assert_contains("digest sha256:")
        // The attestation half of §5.2 is not implemented, and the command says so rather
        // than letting "verified" be read as covering it.
        .assert_contains("attestation: not_checked")
        .assert_contains("SUP-004");

    let json = s.run(&["verify", "app.wasm", "--key", &public, "--json"]);
    json.assert_ok();
    assert!(
        json.stdout.contains("\"ok\":true") && json.stdout.contains("\"state\":\"verified\""),
        "the envelope must agree with the process status:\n{}",
        json.stdout
    );
}

/// One flipped byte is refused, with a non-zero status and the digest of what was refused.
///
/// # Why the digest is asserted on the failure path
///
/// Because the first question about a rejected artifact is "which bytes were rejected?", and a
/// report that answered only "signature failed" would leave the reader unable to tell a
/// corrupted download from a substituted file.
#[test]
fn verify_refuses_a_modified_artifact() {
    let s = Sandbox::new("verify-tampered");
    s.write("qqq.toml", MINIMAL);
    let public = signed_artifact(&s, "app.wasm", b"the artifact bytes");

    // Flip one byte, keeping the original signature.
    s.write_bytes("tampered.wasm", b"the artifact bytez");
    let sig = std::fs::read(s.path.join("app.wasm.sig")).expect("read the signature");
    s.write_bytes("tampered.wasm.sig", &sig);

    let run = s.run(&["verify", "tampered.wasm", "--key", &public]);
    run.assert_failed()
        .assert_contains("does not match the artifact")
        .assert_contains("sha256:");
}

/// An unsigned artifact is `unsigned` under an optional policy and a failure under `require`.
///
/// # Why the two statuses are asserted as a pair
///
/// Because they are the distinction `--policy` exists for. A test that checked only one would
/// pass if the flag were ignored and the policy were hard-coded either way.
#[test]
fn verify_distinguishes_an_absent_signature_from_a_failing_one() {
    let s = Sandbox::new("verify-unsigned");
    s.write("qqq.toml", MINIMAL);
    let public = signed_artifact(&s, "app.wasm", b"signed");
    s.write_bytes("bare.wasm", b"nobody signed this");

    let optional = s.run(&["verify", "bare.wasm", "--key", &public]);
    optional.assert_ok().assert_contains("unsigned");

    let required = s.run(&[
        "verify",
        "bare.wasm",
        "--key",
        &public,
        "--policy",
        "require",
    ]);
    required
        .assert_failed()
        .assert_contains("requires a signature");
}

/// A key the policy does not list is refused, and the remediation names the accepted ones.
#[test]
fn verify_refuses_a_key_the_policy_does_not_accept() {
    let s = Sandbox::new("verify-other-key");
    s.write("qqq.toml", MINIMAL);
    signed_artifact(&s, "app.wasm", b"the artifact bytes");

    let run = s.run(&["verify", "app.wasm", "--key", &"aa".repeat(32)]);
    run.assert_failed().assert_contains("does not accept");
}

/// A signature the policy cannot attribute is refused rather than accepted.
///
/// # Why this is the important negative case
///
/// A signature verified against *nothing* proves only that the file is internally consistent.
/// Treating "no keys configured" as "nothing to check, so pass" is the failure this guards,
/// and it is the one that would make `qqqai verify` decorative.
#[test]
fn verify_refuses_a_signature_it_cannot_attribute() {
    let s = Sandbox::new("verify-no-keys");
    s.write("qqq.toml", MINIMAL);
    signed_artifact(&s, "app.wasm", b"the artifact bytes");

    let run = s.run(&["verify", "app.wasm"]);
    run.assert_failed().assert_contains("no keys");
}

/// Argument mistakes are exit 2, distinct from a verification that ran and failed.
///
/// A gate that read "you typed the flag wrong" the same as "the artifact is untrusted" would
/// report a red build for a command that never checked anything.
#[test]
fn verify_reports_usage_errors_separately_from_findings() {
    let s = Sandbox::new("verify-usage");
    s.write("qqq.toml", MINIMAL);
    signed_artifact(&s, "app.wasm", b"x");

    // A malformed key names the length, because a truncated paste and a base64 key are the
    // two mistakes that actually happen.
    let bad_key = s.run(&["verify", "app.wasm", "--key", "abcd"]);
    bad_key.assert_failed().assert_contains("64 hex characters");

    let bad_policy = s.run(&["verify", "app.wasm", "--policy", "maybe"]);
    bad_policy
        .assert_failed()
        .assert_contains("is not a policy");

    let no_artifact = s.run(&["verify"]);
    no_artifact
        .assert_failed()
        .assert_contains("needs the artifact");
}

/// The §8.3 document carries every field §8.3 names.
///
/// # What this catches
///
/// Measured before: `qqqai schema --all` and `qqqai schema --command caps` both printed the
/// same one-line summary and dropped the flags, so the document §8.3 specifies could not be
/// obtained at all. The four fields that existed were emitted in **`snake_case`**
/// (`schema_version`), and `manifest`, `wit` and `mcp` were missing entirely.
///
/// §2.1 NN-1 says an agent can be given `qqqai schema --all` and write correct code from a
/// cold start. Every assertion here is one of the promises that claim rests on.
#[test]
fn schema_all_emits_the_section_8_3_document() {
    let s = Sandbox::new("schema-all");
    s.write("qqq.toml", MINIMAL);

    let run = s.run(&["schema", "--all", "--json"]);
    run.assert_ok();

    for field in [
        "\"qqqai\"",
        "\"schemaVersion\"",
        "\"commands\"",
        "\"errors\"",
        "\"manifest\"",
        "\"capabilities\"",
        "\"wit\"",
        "\"mcp\"",
    ] {
        assert!(
            run.stdout.contains(field),
            "the §8.3 document must carry {field}:\n{}",
            &run.stdout[..run.stdout.len().min(600)]
        );
    }

    // The camelCase spelling is the contract, and it lives **inside `data`**. The
    // envelope's own top-level `schema_version` is a different key on a different object, so
    // the check is scoped to the document rather than to the whole payload: a substring test
    // over stdout would pass or fail on which of the two happened to be spelled which way.
    let envelope: serde_json::Value =
        serde_json::from_str(&run.stdout).expect("the envelope must be valid JSON");
    let doc = &envelope["data"];
    assert!(
        doc.get("schemaVersion").is_some(),
        "§8.3 spells it `schemaVersion` inside the document, and a consumer generated from \
         the Proposal's example looks for that exact key; `data` carries: {:?}",
        doc.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
    assert!(
        doc.get("schema_version").is_none(),
        "the document must not carry the snake_case spelling as well: two keys for one fact \
         is how a consumer picks the wrong one"
    );

    // **Presence is not the property.** A substring check on `"manifest"` is satisfied by
    // `"manifest":null`, and §8.3's whole point is that these sections carry content. Each
    // one is asserted to be an object (or, for `commands`, a non-empty array), which is the
    // check that distinguishes "the section is there" from "the key is there".
    for section in ["manifest", "wit", "mcp"] {
        assert!(
            doc[section].is_object(),
            "§8.3's `{section}` section must be an object, not a placeholder; it is {:?}",
            doc[section]
        );
    }
    for section in ["commands", "errors", "capabilities"] {
        assert!(
            doc[section].as_array().is_some_and(|a| !a.is_empty()),
            "§8.3's `{section}` section must be a non-empty array; it is {:?}",
            doc[section]
        );
    }

    // A section that is an object but empty would still be a placeholder, so the one field
    // that states completeness is asserted directly rather than inferred from silence.
    assert_eq!(
        doc["wit"]["complete"],
        serde_json::Value::Bool(false),
        "`wit` must say explicitly that it is not the whole story rather than implying \
         completeness by silence"
    );
    assert_eq!(
        doc["mcp"]["complete"],
        serde_json::Value::Bool(false),
        "`mcp` must say explicitly that it is not the whole story"
    );
}

/// `--command <name>` narrows the command list and names the command it answered for.
#[test]
fn schema_command_narrows_and_names_the_command() {
    let s = Sandbox::new("schema-command");
    s.write("qqq.toml", MINIMAL);

    let narrowed = s.run(&["schema", "--command", "caps", "--json"]);
    narrowed.assert_ok();

    // **Parsed, not substring-matched.** The nested `commands` entry is
    // `{"command":"caps",...}`, which serializes to the same text a top-level field would —
    // so `stdout.contains("\"command\":\"caps\"")` is satisfied by the nested entry alone
    // and cannot see the top-level one go missing. Proved by injection: removing the
    // top-level assignment left that substring intact and the test passing.
    let envelope: serde_json::Value =
        serde_json::from_str(&narrowed.stdout).expect("the envelope must be valid JSON");
    let doc = &envelope["data"];
    assert_eq!(
        doc.get("command").and_then(|v| v.as_str()),
        Some("caps"),
        "the answer must name the command at the **top level**, so a caller does not have to \
         search a one-element array to confirm what it got; `data` carries: {:?}",
        doc.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
    assert_eq!(
        doc["commands"].as_array().map(Vec::len),
        Some(1),
        "the command list must be narrowed to the one asked for"
    );
    assert_eq!(
        doc["commands"][0]["command"].as_str(),
        Some("caps"),
        "and that one entry must be the command asked for"
    );

    // The full document still carries every section: asking about one command narrows the
    // command list, and does not turn the document into a command-only fragment.
    for field in ["\"errors\"", "\"manifest\"", "\"wit\"", "\"mcp\""] {
        assert!(
            narrowed.stdout.contains(field),
            "narrowing to one command must not drop {field}"
        );
    }
}

/// An unknown command name is a usage error, not an empty answer.
///
/// An empty `commands` map reads as "this command has no schema". The truth is "that command
/// does not exist", and the two need different fixes — so the refusal names the valid ones.
#[test]
fn schema_refuses_an_unknown_command_name() {
    let s = Sandbox::new("schema-unknown");
    s.write("qqq.toml", MINIMAL);

    let run = s.run(&["schema", "--command", "nope"]);
    run.assert_failed()
        .assert_contains("`nope` is not a command");

    // The remediation lists the commands, because the next action is to pick a real one.
    run.assert_contains("known commands: new, init");

    let json = s.run(&["schema", "--command", "nope", "--json"]);
    json.assert_failed();
    assert!(
        json.stdout.contains("\"exit_code\":2"),
        "the envelope must agree with the process status:\n{}",
        json.stdout
    );

    // An unknown *flag* is refused too, and lists what `schema` accepts.
    let flag = s.run(&["schema", "--bogus"]);
    flag.assert_failed()
        .assert_contains("unknown flag `--bogus` for `schema`");
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
///
/// # Why this asserts `assert_failed` and not `assert_ok`
///
/// It asserted `assert_ok` until 2026-09-24, which **enshrined** the bug: a denied
/// capability exited `0`, so a grant and a denial were indistinguishable to a
/// script. The test passed and the command could not gate anything. Measured on the
/// shipped binary before the fix:
///
/// ```text
/// granted  human  process=0
/// denied   human  process=0
/// denied   json   process=0  envelope_exit_code=0
/// ```
#[test]
fn why_prints_the_stanza_for_a_denied_capability() {
    let s = Sandbox::new("why-denied");
    s.write("qqq.toml", MINIMAL);

    s.run(&["why", "fs.read"])
        .assert_failed()
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
    // The status is the other test's subject; this one counts text, so it asserts
    // only that the run happened and produced output.
    run.assert_failed();
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

/// **The status tells a grant from a denial, and the envelope agrees.**
///
/// The pair is the contract: a script asking "can this build reach the network?"
/// runs `qqqai why http.client` and reads the status. A denial sharing exit `0` with
/// a grant makes the command unable to answer, which is most of what §5.2 defines it
/// for.
///
/// The envelope check is the second half and not decoration: `Envelope::exit_code`
/// was hardcoded to `0` in one renderer once (`§O-208`), and a test that reads only
/// the process status would have missed it. Both must agree.
#[test]
fn why_exit_status_separates_a_grant_from_a_denial() {
    let s = Sandbox::new("why-status");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [capabilities.crypto]\nhash = [\"sha256\"]\n",
    );

    // A grant: success, and the envelope says 0.
    let granted = s.run(&["why", "crypto.hash", "--json"]);
    granted.assert_ok();
    assert!(
        granted.stdout.contains("\"granted\":true"),
        "the grant must be reported:\n{}",
        granted.stdout
    );
    assert!(
        granted.stdout.contains("\"exit_code\":0"),
        "the envelope must carry the status the process returned:\n{}",
        granted.stdout
    );

    // A denial: **non-zero**, and the envelope says the same.
    let denied = s.run(&["why", "http.client", "--json"]);
    denied.assert_failed();
    assert!(
        denied.stdout.contains("\"granted\":false"),
        "the denial must be reported:\n{}",
        denied.stdout
    );
    assert!(
        denied.stdout.contains("\"exit_code\":1"),
        "the envelope must carry the same non-zero status the process returned, or a \
         script reading JSON would still see a denial as success:\n{}",
        denied.stdout
    );
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

// ---------------------------------------------------------------------------
// audit — the output must be the *whole* contract, in every mode
// ---------------------------------------------------------------------------
//
// These four tests exist because 25 unit tests over `audit.rs` passed while
// `qqqai audit` printed its conclusion twice and `qqqai audit --sarif` could not
// be piped into a SARIF consumer. Every unit test asserted on `render()`,
// `summary()` or `to_sarif()` in isolation; none asserted on what the process
// put on stdout. The defects lived in the seam between two components that were
// each individually correct, so the regression tests have to run the binary.

/// A project that trips at least one rule, so the audit has something to say.
const AUDITING: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                        [[capabilities.fs]]\npath = \".\"\nmode = \"read-write\"\n";

/// The conclusion is printed **once**.
///
/// `AuditReport::render` ended with its own `N finding(s); worst severity: X`
/// footer *and* the output layer independently emitted `summary()`, in slightly
/// different words. A human reading two different conclusions has to decide
/// which to believe.
#[test]
fn audit_prints_its_conclusion_exactly_once() {
    let s = Sandbox::new("audit-once");
    s.write("qqq.toml", AUDITING);

    let run = s.run(&["audit"]);
    run.assert_ok();

    for phrase in ["worst severity", "finding(s)"] {
        let n = run.stdout.matches(phrase).count();
        assert_eq!(
            n, 1,
            "`{phrase}` must appear once, found {n}\nstdout:\n{}",
            run.stdout
        );
    }
}

/// `--sarif` must be the entire stdout stream.
///
/// The consumer this flag exists for — GitHub code scanning, a `jq` pipeline —
/// reads stdout as one document. Measured broken twice: once with the render
/// footer after the document, once with the envelope summary before it. Both
/// produced `Extra data` from a JSON parser, which is exactly what the check
/// below looks for without needing a JSON library in the test.
#[test]
fn audit_sarif_is_the_only_thing_on_stdout() {
    let s = Sandbox::new("audit-sarif-pure");
    s.write("qqq.toml", AUDITING);

    let run = s.run(&["audit", "--sarif"]);
    run.assert_ok();

    let trimmed = run.stdout.trim();
    assert!(
        trimmed.starts_with('{'),
        "stdout must begin with the SARIF document, not prose:\n{}",
        run.stdout
    );
    assert!(
        trimmed.ends_with('}'),
        "stdout must end with the SARIF document, not a summary line:\n{}",
        run.stdout
    );
    assert!(
        trimmed.contains("\"version\":\"2.1.0\""),
        "must be a SARIF 2.1.0 document:\n{}",
        run.stdout
    );
    // A second JSON object on the stream is the failure mode.
    assert_eq!(
        run.stdout.matches("\"$schema\"").count(),
        1,
        "exactly one SARIF document:\n{}",
        run.stdout
    );
}

/// `--json` must be parseable, and the parseable thing must be the envelope.
///
/// `render()` was written unconditionally, so `--json audit` emitted five lines
/// of human prose and *then* the envelope. Every `qqqai` command promises
/// "one envelope per invocation" — this one broke it, and the same
/// `some_command_emits_the_json_envelope` helper could not catch it because the
/// prose came first and the envelope still existed somewhere in the output.
#[test]
fn audit_json_is_parseable_and_only_the_envelope() {
    let s = Sandbox::new("audit-json");
    s.write("qqq.toml", AUDITING);

    let run = s.run(&["audit", "--json"]);
    run.assert_ok();

    let lines: Vec<&str> = run
        .stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "`--json` must be a single line, got {}:\n{}",
        lines.len(),
        run.stdout
    );
    let line = lines[0];
    assert!(
        line.starts_with('{') && line.ends_with('}'),
        "the line must be a JSON object:\n{line}"
    );
    for field in [
        "\"producer\":\"qqqai\"",
        "\"command\":\"audit\"",
        "\"ok\":true",
    ] {
        assert!(line.contains(field), "missing {field}:\n{line}");
    }
    assert!(
        !run.stdout.contains("worst severity:\n"),
        "the human rendering must not share the stream with `--json`:\n{}",
        run.stdout
    );
}

/// A threshold must gate **every** output mode.
///
/// `meets_threshold` was computed inside the non-SARIF branch, so
/// `audit --sarif --fail-on note` exited `0` while `audit --fail-on note`
/// exited `1`. A CI job gating on SARIF — the reason the format is offered —
/// would have been green forever. This is the highest-value test in the group:
/// the failure mode is a **silent pass**, which no amount of reading the SARIF
/// output would reveal.
#[test]
fn audit_fail_on_gates_every_output_mode() {
    let s = Sandbox::new("audit-fail-on-modes");
    s.write("qqq.toml", AUDITING);

    for args in [
        vec!["audit", "--fail-on", "note"],
        vec!["audit", "--sarif", "--fail-on", "note"],
        vec!["audit", "--json", "--fail-on", "note"],
    ] {
        let run = s.run(&args);
        assert_eq!(
            run.code,
            1,
            "`{}` must exit 1 on a note-level finding\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            run.stdout,
            run.stderr
        );
    }

    // ...and a threshold above the worst finding must not gate.
    for args in [
        vec!["audit", "--fail-on", "error"],
        vec!["audit", "--sarif", "--fail-on", "error"],
    ] {
        let run = s.run(&args);
        run.assert_ok();
    }
}

/// The envelope reports the threshold decision, so an agent reading `--json`
/// sees *why* the process failed without consulting the exit code.
#[test]
fn audit_json_reports_the_threshold_decision() {
    let s = Sandbox::new("audit-json-failed");
    s.write("qqq.toml", AUDITING);

    let run = s.run(&["audit", "--json", "--fail-on", "note"]);
    assert_eq!(
        run.code, 1,
        "expected the threshold to gate:\n{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("\"failed\":true"),
        "the envelope must say the threshold gated:\n{}",
        run.stdout
    );

    // With no threshold given the field is absent rather than `false`: "not
    // asked" and "asked and satisfied" are different answers.
    let clean = s.run(&["audit", "--json"]);
    clean.assert_ok();
    assert!(
        !clean.stdout.contains("\"failed\""),
        "an ungated audit must omit `failed`:\n{}",
        clean.stdout
    );
}

// ---------------------------------------------------------------------------
// openapi — the document must describe the routes the server actually serves
// ---------------------------------------------------------------------------

/// A manifest exercising the route shapes `openapi` has to handle: a single
/// method, several methods on one path, and a route parameter.
const SERVING: &str = "[package]\nname = \"app\"\nversion = \"1.2.3\"\n\
                       [[server.routes]]\npath = \"/healthz\"\nmethods = [\"GET\"]\nhandler = \"h\"\n\
                       [[server.routes]]\npath = \"/orders\"\nmethods = [\"GET\", \"POST\"]\nhandler = \"list\"\n\
                       [[server.routes]]\npath = \"/orders/:id\"\nmethods = [\"GET\", \"DELETE\"]\nhandler = \"one\"\n";

/// `openapi` prints one line per path and exits zero.
#[test]
fn openapi_summarises_the_routes() {
    let s = Sandbox::new("openapi-summary");
    s.write("qqq.toml", SERVING);

    let run = s.run(&["openapi"]);
    run.assert_ok().assert_contains("3 paths");
    assert!(
        run.stdout.contains("OpenAPI 3.0.3"),
        "the human output must name the version it emits:\n{}",
        run.stdout
    );
}

/// `:id` is a **route** placeholder; `OpenAPI` spells parameters `{id}`.
///
/// Emitting the path verbatim would produce a document whose paths do not
/// match the URLs the server serves, which is worse than no document.
#[test]
fn openapi_rewrites_route_placeholders() {
    let s = Sandbox::new("openapi-params");
    s.write("qqq.toml", SERVING);

    let run = s.run(&["openapi", "--out", "openapi.json"]);
    run.assert_ok();

    let doc = s.read("openapi.json");
    assert!(
        doc.contains("\"/orders/{id}\""),
        "the parameter must be rewritten to OpenAPI syntax:\n{doc}"
    );
    assert!(
        !doc.contains(":id"),
        "the route syntax must not survive into the document:\n{doc}"
    );
}

/// The document must be rejected, not half-written, when a route is unservable.
///
/// `CONNECT` has no `OpenAPI` operation object. Silently dropping it would
/// understate the surface the manifest exposes — the document would say the
/// route does not exist. The whole command must fail instead.
#[test]
fn openapi_refuses_an_unservable_method() {
    let s = Sandbox::new("openapi-connect");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
         [[server.routes]]\npath = \"/tunnel\"\nmethods = [\"CONNECT\"]\nhandler = \"t\"\n",
    );

    let run = s.run(&["openapi"]);
    run.assert_failed();
    assert!(
        run.stderr.contains("CONNECT") || run.stdout.contains("CONNECT"),
        "the refusal must name the offending method:\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
}

/// `--out` writes the document, and stdout stays the envelope.
#[test]
fn openapi_out_keeps_stdout_clean() {
    let s = Sandbox::new("openapi-out");
    s.write("qqq.toml", SERVING);

    let run = s.run(&["openapi", "--out", "api.json"]);
    run.assert_ok();

    let doc = s.read("api.json");
    assert!(
        doc.trim_start().starts_with('{'),
        "the written document must be JSON, not a report:\n{doc}"
    );
    assert!(
        !run.stdout.contains("\"openapi\""),
        "the document must not also land on stdout:\n{}",
        run.stdout
    );
}

// -- `qqqai fmt` and `qqqai lint` (`CLI-014`) ------------------------------

/// A manifest whose language is `rust`, so the driver path is reachable.
fn style_manifest(language: &str) -> String {
    format!(
        "[package]\nname = \"style\"\nversion = \"0.1.0\"\n\n\
         [build]\nlanguage = \"{language}\"\ntarget = \"wasm32-wasip2\"\n"
    )
}

/// A language with no style driver is refused by name, and the refusal names its owner.
///
/// # Why this is the test that matters most here
///
/// The tempting implementation answers "0 problems" for any language whose tool is not
/// wired, and that answer is indistinguishable in a CI log from a real clean run. So the
/// assertion is not merely that the command fails - it is that it fails *for go* and names
/// `LANG-`, which is the checklist area that owns the driver.
#[test]
fn fmt_refuses_a_language_with_no_driver_and_names_the_owner() {
    let s = Sandbox::new("fmt-go");
    s.write("qqq.toml", &style_manifest("go"));
    let run = s.run(&["fmt"]);
    run.assert_failed()
        .assert_contains("go")
        .assert_contains("fmt")
        .assert_contains("LANG-");
    // The control against a refusal that rejects every language alike: `go` IS a language
    // this build knows, so the "not a language" message would be a different bug.
    assert!(
        !run.stdout.contains("not a language this build can drive"),
        "a declared language must not be reported as unknown: {}",
        run.stdout
    );
}

/// `lint` refuses for the same reason and with the same shape, so the pair does not diverge.
#[test]
fn lint_refuses_a_language_with_no_driver_and_names_the_owner() {
    let s = Sandbox::new("lint-go");
    s.write("qqq.toml", &style_manifest("go"));
    let run = s.run(&["lint"]);
    run.assert_failed()
        .assert_contains("go")
        .assert_contains("lint")
        .assert_contains("LANG-");
}

/// Refusal is a usage-shaped failure with a remediation a reader can act on.
///
/// Asserted separately from the message because `QQQ-1003` carries the install/support
/// pointer, and a bare exit code would satisfy a weaker test while leaving the user stuck.
#[test]
fn a_style_refusal_carries_the_checklist_pointer() {
    let s = Sandbox::new("fmt-ts");
    s.write("qqq.toml", &style_manifest("ts"));
    let run = s.run(&["fmt"]);
    run.assert_failed()
        .assert_contains("QQQ-1003")
        .assert_contains("QQQ-Checklist-V1.md");
}

/// Both verbs need a project, and say so rather than guessing a language.
#[test]
fn fmt_without_a_manifest_says_so() {
    let s = Sandbox::new("fmt-nomanifest");
    let run = s.run(&["fmt"]);
    run.assert_failed().assert_contains("qqq.toml");
}

/// `--json` is a global flag and must not be read as a language or a path.
///
/// # Why this parses the envelope rather than searching the text
///
/// `assert_contains("QQQ-1003")` passes just as well on the human rendering, so it says nothing
/// about whether `--json` did anything. The claim under test is *"the output is a JSON
/// envelope"*, and the only way to check that is to parse it — the same lesson `§O-220` records
/// for substring assertions on serialized documents.
#[test]
fn style_accepts_the_global_json_flag() {
    let s = Sandbox::new("lint-json");
    s.write("qqq.toml", &style_manifest("go"));
    let run = s.run(&["lint", "--json"]);
    run.assert_failed();

    let doc: serde_json::Value = serde_json::from_str(&run.stdout).unwrap_or_else(|e| {
        panic!(
            "--json must emit a parseable envelope, got {e}\n--- stdout ---\n{}",
            run.stdout
        )
    });
    // The envelope's error shape, not merely the presence of a code in the text.
    let text = serde_json::to_string(&doc).expect("serialize");
    assert!(
        text.contains("QQQ-1003"),
        "the envelope must carry the code: {text}"
    );
    assert!(
        doc.get("error").is_some() || doc.get("code").is_some() || doc.get("errors").is_some(),
        "the envelope must have an error field, got: {text}"
    );
}

/// A failing style tool must fail the process, and this is the regression test for the defect.
///
/// # Why this test exists
///
/// Measured before the fix: `dispatch_style` called `with_manifest`, which maps every `Ok` to
/// `exit::OK`. `style::run` returns `Ok(StyleOutcome { ok: false, .. })` when clippy fails, so
/// `qqqai lint` on un-lintable code printed *"lint reported problems (exit 101)"* and then
/// **exited 0**. The module doc claimed the opposite — a stated invariant the code did not
/// enforce, which is `§O-124`'s shape.
///
/// The two halves are asserted together because either alone is satisfied by a broken command: a
/// `lint` that always failed would pass the failing case, and one that always succeeded would
/// pass the clean case.
#[test]
fn lint_exits_non_zero_when_the_tool_reports_problems() {
    let s = Sandbox::new("lint-exit-status");

    // A Rust project with a clippy-detectable defect (`clone_on_copy`), plus the manifest.
    //
    // `[workspace]` is in the generated `Cargo.toml` deliberately. Without it cargo searches
    // *upward* for a workspace root and can find an unrelated manifest outside the sandbox —
    // measured on this machine, it reached `C:\Users\Usuario\Cargo.toml` and failed with
    // "invalid potential workspace manifest", which made the clean-code control fail for a
    // reason that has nothing to do with `qqqai lint`.
    s.write("qqq.toml", &style_manifest("rust"));
    s.write(
        "Cargo.toml",
        "[package]\nname = \"lintexit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    );
    s.write(
        "src/main.rs",
        "pub fn f() -> i32 {\n    let x = 1;\n    let y = x.clone();\n    y\n}\nfn main() { println!(\"{}\", f()); }\n",
    );

    let dirty = s.run(&["lint"]);
    dirty.assert_failed();
    assert!(
        dirty.stdout.contains("problems") || dirty.stderr.contains("clone_on_copy"),
        "the failing run must say what happened:\n{}{}",
        dirty.stdout,
        dirty.stderr
    );

    // The control: the same command on clean source must exit 0, or the assertion above is
    // satisfied by a `lint` that fails unconditionally.
    s.write(
        "src/main.rs",
        "pub fn f() -> i32 {\n    1\n}\nfn main() { println!(\"{}\", f()); }\n",
    );
    let clean = s.run(&["lint"]);
    clean.assert_ok();
}

/// An unknown flag is refused rather than ignored.
///
/// # Why this is a security-shaped test
///
/// Measured before the fix: `qqqai lint --check` ran a full lint and exited **0**. A caller
/// asking for a check got a green result from a flag nothing implemented, which is the
/// `CWE-636` fail-open shape external review flagged. The same arm in `verify` silently dropped
/// misspelled flags, so `--policy requier` left the policy *opportunistic* and let an unsigned
/// artifact pass a check the caller believed was mandatory.
#[test]
fn style_refuses_a_flag_it_does_not_understand() {
    let s = Sandbox::new("lint-badflag");
    s.write("qqq.toml", &style_manifest("rust"));
    let run = s.run(&["lint", "--check"]);
    run.assert_failed()
        .assert_contains("--check")
        .assert_contains("does not accept");
    // The exit status distinguishes a usage error from a finding.
    assert_eq!(
        run.code, 2,
        "an unknown flag is a usage error (2), not a finding: {}",
        run.stdout
    );
}

/// A misspelled `--policy` value must not silently become the permissive policy.
#[test]
fn verify_refuses_an_unknown_flag_rather_than_ignoring_it() {
    let s = Sandbox::new("verify-badflag");
    s.write("app.wasm", "not really a component");
    let run = s.run(&["verify", "app.wasm", "--policy", "requier"]);
    run.assert_failed().assert_contains("is not a policy");
    assert_eq!(
        run.code, 2,
        "a bad flag value is a usage error: {}",
        run.stdout
    );

    let unknown = s.run(&["verify", "app.wasm", "--check"]);
    unknown.assert_failed().assert_contains("not a flag");
    assert_eq!(
        unknown.code, 2,
        "an unknown flag is a usage error: {}",
        unknown.stdout
    );
}
