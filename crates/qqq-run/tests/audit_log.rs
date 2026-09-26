// SPDX-License-Identifier: Apache-2.0

//! `qqqai audit-log` reads a record a server wrote — over the real binary, from a real file.
//!
//! # Why these tests spawn the binary rather than calling the dispatcher
//!
//! Because the thing under test is the **command**, and the parts of a command that a unit test
//! cannot reach are the ones that break: whether the name is registered, whether the flag parses,
//! whether the document reaches stdout unwrapped. `serve_policy.rs` records the same reasoning for
//! `qqqai serve`, and it was earned there — every feature in that file had been implemented,
//! unit-tested and **unreachable**.
//!
//! # Why the file is built with the library rather than checked in
//!
//! A checked-in record would be a fixture whose chain a future change to the chain's *definition*
//! would silently invalidate — the file would still parse and stop verifying, and the failure would
//! look like a regression in the command. Building it here means the fixture is computed by the same
//! code the server uses.

use std::path::{Path, PathBuf};
use std::process::Command;

use qqq_cap::capability::Capability;
use qqq_host::audit::{AuditStream, Outcome};
use qqq_host::audit_sink::AuditFile;
use qqq_host::tenant::{ComponentDigest, GrantDigest};

/// A scratch directory that is removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-audit-log-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch");
        Self(p)
    }
    fn file(&self) -> PathBuf {
        self.0.join("audit.jsonl")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Write a two-record record: one granted use and one refusal.
fn write_record(path: &Path) {
    let component = ComponentDigest::new("0011223344556677").expect("digest");
    let grants = GrantDigest::new("aabbccdd").expect("digest");
    let mut stream = AuditStream::with_default_capacity();
    let _ = stream.record(
        None,
        &component,
        &grants,
        Capability::FsRead,
        "handle_request",
        Outcome::Granted,
    );
    let _ = stream.record(
        None,
        &component,
        &grants,
        Capability::FsWrite,
        "handle_request",
        Outcome::Denied,
    );
    let mut sink = AuditFile::open(path).expect("open");
    for record in stream.records() {
        sink.append(record).expect("append");
    }
}

fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args(args)
        .output()
        .expect("spawn qqqai");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// **The compliance report reaches stdout, and names the chain head.**
#[test]
fn the_report_is_rendered_from_a_real_record() {
    let scratch = Scratch::new("report");
    let path = scratch.file();
    write_record(&path);

    let (stdout, stderr, code) = run(&["audit-log", path.to_str().expect("utf8")]);
    assert_eq!(code, 0, "a readable record must succeed; stderr: {stderr}");
    assert!(
        stdout.contains("QQQ capability-audit compliance report"),
        "the report must reach stdout: {stdout}"
    );
    assert!(
        stdout.contains("Chain verified : yes (2 record(s)"),
        "and must state how many records verified: {stdout}"
    );
    assert!(
        stdout.contains("Refusals, individually"),
        "and list the refusal: {stdout}"
    );
    assert!(
        stdout.contains("fs.write"),
        "naming the capability that was refused: {stdout}"
    );
}

/// **`--sarif` emits SARIF and nothing else.**
///
/// A consumer parsing the output as SARIF must receive SARIF — the same rule `qqqai audit --sarif`
/// states, and the reason the document is not wrapped in this CLI's usual envelope.
#[test]
fn sarif_is_the_whole_document() {
    let scratch = Scratch::new("sarif");
    let path = scratch.file();
    write_record(&path);

    let (stdout, stderr, code) = run(&["audit-log", path.to_str().expect("utf8"), "--sarif"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let trimmed = stdout.trim();
    assert!(
        trimmed.starts_with('{') && trimmed.ends_with('}'),
        "SARIF must be the whole document, not wrapped: {trimmed}"
    );
    assert!(trimmed.contains("\"version\":\"2.1.0\""), "got: {trimmed}");
    assert!(
        trimmed.contains("qqq/capability-denied"),
        "the refusal must be a result: {trimmed}"
    );
    // And it must parse, which is the property a substring cannot establish.
    let parsed: serde_json::Value = serde_json::from_str(trimmed).expect("must parse as JSON");
    assert_eq!(parsed["version"], "2.1.0");
}

/// **A file that is not a stream is refused, and the refusal names the file.**
#[test]
fn a_broken_record_is_refused_with_the_path() {
    let scratch = Scratch::new("broken");
    let path = scratch.file();
    write_record(&path);

    // Tamper: rewrite the second record's chain digest, leaving valid JSON.
    let text = std::fs::read_to_string(&path).expect("read");
    let lines: Vec<&str> = text.lines().collect();
    let good = lines[1]
        .split("\"chain\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("a chain digest in the second record")
        .to_owned();
    std::fs::write(&path, text.replace(&good, &"0".repeat(good.len()))).expect("tamper");

    let (stdout, stderr, code) = run(&["audit-log", path.to_str().expect("utf8")]);
    assert_ne!(code, 0, "a tampered record must fail; stdout: {stdout}");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("broken chain") || combined.contains("could not be read"),
        "the refusal must say why: {combined}"
    );
    assert!(
        combined.contains("audit.jsonl"),
        "and must name the file: {combined}"
    );
}

/// **A missing path is a usage error, not a crash.**
#[test]
fn a_missing_argument_is_a_usage_error() {
    let (stdout, stderr, code) = run(&["audit-log"]);
    assert_ne!(code, 0);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("--audit-log") || combined.contains("needs the file"),
        "the error must point at the flag that writes it: {combined}"
    );
}

/// **The command is listed, and it is distinct from `audit`.**
///
/// `§O-297` recorded the risk: two documents sharing a format and nearly a name. The help text is
/// where an operator finds out they are different.
#[test]
fn the_command_is_discoverable_and_distinct() {
    let (stdout, _, _) = run(&["--help"]);
    assert!(
        stdout.contains("audit-log"),
        "the command must be listed: {stdout}"
    );
    assert!(
        stdout.contains("persisted capability-use record"),
        "and its summary must say what it reads: {stdout}"
    );
    // Both exist, and they read different things.
    assert!(stdout.contains("audit") && stdout.contains("audit-log"));
}
