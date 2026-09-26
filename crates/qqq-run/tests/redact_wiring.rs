// SPDX-License-Identifier: Apache-2.0

//! `qqqai serve --redact-from` actually redacts — `OBS-008`, over the real binary.
//!
//! # Why this file exists when `qqq-serve/tests/access.rs` already redacts
//!
//! Because that test builds its `Logger` **in-process, with a `Redactor` constructed directly**:
//!
//! ```ignore
//! let logger = Logger::new(Format::Json, Level::Info)
//!     .with_redactor(Redactor::from_values(["s3cr3t-token"]));
//! ```
//!
//! It proves the *mechanism* works and says nothing about whether the server ever calls it. And
//! the server did not: `serve.rs` built `Logger::new(..)` — the empty redactor — and `server.rs`
//! imported four types from `access_log` and omitted `Redactor` (`§O-303`).
//!
//! **Invariant THREE has now appeared five times in this goal**: a control that is written, tested
//! and never called. The question that finds it is *"who calls this?"*, not *"does this work?"* —
//! so this test spawns the binary, passes a real file, and reads a real log line.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A scratch directory that is removed on drop.
struct Sandbox(PathBuf);

impl Sandbox {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-redact-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch");
        Self(p)
    }

    fn write(&self, name: &str, content: &str) -> PathBuf {
        let target = self.0.join(name);
        std::fs::write(&target, content).expect("write");
        target
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A port nobody else is using, taken and released.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().expect("addr").port();
    drop(l);
    p
}

const MANIFEST: &str = "[package]\nname = \"redact-probe\"\nversion = \"0.1.0\"\n\
     [server]\ndefault_auth = \"none\"\n\
     [[server.routes]]\npath = \"/orders\"\nmethods = [\"GET\"]\nhandler = \"list\"\n";

/// Spawn the server and return it with the port it was told to use.
fn spawn(sandbox: &Sandbox, extra: &[&str]) -> (Child, u16) {
    let config = sandbox.write("qqq.toml", MANIFEST);
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--config",
            config.to_str().expect("utf8"),
            // The server runs until signalled; a test that cannot bound it cannot end by itself,
            // and a test that ends by timing out cannot tell "finished" from "stuck".
            "--accept-limit",
            "1",
        ])
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qqqai serve");
    (child, port)
}

/// Wait for the port to accept, then make one request and return the server's combined output.
fn request_and_collect(child: Child, port: u16, path: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let _ = s.write_all(req.as_bytes());
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let out = child.wait_with_output().expect("wait");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Spawn, request and collect, **retrying the pair on a fresh port when the server produced nothing**.
///
/// # Why the pair and not each half
///
/// Because the lost race is *between* them: `free_port()` drops the listener and the child binds a
/// moment later, so a retry that reused the same port would lose the same race again. `spawn` and
/// `request_and_collect` are one attempt, and this is the retry around them — `§O-326`'s measured
/// cause, and the four sibling files each gained the same guard.
fn serve_and_collect(sandbox: &Sandbox, extra: &[&str], path: &str) -> String {
    for attempt in 1..=common::ATTEMPTS {
        let (child, port) = spawn(sandbox, extra);
        let out = request_and_collect(child, port, path);
        if !common::lost_the_port_race(&out) {
            return out;
        }
        eprintln!(
            "attempt {attempt} of {} produced no output; retrying on a fresh port",
            common::ATTEMPTS
        );
    }
    panic!(
        "all {} attempts produced no output. This is the port-allocation race this helper retries \
         around, not an assertion failure -- the server wrote nothing, so there is nothing to assert \
         about.",
        common::ATTEMPTS
    );
}

/// **A secret in the request path is redacted by the running server — `OBS-008`.**
///
/// This is the assertion the in-process test cannot make: it goes through the flag, the file, the
/// `Logger` and the emit path, so it fails if any one of them is not wired.
#[test]
fn the_served_log_line_redacts_a_declared_secret() {
    let sandbox = Sandbox::new("redacts");
    let secrets = sandbox.write("secrets.env", "TOKEN=s3cr3t-token\n");
    let output = serve_and_collect(
        &sandbox,
        &["--redact-from", secrets.to_str().expect("utf8")],
        "/orders?token=s3cr3t-token",
    );

    assert!(
        output.contains("[redacted:"),
        "the running server must redact a declared secret; output was: {output}"
    );
    assert!(
        !output.contains("s3cr3t-token"),
        "the secret must not appear anywhere in the server's output: {output}"
    );
}

/// **The count is reported and the values are not.**
///
/// A start-up message naming *what* is redacted would be the leak the redactor exists to prevent.
#[test]
fn the_start_up_message_reports_the_count_and_not_the_values() {
    let sandbox = Sandbox::new("count");
    let secrets = sandbox.write("secrets.env", "A=alpha-secret\nB=beta-secret\n");
    let output = serve_and_collect(
        &sandbox,
        &["--redact-from", secrets.to_str().expect("utf8")],
        "/orders",
    );
    assert!(
        output.contains("redacting 2 distinct secret value(s)"),
        "the count must be reported: {output}"
    );
    assert!(
        !output.contains("alpha-secret"),
        "but never a value: {output}"
    );
    assert!(
        !output.contains("beta-secret"),
        "nor the other one: {output}"
    );
}

/// **A malformed secrets file refuses the start rather than serving unredacted.**
///
/// The alternative is a server that believes it redacts and does not, which is worse than one that
/// never claimed to: the operator has no signal, and the secret is in the logs.
#[test]
fn a_malformed_secrets_file_refuses_the_start() {
    let sandbox = Sandbox::new("malformed");
    let secrets = sandbox.write("secrets.env", "GOOD=x\nNOT A PAIR\n");
    let config = sandbox.write("qqq.toml", MANIFEST);
    let port = free_port();

    let out = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--config",
            config.to_str().expect("utf8"),
            "--accept-limit",
            "1",
            "--redact-from",
            secrets.to_str().expect("utf8"),
        ])
        .output()
        .expect("run");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_ne!(
        out.status.code(),
        Some(0),
        "a malformed file must refuse: {combined}"
    );
    assert!(
        combined.contains("no `=`") || combined.contains("malformed"),
        "the refusal must say what was wrong: {combined}"
    );
    // And it must refuse BEFORE serving, not after a request.
    assert!(
        !combined.contains("listening"),
        "the refusal must come before the listener: {combined}"
    );
}

/// **A missing secrets file refuses the start.**
#[test]
fn a_missing_secrets_file_refuses_the_start() {
    let sandbox = Sandbox::new("missing");
    let config = sandbox.write("qqq.toml", MANIFEST);
    let port = free_port();

    let out = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--config",
            config.to_str().expect("utf8"),
            "--accept-limit",
            "1",
            "--redact-from",
            sandbox.0.join("absent.env").to_str().expect("utf8"),
        ])
        .output()
        .expect("run");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_ne!(
        out.status.code(),
        Some(0),
        "a missing file must refuse: {combined}"
    );
    assert!(
        combined.contains("could not be read"),
        "the refusal must name the read failure: {combined}"
    );
}
