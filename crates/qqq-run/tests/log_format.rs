// SPDX-License-Identifier: Apache-2.0

//! §10.3's log format, chosen from the stream — `OBS-007`, over the real binary.
//!
//! # Why this file exists
//!
//! `qqqai serve` built `Logger::new(Format::Human, ..)` unconditionally. §10.3 says:
//!
//! > *"Structured JSON by default; human-readable in a TTY."*
//!
//! So a server whose stdout is a **pipe into a log collector** emitted the human encoding — the
//! rule inverted, in the direction that loses the structure the collector needs. The unit tests in
//! `access_log.rs` assert the policy function; this asserts that the **server consults it**.
//!
//! # Why a child process is the only way to test this
//!
//! Because the input is `stdout().is_terminal()`, and a test harness's stdout is not the server's.
//! `Command` with a piped stdout is a non-terminal — which is precisely the production case — and
//! there is no way to fake that in-process without testing a different thing.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-logfmt-{tag}-{}", std::process::id()));
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

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().expect("addr").port();
    drop(l);
    p
}

const MANIFEST: &str = "[package]\nname = \"logfmt-probe\"\nversion = \"0.1.0\"\n\
     [server]\ndefault_auth = \"none\"\n\
     [[server.routes]]\npath = \"/orders\"\nmethods = [\"GET\"]\nhandler = \"list\"\n";

/// Serve one request and return the server's combined output.
fn serve_once(sandbox: &Sandbox, extra: &[&str]) -> String {
    // **A bounded retry, because the port this helper asks for may be taken before the child binds.**
    //
    // `free_port()` binds a number, reads it, and **drops the listener** -- so between the drop and
    // the child's bind the number is unowned. That is `§O-326`'s measured cause, and this file's
    // helper had no retry while a sibling's did. **Six copies of one racy helper was the object all
    // along**, and the fix belongs in each of them until they share one.
    for attempt in 1..=common::ATTEMPTS {
        let out = attempt_serve_once(sandbox, extra);
        if !common::lost_the_port_race(&out) {
            return out;
        }
        eprintln!(
            "attempt {attempt} of {} read nothing; retrying on a fresh port",
            common::ATTEMPTS
        );
    }
    panic!(
        "all {} attempts read nothing. This is the port-allocation race this helper retries around, \
         not an assertion failure -- the server answered no bytes, so there is nothing to assert \
         about.",
        common::ATTEMPTS
    );
}

fn attempt_serve_once(sandbox: &Sandbox, extra: &[&str]) -> String {
    let config = sandbox.write("qqq.toml", MANIFEST);
    let port = free_port();
    let child: Child = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--config",
            config.to_str().expect("utf8"),
            "--accept-limit",
            "1",
        ])
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qqqai serve");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = s.write_all(b"GET /orders HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
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

/// **With stdout piped — not a terminal — the served log line is JSON — `OBS-007`.**
///
/// This is the production case: a server whose output goes to a collector. Before the fix it
/// emitted the human encoding, so a collector received a line it could not parse.
#[test]
fn a_piped_server_logs_json() {
    let sandbox = Sandbox::new("piped");
    let output = serve_once(&sandbox, &[]);

    // The record itself, not just the shape: `{"level":` is the first thing a JSON line carries.
    assert!(
        output.contains("{\"level\":\""),
        "a piped server must emit the structured encoding; output was: {output}"
    );
    assert!(
        output.contains("\"trace_id\":") && output.contains("\"tenant\":"),
        "and the mandatory §10.3 fields: {output}"
    );
}

/// **`--log-format human` overrides the stream, so a piped server can still be read by a person.**
#[test]
fn the_flag_overrides_the_stream() {
    let sandbox = Sandbox::new("human");
    let output = serve_once(&sandbox, &["--log-format", "human"]);

    assert!(
        !output.contains("{\"level\":\""),
        "the override must suppress the JSON encoding: {output}"
    );
    // The human record still carries the same facts, in its own shape.
    assert!(
        output.contains("GET /orders"),
        "and the record must still describe the request: {output}"
    );
}

/// **A typo in the format refuses the start, naming both spellings.**
///
/// A server that silently ignored `--log-format jsonn` would emit the other encoding and look
/// configured — the same failure mode `--redact-from` refuses.
#[test]
fn a_format_typo_refuses_the_start() {
    let sandbox = Sandbox::new("typo");
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
            "--log-format",
            "jsonn",
        ])
        .output()
        .expect("run");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_ne!(out.status.code(), Some(0), "a typo must refuse: {combined}");
    assert!(
        combined.contains("`json` or `human`"),
        "the refusal must list the accepted spellings: {combined}"
    );
    assert!(
        !combined.contains("listening"),
        "and must come before the listener: {combined}"
    );
}
