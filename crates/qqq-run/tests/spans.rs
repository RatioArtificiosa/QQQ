// SPDX-License-Identifier: Apache-2.0

//! Automatic spans and host-controlled sampling — `OBS-009` and `OBS-011`, over the real binary.
//!
//! # Why this file exists
//!
//! `§O-311` recorded that a `span` module was built and **reverted because nothing called it**, and
//! that `OBS-009`/`010`/`011`/`014` formed a **subtree with no root**: no span was ever emitted, so
//! there was nothing to propagate, nothing to sample, and nothing for a guest to try to influence.
//!
//! This is the root. The module's own doctests cover the constructor; **these cover the wiring** —
//! that a request through `qqqai serve` produces a span, that the default produces none, and that a
//! rate is a real rate.
//!
//! # The read discipline `§O-309` and `§O-314` earned
//!
//! **Every read has a deadline, and an empty read is a failure in itself.** `!response.contains(x)`
//! is satisfied by an empty response, so an assertion about *absence* cannot tell "the server
//! answered correctly" from "the server answered nothing" — which is how a test of mine once failed
//! with a message about a missing 404 when the truth was an expired read.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long any single read may block. **A deadline, not a hope.**
///
/// 30 s rather than 5: the smaller value is enough on a developer machine and not under CI load,
/// where several tests each spawn a server alongside the rest of the workspace (`§O-314`).
const READ_DEADLINE: Duration = Duration::from_secs(30);

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-span-{tag}-{}", std::process::id()));
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

const MANIFEST: &str = "[package]\nname = \"span-probe\"\nversion = \"0.1.0\"\n\
     [server]\ndefault_auth = \"none\"\n\
     [[server.routes]]\npath = \"/orders\"\nmethods = [\"GET\"]\nhandler = \"list\"\n";

/// Serve `count` requests on one server and return everything it wrote.
fn serve(sandbox: &Sandbox, extra: &[&str], count: u32) -> String {
    // **A bounded retry, because the port this helper asks for may be taken before the child binds.**
    //
    // `free_port()` binds a number, reads it, and **drops the listener** -- so between the drop and
    // the child's bind the number is unowned. That is `§O-326`'s measured cause, and this file's
    // helper had no retry while a sibling's did. **Six copies of one racy helper was the object all
    // along**, and the fix belongs in each of them until they share one.
    for attempt in 1..=common::ATTEMPTS {
        let out = attempt_serve(sandbox, extra, count);
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

fn attempt_serve(sandbox: &Sandbox, extra: &[&str], count: u32) -> String {
    let config = sandbox.write("qqq.toml", MANIFEST);
    let port = free_port();
    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--config",
            config.to_str().expect("utf8"),
            "--accept-limit",
            &count.to_string(),
        ])
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut served = 0;
    let mut lost = false;
    while served < count && Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = s.set_read_timeout(Some(READ_DEADLINE));
            let _ = s.write_all(b"GET /orders HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            // **An empty read is a failure in itself, asserted here once rather than in each
            // caller.** `!contains(x)` is satisfied by an empty response, so an absence assertion
            // cannot tell a correct answer from no answer at all.
            // **Return empty so the wrapper can retry, rather than asserting here.**
            //
            // This was an `assert!`, and it made the retry above **inert for the one failure it
            // exists to retry**: the panic happens *inside* the attempt, so the wrapper never sees a
            // result to inspect. **A retry cannot retry what the attempt asserts about.** Measured on
            // CI: `no_span_without_the_flag` failed with *"the server answered nothing within 30s on
            // request 1 of 1"* -- this assertion, not the wrapper's message.
            if buf.is_empty() {
                // A lost race: stop probing, but let the reap below run. **A `return` here would
                // leave the child unwaited** -- clippy's `zombie_processes` caught exactly that, and
                // it is a real leak rather than a lint.
                lost = true;
                break;
            }
            served += 1;
        }
    }

    // Killed rather than waited on: a server that did not exit would hang the test, and what this is
    // for is the bytes.
    let _ = child.kill();
    let out = child.wait_with_output().expect("reap");
    // **The retry signal, decided after the reap** -- so every path kills and waits, and a lost race
    // leaves no process behind.
    if lost || served != count {
        return String::new();
    }
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// **`--trace-sample on` emits a span for the §4.4 step the request passed through — `OBS-009`.**
#[test]
fn a_sampled_request_emits_a_span() {
    let sandbox = Sandbox::new("on");
    let out = serve(&sandbox, &["--trace-sample", "on"], 1);
    assert!(
        out.contains("span step=3"),
        "the request must produce a span for ROUTE MATCH: {out}"
    );
    assert!(
        out.contains("name=ROUTE MATCH"),
        "and the step's name comes from `lifecycle`, so a span cannot invent one: {out}"
    );
    assert!(out.contains("micros="), "and it carries a duration: {out}");
}

/// **Without the flag, no span is emitted — the default is quiet.**
///
/// A span per §4.4 step multiplies log volume, and whether that is wanted is the operator's decision.
#[test]
fn no_span_without_the_flag() {
    let sandbox = Sandbox::new("off");
    let out = serve(&sandbox, &[], 1);
    assert!(
        !out.contains("span step="),
        "no span may be emitted without `--trace-sample`: {out}"
    );
}

/// **`--trace-sample off` emits none, and still serves the request.**
///
/// The second half is the part that matters: a sampler that dropped the *request* rather than the
/// *span* would be a sampling feature that broke the server.
#[test]
fn trace_sample_off_serves_but_does_not_span() {
    let sandbox = Sandbox::new("off-flag");
    let out = serve(&sandbox, &["--trace-sample", "off"], 1);
    assert!(
        !out.contains("span step="),
        "`off` must emit no span: {out}"
    );
    // **The request is still served and still logged.** The project has no built artifact, so the
    // response is 503 from the unbuilt handler -- and a sampler that dropped the *request* rather
    // than the *span* would be a sampling feature that broke the server.
    //
    // Asserted on the access record's own fields rather than on the handler's header: stdout is
    // piped here, so `Format::for_terminal(false)` emits JSON, and the header is on the wire rather
    // than in the log.
    assert!(
        out.contains("/orders") && out.contains("503"),
        "and the request must still be served and logged: {out}"
    );
}

/// **A rate of `0.25` is a real rate: some traces sampled, some not — `OBS-011`.**
///
/// The decision is taken from the trace id, which the host allocates per connection, so a run of
/// requests against a 1-in-4 rate produces **both** outcomes. A sampler stuck at always or never
/// would satisfy every other test in this file.
///
/// # This is the test that caught the tail option
///
/// `§O-317`: with the tail option on for every policy, and a failure read from `status >= 500`, a
/// project answering 503 to everything sampled **24 of 24** — the rate was not the rate. The
/// assertion below is what said so.
#[test]
fn a_quarter_rate_produces_both_outcomes() {
    let sandbox = Sandbox::new("quarter");
    let out = serve(&sandbox, &["--trace-sample", "0.25"], 24);
    let sampled = out.matches("span step=").count();
    assert!(
        sampled > 0,
        "a 1-in-4 rate must sample something out of 24 requests: {sampled} spans"
    );
    assert!(
        sampled < 24,
        "and must drop something: {sampled} spans for 24 requests"
    );
}

/// **The tail option keeps a trace the head dropped — §10.4's *"tail sampling option"*.**
///
/// With `--trace-keep-failures` and a project whose every response is 503, a `0.25` rate keeps
/// **everything**, because every request is a failure the option exists to keep. That is the
/// behaviour, stated: the option is an **exception to the rate**, which is why it is a flag of its
/// own and not bundled into `--trace-sample`.
#[test]
fn the_tail_option_keeps_every_failure() {
    let sandbox = Sandbox::new("tail");
    let out = serve(
        &sandbox,
        &["--trace-sample", "0.25", "--trace-keep-failures"],
        24,
    );
    let sampled = out.matches("span step=").count();
    assert_eq!(
        sampled, 24,
        "with the tail option on and every response a 503, every trace is a failure it keeps: \
         {sampled} spans for 24 requests"
    );
}
