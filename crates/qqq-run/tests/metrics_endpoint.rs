// SPDX-License-Identifier: Apache-2.0

//! The Prometheus scrape endpoint — `OBS-013`, over the real binary.
//!
//! # Why this file exists, and why it is the second version
//!
//! `§O-308` recorded that the *renderer* was built and the endpoint was not. The first attempt at
//! the endpoint **worked and was reverted** (`§O-309`), for three reasons this file is written
//! against:
//!
//! 1. **The first failure was the test's, not the code's.** The assertion checked a lowercase
//!    `content-type:` and the response emits `Content-Type:`. So the assertions below check the
//!    **value** (`text/plain; version=0.0.4`), which is what a scraper actually uses, rather than a
//!    header's spelling.
//! 2. **The harness hung rather than failed.** A read with no deadline on a connection the server
//!    keeps alive blocks forever, and *a hang is not a diagnosis* — it costs a full timeout and says
//!    nothing. **Every read below has a deadline.**
//! 3. **`clippy::too_many_lines` fired on three different functions**, because a one-line addition
//!    to a function at its budget is not a one-line addition. That was fixed in the code, not here.
//!
//! # The three questions `§O-308` left open, and the answers asserted here
//!
//! 1. **Where** — on the application listener, opt-in via `--metrics-path`. A separate admin port is
//!    the conventional answer and a larger change; it is recorded, not half-built.
//! 2. **Opt-in** — yes, and `nothing_is_exposed_without_the_flag` keeps the default honest.
//! 3. **Collision** — refused at start-up, because a silent shadow hides either an app route or the
//!    metrics and neither is visible from outside.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long any single read may block. **A deadline, not a hope**: without it a server that keeps
/// the connection alive turns an assertion failure into a hang, and a hang tells you nothing.
///
/// # Why 30 s and not 5
///
/// 5 s was the first value and it was **too short under CI load**, where four tests each spawn a
/// server alongside the rest of the workspace. Measured on Ubuntu: the read expired, the response
/// came back **empty**, and — this is the part that matters — the test still *failed correctly* but
/// for a reason its message did not name (`§O-313`). A test that waits longer is better than one
/// that flakes.
const READ_DEADLINE: Duration = Duration::from_secs(30);

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-metrics-{tag}-{}", std::process::id()));
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

const MANIFEST: &str = "[package]\nname = \"metrics-probe\"\nversion = \"0.1.0\"\n\
     [server]\ndefault_auth = \"none\"\n\
     [[server.routes]]\npath = \"/orders\"\nmethods = [\"GET\"]\nhandler = \"list\"\n";

/// Serve one request, **retrying on a fresh port when the client reads nothing**.
///
/// # Why this retries, and what it is retrying
///
/// `free_port()` **binds a port, reads it, and drops the listener** — so between the drop and the
/// child's bind the number is unowned, and on a loaded runner another process (or another test in this
/// file) can take it. Measured on Ubuntu three times: the client reads **nothing**, and the server's
/// own output is **empty**, which is what a child that never bound looks like.
///
/// **Two fixes were tried and both were wrong** — a longer deadline, then a higher accept limit — and
/// each was recorded as a hypothesis rather than a fix. **Neither addressed the allocation**, which is
/// the thing the evidence points at.
///
/// So this **retries the whole attempt on a fresh port**. That is honest about what it is: **a bounded
/// retry around a known-unreliable allocation**, not a repair of it. The real repair is for the server
/// to report the address it *bound* rather than the one it was asked for, which would let these tests
/// use `--listen 127.0.0.1:0` and remove the allocation entirely.
///
/// # Why the retry is here and not in each test
///
/// Because every assertion in this file is a `contains`, and **`!contains(x)` is satisfied by nothing
/// at all** — so an empty read must be handled once, centrally, or an absence assertion silently
/// passes.
fn request_once(sandbox: &Sandbox, extra: &[&str], target: &str) -> String {
    const ATTEMPTS: u32 = 4;
    for attempt in 1..=ATTEMPTS {
        let response = attempt_once(sandbox, extra, target);
        if !response.is_empty() {
            return response;
        }
        eprintln!("attempt {attempt} of {ATTEMPTS} read nothing; retrying on a fresh port");
    }
    panic!(
        "all {ATTEMPTS} attempts read nothing. This is the port-allocation race this helper retries \
         around, not an assertion failure -- the server answered no bytes, so there is nothing to \
         assert about."
    );
}

/// One attempt: a fresh port, a fresh child, one request.
fn attempt_once(sandbox: &Sandbox, extra: &[&str], target: &str) -> String {
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
            "4",
        ])
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut response = String::new();
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = s.set_read_timeout(Some(READ_DEADLINE));
            let req = format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let _ = s.write_all(req.as_bytes());
            let _ = s.read_to_string(&mut response);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // The child is killed rather than waited on: if the server did not exit, waiting would hang the
    // test, and what this function is for is the bytes on the wire.
    let mut child = child;
    let _ = child.kill();
    let mut child = child;
    let _ = child.kill();
    let out = child.wait_with_output().expect("reap");

    // An empty read is returned **as empty**, so the wrapper above can retry it on a fresh port. It
    // is reported here with the server's own output, because a child that never bound prints nothing
    // -- and **that silence is the diagnosis**: a request that timed out would still have produced a
    // start-up line.
    if response.is_empty() {
        eprintln!(
            "  the server answered nothing within {READ_DEADLINE:?}; its own output was: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    response.push_str(&String::from_utf8_lossy(&out.stdout));
    response.push_str(&String::from_utf8_lossy(&out.stderr));
    response
}

/// Run the binary and return its output, for the start-up refusals that never listen.
fn run_refused(sandbox: &Sandbox, extra: &[&str]) -> String {
    let config = sandbox.write("qqq.toml", MANIFEST);
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--config",
            config.to_str().expect("utf8"),
            "--accept-limit",
            "4",
        ])
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    // Bounded: a refusal exits at once, and a server that did NOT refuse would run forever. Waiting
    // unbounded is how the first version of this file hung instead of failing.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => break,
            None if Instant::now() > deadline => {
                let _ = child.kill();
                break;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let out = child.wait_with_output().expect("reap");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// **The exposition is served, with the content type a scraper needs — `OBS-013`.**
#[test]
fn the_endpoint_serves_the_exposition() {
    let sandbox = Sandbox::new("serves");
    let response = request_once(
        &sandbox,
        &["--metrics-path", "/internal/metrics"],
        "/internal/metrics",
    );

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the endpoint must answer 200: {response}"
    );
    // The VALUE, not the header's spelling: the response emits `Content-Type` and the first version
    // of this test asserted a lowercase name -- failing about a working endpoint.
    assert!(
        response.contains("text/plain; version=0.0.4"),
        "the content type names the exposition format, without which a scraper cannot parse it: \
         {response}"
    );
    assert!(
        response.contains("# TYPE qqq_http_requests_total counter"),
        "and the body is the exposition: {response}"
    );
    // **The scrape does not count itself**, and that is the correct ordering rather than a gap: the
    // body is rendered before the access record for this request is emitted, so a count written
    // afterwards cannot appear in it. The first version of this test asserted a self-count and
    // failed — about a working endpoint, which is `§O-309`'s finding in miniature.
    assert!(
        !response.contains("qqq_http_requests_total{"),
        "the scrape must not count itself: the body is rendered before its own record is written: \
         {response}"
    );
    assert!(
        response.contains("qqq_http_request_duration_seconds_count 0"),
        "and the histogram reports no observations yet, for the same reason: {response}"
    );
}

/// **Nothing is exposed without the flag — the default is honest.**
///
/// The registry holds **tenant names and traffic volume**; who may read that is the operator's
/// decision, not the framework's.
#[test]
fn nothing_is_exposed_without_the_flag() {
    let sandbox = Sandbox::new("off");
    let response = request_once(&sandbox, &[], "/internal/metrics");
    assert!(
        !response.contains("qqq_http_requests_total"),
        "the exposition must not be reachable without `--metrics-path`: {response}"
    );
    assert!(
        response.contains("404"),
        "and the path is simply not a route: {response}"
    );
}

/// **A path that collides with a declared route refuses the start.**
#[test]
fn a_collision_with_a_declared_route_refuses_the_start() {
    let sandbox = Sandbox::new("collide");
    let combined = run_refused(&sandbox, &["--metrics-path", "/orders"]);
    assert!(
        combined.contains("is also a route in the manifest"),
        "the refusal must name the collision: {combined}"
    );
    assert!(
        !combined.contains("listening"),
        "and must come before the listener: {combined}"
    );
}

/// **A relative path refuses the start, because it could never match a request target.**
///
/// A server that accepted `--metrics-path metrics` would name an endpoint in the operator's command
/// line that can never answer — the "looks configured" failure this repository refuses elsewhere.
#[test]
fn a_relative_path_refuses_the_start() {
    let sandbox = Sandbox::new("relative");
    let combined = run_refused(&sandbox, &["--metrics-path", "metrics"]);
    assert!(
        combined.contains("is not an absolute path"),
        "the refusal must say what is wrong: {combined}"
    );
}
