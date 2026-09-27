// SPDX-License-Identifier: Apache-2.0

//! The port-race retry — `§O-355`'s two halves, each tested in both directions.
//!
//! **One retry decision has two halves**: *how long to wait* (`reap_within`, which bounds a wait that
//! used to be unbounded) and *whether to retry at all* (`should_retry`, which used to be blind to the
//! failure it exists for). Both live here because **both were wrong**, and because fixing one without
//! the other converts a hang into a red CI run rather than into a passing one — which is exactly what
//! happened: the bound turned an ubuntu hang into a 30-second assertion failure, and the predicate is
//! what makes it retry instead.
//!
//! # Why these tests assert a DECISION rather than a duration
//!
//! `common::reap_within` bounds a child wait that used to be unbounded, and **the failure mode it
//! prevents is a hang, not an assertion failure.** A test that proved the bound by removing it would
//! hang the suite — the incident rather than the test. So the helper returns **whether it had to
//! kill**, and these tests assert that decision: injectable, and safe to run.
//!
//! # The two directions, and why one is not enough
//!
//! 1. A child that **never exits** must be killed, and the reap must still return.
//! 2. A child that **exits on its own** must **not** be killed.
//!
//! Asserting only (1) would be satisfied by `child.kill()` followed by an unconditional reap — which
//! is the same defect in the other direction, and would race `log_format.rs`'s log line out of
//! existence while these tests still passed.

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{free_port, lost_the_port_race, reap_within, should_retry, Sandbox, ATTEMPTS};

/// A minimal manifest that `serve` accepts, so the child's only way out is a signal.
const MANIFEST: &str = "[package]\nname = \"reap-probe\"\nversion = \"0.1.0\"\n\
     [server]\ndefault_auth = \"none\"\n\
     [[server.routes]]\npath = \"/orders\"\nmethods = [\"GET\"]\nhandler = \"list\"\n";

/// **A child that never exits is killed, and the reap returns.**
///
/// The child is `qqqai serve` with **no `--accept-limit`** — the shape that hangs a bare
/// `wait_with_output()` forever, and the shape two test files actually used.
///
/// # The premise is CHECKED, not assumed
///
/// `free_port()` documents that the number is unowned between the drop and the child's bind, so a
/// lost race makes `serve` exit immediately — and then **there is nothing to bound**, and a test that
/// reported success would be reporting a bound it never exercised (`§O-280`). Each attempt checks
/// that the child was still running before reaping, retries on a fresh port, and fails naming the
/// race rather than the helper.
#[test]
fn a_child_that_never_exits_is_killed_and_the_reap_returns() {
    let mut last = String::new();
    for attempt in 1..=ATTEMPTS {
        let sandbox = Sandbox::new(&format!("reap-never-{attempt}"));
        let config = sandbox.write("qqq.toml", MANIFEST);
        let port = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_qqqai"))
            .args([
                "serve",
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--config",
                config.to_str().expect("utf8"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn qqqai serve");

        // Give it long enough to either bind or fail, so the reap below is measuring a RUNNING child.
        std::thread::sleep(Duration::from_millis(400));

        let started = Instant::now();
        let (out, killed) = reap_within(child, Duration::from_millis(750));
        let elapsed = started.elapsed();
        last = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        if !killed {
            eprintln!(
                "attempt {attempt} of {ATTEMPTS}: the server exited on its own, so there was nothing \
                 to bound; retrying on a fresh port. Its output was: {last}"
            );
            continue;
        }

        assert!(
            elapsed >= Duration::from_millis(750),
            "the deadline must actually be waited for rather than short-circuited: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "and the reap must then RETURN rather than keep waiting: {elapsed:?}"
        );
        // The child's output is still collected after the kill, which is why the helper kills rather
        // than dropping the handle — `log_format.rs` asserts on a line the server wrote.
        assert!(
            !last.is_empty(),
            "a killed child's output is still readable, which is the point of killing rather than \
             abandoning it"
        );
        return;
    }

    panic!(
        "the server exited on its own on all {ATTEMPTS} attempts, so **the bound was never \
         exercised** — this is the port race `free_port()` documents, not a failure of the reap. \
         Last output: {last}"
    );
}

/// **A child that exits on its own is NOT killed.**
///
/// Because `log_format.rs` asserts on the server's own log line, written as the request is served. A
/// helper that killed unconditionally would race that line away — and the test above would still
/// pass, which is why this direction exists.
#[test]
fn a_child_that_exits_on_its_own_is_not_killed() {
    let child = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qqqai --version");

    let (out, killed) = reap_within(child, Duration::from_secs(30));

    assert!(
        !killed,
        "a child that finished on its own must NOT be killed -- killing it would race its output, \
         and this is the direction the never-exits test cannot check"
    );
    assert!(
        out.status.success(),
        "and its exit status is reported rather than replaced by a signal: {:?}",
        out.status
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("qqqai"),
        "and its output survived the reap"
    );
}

/// **The retry predicate sees the third way an attempt fails — `§O-355`.**
///
/// # The case that hung CI, stated as an assertion
///
/// A lost port race leaves a child that **started, logged `listening on ...`, and then never accepted
/// anything**. Its output is therefore **non-empty and names no error**, so `lost_the_port_race`
/// — which sees only an empty read or a `QQQ-6002` bind failure — returns **false** for it. The first
/// two assertions below are that fact: the text alone cannot see this failure, and an attempt that
/// never connected must still be retried.
///
/// # And the three cases the predicate already covered
///
/// Because a predicate that retried *everything* would also pass the case above, and would turn a
/// genuinely broken server into four attempts and a confusing panic instead of one clear failure.
#[test]
fn the_retry_predicate_sees_an_attempt_that_never_reached_the_server() {
    // The child's own startup line: what a lost race actually leaves behind.
    let logged = "{\"level\":\"info\",\"msg\":\"listening on 127.0.0.1:56542\"}";

    assert!(
        !lost_the_port_race(logged),
        "the text alone cannot see this failure -- that is the whole defect, so this assertion is \
         what would break if `should_retry` were reduced to `lost_the_port_race` again"
    );
    assert!(
        should_retry(false, logged),
        "**an attempt that never connected must be retried**, whatever the child happened to log"
    );

    // The cases the old predicate did cover, still covered.
    assert!(should_retry(false, ""), "nothing read at all");
    assert!(
        should_retry(true, "QQQ-6002 the address is already in use"),
        "the child reported the bind failure"
    );
    assert!(
        should_retry(true, ""),
        "connected, but the server wrote nothing"
    );

    // And the case that must NOT retry: a served attempt is finished, log line and all.
    assert!(
        !should_retry(true, logged),
        "a server that connected and exited on its own is a completed attempt, not a lost race -- \
         retrying it would hide a real failure behind four attempts"
    );
    assert!(
        !should_retry(true, "HTTP/1.1 200 OK\r\n\r\n{}"),
        "and neither is a clean response"
    );
}
