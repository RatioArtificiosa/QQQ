// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for the tests that run `qqqai serve` over a real socket — `§O-326`'s route 1.
//!
//! # Why this module exists
//!
//! **Six test files carried their own copy of the same helper**, and the flake that four rounds of
//! fixes chased was not a test — it was **the pattern**, present six times. Two of the six have now
//! flaked on Ubuntu, and each fix had been aimed at whichever file happened to fail.
//!
//! `§O-326` measured that and named two routes. **Route 2 is closed by design** — `ListenAddr::parse`
//! refuses port `0` on purpose, and its own comment says why:
//!
//! > *"Port 0 asks the OS for any free port. That is legitimate in a test harness and dangerous in a
//! > manifest, because the deployed service would listen somewhere nobody knows. Refused here, and the
//! > test helper uses an explicit high port instead."*
//!
//! So the design **anticipated this exact situation** and chose the manifest's safety over the
//! harness's convenience — **which is the right trade** — and told the helper what to do: **use an
//! explicit high port.** This module is that helper, in one place.
//!
//! # What it can and cannot fix
//!
//! `free_port()` binds a port, reads it, and **drops the listener** — so between the drop and the
//! child's bind the number is unowned, and another process can take it. **That race is inherent to
//! the design's chosen approach and this module does not pretend otherwise.** What it does is:
//!
//! 1. **Retry the whole attempt on a fresh port** when the server answers nothing, so a lost race is
//!    a retry rather than a failure;
//! 2. **Do it in one place**, so the next six files inherit it instead of re-inventing it;
//! 3. **Never hand back an empty response** — every assertion in these files is a `contains`, and
//!    `!contains(x)` is satisfied by nothing at all (`§O-314`).
//!
//! # Why `dead_code` is allowed
//!
//! Each test binary compiles this module separately and uses a **subset** of it. Without the allow,
//! every binary that does not call a given helper reports it as dead — which is a fact about Rust's
//! test harness, not about this code.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long any single read may block. **A deadline, not a hope** (`§O-309`).
///
/// 30 s rather than 5: the smaller value is enough on a developer machine and not under CI load,
/// where several test binaries each spawn a server alongside the rest of the workspace (`§O-314`).
pub const READ_DEADLINE: Duration = Duration::from_secs(30);

/// How many times a helper retries a lost port race before giving up.
pub const ATTEMPTS: u32 = 4;

/// A scratch directory that removes itself.
pub struct Sandbox(PathBuf);

impl Sandbox {
    /// A fresh, empty directory named for `tag`.
    pub fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch");
        Self(p)
    }

    /// Write a file into the sandbox and return its path.
    pub fn write(&self, name: &str, content: &str) -> PathBuf {
        let target = self.0.join(name);
        std::fs::write(&target, content).expect("write");
        target
    }

    /// A target dir the sandbox owns, for children that resolve artifacts through
    /// `CARGO_TARGET_DIR`.
    ///
    /// The directory is intentionally left uncreated and empty: the sandbox project is
    /// unbuilt by design, and an empty lookup must resolve to "no component". Inheriting
    /// the ambient variable lets a same-named artifact from a shared target root satisfy
    /// the lookup instead, and the child then serves (or dies on) a foreign guest —
    /// measured on the Linux bridge, where the gate's own `app.wasm` killed every
    /// `serve_policy` spawn. Same mechanism as `cli.rs`'s `target_dir_for`.
    pub fn target_dir(&self) -> PathBuf {
        self.0.join(".cargo-target")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A port that was free a moment ago, and may not be now.
///
/// # Why this is not a defect to fix here
///
/// `ListenAddr::parse` refuses port `0` **on purpose** and its comment says the test helper should use
/// an explicit high port. This is that helper, and **the window between the drop and the child's bind
/// is the price of the design's choice** — accepted deliberately, mitigated by [`serve_and_request`]'s
/// retry rather than pretended away.
pub fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().expect("addr").port();
    drop(l);
    p
}

/// A server serving one request, with the bytes it wrote.
pub struct Served {
    /// What the client read: the HTTP response, then the server's own output.
    pub text: String,
}

/// Spawn `qqqai serve`, make one request, and return everything written.
///
/// **Retries the whole attempt on a fresh port when the client reads nothing.** That is the mitigation
/// for the allocation race above: a lost race becomes a retry, and an exhausted retry **names the
/// race** rather than an assertion that never ran.
pub fn serve_and_request(
    sandbox: &Sandbox,
    manifest: &str,
    extra: &[&str],
    target: &str,
) -> Served {
    for attempt in 1..=ATTEMPTS {
        let served = attempt_once(sandbox, manifest, extra, target);
        if !served.text.is_empty() {
            return served;
        }
        eprintln!("attempt {attempt} of {ATTEMPTS} read nothing; retrying on a fresh port");
    }
    panic!(
        "all {ATTEMPTS} attempts read nothing. This is the port-allocation race this helper retries \
         around, not an assertion failure -- the server answered no bytes, so there is nothing to \
         assert about."
    );
}

/// Whether this output is **the port race**, by the error the loser reports.
///
/// # Why the code and not emptiness
///
/// A child that **failed to bind** does not write nothing — it writes `QQQ-6002` and exits. So a retry
/// keyed on emptiness never fires for the failure it exists to retry, and a retry keyed on a missing
/// HTTP response cannot serve the files that observe the server's **log** rather than its response.
///
/// **The bind failure is the one signal both kinds of helper see**, and it names the race instead of
/// inferring it. Measured twice: the first condition (`!text.is_empty()`) was inert, the second
/// (`!answered`) broke three files that never see a status line.
pub fn lost_the_port_race(text: &str) -> bool {
    // **Two signals, because the helpers report the loss two ways.**
    //
    // A helper that observes the server's *log* returns it, so a child that failed to bind shows up as
    // `QQQ-6002` in the text. A helper that observes the *response* returns empty when the read came
    // back with nothing. The first version of this predicate covered only the code, so for the
    // response-observing helpers it answered `false` on an empty result and the wrapper **returned the
    // emptiness instead of retrying it** -- measured on CI as `spans::no_span_without_the_flag`
    // failing at its own assertion.
    text.is_empty() || text.contains("QQQ-6002")
}

/// Whether an attempt should be **retried on a fresh port**.
///
/// # Why this is one function and not a condition at each call site
///
/// Because it was a condition at each call site, and **both were wrong the same way** (`§O-355`).
/// Each retry loop tested only `lost_the_port_race(&text)`, which sees two things: an empty read, and
/// the child's own `QQQ-6002` bind failure. It **cannot** see the third way an attempt fails — a child
/// that started, logged `listening on ...`, and then never accepted anything — because that child's
/// output is **non-empty and names no error**.
///
/// That case is reachable exactly when `free_port()`'s race is lost, and it was **invisible** for as
/// long as the wait after it never returned: the job hung instead of the attempt being retried.
/// Bounding the wait (`reap_within`) made it visible, and on ubuntu it made `redact_wiring` fail an
/// assertion after exactly `READ_DEADLINE` instead of retrying.
///
/// # Why `reached` rather than a cleverer parse of the text
///
/// Because the caller **knows** whether it connected. Inferring it from the output would be a guess
/// about a child's logging, and the signal is a fact at the call site and an inference here.
#[must_use]
pub fn should_retry(reached: bool, text: &str) -> bool {
    !reached || lost_the_port_race(text)
}

/// Whether the server **answered at all** — an HTTP status line is present.
///
/// # Why this and not `is_empty`
///
/// Because the combined text carries the child's own output, and a child that **failed to bind** —
/// the exact shape of a lost port race — still writes an error. **A retry keyed on emptiness would
/// never fire for the failure it exists to retry.**
pub fn answered(text: &str) -> bool {
    text.contains("HTTP/1.1 ")
}

/// One attempt: a fresh port, a fresh child, one request.
fn attempt_once(sandbox: &Sandbox, manifest: &str, extra: &[&str], target: &str) -> Served {
    let config = sandbox.write("qqq.toml", manifest);
    let port = free_port();
    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--config",
            config.to_str().expect("utf8"),
            "--accept-limit",
            "8",
        ])
        .args(extra)
        // Sandbox-local target dir: `Sandbox::target_dir` explains why the ambient one
        // must not leak into the child.
        .env("CARGO_TARGET_DIR", sandbox.target_dir())
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

    // Killed rather than waited on: a server that did not exit would hang the test, and what this is
    // for is the bytes.
    let _ = child.kill();
    let out = child.wait_with_output().expect("reap");

    if response.is_empty() {
        eprintln!(
            "  the server answered nothing within {READ_DEADLINE:?}; its own output was: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    response.push_str(&String::from_utf8_lossy(&out.stdout));
    response.push_str(&String::from_utf8_lossy(&out.stderr));
    Served { text: response }
}

/// Run the binary and return its output, for the start-up refusals that never listen.
///
/// Bounded: a refusal exits at once, and a server that did **not** refuse would run forever — waiting
/// unbounded is how the first version of one of these files hung instead of failing (`§O-309`).
pub fn run_refused(sandbox: &Sandbox, manifest: &str, extra: &[&str]) -> String {
    let config = sandbox.write("qqq.toml", manifest);
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--config",
            config.to_str().expect("utf8"),
            "--accept-limit",
            "8",
        ])
        .args(extra)
        // Sandbox-local target dir: `Sandbox::target_dir` explains why the ambient one
        // must not leak into the child.
        .env("CARGO_TARGET_DIR", sandbox.target_dir())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

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

/// Reap a child **within a deadline**, killing it if it outlives one.
///
/// Returns the child's output and **whether it had to be killed** — the flag is what makes this
/// testable without a test that hangs when the bound is removed (`§O-355`).
///
/// # What this prevents
///
/// `Child::wait_with_output()` has **no timeout**. Called on a child that never exits, it blocks
/// forever — and on CI that is not a failing test, it is a job that runs until GitHub's 360-minute
/// default. Measured: `d2fea05`'s `Rust (ubuntu-latest)` sat at the `test` step for **70+ minutes**
/// with the run still `in_progress`, while the same job on `b141ca2` finished in **5.2 minutes**.
///
/// # The shape that hangs, and why it only bites on CI
///
/// `log_format.rs` and `redact_wiring.rs` each connected in a bounded loop and then waited
/// **unboundedly**:
///
/// ```text
/// while Instant::now() < deadline {              // 10 s to connect
///     if let Ok(mut s) = TcpStream::connect(..) { ..; break; }
///     sleep(50ms);
/// }
/// let out = child.wait_with_output().expect(..); // <- never returns if the loop timed out
/// ```
///
/// The child is `qqqai serve --accept-limit 1`, which **exits only after accepting one connection**.
/// So when the connect loop loses the port race, **nothing is accepted, the child never exits, and
/// the wait never returns.** That race is `free_port()`'s documented gap — "between the drop and the
/// child's bind the number is unowned" — and it is lost under CI load, which is why neither file
/// failed on a developer machine.
///
/// # Why bound the wait rather than kill first
///
/// Because `log_format.rs` asserts on the **server's own log line** (`OBS-007`), written as the
/// request is served. Killing immediately after the response can race that line out of existence.
/// So a child that exits on its own is collected **with its output intact**, and only one that
/// outlives the deadline is killed.
pub fn reap_within(mut child: Child, deadline: Duration) -> (std::process::Output, bool) {
    let until = Instant::now() + deadline;
    let mut killed = false;
    loop {
        match child.try_wait() {
            // **Two causes, one effect: stop waiting.** `Ok(Some(_))` is the child that finished on
            // its own; `Err(_)` is `try_wait` itself failing, which is **not** a reason to fall
            // through to an unbounded wait on a child we can no longer ask about — that is the very
            // bug this helper exists to close. They share an arm because clippy is right that an arm
            // existing only to repeat its neighbour is a place for the two to drift apart.
            Ok(Some(_)) | Err(_) => break,
            Ok(None) if Instant::now() > until => {
                // **Killed, and said so.** A helper that silently killed a stuck child would turn a
                // hang into a pass with missing output, which is worse than the hang.
                eprintln!("  the child did not exit within {deadline:?}; killing it");
                let _ = child.kill();
                killed = true;
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
        }
    }
    (child.wait_with_output().expect("reap"), killed)
}
