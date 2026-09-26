// SPDX-License-Identifier: Apache-2.0

//! A guest cannot influence sampling — `OBS-014`, the security claim §10.4 makes.
//!
//! > *"Sampling is host-controlled (head-based with tail sampling option) and **never**
//! > guest-controlled."*
//!
//! # Why this file needs two kinds of evidence
//!
//! **A behavioural test alone is not enough here**, and saying so is the point of the item. A runtime
//! test can show that a *particular* hostile input changes nothing; it cannot show that **no**
//! guest-reachable input exists, because that is a claim about what the code *can read*. So:
//!
//! 1. **Behavioural** — a `traceparent` claiming `sampled=1`, the W3C flag that a conventional
//!    implementation honours, does not force a span and does not raise the rate.
//! 2. **Structural** — [`span`] owns the decision, and it must contain **no reference to a request
//!    field**. This is the same shape as `tools/check_public_reachability.py`: a property no runtime
//!    test can reach, checked where it actually lives.
//!
//! **The injection for this item is the vulnerability itself**: make the decision consult the
//! inbound `traceparent`. The behavioural tests must fail — and the structural one must too, which is
//! what makes it worth having.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long any single read may block. **A deadline, not a hope** (`§O-309`, `§O-314`).
const READ_DEADLINE: Duration = Duration::from_secs(30);

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-influence-{tag}-{}", std::process::id()));
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

const MANIFEST: &str = "[package]\nname = \"influence-probe\"\nversion = \"0.1.0\"\n\
     [server]\ndefault_auth = \"none\"\n\
     [[server.routes]]\npath = \"/orders\"\nmethods = [\"GET\"]\nhandler = \"list\"\n";

/// Serve `count` requests, each carrying a hostile `traceparent`, and return the server's output.
///
/// # The hostile input
///
/// `00-<32 hex>-<16 hex>-01` is a **well-formed** W3C `traceparent` whose `sampled` flag is **1**.
/// A conventional implementation inherits that flag, which is exactly what §10.4 forbids here: a
/// caller would be choosing whether its own traffic is recorded.
fn serve_hostile(sandbox: &Sandbox, extra: &[&str], count: u32) -> String {
    // **A bounded retry, because the port this helper asks for may be taken before the child binds.**
    //
    // `free_port()` binds a number, reads it, and **drops the listener** -- so between the drop and
    // the child's bind the number is unowned. That is `§O-326`'s measured cause, and this file's
    // helper had no retry while a sibling's did. **Six copies of one racy helper was the object all
    // along**, and the fix belongs in each of them until they share one.
    for attempt in 1..=common::ATTEMPTS {
        let out = attempt_serve_hostile(sandbox, extra, count);
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

fn attempt_serve_hostile(sandbox: &Sandbox, extra: &[&str], count: u32) -> String {
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
            // A DIFFERENT trace id every time, all claiming `sampled=1`. If the host inherited the
            // flag, every one of them would be recorded.
            let req = format!(
                "GET /orders HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
                 traceparent: 00-{served:032x}-{served:016x}-01\r\n\r\n"
            );
            let _ = s.write_all(req.as_bytes());
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            // **An empty read is a failure in itself** — `!contains(x)` is satisfied by nothing.
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

/// **A `traceparent` claiming `sampled=1` cannot force a span — `OBS-014`.**
///
/// `--trace-sample off` is the host's decision, and it stands. This is the attack the item names: a
/// conventional implementation *inherits* the W3C flag, so a caller could choose to be recorded.
#[test]
fn a_hostile_traceparent_cannot_force_sampling() {
    let sandbox = Sandbox::new("force");
    let out = serve_hostile(&sandbox, &["--trace-sample", "off"], 8);
    assert!(
        !out.contains("span step="),
        "a guest's `sampled=1` must not override `--trace-sample off`: {out}"
    );
    // And the requests were served, so the absence is a decision rather than a failure to run.
    assert!(
        out.contains("/orders"),
        "the requests must have been served for the absence to mean anything: {out}"
    );
}

/// **A flood of hostile `traceparent`s cannot raise the rate — `OBS-014`.**
///
/// The rate is chosen from the **host's** trace id, so 24 crafted headers produce roughly a quarter
/// of the spans rather than all of them. A host that honoured the flag would produce 24 of 24, which
/// is the measurement `§O-317` used to catch a different defect in this same area.
#[test]
fn a_hostile_traceparent_cannot_raise_the_rate() {
    let sandbox = Sandbox::new("rate");
    let out = serve_hostile(&sandbox, &["--trace-sample", "0.25"], 24);
    let sampled = out.matches("span step=").count();
    assert!(
        sampled < 24,
        "24 `sampled=1` headers must not yield 24 spans: the flag is a correlation hint, not a \
         decision: {sampled} spans"
    );
    assert!(
        sampled > 0,
        "and the rate must still record something, or this test would pass for a sampler that \
         records nothing: {sampled} spans"
    );
}

/// **The module that owns the decision reads no request field — the structural half of `OBS-014`.**
///
/// # Why a source check and not only a runtime one
///
/// Because the claim is about **what the code can read**, and no runtime test can prove a negative
/// about a capability: a behavioural test shows that *this* hostile input changes nothing, not that
/// no guest-reachable input exists.
///
/// [`span`] is where the decision lives. If it names a header, a path, a target or a tenant, then a
/// guest has a way in — whatever the current tests happen to cover. **This is the same shape as
/// `tools/check_public_reachability.py`**: a property checked where it actually lives.
///
/// The comments are stripped before the scan, because the module's own documentation *discusses*
/// `traceparent` — and a guard that fires on prose is a guard that gets worked around.
#[test]
fn the_decision_module_reads_no_request_field() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../qqq-serve/src/span.rs");
    let src = std::fs::read_to_string(path).expect("span.rs is readable");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    for forbidden in [
        "traceparent",
        "RequestHead",
        "header(",
        ".target",
        "tenant",
        "wasi:http",
    ] {
        assert!(
            !code.contains(forbidden),
            "`span.rs` names `{forbidden}` in code. The sampling decision must be a function of \
             host state alone (§10.4, `OBS-014`) — if this module can read a request field, a guest \
             has a way into the decision."
        );
    }

    // And the decision's only input is the trace id, which the host allocates. Asserted on the
    // signature rather than described, because a signature is what a future edit must change.
    assert!(
        code.contains("fn decide(&self, trace: &TraceId)"),
        "the decision must take a `TraceId` and nothing else: {code}"
    );
}

/// **The span decision's inputs are host state alone — the guard widened twice by what injections
/// taught.**
///
/// # Why this test exists, and both widenings were measured rather than imagined
///
/// **First widening**: the original guard scanned **`span.rs` alone**, and an injection proved that
/// too narrow. A guest-forced decision introduced at the **call site** left the structural check
/// *passing* while the behavioural tests caught it — `span.rs` was untouched, so the guard had nothing
/// to say.
///
/// **Second widening**: the guard was then pointed at `emit_span`'s **definition**, and a second
/// injection proved *that* too narrow — the vulnerability was at the **call**, one region over, and
/// the guard passed again.
///
/// **A guard is only as wide as its file list, its pattern, *and* its extent.** The decision's inputs
/// are what matters, so this scans **every region that supplies one**: `span.rs`, and the argument
/// list of every `emit_span(...)` call in `server.rs`.
///
/// Comments are stripped throughout, because these files legitimately *discuss* `traceparent` — and a
/// guard that fires on prose is a guard that gets worked around.
#[test]
fn the_span_decision_takes_host_state_alone() {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../qqq-serve/src/");
    let strip = |s: &str| -> String {
        s.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    // (1) The module that owns the decision.
    let module = std::fs::read_to_string(format!("{base}span.rs")).expect("span.rs is readable");
    let mut regions = vec![strip(&module)];

    // (2) Every call site: the argument list is an *input* to the decision, so it is scanned too.
    let server =
        std::fs::read_to_string(format!("{base}server.rs")).expect("server.rs is readable");
    let mut from = 0;
    while let Some(at) = server[from..].find("emit_span(") {
        let start = from + at;
        let end = server[start..]
            .find(");")
            .map_or(server.len(), |e| start + e + 2);
        regions.push(strip(&server[start..end]));
        from = end;
    }

    for region in &regions {
        for forbidden in ["traceparent", "head.header", ".target", "wasi:http"] {
            assert!(
                !region.contains(forbidden),
                "a span-decision input names `{forbidden}`. The decision must be a function of host \
                 state alone (§10.4, `OBS-014`): a call site that reads a request field can force or \
                 suppress a span without the sampler knowing.\n{region}"
            );
        }
    }

    assert!(
        regions.len() > 1,
        "the call-site regions must have been found, or this guard checks only the module"
    );
}
