// SPDX-License-Identifier: Apache-2.0

//! Audit durability under real load and real kills (`F-09`).
//!
//! # Why these tests spawn servers rather than driving the handler
//!
//! The claim under test is end to end: 200,000 requests through a real
//! listener leave 200,000 requests' rows in the file, in chain order,
//! and a `kill -9` mid-load loses no acknowledged row while a torn tail
//! quarantines on restart. A `GuestApp` in-process cannot be killed, and
//! a file written by the test itself would prove the writer, not the
//! server. So these tests drive `qqqai serve` over loopback like
//! `serve_policy.rs` does, and read the file back with the shipped
//! loader.
//!
//! # Why ignored by default
//!
//! They build a guest and drive hundreds of thousands of requests: minutes,
//! not milliseconds. The `rust` CI job runs them explicitly with
//! `--ignored`, on all three platforms; the bridge manifest does not
//! include them (its `cargo test --workspace` runs the unignored set).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const REQUESTS: u64 = 200_000;
const CLIENT_THREADS: u64 = 12;
const LOAD_WORKERS: u32 = 16;

/// Client threads stay strictly below worker slots: at parity a timing
/// window still saturates the pool, and saturation renders 502
/// (`InstancePoolExhausted`) — correct product behavior that would fail
/// a test asserting all-200. The audit lock-step is what is under test,
/// not pool shedding, so the driver never offers more concurrency than
/// the server staffs.
///
/// The three tests never run concurrently.
///
/// Each builds the reference guest in the same directory, starts live
/// servers, and (for the big one) hammers loopback with sixteen client
/// threads: three of those at once turns every timeout into scheduling
/// luck and every build into lock contention. Sequential is slower and
/// honest; the CI budget covers the sum.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The repository root, for reaching `examples/orders-api`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the repository root")
}

/// A scratch directory removed on drop: HOME/USERPROFILE shadow and the
/// audit log live here, never in the real profile or the repo.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "qqq-audit-load-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch");
        Self(p)
    }
    fn audit_log(&self) -> PathBuf {
        self.0.join("audit.jsonl")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A free port, bound and released: a hard-coded port collides between
/// concurrent runs, and the failure then looks like a server bug.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

/// A running `qqqai serve`, killed if the test ends without stopping it.
struct Serving {
    child: Child,
    port: u16,
}

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Build the reference guest with the product's own command, so the load
/// always runs the current artifact rather than a stale component.
fn build_reference_guest(app: &Path) {
    let built = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .arg("build")
        .current_dir(app)
        .output()
        .expect("`qqqai build` must be runnable");
    assert!(
        built.status.success(),
        "the reference application must build.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );
    assert!(
        app.join("target")
            .join("qqq")
            .join("orders-api.component.wasm")
            .is_file(),
        "the built component must exist"
    );
}

/// Start `qqqai serve` on the reference application with an audit file,
/// waiting until the port is bound.
///
/// Readiness is probed by *binding*, never by connecting: a connect is an
/// accept, and an accept would consume budget the test then measures.
fn start(app: &Path, scratch: &Scratch, audit_log: &Path, workers: u32) -> Serving {
    const ATTEMPTS: usize = 5;
    for _ in 1..=ATTEMPTS {
        let port = free_port();
        let mut serving = Serving {
            child: Command::new(env!("CARGO_BIN_EXE_qqqai"))
                .args([
                    "serve",
                    "--listen",
                    &format!("127.0.0.1:{port}"),
                    "--workers",
                    &workers.to_string(),
                    "--audit-log",
                    audit_log.to_str().expect("utf8"),
                ])
                .current_dir(app)
                .env("HOME", &scratch.0)
                .env("USERPROFILE", &scratch.0)
                // The component is already built at the project's own
                // target dir: pointing the child there keeps the lookup
                // true under environments (like the bridge) that set a
                // global `CARGO_TARGET_DIR` at a shared root.
                .env("CARGO_TARGET_DIR", app.join("target"))
                // Inherited, never piped-unread: a child whose pipes
                // nobody drains blocks once they fill, which turns a
                // chatty server into a hung test. Inheritance also puts
                // the server's own errors in the test output, where a
                // bind failure is diagnosable instead of bare.
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("`qqqai serve` must be runnable"),
            port,
        };
        // Bound-but-dead means another process holds the port: exiting the
        // child is the signal the port is not ours, and the loop retries
        // with a fresh one rather than spinning to the deadline.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if serving.child.try_wait().expect("child status").is_some() {
                break;
            }
            if TcpListener::bind(("127.0.0.1", port)).is_err() {
                return serving;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = serving.child.kill();
        let _ = serving.child.wait();
    }
    panic!("`qqqai serve` never bound a port");
}

/// Drive `total` requests over `threads` persistent connections.
///
/// One connection per request would burn an ephemeral port per request:
/// 200,000 closes leave ~100,000 sockets in `TIME_WAIT`, the client
/// runs out of ports near request 70,000, and every later connect fails
/// — a harness artifact that reads as server failures. Keep-alive
/// reuses one connection per thread, so the measured thing is request
/// handling and audit persistence, not port recycling. A dead
/// connection reconnects; the failed request counts as `other`, never
/// retried silently (a retry would double-drive one request and break
/// the lock-step count).
fn drive(port: u16, total: u64, threads: u64) -> (u64, u64) {
    let ok = Arc::new(AtomicU64::new(0));
    let other = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for t in 0..threads {
        let (ok, other) = (Arc::clone(&ok), Arc::clone(&other));
        handles.push(std::thread::spawn(move || {
            let mut stream: Option<TcpStream> = None;
            let mut i = t;
            while i < total {
                let status = request_keepalive(port, &mut stream);
                match status {
                    Some(200) => {
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        other.fetch_add(1, Ordering::Relaxed);
                    }
                }
                i += threads;
            }
        }));
    }
    for handle in handles {
        handle.join().expect("client thread");
    }
    (ok.load(Ordering::Relaxed), other.load(Ordering::Relaxed))
}

/// One `GET /healthz` over a persistent connection, reconnecting when
/// the server closed it. Returns the status, or `None` when the request
/// itself failed.
fn request_keepalive(port: u16, stream: &mut Option<TcpStream>) -> Option<u16> {
    for _ in 0..2 {
        if stream.is_none() {
            let fresh = TcpStream::connect(("127.0.0.1", port)).ok()?;
            fresh.set_read_timeout(Some(Duration::from_secs(30))).ok()?;
            *stream = Some(fresh);
        }
        let result = request_once(stream.as_mut().expect("connected"));
        match result {
            Some((status, keep)) => {
                if !keep {
                    *stream = None;
                }
                return Some(status);
            }
            None => {
                *stream = None;
            }
        }
    }
    None
}

/// One request on an open connection: status plus whether the server
/// will reuse the connection. `None` on any I/O failure.
fn request_once(stream: &mut TcpStream) -> Option<(u16, bool)> {
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
        .ok()?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        head.extend_from_slice(&byte);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 16_384 {
            return None;
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())?;
    let mut length: Option<usize> = None;
    let mut close = false;
    for line in text.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            length = value.trim().parse().ok();
        }
        if lower.contains("connection: close") {
            close = true;
        }
    }
    match length {
        Some(0) => {}
        Some(n) => {
            let mut body = vec![0u8; n];
            stream.read_exact(&mut body).ok()?;
        }
        None => {
            // No length: the server will close, so drain to end.
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).ok()?;
            close = true;
        }
    }
    Some((status, !close))
}

/// Rows per request, measured on a fresh server: the lock-step constant
/// the main run asserts against. The guest is deterministic per route,
/// so every request leaves exactly this many rows.
fn calibrate(app: &Path, scratch: &Scratch) -> u64 {
    let log = scratch.audit_log();
    let serving = start(app, scratch, &log, 4);
    let (ok, other) = drive(serving.port, 200, 3);
    assert_eq!(other, 0, "calibration requests must all serve");
    assert_eq!(ok, 200);
    drop(serving);
    let lines = std::fs::read_to_string(&log).expect("read").lines().count() as u64;
    assert_eq!(
        lines % 200,
        0,
        "rows per request must be constant: {lines} for 200"
    );
    lines / 200
}

/// **F-09: 200,000 requests keep the audit file in lock-step.**
///
/// Every served request leaves exactly its rows; the file holds exactly
/// `REQUESTS × k` lines for the calibrated constant `k`, and the chain
/// verifies over all of them. A dropped, duplicated, or forged row
/// breaks one of the three.
#[test]
#[ignore = "drives 200k requests through a live server; runs in the rust CI job explicitly"]
fn f09_two_hundred_thousand_requests_stay_in_lock_step() {
    let _serial = serial();
    let root = repo_root();
    let app = root.join("examples").join("orders-api");
    build_reference_guest(&app);
    let scratch = Scratch::new("lockstep");
    let per_request = calibrate(&app, &scratch);
    assert!(
        per_request >= 1,
        "each request leaves at least its handle row"
    );

    let log = scratch.0.join("main.jsonl");
    let serving = start(&app, &scratch, &log, LOAD_WORKERS);
    let begin = Instant::now();
    let (ok, other) = drive(serving.port, REQUESTS, CLIENT_THREADS);
    let elapsed = begin.elapsed();
    assert_eq!(other, 0, "every request must serve");
    assert_eq!(ok, REQUESTS);
    drop(serving);
    eprintln!(
        "served {REQUESTS} requests in {} s ({} rps)",
        elapsed.as_secs(),
        REQUESTS / elapsed.as_secs().max(1)
    );

    let text = std::fs::read_to_string(&log).expect("read");
    assert_eq!(
        text.lines().count() as u64,
        REQUESTS * per_request,
        "the file grows in lock-step with the request count"
    );
    let (stream, _) =
        qqq_host::audit_sink::resume_or_start(&log, usize::MAX).expect("the loaded file resumes");
    assert!(stream.verify_chain().is_ok(), "the whole chain verifies");
}

/// **F-09: `kill -9` mid-load loses no acknowledged row.**
///
/// The server dies abruptly; on restart it serves again, the chain
/// verifies, and the file holds at least one handle row per response
/// the client received — every acknowledged answer has its evidence.
/// A torn tail quarantines when the kill lands mid-write (proven
/// deterministically by the restart test below); here the assertions
/// hold with or without one.
#[test]
#[ignore = "kills a live server; runs in the rust CI job explicitly"]
fn f09_kill_during_load_loses_no_acknowledged_row() {
    let _serial = serial();
    let root = repo_root();
    let app = root.join("examples").join("orders-api");
    build_reference_guest(&app);
    let scratch = Scratch::new("kill");
    let log = scratch.audit_log();
    let mut serving = start(&app, &scratch, &log, 8);
    let (ok, other) = drive(serving.port, 2_000, 6);
    assert_eq!(other, 0);
    assert_eq!(ok, 2_000);
    serving.child.kill().expect("kill");
    let _ = serving.child.wait();
    drop(serving);

    let serving = start(&app, &scratch, &log, 8);
    let (ok2, other2) = drive(serving.port, 500, 4);
    assert_eq!(other2, 0);
    drop(serving);

    let text = std::fs::read_to_string(&log).expect("read");
    let handles = text
        .lines()
        .filter(|line| line.contains("\"function\":\"handle_request\""))
        .count() as u64;
    assert!(
        handles >= ok + ok2,
        "every acknowledged response keeps its handle row: {handles} < {}",
        ok + ok2
    );
    let (stream, _) =
        qqq_host::audit_sink::resume_or_start(&log, usize::MAX).expect("resumes after kill");
    assert!(stream.verify_chain().is_ok());
}

/// **F-09: restart on a torn file quarantines and serves.**
///
/// The torn tail is crafted (a kill lands mid-write too rarely to be a
/// test): the server must start, move the fragment to
/// `<log>.partial-<ms>`, serve new requests, and keep the chain
/// verifying over old plus new rows.
#[test]
#[ignore = "spawns a live server; runs in the rust CI job explicitly"]
fn f09_restart_on_a_torn_file_quarantines_and_serves() {
    let _serial = serial();
    let root = repo_root();
    let app = root.join("examples").join("orders-api");
    build_reference_guest(&app);
    let scratch = Scratch::new("torn");
    let log = scratch.audit_log();
    let serving = start(&app, &scratch, &log, 4);
    let (ok, _) = drive(serving.port, 20, 3);
    assert_eq!(ok, 20);
    drop(serving);

    let text = std::fs::read_to_string(&log).expect("read");
    let torn = text.trim_end_matches('\n');
    let torn = &torn[..torn.len() - 25];
    std::fs::write(&log, torn).expect("tear the tail");

    let serving = start(&app, &scratch, &log, 4);
    let (ok2, other2) = drive(serving.port, 20, 3);
    assert_eq!(other2, 0, "the restarted server serves");
    assert_eq!(ok2, 20);
    drop(serving);

    let partials: Vec<_> = std::fs::read_dir(&scratch.0)
        .expect("readdir")
        .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
        .filter(|name| {
            name.to_str()
                .is_some_and(|name| name.starts_with("audit.jsonl.partial-"))
        })
        .collect();
    assert_eq!(partials.len(), 1, "exactly one quarantine: {partials:?}");
    let (stream, _) = qqq_host::audit_sink::resume_or_start(&log, usize::MAX).expect("resumes");
    assert!(stream.verify_chain().is_ok());
}
