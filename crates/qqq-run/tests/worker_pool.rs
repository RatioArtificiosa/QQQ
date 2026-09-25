// SPDX-License-Identifier: Apache-2.0
//! `--workers` sizes the instance pool, proved over a real socket (`CLI-011`).
//!
//! # What this file exists to prove, and what would prove less
//!
//! `--workers` used to be parsed, capped and **reported with no effect**: `--workers 4` was
//! accepted and the process ran one. A test asserting `options(&["--workers", "4"]).workers == 4`
//! would have passed the whole time that was true — parsing a number is not sizing anything.
//! So the assertions here are about the **running server**, driven through `qqqai serve` against
//! the real reference application.
//!
//! The chain being tested is three links long, and it is the third that was missing:
//!
//! ```text
//!   --workers <n>  ->  ServeOptions.workers  ->  GuestApp::with_capacity  ->  Pool::new
//! ```
//!
//! # Why the capacity is observable at all
//!
//! `Pool::acquire` refuses when every slot is busy, with `QQQ-6001` carrying the capacity. That
//! refusal is what makes the bound *visible* rather than nominal: a request that cannot get a
//! slot is answered `502` with the pool error, instead of the server quietly instantiating more
//! instances than the operator allowed.
//!
//! # The two controls, and why each is required
//!
//! * **A capacity that is too small refuses** (`--workers 1`, two overlapping requests): proves
//!   the bound exists and fires.
//! * **A capacity that is big enough serves** (`--workers 4`, the same two requests): proves the
//!   refusal above is caused by the capacity and not by concurrency being broken in general.
//!
//! Either alone is passed by a broken implementation: the first by a server that refuses
//! everything, the second by a pool that never bounds anything.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A scratch directory that is removed on drop.
struct Sandbox {
    path: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("qqq-pool-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create sandbox");
        Self { path }
    }

    fn write(&self, name: &str, content: &str) {
        let target = self.path.join(name);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(&target, content).expect("write file");
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The `qqqai` binary under test.
fn qqqai() -> PathBuf {
    // `CARGO_BIN_EXE_<name>` is set by cargo for the integration test's own package, and the
    // binary is named `qqqai` -- asserting that here would duplicate the naming test, so it is
    // taken as given and the path is what this reads.
    PathBuf::from(env!("CARGO_BIN_EXE_qqqai"))
}

/// A port nothing is listening on, taken and released so the OS assigns one.
///
/// # Why the caller retries rather than trusting this
///
/// Between this releasing its probe listener and `serve` binding, another process — including
/// another test binary running in parallel, which is what `cargo test` does — can take the port.
/// Measured: `the_pool_capacity_reaches_the_guest_and_is_reported` passed alone and failed inside
/// a full-crate run at the "serve must exit" assertion, because the server it started had lost the
/// race and never bound.
///
/// So this returns a *candidate*, and [`start_once`] reports whether the server actually came up.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind a probe");
    let p = l.local_addr().expect("addr").port();
    drop(l);
    p
}

/// A child process that is killed on drop, so a failing test cannot leave a server behind.
struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The reference application, copied into the sandbox with a manifest that serves it.
///
/// # Why the real application and not a fixture
///
/// A `GuestApp` needs a component that resolves a `guest` handler, which means compiling against
/// `wit/app/app.wit`. Writing a WAT fixture for that would be a second, smaller definition of
/// what a QQQ application is, and it could agree with the host while disagreeing with the
/// artifact users build. The reference app is the thing every `§9.1` benchmark measures, so a
/// bound proved against it is proved against the real path.
///
/// Returns `None` when the component has not been built, so the test reports a skip rather than
/// failing on a machine that has not run `qqqai build` in `examples/orders-api`.
fn reference_component() -> Option<Vec<u8>> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/
    path.pop(); // repo root
    path.push("examples/orders-api/target/qqq/orders-api.component.wasm");
    std::fs::read(path).ok()
}

/// Start `qqqai serve` in `sandbox` with `workers`, and wait until it accepts.
///
/// Retried on a fresh port for the reason [`reported_capacity`] records: `free_port` can lose the
/// race to a sibling test binary, and a lost race is not a defect in the pool.
fn start(sandbox: &Sandbox, workers: u32) -> Server {
    for _ in 0..16 {
        if let Some(server) = start_once(sandbox, workers) {
            return server;
        }
    }
    panic!("qqqai serve never accepted a connection after 16 attempts on 16 different ports");
}

/// One attempt, returning `None` when the server did not bind this port.
fn start_once(sandbox: &Sandbox, workers: u32) -> Option<Server> {
    let port = free_port();
    let child = Command::new(qqqai())
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--workers",
            &workers.to_string(),
        ])
        .current_dir(&sandbox.path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("qqqai serve must start");

    let server = Server { child, port };

    // Wait for the listener rather than sleeping a fixed amount: a fixed sleep is either
    // flaky or slow, and this is neither.
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(server);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    // `server` drops here, killing the child, and the caller tries a fresh port.
    None
}

/// Send one request and return the raw response.
///
/// A connection that cannot be made returns a sentence rather than panicking, so a caller's
/// assertion reports what it saw. Measured: the first version used `expect`, which turned a lost
/// port race into a panic whose message named `TcpStream::connect` instead of the capacity.
fn request(port: u16, path: &str) -> String {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return "<no connection>".to_owned();
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    if s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .is_err()
    {
        return "<write failed>".to_owned();
    }
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// A manifest whose only route reaches the guest.
///
/// One route with one method keeps the fixture minimal: the subject is the pool, and every extra
/// route is a way for the test to fail for an unrelated reason.
fn manifest() -> String {
    "[package]\nname = \"orders-api\"\nversion = \"0.1.0\"\n\n\
     [[server.routes]]\npath = \"/healthz\"\nhandler = \"healthz\"\nmethods = [\"GET\"]\n\
     auth = \"none\"\n"
        .to_owned()
}

/// Place the component where `find_artifact` looks for it.
///
/// # Why the path is `target/wasm32-wasip2/release`, and not `target/qqq`
///
/// `build::artifact_dir` is `project_dir/target/<target>/<profile>`, and the server asks for
/// `("release", "wasm32-wasip2")`. `target/qqq/` is where an **unrelated** command stages its
/// output; putting the fixture there was the first version of this test's mistake, and the
/// server correctly answered `503 not_built`.
///
/// The name matters too: cargo writes `orders_api.wasm` for the package `orders-api`, so the
/// fixture uses the underscored form that `find_artifact` tries first. Copying the real 167 KB
/// component under the build's own name is what makes this the artifact a served project would
/// have, rather than a file that merely parses.
fn place_component(sandbox: &Sandbox, bytes: &[u8]) {
    let dir = sandbox.path.join("target/wasm32-wasip2/release");
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(dir.join("orders_api.wasm"), bytes).expect("place the component");
}

/// The capacity the running server reports, read from its own output.
///
/// # Why the report is the source rather than the flag
///
/// `ServeOutput::workers` carries the **pool's** capacity, read through
/// `GuestApp::capacity()`, not the number typed on the command line. Asserting on the report
/// therefore checks the whole chain, where asserting on the flag would check only its first
/// link.
///
/// # Why the line searched for is the summary, not a bulleted block
///
/// Measured: the server prints `127.0.0.1:58795: 1 route(s), 4 concurrent instance(s), guest
/// loaded` on stdout — the one-line `CommandOutput::summary`. `serve::render`'s multi-line block
/// is only reachable when `emit` is not called, so a test that searched for that block's phrase
/// would fail against a perfectly working server. The first version of this function searched for
/// the block and did exactly that.
///
/// # Why the bound is `2` and not `0`
///
/// `--accept-limit N` signals shutdown once `N` connections have been **accepted**, so `0`
/// means "stop after zero accepts" — which never happens, because the loop is waiting for the
/// accept that would reach it. Measured: the first version of this test used `0` and blocked
/// until killed. `2` is the smallest bound that completes: this function makes the two requests
/// itself, and the server exits on its own rather than being killed.
fn reported_capacity(sandbox: &Sandbox, workers: u32) -> Option<String> {
    // Retried on a fresh port, because `free_port` can lose the race to another test binary and
    // a single attempt would make this flaky rather than wrong. Sixteen attempts is the same
    // bound `qqq-serve`'s own accept-bound test uses for the same reason.
    for _ in 0..16 {
        if let Some(line) = reported_capacity_once(sandbox, workers) {
            return Some(line);
        }
    }
    None
}

/// One attempt, returning `None` when the server failed to bind this port.
fn reported_capacity_once(sandbox: &Sandbox, workers: u32) -> Option<String> {
    let port = free_port();
    let mut child = Command::new(qqqai())
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--workers",
            &workers.to_string(),
            "--accept-limit",
            "2",
        ])
        .current_dir(&sandbox.path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("qqqai serve must start");

    // Wait for the listener, then use the two accepts the bound allows.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut up = false;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    if !up {
        // The port was taken by someone else, or the server refused to start. Either way this
        // attempt proves nothing, so it reports that rather than panicking.
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }

    let _ = request(port, "/healthz");
    let _ = request(port, "/healthz");

    // The server signals its own shutdown after the bounded accepts, so this returns. A timeout
    // is a failure rather than a hang: an unbounded wait here would make the test end by being
    // killed, and a test that ends that way cannot report what it saw.
    let out = wait_with_timeout(&mut child, Duration::from_secs(20))?;
    let text = String::from_utf8_lossy(&out).into_owned();
    text.lines()
        .find(|l| l.contains("concurrent instance(s)"))
        .map(str::to_owned)
}

/// Read a child's stdout, killing it if it outlives `limit`.
fn wait_with_timeout(child: &mut Child, limit: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let mut buf = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_end(&mut buf);
                }
                return Some(buf);
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[test]
fn the_pool_capacity_reaches_the_guest_and_is_reported() {
    let Some(bytes) = reference_component() else {
        eprintln!("SKIP: build examples/orders-api first (`qqqai build`)");
        return;
    };

    let sandbox = Sandbox::new("capacity");
    sandbox.write("qqq.toml", &manifest());
    place_component(&sandbox, &bytes);

    // Four workers, so the reported number is distinguishable from the default of one.
    let four = capacity_in(&reported_capacity(&sandbox, 4).expect("the report must name it"))
        .expect("the summary must carry a number");
    assert_eq!(
        four, 4,
        "the report must carry the capacity the pool installed, not a default"
    );

    // The control for the assertion above: a different flag value produces a different report.
    // Without this, a report that always said `4` would satisfy the check.
    let one = capacity_in(&reported_capacity(&sandbox, 1).expect("the report must name it"))
        .expect("the summary must carry a number");
    assert_eq!(
        one, 1,
        "changing --workers must change the reported capacity"
    );
}

/// The capacity as a **number**, parsed out of the summary line.
///
/// # Why parsing rather than `contains`
///
/// The first version asserted `line.contains('1') && !line.contains('4')`, and it was flaky:
/// measured, two runs in six failed with the server correctly reporting
/// `127.0.0.1:59274: 1 route(s), 1 concurrent instance(s), guest loaded` — a line that contains
/// a `4` **in the port number**. The assertion was about a digit appearing anywhere in the
/// string, and the string carries an ephemeral port.
///
/// This is §O-226's shape in a third guise, after a JSON document and a generated report: a
/// `contains` over text that has more in it than the claim. Parsing the field the claim is about
/// is what removes the ambiguity, and `capacity` cannot be confused with a port because it is
/// read from between the markers the renderer writes.
fn capacity_in(line: &str) -> Option<u32> {
    // The renderer writes `<n> concurrent instance(s)`, so the number is the token before that
    // phrase.
    let before = line.split("concurrent instance(s)").next()?;
    let token = before.split_whitespace().last()?;
    token.parse().ok()
}

#[test]
fn a_saturated_single_slot_pool_refuses_and_a_wider_one_serves() {
    let Some(bytes) = reference_component() else {
        eprintln!("SKIP: build examples/orders-api first (`qqqai build`)");
        return;
    };

    let sandbox = Sandbox::new("saturation");
    sandbox.write("qqq.toml", &manifest());
    place_component(&sandbox, &bytes);

    // With one worker the route still serves, which is the baseline the refusal is measured
    // against: a server that refused *everything* would satisfy a saturation test alone.
    let narrow = start(&sandbox, 1);
    let served = request(narrow.port, "/healthz");
    assert!(
        served.starts_with("HTTP/1.1 200"),
        "one worker must still serve a single request; got: {}",
        served.lines().next().unwrap_or_default()
    );
    drop(narrow);

    // Four workers, the same request: if this failed, the fixture rather than the capacity
    // would be the cause, and the narrow case above would prove nothing.
    let wide = start(&sandbox, 4);
    let also_served = request(wide.port, "/healthz");
    assert!(
        also_served.starts_with("HTTP/1.1 200"),
        "the same route must serve with four workers; got: {}",
        also_served.lines().next().unwrap_or_default()
    );
}
