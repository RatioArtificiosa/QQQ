// SPDX-License-Identifier: Apache-2.0

//! What the manifest says must be what the server does, proven over a real socket.
//!
//! # Why these tests exist
//!
//! Every feature exercised here was **implemented, unit-tested and unreachable**. The
//! manifest's `default_auth` defaults to `deny`; `qqq-run` computed the mode for every
//! declared route; `qqq-serve` had an enforcement point and a policy type; the tests for
//! both passed. And `qqqai serve` served every route on every manifest, because
//! `serve::prepare` built the per-route modes, the per-tenant limits and the CORS policy
//! and then handed the server a `ServerConfig` with all three absent.
//!
//! No unit test could see it. Each half was correct; the edge between them did not exist.
//! That is the failure mode this file is written against, so these tests deliberately
//! **spawn the real binary, open a real TCP connection and read the real bytes**. A test
//! that called `AuthPolicy::decide` directly would have passed throughout the whole period
//! the server was ignoring the policy.
//!
//! # Why the assertions are about headers and status, not about a 200
//!
//! Because "not a 403" is not the property being checked — the property is *which* policy
//! was consulted. `X-QQQ-Auth-Mode` names the mode that refused, so a test can distinguish
//! "refused by `deny`" from "refused because something else went wrong". The reference
//! application is not built in these sandboxes, so a route that reaches the dispatcher
//! answers `503`; that is the *positive* signal here, and it is a stronger one than a 200
//! would be, because it proves the request travelled past the policy.
//!
//! # Why `--accept-limit` matters to these tests
//!
//! The server runs until signalled, so a test that spawns it must be able to bound it.
//! `--accept-limit N` signals the same shutdown the drain path uses once `N` connections
//! have been accepted, which lets each test end by itself instead of by timeout — and a
//! test that ends by timing out cannot tell "finished" from "stuck".

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
        path.push(format!("qqq-serve-policy-{tag}-{}", std::process::id()));
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

/// A port that is free right now.
///
/// Bound and released rather than picked from a range: a hard-coded port makes two
/// concurrent test runs collide, and the failure then looks like a server bug. The window
/// between release and the server's own bind is unavoidable and small; a collision shows up
/// as a bind failure naming the address, which is diagnosable.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = l.local_addr().expect("local addr").port();
    drop(l);
    port
}

/// A running `qqqai serve`, killed if the test ends without it stopping.
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

/// Start `qqqai serve` in `dir` and wait until it has bound the port.
///
/// # Why readiness is probed by *binding*, not by connecting
///
/// The first version of this helper connected to the port to see whether the server was
/// up — and that connection is an **accept**, so with `--accept-limit 1` the readiness
/// probe consumed the server's entire budget and every test failed with "never accepted a
/// connection" while the server was in fact healthy. A probe that changes the thing it is
/// observing is not a probe.
///
/// Attempting to bind the same port is free: while the server holds it the bind fails with
/// `AddrInUse`, and the moment it stops holding it the bind succeeds. Nothing is accepted
/// and nothing is counted.
fn start(dir: &Sandbox, tag: &str, accepts: u32) -> Serving {
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--accept-limit",
            &accepts.to_string(),
        ])
        .current_dir(&dir.path)
        .env("HOME", &dir.path)
        .env("USERPROFILE", &dir.path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("`qqqai serve` must be runnable for {tag}: {e}"));

    // The `Serving` is built *before* the probe, not returned from inside it, so that a
    // panic on the failure path unwinds through its `Drop`. Built after the probe, that
    // path dropped a bare `Child` -- and `Child`'s own `Drop` neither kills nor waits, so
    // a server that never bound left a live process behind on a port the next test then
    // failed to claim. The `Serving`'s `Drop` owns the child's whole lifetime, which is
    // also why no `wait()` appears here for `clippy::zombie_processes` to find.
    let mut serving = Serving { child, port };

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        // # Why the child's liveness is checked, not only the port's
        //
        // `bind().is_err()` proves *some* process holds the port. It does not prove **ours**
        // does, and `cargo test` runs test binaries concurrently - so another test's server
        // holding this port satisfies the probe, this helper returns believing its own server is
        // up, and the caller writes to a server whose lifecycle it does not own.
        //
        // Measured: `a_route_that_does_not_exist_is_a_404_and_not_a_403` panicked at its
        // `write_all` on two CI platforms, in the same runs that introduced a second test binary
        // spawning servers. The child exiting is the signal that the port is not ours, and
        // `try_wait` reads it without consuming the child.
        if let Ok(Some(_)) = serving.child.try_wait() {
            continue; // still unwinding: the loop's deadline will report a real failure
        }
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            return serving;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("`qqqai serve` never bound 127.0.0.1:{port} for {tag}");
}

/// Send one raw request and return the raw response.
///
/// Raw bytes rather than an HTTP client, because the assertions are about the exact status
/// line and header spelling the server writes — a client library would normalise away the
/// thing under test.
///
/// # Why a failed write returns a sentence rather than panicking
///
/// Measured: this panicked at `write_all` on two CI platforms when a sibling test binary held the
/// port, and the message named `write the request` — which sends a reader looking at the request
/// rather than at the port. A caller's assertion reports what it saw, and `<write failed>` is
/// that; a panic here replaces the assertion the test is about with a message about plumbing.
fn request(port: u16, raw: &str) -> String {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return "<no connection>".to_owned();
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    if stream.write_all(raw.as_bytes()).is_err() {
        return "<write failed>".to_owned();
    }
    let _ = stream.flush();

    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        // End-of-stream and a read error end the same way here, in one arm: both mean "no
        // more bytes are coming", and every assertion below is about what already arrived.
        // Written as two arms with the same body, clippy's `match_same_arms` is right that
        // the distinction is not one this test makes -- and an `Err` is not a failure to
        // report, because a server that closes after a refusal produces exactly that.
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        out.extend_from_slice(&buf[..n]);
        // One response per connection is all these tests ask for; the server closes after a
        // refusal, so end-of-stream is the normal terminator. The head being complete and
        // the read having returned a short buffer means the body (if any) arrived with it.
        if out.windows(4).any(|w| w == b"\r\n\r\n") && n < buf.len() {
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn get(port: u16, path: &str) -> String {
    request(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
    )
}

fn status_of(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in: {response:?}"))
}

// ---------------------------------------------------------------------------
// The authentication policy
// ---------------------------------------------------------------------------

/// A manifest with one route and no `default_auth`, which means `deny`.
const DENY_BY_DEFAULT: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
    [[server.routes]]\npath = \"/healthz\"\nmethods = [\"GET\"]\nhandler = \"health\"\n";

#[test]
fn a_manifest_that_forgets_default_auth_refuses_its_routes() {
    // The load-bearing case, and the one that was wrong in production: `deny` is the
    // documented default, so a manifest that lists a route and says nothing about
    // authentication must not serve it.
    let s = Sandbox::new("deny-default");
    s.write("qqq.toml", DENY_BY_DEFAULT);

    let serving = start(&s, "deny-default", 1);
    let response = get(serving.port, "/healthz");

    assert_eq!(
        status_of(&response),
        403,
        "a route with no `default_auth` must be refused, not served:\n{response}"
    );
    assert!(
        response.contains("X-QQQ-Auth-Mode: deny"),
        "the refusal must name the mode that refused:\n{response}"
    );
    assert!(
        response.contains("X-QQQ-Error: unauthenticated"),
        "the refusal must be machine-readable:\n{response}"
    );
}

#[test]
fn an_explicitly_public_route_reaches_the_dispatcher() {
    // The positive control for the test above. Without it, a server that refused
    // *everything* would pass `a_manifest_that_forgets_default_auth_refuses_its_routes`
    // while being just as broken in the other direction.
    let s = Sandbox::new("public");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[server]\ndefault_auth = \"none\"\n\
         [[server.routes]]\npath = \"/healthz\"\nmethods = [\"GET\"]\nhandler = \"health\"\n",
    );

    let serving = start(&s, "public", 1);
    let response = get(serving.port, "/healthz");

    assert_ne!(
        status_of(&response),
        403,
        "`auth = \"none\"` must not be refused:\n{response}"
    );
    // No component is built in this sandbox, so the dispatcher answers 503. Reaching the
    // dispatcher is the property under test.
    assert_eq!(
        status_of(&response),
        503,
        "a public route must reach the dispatcher, which answers `not built`:\n{response}"
    );
    assert!(
        response.contains("X-QQQ-Error: not_built"),
        "the dispatcher's own answer must be visible:\n{response}"
    );
}

#[test]
fn an_unimplemented_authenticator_refuses_and_names_itself() {
    // `bearer-jwt` names a check that would have to pass. No JWT validator exists, so the
    // request cannot be shown to satisfy it, and serving it would treat "could not check"
    // as "check passed". The refusal must name the mode, because the deployment's next
    // action is to discover it asked for something the runtime cannot do.
    let s = Sandbox::new("bearer");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[server]\ndefault_auth = \"none\"\n\
         [[server.routes]]\npath = \"/orders\"\nmethods = [\"GET\"]\nhandler = \"list\"\n\
         auth = \"bearer-jwt\"\n",
    );

    let serving = start(&s, "bearer", 1);
    let response = get(serving.port, "/orders");

    assert_eq!(
        status_of(&response),
        403,
        "a route needing an authenticator that does not exist must be refused:\n{response}"
    );
    assert!(
        response.contains("X-QQQ-Auth-Mode: bearer-jwt"),
        "the refusal must name the manifest's spelling:\n{response}"
    );
}

#[test]
fn a_route_that_does_not_exist_is_a_404_and_not_a_403() {
    // A 403 for an undeclared path would tell an unauthenticated caller which paths exist.
    // The policy is consulted only for a route the router matched; everything else is the
    // dispatcher's 404.
    let s = Sandbox::new("no-route");
    s.write("qqq.toml", DENY_BY_DEFAULT);

    let serving = start(&s, "no-route", 1);
    let response = get(serving.port, "/not-declared");

    assert_eq!(
        status_of(&response),
        404,
        "an undeclared path must be a 404, not a policy refusal:\n{response}"
    );
    assert!(
        !response.contains("X-QQQ-Auth-Mode"),
        "a path that matched no route must not be attributed to a policy:\n{response}"
    );
}

// ---------------------------------------------------------------------------
// The CORS policy
// ---------------------------------------------------------------------------

const CORS_MANIFEST: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
    [server]\ndefault_auth = \"none\"\n\
    [server.cors]\nallow_origins = [\"https://app.example.com\"]\n\
    allow_credentials = true\nmax_age = 600\n\
    [[server.routes]]\npath = \"/healthz\"\nmethods = [\"GET\"]\nhandler = \"health\"\n";

#[test]
fn the_manifest_cors_policy_reaches_the_response() {
    // `SRV-019` was ticked with the claim that the policy "carries into `serve_connection`,
    // which applies it to **every** response". The wiring tests set `ServerConfig::cors`
    // directly; the manifest path never did, so the policy was reachable from a test and
    // from nothing else.
    let s = Sandbox::new("cors-allow");
    s.write("qqq.toml", CORS_MANIFEST);

    let serving = start(&s, "cors-allow", 1);
    let response = request(
        serving.port,
        "GET /healthz HTTP/1.1\r\nHost: x\r\nOrigin: https://app.example.com\r\nConnection: close\r\n\r\n",
    );

    assert!(
        response.contains("Access-Control-Allow-Origin: https://app.example.com"),
        "an allowed origin must be granted:\n{response}"
    );
    assert!(
        response.contains("Access-Control-Allow-Credentials: true"),
        "`allow_credentials = true` must reach the response:\n{response}"
    );
}

#[test]
fn an_origin_outside_the_manifest_list_is_not_granted() {
    // The other half, and the one that matters: a policy that granted every origin would
    // pass the test above while being no policy at all.
    let s = Sandbox::new("cors-deny");
    s.write("qqq.toml", CORS_MANIFEST);

    let serving = start(&s, "cors-deny", 1);
    let response = request(
        serving.port,
        "GET /healthz HTTP/1.1\r\nHost: x\r\nOrigin: https://evil.example.com\r\nConnection: close\r\n\r\n",
    );

    assert!(
        !response.contains("Access-Control-Allow-Origin"),
        "an origin outside the list must not be granted:\n{response}"
    );
    // The denial must still be *cached correctly*: without `Vary: Origin` a shared cache
    // could serve the granted response to this client.
    assert!(
        response.to_ascii_lowercase().contains("vary: origin"),
        "a CORS decision must vary on Origin:\n{response}"
    );
}

// ---------------------------------------------------------------------------
// The per-tenant request limits
// ---------------------------------------------------------------------------

#[test]
fn the_manifest_body_limit_is_enforced_on_a_real_request() {
    // `SRV-020` was ticked with "Enforced, and `SRV-020` is done". The limiter was correct
    // and the conversion existed; `ServerConfig::limits` was `None` on the manifest path, so
    // nothing enforced anything.
    let s = Sandbox::new("body-limit");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[server]\ndefault_auth = \"none\"\n\
         [server.limits.default]\nmax_body_bytes = 16\n\
         [[server.routes]]\npath = \"/orders\"\nmethods = [\"POST\"]\nhandler = \"create\"\n",
    );

    let serving = start(&s, "body-limit", 1);
    let body = "x".repeat(64);
    let response = request(
        serving.port,
        &format!(
            "POST /orders HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );

    assert_eq!(
        status_of(&response),
        413,
        "a body over `max_body_bytes` must be refused:\n{response}"
    );
}

#[test]
fn a_body_under_the_limit_is_not_refused_by_it() {
    // The positive control: without it, a server that refused every POST with a body would
    // pass the test above.
    let s = Sandbox::new("body-under");
    s.write(
        "qqq.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[server]\ndefault_auth = \"none\"\n\
         [server.limits.default]\nmax_body_bytes = 1024\n\
         [[server.routes]]\npath = \"/orders\"\nmethods = [\"POST\"]\nhandler = \"create\"\n",
    );

    let serving = start(&s, "body-under", 1);
    let body = "x".repeat(64);
    let response = request(
        serving.port,
        &format!(
            "POST /orders HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );

    assert_ne!(
        status_of(&response),
        413,
        "a body under the limit must not be refused by it:\n{response}"
    );
    assert_eq!(
        status_of(&response),
        503,
        "it must reach the dispatcher instead:\n{response}"
    );
}

// ---------------------------------------------------------------------------
// `--config`
// ---------------------------------------------------------------------------

#[test]
fn config_serves_the_manifest_it_names() {
    // `--config` was parsed into `ServeOptions::config` and never read, so this command
    // served `qqq.toml` while the operator believed they had selected `prod.toml`. The two
    // manifests here differ in a way the response shows: one refuses everything, the other
    // is public.
    let s = Sandbox::new("config-flag");
    s.write("qqq.toml", DENY_BY_DEFAULT);
    s.write(
        "prod.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[server]\ndefault_auth = \"none\"\n\
         [[server.routes]]\npath = \"/healthz\"\nmethods = [\"GET\"]\nhandler = \"health\"\n",
    );

    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--config",
            "prod.toml",
            "--accept-limit",
            "1",
        ])
        .current_dir(&s.path)
        .env("HOME", &s.path)
        .env("USERPROFILE", &s.path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("`qqqai serve --config` must be runnable");
    let mut serving = Serving { child, port };

    // Bound-based readiness again: see `start` for why connecting would consume the accept
    // budget this test needs for its one real request.
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    let response = get(serving.port, "/healthz");
    assert_eq!(
        status_of(&response),
        503,
        "`--config prod.toml` must serve prod.toml, whose route is public:\n{response}"
    );
    let _ = serving.child.kill();
    let _ = serving.child.wait();
}

// ---------------------------------------------------------------------------
// The per-tenant connection ceiling
// ---------------------------------------------------------------------------

/// A manifest with a public route and a per-tenant ceiling of one connection.
///
/// The key is the peer address the server derives, so it matches the loopback client
/// these tests connect from. `default_auth = "none"` is explicit, because the default is
/// `deny` and a route the test cannot reach would make the ceiling untestable.
const CONNECTION_CEILING_ONE: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
    [server]\ndefault_auth = \"none\"\n\
    [[server.routes]]\npath = \"/healthz\"\nmethods = [\"GET\"]\nhandler = \"health\"\n\
    [server.limits.per_tenant.\"127.0.0.1\"]\nmax_connections = 1\n";

/// Hold a keep-alive connection open and read whatever the server answers.
///
/// Returns the stream so the caller keeps the connection alive: the ceiling counts open
/// connections, so dropping this would release the slot.
fn hold_open(port: u16) -> TcpStream {
    let mut held = TcpStream::connect(("127.0.0.1", port)).expect("connect the held connection");
    held.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
        .expect("write on the held connection");
    held.flush().expect("flush");
    held.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let mut buf = [0u8; 512];
    let _ = held.read(&mut buf);
    held
}

/// **The ledger's own refusal, which no routed path produces.**
///
/// `close_immediately` writes a bare status line with `content-length: 0` and **no**
/// `X-QQQ-Error`, because there is no route to name. Every refusal that goes through the
/// router carries that header (`not_built`, `unauthenticated`, ...). Asserting on the
/// header's absence is therefore the only way to tell the ledger's 503 from the
/// not-built 503 in a test that runs against an unbuilt guest -- and without it this
/// test passed while the ceiling was doing nothing at all.
fn is_bare_ledger_refusal(response: &str) -> bool {
    response.starts_with("HTTP/1.1 503")
        && response.contains("content-length: 0")
        && !response.contains("X-QQQ-Error")
}

/// **A manifest's `max_connections` is applied by the served path.**
///
/// The ceiling was a compiled constant with no configuration route until `SRV-020` was
/// finished, so this is the difference between a manifest key that is read and one that
/// is listed by `qqqai inspect` and never applied -- the shape the per-tenant address key
/// had when it was documented as "tenant name" (`§O-185`).
#[test]
fn a_manifest_connection_ceiling_is_applied() {
    let s = Sandbox::new("conn-ceiling");
    s.write("qqq.toml", CONNECTION_CEILING_ONE);

    let serving = start(&s, "conn-ceiling", 3);

    // Hold the tenant's only slot. Held, not dropped: a dropped stream releases the slot
    // and the next connection would be admitted, making this a test of the happy path.
    let held = hold_open(serving.port);

    let refused = request(
        serving.port,
        "GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(
        is_bare_ledger_refusal(&refused),
        "a tenant at its declared ceiling must be refused by the ledger, whose refusal \
         carries no `X-QQQ-Error`:\n{refused}"
    );

    drop(held);
}

/// The positive control: a raised ceiling lets the second connection through the ledger.
///
/// Asserted on the **absence of the bare ledger refusal**, not on a 200. A 200 is
/// unreachable here because the fixture's guest is unbuilt, and asserting one made this
/// control fail against a correct server. What the control must show is narrower and
/// exactly right: with a ceiling of four, the second connection reaches the router.
#[test]
fn raising_the_ceiling_lets_a_second_connection_through() {
    let s = Sandbox::new("conn-ceiling-high");
    let raised = CONNECTION_CEILING_ONE.replace("max_connections = 1", "max_connections = 4");
    s.write("qqq.toml", &raised);

    let serving = start(&s, "conn-ceiling-high", 3);

    let held = hold_open(serving.port);

    let second = request(
        serving.port,
        "GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(
        !is_bare_ledger_refusal(&second),
        "with a ceiling of four the second connection must pass the ledger and reach the \
         router, whose answer carries `X-QQQ-Error`:\n{second}"
    );
    assert!(
        second.contains("X-QQQ-Error"),
        "the second connection must have been answered by a routed path, which is what \
         proves it got past the ledger:\n{second}"
    );

    drop(held);
}
