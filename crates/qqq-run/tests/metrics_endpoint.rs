// SPDX-License-Identifier: Apache-2.0

//! The Prometheus scrape endpoint — `OBS-013`, over the real binary.
//!
//! # Why this file exists, and why it is the third version
//!
//! `§O-308` recorded that the *renderer* was built and the endpoint was not. `§O-317` recorded the
//! first attempt at the endpoint **working and being reverted**. This is the version that landed.
//!
//! # And why its helpers are now in `common`
//!
//! **Six test files carried their own copy of the same helper**, and the flake that four rounds of
//! fixes chased was not a test — it was **the pattern**, present six times (`§O-326`). Two of the six
//! flaked on Ubuntu, and each fix had been aimed at whichever file happened to fail.
//!
//! `common/mod.rs` is that helper, once. It retries the whole attempt on a fresh port when the server
//! answers nothing, and it **never hands back an empty response** — because every assertion in these
//! files is a `contains`, and `!contains(x)` is satisfied by nothing at all (`§O-314`).
//!
//! # The three questions `§O-308` left open, and the answers asserted here
//!
//! 1. **Where** — on the application listener, opt-in via `--metrics-path`.
//! 2. **Opt-in** — yes, and `nothing_is_exposed_without_the_flag` keeps the default honest.
//! 3. **Collision** — refused at start-up, because a silent shadow hides either an app route or the
//!    metrics and neither is visible from outside.

mod common;

use common::{run_refused, serve_and_request, Sandbox};

const MANIFEST: &str = "[package]\nname = \"metrics-probe\"\nversion = \"0.1.0\"\n\
     [server]\ndefault_auth = \"none\"\n\
     [[server.routes]]\npath = \"/orders\"\nmethods = [\"GET\"]\nhandler = \"list\"\n";

/// **The exposition is served, with the content type a scraper needs — `OBS-013`.**
#[test]
fn the_endpoint_serves_the_exposition() {
    let sandbox = Sandbox::new("metrics-serves");
    let served = serve_and_request(
        &sandbox,
        MANIFEST,
        &["--metrics-path", "/internal/metrics"],
        "/internal/metrics",
    );
    let response = served.text;

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
    // afterwards cannot appear in it.
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
    let sandbox = Sandbox::new("metrics-off");
    let response = serve_and_request(&sandbox, MANIFEST, &[], "/internal/metrics").text;
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
///
/// A silent shadow hides either the application's route or the metrics, and neither failure is visible
/// from outside — so it is refused where an operator can act on it.
#[test]
fn a_collision_with_a_declared_route_refuses_the_start() {
    let sandbox = Sandbox::new("metrics-collide");
    let combined = run_refused(&sandbox, MANIFEST, &["--metrics-path", "/orders"]);
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
    let sandbox = Sandbox::new("metrics-relative");
    let combined = run_refused(&sandbox, MANIFEST, &["--metrics-path", "metrics"]);
    assert!(
        combined.contains("is not an absolute path"),
        "the refusal must say what is wrong: {combined}"
    );
}
