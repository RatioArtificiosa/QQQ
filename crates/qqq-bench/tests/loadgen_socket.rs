// SPDX-License-Identifier: Apache-2.0

//! Drive the load generator against a real listener, over a real socket.
//!
//! # Why this is an integration test and not a unit test
//!
//! The unit tests in `loadgen.rs` prove the *encoding* and the *parsing* are
//! correct. They cannot prove the driver works, because they never open a socket —
//! and this repository has been bitten four times by a suite that tested a type
//! and never its wiring (`§O-130`).
//!
//! The listener here is built from `tokio` directly rather than from `qqq-serve`,
//! because `qqq-bench` sits *below* `qqq-serve` in the topology order by design: a
//! harness that depended on the server could not be used to time the server's own
//! startup. So this test proves the driver against a socket it controls, and
//! `qqqai bench`'s integration tests prove it against the real application.

use std::net::SocketAddr;
use std::time::Duration;

use qqq_bench::loadgen::{drive, one_request, parse_response, Limit, Plan};
use qqq_bench::methodology::Concurrency;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Start a listener that answers every request with `response`, and return its
/// address plus a counter of how many requests it served.
///
/// The counter is what makes the warmup tests meaningful: the difference between
/// "the harness sent 10 requests" and "the harness sent 110 and reported 100" is
/// only observable from the server's side.
async fn spawn_server(
    response: &'static str,
    body: &'static str,
) -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("a bound address");
    let served = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = std::sync::Arc::clone(&served);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let counter = std::sync::Arc::clone(&counter);
            tokio::spawn(async move {
                // Read the head, then answer. `read` once is enough for these
                // requests; the harness always sends a complete head in one write.
                let mut buf = vec![0_u8; 4_096];
                let _ = stream.read(&mut buf).await;
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                // # Why the framing is built in this order
                //
                // The first version wrote `{status}\r\nContent-Length: ..\r\n\r\n{body}`
                // with the status line ALREADY containing its own `\r\n`, so the
                // blank line landed *before* `Content-Length` and everything after
                // it -- headers included -- was counted as body. The test caught it
                // (38 bytes for a 2-byte body), which is why the assertion is on an
                // exact length rather than `> 0`.
                //
                // So: status line, then headers, then the blank line, then the body.
                let full = format!("{response}\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                let _ = stream.write_all(full.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    (addr, served)
}

fn plan_for(addr: SocketAddr, concurrency: Concurrency) -> Plan {
    let mut plan = Plan::get(addr, "/healthz", concurrency);
    plan.timeout = Duration::from_secs(5);
    plan
}

#[tokio::test]
async fn one_request_against_a_real_listener_returns_a_sample() {
    let (addr, _served) = spawn_server("HTTP/1.1 200 OK", "ok").await;
    let plan = plan_for(addr, Concurrency::Sequential);

    let sample = one_request(&plan).await.expect("the request must succeed");
    assert_eq!(sample.status, 200);
    assert_eq!(sample.body_bytes, 2, "the body is `ok`");
    assert!(sample.nanos > 0, "the timer must have advanced");
}

#[tokio::test]
async fn a_server_answer_is_measured_and_counted() {
    let (addr, served) = spawn_server("HTTP/1.1 200 OK", "ok").await;
    let mut plan = plan_for(addr, Concurrency::Sequential);
    plan.warmup = 0;
    plan.limit = Limit::Requests(20);

    let result = drive(&plan).await.expect("the run must complete");
    assert_eq!(result.attempted, 20);
    assert_eq!(result.failed, 0, "every request must have been answered");
    assert_eq!(result.completed(), 20);
    assert_eq!(result.distribution.len(), 20);
    assert_eq!(served.load(std::sync::atomic::Ordering::Relaxed), 20);
    assert!(result.requests_per_second().expect("a non-zero run") > 0.0);
}

#[tokio::test]
async fn warmup_requests_are_sent_and_not_counted() {
    // §9.1 requires the warmup procedure be *stated*, which means the harness must
    // actually perform the stated number. The server's own counter is how this is
    // checked: 5 warmup + 10 measured = 15 served, 10 reported.
    let (addr, served) = spawn_server("HTTP/1.1 200 OK", "ok").await;
    let mut plan = plan_for(addr, Concurrency::Sequential);
    plan.warmup = 5;
    plan.limit = Limit::Requests(10);

    let result = drive(&plan).await.expect("the run must complete");
    assert_eq!(result.attempted, 10, "warmup must not be reported");
    assert_eq!(result.distribution.len(), 10);
    assert_eq!(
        served.load(std::sync::atomic::Ordering::Relaxed),
        15,
        "the server must have seen the warmup requests too"
    );
}

#[tokio::test]
async fn zero_warmup_sends_no_warmup_requests() {
    // The control for the test above. Without it, a harness that always warmed up
    // 5 times would pass that test while making `cold`'s stated "no warmup" false.
    let (addr, served) = spawn_server("HTTP/1.1 200 OK", "ok").await;
    let mut plan = plan_for(addr, Concurrency::Sequential);
    plan.warmup = 0;
    plan.limit = Limit::Requests(10);

    let _ = drive(&plan).await.expect("the run must complete");
    assert_eq!(
        served.load(std::sync::atomic::Ordering::Relaxed),
        10,
        "zero warmup must send exactly the measured requests"
    );
}

#[tokio::test]
async fn concurrency_actually_changes_how_many_requests_are_in_flight() {
    // The property `§9.1` requires the result to disclose. Asserted by the
    // server's counter and the request total, both of which must be exact
    // regardless of how the work was distributed across workers.
    for connections in [1_u32, 4, 16] {
        let (addr, served) = spawn_server("HTTP/1.1 200 OK", "ok").await;
        let mut plan = plan_for(addr, Concurrency::Fixed { connections });
        plan.warmup = 0;
        plan.limit = Limit::Requests(64);

        let result = drive(&plan).await.expect("the run must complete");
        assert_eq!(
            result.attempted, 64,
            "{connections} connections must still send exactly 64 requests"
        );
        assert_eq!(
            served.load(std::sync::atomic::Ordering::Relaxed),
            64,
            "{connections} connections: the server must see exactly the total"
        );
    }
}

#[tokio::test]
async fn a_request_count_that_does_not_divide_evenly_is_still_exact() {
    // The remainder path. 100 requests over 8 workers is 12 each with 4 left over;
    // an off-by-one there would report 96 or 104 and nothing else would notice.
    let (addr, served) = spawn_server("HTTP/1.1 200 OK", "ok").await;
    let mut plan = plan_for(addr, Concurrency::Fixed { connections: 8 });
    plan.warmup = 0;
    plan.limit = Limit::Requests(100);

    let result = drive(&plan).await.expect("the run must complete");
    assert_eq!(result.attempted, 100);
    assert_eq!(result.distribution.len(), 100);
    assert_eq!(served.load(std::sync::atomic::Ordering::Relaxed), 100);
}

#[tokio::test]
async fn a_duration_limited_run_stops_and_reports_a_rate() {
    let (addr, _served) = spawn_server("HTTP/1.1 200 OK", "ok").await;
    let mut plan = plan_for(addr, Concurrency::Fixed { connections: 2 });
    plan.warmup = 0;
    plan.limit = Limit::Duration(Duration::from_millis(300));

    let result = drive(&plan).await.expect("the run must complete");
    assert!(result.attempted > 0, "a sustained run must send something");
    assert_eq!(result.failed, 0);
    assert!(
        result.elapsed >= Duration::from_millis(250),
        "the run must actually last the stated duration, got {:?}",
        result.elapsed
    );
    assert!(result.requests_per_second().expect("non-zero") > 0.0);
}

#[tokio::test]
async fn a_refused_connection_is_a_failure_not_a_zero_latency_sample() {
    // Bound and immediately dropped, so the port is almost certainly free and the
    // connect is refused.
    let addr: SocketAddr = {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let a = listener.local_addr().expect("addr");
        drop(listener);
        a
    };

    let mut plan = plan_for(addr, Concurrency::Sequential);
    plan.warmup = 0;
    plan.limit = Limit::Requests(3);
    plan.timeout = Duration::from_millis(500);

    let result = drive(&plan).await.expect("the run itself must not error");
    assert_eq!(result.attempted, 3);
    assert_eq!(
        result.failed, 3,
        "a refused connection must be counted as a failure"
    );
    assert_eq!(result.completed(), 0);
    assert!(
        result.distribution.is_empty(),
        "a failed request must contribute no latency sample -- counting it as 0 ns \
         would report a perfect p99 for a server that never answered"
    );
}

#[tokio::test]
async fn a_post_body_reaches_the_server() {
    // The defect `§O-155` recorded for the reference app, tested at the harness
    // level: a request whose body never arrives measures the wrong workload under
    // the right name.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    // A std channel rather than `tokio::sync::oneshot`: the receiving side blocks
    // in a synchronous context anyway, and taking a Tokio feature this crate does
    // not otherwise need would enlarge the dependency surface to satisfy one test.
    let (tx, rx) = std::sync::mpsc::channel::<String>();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buf = vec![0_u8; 4_096];
        let n = stream.read(&mut buf).await.expect("read");
        let received = String::from_utf8_lossy(&buf[..n]).to_string();
        let _ = tx.send(received);
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await;
        let _ = stream.shutdown().await;
    });

    let mut plan = plan_for(addr, Concurrency::Sequential);
    plan.method = "POST".to_owned();
    plan.path = "/crypto/100".to_owned();
    plan.body = Some(b"seed=abc".to_vec());

    let _ = one_request(&plan).await.expect("the request must succeed");
    let received = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the server must have read something");

    assert!(
        received.contains("POST /crypto/100 HTTP/1.1"),
        "got: {received}"
    );
    assert!(
        received.contains("Content-Length: 8"),
        "the length must be declared: {received}"
    );
    assert!(
        received.ends_with("seed=abc"),
        "the body must actually arrive: {received}"
    );
}

#[tokio::test]
async fn a_status_code_reaches_the_result() {
    // A 404 must be recorded as a 404, not folded into "success". A harness that
    // reported only latencies would let a wrong route look like a fast one.
    let (addr, _served) = spawn_server("HTTP/1.1 404 Not Found", "no").await;
    let mut plan = plan_for(addr, Concurrency::Sequential);
    plan.warmup = 0;
    plan.limit = Limit::Requests(5);

    let result = drive(&plan).await.expect("the run must complete");
    assert_eq!(result.statuses(), vec![404]);
    assert_eq!(
        result.failed, 0,
        "a 404 is an answer, not a connection failure"
    );
    assert!(result.any_body());
}

#[tokio::test]
async fn an_empty_body_route_is_detectable() {
    // `§9.1`'s `json` row claims a 1 KB serialization. A run of contentless
    // responses must be distinguishable, and `any_body` is how.
    let (addr, _served) = spawn_server("HTTP/1.1 200 OK", "").await;
    let mut plan = plan_for(addr, Concurrency::Sequential);
    plan.warmup = 0;
    plan.limit = Limit::Requests(3);

    let result = drive(&plan).await.expect("the run must complete");
    assert_eq!(result.statuses(), vec![200]);
    assert!(!result.any_body(), "an empty body must be visible as such");
}

#[tokio::test]
async fn the_parser_agrees_with_a_response_this_server_actually_sent() {
    // The spec-derived check: parse what a real server wrote, rather than what the
    // test imagined it wrote. `parse_response`'s unit tests use literals; this one
    // uses bytes that came off a socket.
    let (addr, _served) = spawn_server("HTTP/1.1 201 Created", "created").await;
    let plan = plan_for(addr, Concurrency::Sequential);

    let sample = one_request(&plan).await.expect("the request must succeed");
    assert_eq!(sample.status, 201);
    assert_eq!(sample.body_bytes, 7, "`created` is seven bytes");

    // And confirm the parser is the thing that decided, by re-parsing a
    // reconstructible head.
    let parsed = parse_response(b"HTTP/1.1 201 Created\r\nContent-Length: 7\r\n\r\ncreated")
        .expect("well-formed");
    assert_eq!(parsed.status, sample.status);
    assert_eq!(
        u64::try_from(parsed.body_bytes).expect("small"),
        sample.body_bytes
    );
}
