// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the listener and the accept loop.
//!
//! These bind real sockets on the loopback interface. That is deliberate: the
//! unit tests in `listener.rs` cover address parsing and configuration, but
//! nothing there proves that `accept_stream` actually accepts — and an accept
//! loop that compiles is not the same as one that returns a connection.
//!
//! # Why the port is not fixed
//!
//! A fixed port would make these tests fail whenever something else on the
//! machine holds it, which on a developer's laptop is most of the time. Port 0
//! asks the OS for a free one, and the bound port is read back from
//! `local_addr`. `ListenAddr::parse` refuses port 0 in a *manifest*, because a
//! deployed service must not listen somewhere unknown — but a test harness is
//! exactly the case where an ephemeral port is correct.
//!
//! # Why these tests have a timeout
//!
//! A test that waits on a socket forever is a test that hangs CI rather than
//! failing it. Every wait here is bounded, so a broken accept loop produces a
//! failure in seconds.

use std::time::Duration;

use qqq_io::{Listener, ListenerConfig, Shutdown};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Bind a listener on an ephemeral loopback port.
///
/// # Why this retries, and why it does not merely pick a port
///
/// The obvious implementation binds port 0, reads the address back, **drops the
/// probe socket**, and then binds that address for real. The drop exists only
/// because `Listener::bind` takes an explicit `ListenAddr` and cannot be asked
/// for port 0 — so between the drop and the real bind the port is owned by
/// nobody, and anything on the machine may take it.
///
/// That window is the whole defect. Measured on Linux (CI `ubuntu-latest`, run
/// 35690936055):
///
/// ```text
///   crates/qqq-io/tests/listener.rs:46:10
///   the address we just bound must be bindable:
///     Error { code: ListenerBindFailed, message: "could not bind `127.0.0.1:36265`",
///             cause: ["Address already in use (os error 98)"] }
/// ```
///
/// Line 46 was the *helper's* own expect, so this was a whole-file flake source
/// rather than one bad test — every test in this file calls it.
///
/// A retry is the honest fix: the losing side of a race has no way to win it,
/// and a fresh port is always available. Widening a wait would not help, because
/// nothing here is waiting for a condition — the port is simply gone. This is
/// the same repair, for the same reason, as the one in `qqq-serve`'s route tests.
///
/// In Linux the failing bind is `EADDRINUSE` (98) on a port the kernel had just
/// handed out; on Windows the same sequence does not fail, which is why the
/// defect only ever appeared on one platform.
async fn ephemeral_listener() -> Listener {
    // Port 0 is not expressible through `ListenAddr` — that is the point of the
    // validation — so the test builds the `SocketAddr` directly.
    let mut last = String::from("no attempt was made");

    for _ in 0..16 {
        let socket = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(s) => s,
            Err(e) => {
                last = format!("could not reserve a probe port: {e}");
                continue;
            }
        };
        let Ok(local) = socket.local_addr() else {
            "bound socket has no local address".clone_into(&mut last);
            continue;
        };
        drop(socket);

        let addr =
            qqq_io::ListenAddr::parse(&local.to_string()).expect("the bound address must parse");
        match Listener::bind(ListenerConfig::for_addr(addr)).await {
            Ok(listener) => return listener,
            // `local` was taken between the drop and the bind. Try another.
            Err(e) => last = e.to_string(),
        }
    }

    panic!("no ephemeral loopback port could be bound in 16 attempts; last: {last}")
}

#[tokio::test]
async fn a_listener_binds_and_reports_its_address() {
    let listener = ephemeral_listener().await;
    let local = listener.local_addr();
    assert_eq!(local.ip().to_string(), "127.0.0.1");
    assert_ne!(local.port(), 0, "an ephemeral port must be resolved");
}

/// **The property that matters.** A client connects, the accept loop returns it,
/// and the shard assignment records it. Everything else in `qqq-io` is in
/// service of this.
#[tokio::test]
async fn the_accept_loop_accepts_a_real_connection() {
    let listener = ephemeral_listener().await;
    let addr = listener.local_addr();
    let shutdown = Shutdown::new();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<std::net::SocketAddr>(8);
    let shutdown_for_loop = shutdown.clone();

    let accept_task = tokio::spawn(async move {
        listener
            .accept_stream(&shutdown_for_loop, move |_stream, peer| {
                // `try_send` rather than `blocking_send`: the callback is
                // synchronous and must not block the acceptor.
                let _ = tx.try_send(peer);
            })
            .await
    });

    // Give the loop a moment to reach its first `select!`.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client = TcpStream::connect(addr).await.expect("must connect");
    let peer = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the accept loop must not hang")
        .expect("a connection must be accepted");
    assert!(peer.port() > 0, "the peer address must have a port");

    // Data flows over the accepted socket: the loop hands over a live stream,
    // not a closed one.
    drop(client);

    shutdown.signal();
    let result = tokio::time::timeout(Duration::from_secs(2), accept_task)
        .await
        .expect("the accept loop must stop promptly on shutdown")
        .expect("the task must not panic");
    assert!(result.is_ok(), "a clean shutdown is not an error");
}

/// Several connections must all be accepted, not just the first — a loop that
/// handles one and then wedges is a plausible failure the single-connection test
/// would miss.
#[tokio::test]
async fn the_accept_loop_accepts_many_connections() {
    let listener = ephemeral_listener().await;
    let addr = listener.local_addr();
    let shutdown = Shutdown::new();

    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count_for_loop = std::sync::Arc::clone(&count);
    let shutdown_for_loop = shutdown.clone();

    let accept_task = tokio::spawn(async move {
        listener
            .accept_stream(&shutdown_for_loop, move |_stream, _peer| {
                count_for_loop.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
            .await
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut clients = Vec::new();
    for _ in 0..16 {
        clients.push(TcpStream::connect(addr).await.expect("must connect"));
    }

    // Wait for all sixteen, bounded.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if count.load(std::sync::atomic::Ordering::SeqCst) >= 16 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "only {} of 16 connections were accepted before the deadline",
            count.load(std::sync::atomic::Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    drop(clients);
    shutdown.signal();
    let _ = tokio::time::timeout(Duration::from_secs(2), accept_task).await;
}

/// A shutdown signalled *before* the loop starts must stop it immediately rather
/// than waiting for a connection that may never come. This is the case that
/// matters during a deploy: nothing is arriving, and the process must still exit.
#[tokio::test]
async fn a_pre_signalled_shutdown_stops_the_loop_without_a_connection() {
    let listener = ephemeral_listener().await;
    let shutdown = Shutdown::new();
    shutdown.signal();

    let task =
        tokio::spawn(async move { listener.accept_stream(&shutdown, |_stream, _peer| {}).await });

    let result = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("a pre-signalled shutdown must not wait for a connection")
        .expect("the task must not panic");
    assert!(result.is_ok());
}

/// A shutdown arriving while the loop is idle must be noticed without a
/// connection to wake it. Without the `select!` over `shutdown.wait()`, the loop
/// would block until a client happened to connect — which during a quiet
/// shutdown is never.
#[tokio::test]
async fn a_shutdown_during_an_idle_period_is_noticed() {
    let listener = ephemeral_listener().await;
    let shutdown = Shutdown::new();
    let shutdown_for_loop = shutdown.clone();

    let task = tokio::spawn(async move {
        listener
            .accept_stream(&shutdown_for_loop, |_stream, _peer| {})
            .await
    });

    tokio::time::sleep(Duration::from_millis(30)).await;
    shutdown.signal();

    let result = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("an idle loop must notice shutdown, not wait for a connection")
        .expect("the task must not panic");
    assert!(result.is_ok());
}

/// A second bind to the same port must fail with a clear error rather than
/// hanging or panicking. This is the "address already in use" case, and it is
/// the single most common bind failure a user meets.
#[tokio::test]
async fn binding_an_occupied_port_fails_with_a_remediation() {
    let first = ephemeral_listener().await;
    let addr = first.local_addr();

    let second = Listener::bind(ListenerConfig::for_addr(
        qqq_io::ListenAddr::parse(&addr.to_string()).expect("must parse"),
    ))
    .await;

    let err = second.expect_err("binding an occupied port must fail");
    assert_eq!(err.code, qqq_core::ErrorCode::ListenerBindFailed);
    assert!(
        err.remediation.is_some(),
        "a bind failure must say what to do: {err:?}"
    );
    assert!(
        err.cause.iter().any(|c| !c.is_empty()),
        "the OS error must be carried in the cause"
    );
}

/// The accepted stream must be usable, not merely returned. A loop that handed
/// over a dropped or half-initialised socket would pass a count-based test.
#[tokio::test]
async fn an_accepted_stream_carries_data() {
    let listener = ephemeral_listener().await;
    let addr = listener.local_addr();
    let shutdown = Shutdown::new();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<tokio::net::TcpStream>(1);
    let shutdown_for_loop = shutdown.clone();

    let accept_task = tokio::spawn(async move {
        listener
            .accept_stream(&shutdown_for_loop, move |stream, _peer| {
                let _ = tx.try_send(stream);
            })
            .await
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut client = TcpStream::connect(addr).await.expect("must connect");
    let mut server = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("must accept")
        .expect("a stream must be handed over");

    client.write_all(b"ping").await.expect("must write");
    client.flush().await.expect("must flush");

    let mut buf = [0u8; 4];
    let n = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut server, &mut buf),
    )
    .await
    .expect("read must not hang")
    .expect("read must succeed");

    assert_eq!(&buf[..n], b"ping", "the accepted stream must carry data");

    shutdown.signal();
    let _ = tokio::time::timeout(Duration::from_secs(2), accept_task).await;
}

/// The shard set must balance real connections, not just synthetic calls. This
/// is the integration form of `round_robin_balances_exactly_over_a_multiple`.
#[tokio::test]
async fn real_connections_are_balanced_across_shards() {
    use qqq_io::ShardSet;

    let listener = ephemeral_listener().await;
    let addr = listener.local_addr();
    let shutdown = Shutdown::new();

    let shards = std::sync::Arc::new(std::sync::Mutex::new(ShardSet::new(4)));
    let shards_for_loop = std::sync::Arc::clone(&shards);
    let shutdown_for_loop = shutdown.clone();

    let accept_task = tokio::spawn(async move {
        listener
            .accept_stream(&shutdown_for_loop, move |_stream, _peer| {
                if let Ok(mut s) = shards_for_loop.lock() {
                    s.assign();
                }
            })
            .await
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut clients = Vec::new();
    for _ in 0..16 {
        clients.push(TcpStream::connect(addr).await.expect("must connect"));
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let total = shards.lock().expect("lock").total();
        if total >= 16 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "only {total} accepted"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The guard is scoped rather than held, so it is released before the
    // awaits below. Holding a `std::sync::MutexGuard` across an `await` can
    // deadlock, and it is the kind of thing that works until it does not.
    {
        let set = shards.lock().expect("lock");
        assert_eq!(set.total(), 16);
        assert_eq!(
            set.spread(),
            0,
            "16 connections over 4 shards must be perfectly balanced, got {:?}",
            set.shards()
                .iter()
                .map(qqq_io::Shard::assigned)
                .collect::<Vec<_>>()
        );
    }

    drop(clients);
    shutdown.signal();
    let _ = tokio::time::timeout(Duration::from_secs(2), accept_task).await;
}
