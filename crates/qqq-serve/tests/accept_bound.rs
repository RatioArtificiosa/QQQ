// SPDX-License-Identifier: Apache-2.0

//! The accept bound is honoured on the path where the ledger refuses (`SRV-020`).
//!
//! # The defect these pin
//!
//! `stop_after_the_bound` signals the shared shutdown once the number of *accepted*
//! connections reaches `accept_limit`. The counter is incremented on the acceptor, before
//! the connection task is spawned, so **a connection the ledger refuses is counted** --
//! deliberately, because the bound is on accepts rather than on requests served.
//!
//! The signal, though, was reached only at the end of the connection task, after
//! `serve_connection` returns. The refusal path returned early:
//!
//! ```text
//! if !l.admit(&id.tenant) { drop(l); close_immediately(stream, 503).await; return; }
//! ```
//!
//! So a refused connection incremented the counter and never signalled. With
//! `accept_limit = N`, if the Nth accept is one the ledger refuses, the server never
//! stopped: it kept accepting until something else ended the process. A burst of
//! connection attempts is both the load a bound exists for and the load that produces
//! refusals, so the two conditions arrive together.
//!
//! # Why these drive `serve` on a real socket
//!
//! The refusal happens inside the spawned task, on the acceptor's callback, with a real
//! `TcpStream` in hand. A unit test of `stop_after_the_bound` cannot see it, because the
//! defect is that the function is **not reached** -- a property of the control flow, not of
//! the function's body. Only a test that opens two real connections can show that the
//! second, refused one leaves the server running.
//!
//! # Why readiness is probed by *binding*
//!
//! Connecting to the port to see whether the server is up is itself an accept, and it is
//! counted. With a small `accept_limit` the probe spends the budget the test needs -- in an
//! earlier version of this file it spent the server's only accept and shut it down before
//! the first assertion, so the test failed against a *correct* server. Attempting to bind
//! the same port is free: while the server holds it the bind fails with `AddrInUse`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use qqq_io::listener::{ListenAddr, Shutdown};
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::route::{Method as RouteMethod, Route, RouteTable};
use qqq_serve::server::{serve, Dispatch, Handler, ServerConfig};
use qqq_serve::{RequestHead, Response, RouteMatch};

/// A port nobody is using, for the reason `tests/socket.rs` documents.
fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().expect("addr");
    drop(l);
    a
}

/// One route, so a request that is *served* has somewhere to go.
fn table() -> RouteTable {
    let mut t = RouteTable::new();
    t.insert(Route::new(RouteMethod::Get, "/ok", "ok").expect("valid route"))
        .expect("distinct");
    t
}

fn handler() -> Handler {
    Arc::new(|_head: &RequestHead, _m: &RouteMatch| Response::text(200, "ok"))
}

/// A running server whose shutdown can be observed without consuming it.
struct Server {
    addr: SocketAddr,
    shutdown: Shutdown,
    /// Held so the accept loop keeps running while the test works.
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    /// Start `serve` bounding accepts to `accept_limit` and admitting one connection per
    /// tenant.
    ///
    /// Retried on a fresh port, because between `free_addr` dropping its listener and
    /// `serve` binding, another test in this process can take the port.
    async fn start(accept_limit: u64) -> Self {
        // The probe's deadline, and the reason the failure message carries its total.
        //
        // A 16-attempt cascade of 20-second probes is up to 320 seconds before this fails, which
        // is what a full-suite run costs when the machine is busy: measured, `cargo test
        // --workspace` on a loaded host reported "could not bind a server after 16 attempts on
        // 16 different ports" after 320.11s, while the same test alone passes in 0.28s.
        //
        // That is a **contended environment**, not a broken server — and the two are
        // indistinguishable from the message, which is the part worth fixing. The panic below
        // now states the elapsed time and what it means, so the next person reads "this machine
        // was busy" instead of "the server does not bind".
        const ATTEMPTS: u32 = 16;
        const PROBE_DEADLINE: Duration = Duration::from_secs(20);
        let started = std::time::Instant::now();

        for _ in 0..ATTEMPTS {
            let addr = free_addr();
            let listen = ListenAddr::parse(&addr.to_string()).expect("parses");
            let shutdown = Shutdown::new();
            let mut config = ServerConfig::for_addr(listen);
            config.accept_limit = Some(accept_limit);
            // One slot per tenant: the first connection takes it and holds it, so the
            // second is refused. That refusal is the accept that must honour the bound.
            config.connections_per_tenant = 1;
            let local = shutdown.clone();
            let task = tokio::spawn(async move {
                if let Err(e) = serve(
                    config,
                    table(),
                    Dispatch::flat(handler()),
                    local,
                    Logger::new(Format::Json, Level::Error),
                )
                .await
                {
                    eprintln!("server stopped early: {}", e.render());
                }
            });

            let s = Self {
                addr,
                shutdown,
                task,
            };
            // The bind probe on a blocking thread, so the runtime thread stays free for
            // `serve` to bind.
            let probe_addr = addr;
            let bound = tokio::task::spawn_blocking(move || {
                let deadline = std::time::Instant::now() + PROBE_DEADLINE;
                while std::time::Instant::now() < deadline {
                    if std::net::TcpListener::bind(probe_addr).is_err() {
                        return true;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                false
            })
            .await
            .expect("probe thread");
            if bound {
                return s;
            }
            // Not bound after the deadline: signal and let this attempt go, then try a fresh
            // port. `abort` rather than awaiting the handle, because awaiting it would move the
            // field out of a type that implements `Drop`, which the compiler refuses --
            // and the server task is a detached probe whose end this test does not need.
            s.shutdown.signal();
            s.task.abort();
        }

        let elapsed = started.elapsed();
        panic!(
            "could not bind a server after {ATTEMPTS} attempts on {ATTEMPTS} different ports, \
             {elapsed:?} elapsed.\n\
             This is almost always a **contended machine**, not a broken server: each attempt \
             waits {PROBE_DEADLINE:?} for the port to refuse a bind, and under load the OS can \
             keep handing the port out for longer than that.\n\
             Check by running this test alone -- it needs well under a second when the host is \
             quiet:\n\
             \x20   cargo test -p qqq-serve --test accept_bound\n\
             If it passes alone, the failure was environmental. If it fails alone, `serve` is \
             genuinely not binding and that is the defect."
        );
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.signal();
    }
}

/// **A connection the ledger refuses still honours the accept bound.**
///
/// The first connection is admitted and held open, consuming the tenant's only slot and
/// reaching accept one of two. The second is refused with a `503` -- accept two, the bound
/// -- and the server must signal its shutdown. Before the fix the refusal returned before
/// `stop_after_the_bound`, and the loop below exhausted its polls with the server still
/// running.
///
/// The first connection is held by a live stream, so it is genuinely open when the second
/// arrives; a dropped first stream would release the slot and the second connection would
/// be admitted instead of refused, which would make this a test of the wrong path.
#[tokio::test]
async fn a_refused_connection_still_honours_the_accept_bound() {
    let server = Server::start(2).await;

    let mut held = TcpStream::connect(server.addr)
        .await
        .expect("connect the first connection");
    held.write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
        .await
        .expect("write on the first connection");
    held.flush().await.expect("flush");
    // Let the first connection be admitted and answered before the second arrives, so the
    // ledger is holding its slot rather than still admitting it.
    let mut first = [0u8; 256];
    let _ = tokio::time::timeout(Duration::from_secs(5), held.read(&mut first)).await;

    let refusal = TcpStream::connect(server.addr)
        .await
        .expect("connect the second connection");
    let mut refusal = refusal;
    refusal
        .write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .expect("write on the second connection");
    refusal.flush().await.expect("flush");

    // The refusal is asynchronous: it happens in the spawned task for the second accept,
    // and the signal lands after the task is scheduled. Poll rather than asserting once, so
    // the test does not race the scheduler on a correct server.
    for _ in 0..400 {
        if server.shutdown.is_signalled() {
            drop(held);
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    drop(held);
    panic!(
        "the refused connection reached the accept bound and the server did not signal \
         shutdown: a refused accept is still an accept"
    );
}
