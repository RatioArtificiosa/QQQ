// SPDX-License-Identifier: Apache-2.0

//! Minimal hyper h2 server for the h2spec conformance job (TEST-019).
//!
//! Binds 127.0.0.1:<port>, serves `GET /` as 200 text on HTTP/2
//! (cleartext, prior knowledge) until killed. Every other route is a
//! 404 through ordinary routing. Nothing here is product surface:
//! the driver under test is `serve_hyper_h2`; this is its launch
//! harness, kept small on purpose so the spec measures hyper, not it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use qqq_io::listener::Shutdown;
use qqq_serve::access_log::{Format, Level, Logger};
use qqq_serve::metrics::TenantLabels;
use qqq_serve::route::{Method, Route, RouteTable};
use qqq_serve::serve_hyper::serve_hyper_h2;
use qqq_serve::server::{ConnectionContext, ConnectionId, Dispatch, Handler, RouteMatch};
use qqq_serve::transport::{HyperLimits, hyper_limits_for};
use qqq_serve::ws::WsConfig;
use qqq_serve::{ConnectionConfig, RequestHead, Response};

fn hello(_head: &RequestHead, _m: &RouteMatch) -> Response {
    Response::text(200, "hello from h")
}

/// Usage failure or bind failure: stderr plus a distinct exit code,
/// because a conformance harness that cannot start must fail loudly
/// rather than look like a passing empty run.
fn die(what: &str) -> ! {
    eprintln!("h2spec_serve: {what}");
    std::process::exit(2);
}

fn port_arg() -> u16 {
    match std::env::args().nth(1).map(|s| s.parse::<u16>()) {
        Some(Ok(port)) => port,
        _ => die("usage: h2spec_serve <port>"),
    }
}

#[tokio::main]
async fn main() {
    let port = port_arg();
    let mut table = RouteTable::new();
    if table
        .insert(match Route::new(Method::Get, "/", "hello") {
            Ok(route) => route,
            Err(error) => die(&format!("bad route: {error}")),
        })
        .is_err()
    {
        die("route table rejected the route");
    }
    let table = Arc::new(table);
    let dispatch: Dispatch = Dispatch::flat({
        let h: Handler = Arc::new(hello);
        h
    });
    let shutdown = Shutdown::new();
    let logger = Logger::new(Format::Json, Level::Error);
    let ws = WsConfig::default();
    let ws_buffer = Arc::new(tokio::sync::Semaphore::new(16));
    let tenant_labels = Arc::new(TenantLabels::new());
    let limits: HyperLimits = hyper_limits_for(&ConnectionConfig::default());
    let listener = match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(listener) => listener,
        Err(error) => die(&format!("cannot bind 127.0.0.1:{port}: {error}")),
    };
    eprintln!("h2spec_serve: listening on 127.0.0.1:{port}");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            // Transient accept errors (fd pressure storms) must not
            // kill the harness mid-suite: back off briefly and keep
            // serving. The job's trap kills the process at the end.
            Err(error) => {
                eprintln!("h2spec_serve: accept failed, retrying: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // Spawned per connection like the real accept loop: h2spec
        // opens a fresh connection per case and may leave the old
        // one open, so serializing would stall the suite into
        // timeouts that look like failures.
        let task = ServeTask {
            table: Arc::clone(&table),
            dispatch: dispatch.clone(),
            shutdown: shutdown.clone(),
            logger: logger.clone(),
            ws: ws.clone(),
            ws_buffer: Arc::clone(&ws_buffer),
            tenant_labels: Arc::clone(&tenant_labels),
            limits,
            stream,
            peer,
        };
        tokio::spawn(async move {
            task.serve().await;
        });
    }
}

struct ServeTask {
    table: Arc<RouteTable>,
    dispatch: Dispatch,
    shutdown: Shutdown,
    logger: Logger,
    ws: WsConfig,
    ws_buffer: Arc<tokio::sync::Semaphore>,
    tenant_labels: Arc<TenantLabels>,
    limits: HyperLimits,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
}

impl ServeTask {
    async fn serve(self) {
        let id = ConnectionId::new(self.peer, 1);
        let ctx = ConnectionContext {
            id: &id,
            shutdown: &self.shutdown,
            logger: &self.logger,
            cors: None,
            metrics_path: None,
            sampler: None,
            auth: None,
            idle_timeout: Some(Duration::from_secs(30)),
            metrics: None,
            limits: None,
            global_requests: None,
            ws: &self.ws,
            loopback_only: false,
            ws_buffer: &self.ws_buffer,
            tenant_labels: &self.tenant_labels,
        };
        let _ = serve_hyper_h2(
            self.stream,
            Arc::clone(&self.table),
            self.dispatch,
            self.limits,
            &ctx,
        )
        .await;
    }
}
