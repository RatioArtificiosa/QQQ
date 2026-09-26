// SPDX-License-Identifier: Apache-2.0

//! The accept loop: joining the socket layer to the connection state machine.
//!
//! Implements `SRV-001` (HTTP/1.1 with keep-alive, timeouts and connection
//! limits); Proposal §6.4, §4.4.
//!
//! # What existed before this module, and what did not
//!
//! Every piece of the request path was already built and individually tested:
//!
//! | Piece | Module |
//! |---|---|
//! | route table (radix trie) | `route` |
//! | head parser, header limits | `http1` |
//! | response writer, error mapping | `response` |
//! | connection lifetime, keep-alive, drain | `conn` |
//! | listener, shards, shutdown | `qqq-io` |
//!
//! Nothing joined them. That is worth stating plainly, because "the pieces
//! exist" reads like progress and is not: a router with no socket is a data
//! structure, and a parser with no loop is a function. This module is the loop.
//!
//! # The loop, and why it is structured this way
//!
//! ```text
//! accept ──> admit (per-tenant ceiling) ──┐
//!                                         v
//!              read head ──> parse ──> route ──> respond
//!                    │                    │
//!                    └── timeout/limit ───┘
//! ```
//!
//! Three decisions shape it:
//!
//! 1. **Timeouts are enforced by the connection state machine**, not by
//!    `tokio::time::timeout` around a read. `Connection::poll(now)` already
//!    knows the idle and header deadlines, and wrapping reads as well would
//!    give two authorities on one answer — they would disagree eventually, and
//!    the disagreement would be a connection that hangs.
//! 2. **The ledger is checked before the first byte is read.** A tenant at its
//!    ceiling is closed rather than served-then-rejected, because reading a
//!    request the server will not answer spends the attacker's cost on the
//!    defender.
//! 3. **A handler that traps closes the connection**, rather than keeping it
//!    alive. The connection state machine decides that through
//!    `server_wants_close`, so the policy lives in one place.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use qqq_core::{Error, ErrorCode, Result};
use qqq_io::listener::{AcceptError, ListenAddr, Listener, ListenerConfig, Shutdown};

use crate::access_log::{Level, Logger, Record, TraceId};
use crate::conn::{Action, CloseReason, Connection, ConnectionConfig, ConnectionLedger};
use crate::http1::{self, ParseError, RequestHead, Version};
use crate::response::{self, Response};
use crate::route::RouteTable;

/// How the server behaves.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Where to listen.
    pub addr: ListenAddr,
    /// Connection lifetime rules.
    pub connection: ConnectionConfig,
    /// Per-tenant connection ceiling.
    pub connections_per_tenant: u32,
    /// Shards to bind.
    ///
    /// `None` uses the shard count `qqq-io` derives from the machine. An
    /// explicit value is for testing and for deployments that have measured a
    /// different number.
    pub shards: Option<usize>,
    /// Where per-request counters go, or `None` to record nothing.
    ///
    /// On the config rather than on the listener because it is a property of the server's
    /// *behaviour*, not of where it listens. `Arc` because the accept loop clones it into
    /// every connection task and the registry must be **one** value — an owned clone per
    /// connection would give each connection its own counters, which is exactly what a
    /// shared registry exists to avoid and which looks like "the metric is always 1".
    pub metrics: Option<Arc<crate::metrics::HttpMetrics>>,
    /// The path the registry is exposed on, or `None` to expose nothing — `OBS-013`.
    ///
    /// # Why this is a config field and not a route
    ///
    /// Because it is the **server's** path, not the application's: `serve::prepare` refuses a value
    /// that collides with a declared route, so the two can never contend. Making it a route would
    /// have put it in the table the manifest owns, where the application could shadow it.
    ///
    /// `None` is the honest default. The registry holds tenant names and traffic volume, and who
    /// may read that is the operator's decision.
    pub metrics_path: Option<String>,
    /// The per-tenant request limits, or `None` for none (`SRV-020`).
    ///
    /// **`Arc` for a reason the registry's does not share**: the rate windows are mutable
    /// state that must be shared across connections. A per-connection copy would give every
    /// connection its own allowance, so a tenant with a limit of 100 could make 100 requests
    /// *per connection* — the limit would exist, be tested, and enforce nothing. That is the
    /// failure this type's `Arc` prevents by construction.
    pub limits: Option<Arc<crate::limits::TenantLimits>>,
    /// The cross-origin policy, or `None` for no CORS at all.
    ///
    /// # Why the default is `None` and not a permissive policy
    ///
    /// `SRV-019`'s item is *"implement CORS configuration with safe defaults"*, and the
    /// safe default for a relaxation of the same-origin policy is not to relax it. A
    /// server that emitted `Access-Control-Allow-Origin: *` unless told otherwise would
    /// make every QQQ application cross-origin-readable without its author asking.
    ///
    /// `None` and `Some(Cors::none())` behave identically — both emit nothing — and the
    /// distinction is only that the second says the author configured CORS and allowed
    /// no origins. Keeping the field optional means a manifest with no `[server.cors]`
    /// table produces a server that has never heard of CORS.
    pub cors: Option<crate::cors::Cors>,
    /// The per-route authentication policy, or `None` for none.
    ///
    /// `None` means **no policy is installed**, which is different from a policy that
    /// refuses everything and different again from one that allows. With `None` the server
    /// has no opinion about authority and serves every route it can match — which is
    /// correct for `qqq-serve`'s own socket tests and for an embedder that enforces
    /// authority itself, and is **not** what `qqqai serve` may do, because the manifest
    /// always has an opinion (`default_auth`, whose default is `deny`).
    ///
    /// `qqq-run` is therefore the crate that must supply it, and
    /// `qqq_serve::auth::AuthPolicy::decide` is fail-closed for a route it was not told
    /// about. See that module for why the missing-entry case refuses.
    pub auth: Option<Arc<crate::auth::AuthPolicy>>,
    /// Stop accepting after this many connections, or `None` to run until shutdown.
    ///
    /// # Why this is a server setting and not a test harness
    ///
    /// An unbounded accept loop that cannot be bounded is a loop that cannot be verified:
    /// a socket test has to be able to say "serve exactly three connections and then
    /// finish", or it either hangs or relies on a timeout to end it, and a test that ends
    /// by timing out cannot distinguish "done" from "stuck".
    ///
    /// The count is of connections **accepted**, not served: a connection refused by the
    /// ledger still counts, because the bound exists to end the loop rather than to measure
    /// work. Reaching the bound signals the same shutdown the drain path uses, so the
    /// listener, the connections in flight and the exit all take the one path that already
    /// has tests.
    pub accept_limit: Option<u64>,
}

impl ServerConfig {
    /// A configuration for an address, with the documented defaults.
    #[must_use]
    pub fn for_addr(addr: ListenAddr) -> Self {
        Self {
            addr,
            connection: ConnectionConfig::default(),
            connections_per_tenant: 10_000,
            shards: None,
            cors: None,
            // Off by default. A registry that always allocated would make the default
            // server pay for a feature it was not asked for; the recording sites are
            // `Option`-checked precisely so that absence is free.
            metrics: None,
            metrics_path: None,
            // Likewise: a server whose manifest declared no `[server.limits]` applies none.
            // A built-in cap here would be a number this crate invented, silently changing
            // behaviour on upgrade -- see `qqq_cap::manifest::RequestLimits`.
            limits: None,
            // No policy is installed by default. An embedder that has already decided
            // authority does not need a second opinion from this crate, and inventing one
            // here would make every socket test carry a policy it never asked for. The
            // manifest-driven path installs one; see `ServerConfig::auth`.
            auth: None,
            // Unbounded by default: a production server runs until it is told to stop, and a
            // default bound would be a number this crate invented that silently stopped
            // serving. `qqqai serve --accept-limit` sets it.
            accept_limit: None,
        }
    }
}

/// What a handler returns.
///
/// A handler is a **pure function of the request** in V1: it receives the parsed
/// head and produces a response. It does not touch the socket, which keeps the
/// routing and encoding testable without a listener and means a handler cannot
/// hold a connection open by accident.
pub type Handler = Arc<dyn Fn(&RequestHead, &RouteMatch) -> Response + Send + Sync>;

/// The handlers a server dispatches to, by kind.
///
/// # Why a streaming handler is registered by **name**, not by a field on `Route`
///
/// [`crate::route::Route`]'s `handler` is deliberately a name the host resolves at
/// dispatch, so a component instance can be replaced on reload without rebinding a
/// pointer. A `streaming: bool` on `Route` would be a second, parallel statement about
/// the same handler, and the router is not the authority on how a guest is invoked —
/// the dispatcher is.
///
/// Keying by name also means the two kinds can be registered independently: a route
/// whose name has no streaming handler falls through to the flat one, which is what a
/// server with no streaming routes at all should do.
#[derive(Clone)]
pub struct Dispatch {
    /// The flat handler, called for every matched route without a streaming entry.
    pub flat: Handler,
    /// Streaming handlers, by the route's `handler` name.
    ///
    /// Empty by default. A server that registers none behaves exactly as before, which
    /// is why adding this did not change any existing caller's meaning.
    pub streaming: Arc<std::collections::BTreeMap<String, crate::stream::StreamingHandler>>,
    /// WebSocket handlers, by the route's `handler` name.
    ///
    /// A third kind, for the same reason there are two: a WebSocket connection is not a
    /// request that produces a response — it **becomes a different protocol** and stays
    /// open. A flat handler cannot express that and a streaming one should not have to.
    ///
    /// Keyed by name like the others, so a route whose handler has no WebSocket entry
    /// falls through to whichever kind it does have.
    pub websocket:
        Arc<std::collections::BTreeMap<String, Arc<dyn crate::ws_conn::WebSocketHandler>>>,
    /// Body-aware handlers, by the route's `handler` name.
    ///
    /// # Why a fourth kind
    ///
    /// `flat` cannot stream and this one cannot either, so why not widen `flat`? Because
    /// `Handler`'s signature is `Fn(&RequestHead, &RouteMatch) -> Response` and twelve
    /// call sites -- six integration tests plus the guest bridge -- are written against
    /// it. Widening it breaks `qqq-serve`'s public API for callers with no interest in
    /// the body, and makes "I ignore bodies" invisible in the type.
    ///
    /// So the kinds differ and the type says which is in use, exactly as for streaming
    /// and WebSocket handlers. A route with no entry here uses `flat`, so every existing
    /// caller's behaviour is unchanged.
    ///
    /// # Why this exists at all, stated plainly
    ///
    /// `serve_connection` drained the body, counted it for the `body_bytes` metric, and
    /// then dispatched without it. `POST /orders` with a form body answered
    /// ``the `id` field is required`` -- the bytes had crossed the socket and been
    /// thrown away. A handler that cannot see the body cannot serve any write request.
    pub body: Arc<std::collections::BTreeMap<String, crate::body_bytes::BodyHandler>>,
}

impl Dispatch {
    /// A dispatcher with only a flat handler — no streaming routes.
    #[must_use]
    pub fn flat(handler: Handler) -> Self {
        Self {
            flat: handler,
            streaming: Arc::new(std::collections::BTreeMap::new()),
            websocket: Arc::new(std::collections::BTreeMap::new()),
            body: Arc::new(std::collections::BTreeMap::new()),
        }
    }

    /// Register a streaming handler for a route's handler name.
    #[must_use]
    pub fn with_streaming(
        mut self,
        name: impl Into<String>,
        handler: crate::stream::StreamingHandler,
    ) -> Self {
        let streaming = Arc::make_mut(&mut self.streaming);
        streaming.insert(name.into(), handler);
        self
    }

    /// The streaming handler for a name, if one is registered.
    #[must_use]
    pub fn streaming_for(&self, name: &str) -> Option<&crate::stream::StreamingHandler> {
        self.streaming.get(name)
    }

    /// Register a WebSocket handler for a route's handler name.
    #[must_use]
    pub fn with_websocket(
        mut self,
        name: impl Into<String>,
        handler: Arc<dyn crate::ws_conn::WebSocketHandler>,
    ) -> Self {
        let websocket = Arc::make_mut(&mut self.websocket);
        websocket.insert(name.into(), handler);
        self
    }

    /// The WebSocket handler for a name, if one is registered.
    #[must_use]
    pub fn websocket_for(&self, name: &str) -> Option<&Arc<dyn crate::ws_conn::WebSocketHandler>> {
        self.websocket.get(name)
    }

    /// Register a body-aware handler for a route's handler name.
    #[must_use]
    pub fn with_body(
        mut self,
        name: impl Into<String>,
        handler: crate::body_bytes::BodyHandler,
    ) -> Self {
        let body = Arc::make_mut(&mut self.body);
        body.insert(name.into(), handler);
        self
    }

    /// The body-aware handler for a name, if one is registered.
    #[must_use]
    pub fn body_for(&self, name: &str) -> Option<&crate::body_bytes::BodyHandler> {
        self.body.get(name)
    }
}

/// The route decision a handler is given.
///
/// Carries the matched handler name and the captured parameters, so a handler
/// does not re-parse the target — the router already did, and doing it twice is
/// how the two disagree about a path with an encoded separator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatch {
    /// The handler name from the matched route.
    pub handler: String,
    /// The pattern that matched.
    pub pattern: String,
    /// Captured parameters, in pattern order.
    pub params: Vec<(String, String)>,
}

/// The outcomes a single connection can end with, for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// The client closed cleanly between requests.
    ClientClosed,
    /// The connection reached its request ceiling.
    RequestLimit,
    /// The connection was idle past its deadline.
    IdleTimeout,
    /// The client sent no complete head within its deadline.
    HeaderTimeout,
    /// A parse error ended the connection.
    BadRequest,
    /// The request body was malformed or exceeded `max_request_bytes`, so it was
    /// answered with an error and the connection closed.
    ///
    /// Kept distinct from [`Self::BadRequest`] because the two are different
    /// client mistakes with different fixes, and an access log that merges them
    /// tells an operator "malformed request" for a client that simply sent too
    /// much — the diagnosis this project has repeatedly found harder than the
    /// bug (`§O-043b`).
    BodyRejected,
    /// A per-tenant **rate** limit refused the request.
    ///
    /// Distinct from [`Self::BodyRejected`], which is about *how much* one request carried;
    /// this is about *how many* the tenant has sent. An operator reading a log where the two
    /// were merged would look for a large payload when the answer is a busy client — the
    /// same "diagnosis is harder than the bug" argument `BodyRejected`'s own doc makes.
    ///
    /// The body was **not** read, so the connection cannot be reused: the framing offset is
    /// unknown. That is why this is an outcome rather than a response the loop could continue
    /// from.
    Refused,
    /// The manifest's authentication policy refused the route.
    ///
    /// Distinct from [`Self::Refused`] in the **log** and identical to it in the metric,
    /// which is the same split [`Self::BodyRejected`] and [`Self::Refused`] make for the
    /// same reason: an operator needs to know which of "too many", "too much" and "you may
    /// not" fired, while §10.2 needs a bounded label set. The status code carries the
    /// distinction into the access record; the counter stays five-valued.
    ///
    /// The body was not read, so the connection cannot be reused.
    Unauthorized,
    /// The server is draining and closed it.
    Drained,
    /// The handler asked to close.
    HandlerClosed,
}

/// Serve requests on an address until shutdown.
///
/// The error a failed bind produces — extracted from `serve`, which is at its line budget.
///
/// # Why the message names the address *and* the cause
///
/// Because the two failures this covers want different fixes: a port below 1024 needs a privilege,
/// and a port already in use needs a different number. The cause is the OS's own sentence, carried
/// verbatim rather than paraphrased — a paraphrase of `EADDRINUSE` is a worse `EADDRINUSE`.
fn bind_failed(addr: &str, cause: &str) -> Error {
    Error::new(
        ErrorCode::ListenerBindFailed,
        format!("could not bind `{addr}`"),
    )
    .with_cause(cause.to_string())
    .with_remediation(
        "check the address is free and the port is above 1024, or that the \
process may bind it",
    )
}

/// The connection ledger for one server — extracted from `serve`, which is at its line budget.
///
/// # Why the ceiling and the per-tenant allowance are read here and not at admit time
///
/// Because they are **configuration**, and reading configuration once means every connection is
/// admitted against the same numbers. A ledger that re-read them per admit could see two different
/// ceilings in one run — which is the class of drift the shared `Arc` exists to prevent.
fn ledger_for(config: &ServerConfig) -> Arc<tokio::sync::Mutex<ConnectionLedger>> {
    Arc::new(tokio::sync::Mutex::new(ConnectionLedger::with_limits(
        connection_ceilings(config),
        config.connections_per_tenant,
    )))
}

/// # Errors
///
/// * `QQQ-6002` — the listener could not bind. The error names the address and
///   the OS error, because "could not bind" without the address sends an
///   operator to the wrong config file.
/// * `QQQ-6004` — an internal invariant. Always a bug in QQQ.
pub async fn serve(
    config: ServerConfig,
    table: RouteTable,
    dispatch: Dispatch,
    shutdown: Shutdown,
    logger: Logger,
) -> Result<()> {
    let listener_config = ListenerConfig::for_addr(config.addr.clone());
    // Shared with every connection task. `Arc` rather than a clone per connection: the
    // policy is one immutable configuration, and a copy per connection would be a value
    // that could drift from the others — the argument the logger's own comment makes.
    // `None` when the manifest declared no `[server.cors]`, which is the common case and
    // costs nothing to carry.
    let cors: Option<Arc<crate::cors::Cors>> = config.cors.clone().map(Arc::new);
    // Cloned into every connection task rather than one clone per connection: a copy of the
    // *registry* would give each connection its own counters, and the metric would read 1
    // forever. The `Arc` is what makes "one registry, many connections" structural.
    let (metrics, metrics_path) = (config.metrics.clone(), config.metrics_path.clone());
    // Cloned into every connection task, which clones the `Arc`. The rate windows are shared
    // **mutable** state, so this is not merely an optimisation: a per-connection copy would
    // give each connection its own allowance and the limit would enforce nothing.
    let limits: Option<Arc<crate::limits::TenantLimits>> = config.limits.clone();
    // Cloned per task, which clones only the `Arc`: one policy, many connections. See
    // `ServerConfig::auth` for why `None` here means "no policy installed" rather than
    // "everything is public".
    let auth: Option<Arc<crate::auth::AuthPolicy>> = config.auth.clone();
    // Bounded tenant labels, shared for the same reason the registry is: a per-connection
    // copy would let each connection disagree about which tenants are named and which are
    // collapsed, so the same tenant could appear under two labels depending on which
    // connection served it.
    let tenant_labels = Arc::new(crate::metrics::TenantLabels::new());
    // Shared into each connection task. An `Arc` rather than a per-connection
    // clone: the logger is one configuration every connection reads, and a copy
    // per connection would be a value that could drift from the others.
    let logger = Arc::new(logger);
    let listener = Listener::bind(listener_config)
        .await
        .map_err(|e| bind_failed(&config.addr.render(), &e.to_string()))?;

    let table = Arc::new(table);
    let ledger = ledger_for(&config);
    // Wrapped in an `Arc` so each connection task shares one immutable config
    // rather than cloning it per connection. `ConnectionConfig` is four small
    // fields, so this is not about size — it is about the closure being `FnMut`
    // and therefore unable to move a captured value out on each call.
    let connection_config = Arc::new(config.connection.clone());

    // A clone for the closure, so the acceptor's own borrow of `shutdown` is a
    // different value from the one each connection task carries. Sharing one
    // would mean the tasks and the acceptor contend on the same borrow, which
    // the compiler refuses — correctly, because it would be a clone of a
    // handle whose lifetime the tasks outlive.
    let task_shutdown = shutdown.clone();

    // The trace counter, shared across every connection task.
    //
    // # Why the acceptor owns it and the connection does not
    //
    // A trace id exists to correlate records **across** connections — that is the
    // whole reason §10.3 asks for one. A per-connection counter cannot do that: every
    // connection begins at zero, so the first request on each concurrent connection
    // produced the identical id `00000000000000000000000000000001`. Measured before
    // this change, and it is the difference between an identifier and a request
    // ordinal.
    let trace_counter = Arc::new(TraceCounter::new());

    // The accept bound. Read once from the config rather than borrowed, so the closure does
    // not capture `config` and cannot accidentally read a field that changed underneath it.
    let accept_limit: Option<u64> = config.accept_limit;
    // Counted on the acceptor rather than per connection: the bound is on connections
    // *accepted*, and a connection that the ledger refuses still consumed an accept.
    let accepted = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // The accept loop hands each connection to a task. `accept_stream` takes a
    // synchronous callback, so the spawn happens here rather than inside it —
    // and the callback must not block, because it runs on the acceptor.
    let result = listener
        .accept_stream(&shutdown, move |stream, peer| {
            let table = Arc::clone(&table);
            let dispatch = dispatch.clone();
            let ledger = Arc::clone(&ledger);
            let connection_config = Arc::clone(&connection_config);
            let local_shutdown = task_shutdown.clone();
            let logger = Arc::clone(&logger);
            let trace_counter = Arc::clone(&trace_counter);
            let cors = cors.clone();
            // Cloned per connection task, which clones only the `Arc` — the registry
            // itself stays one value. See `ServerConfig::metrics` for why that distinction
            // is the whole point.
            let (metrics, metrics_path) = (metrics.clone(), metrics_path.clone());
            // Cloned per task, which clones the `Arc` -- one limiter, many connections.
            let limits = limits.clone();
            // Cloned per task, which clones the `Arc` -- one policy, many connections.
            let auth = auth.clone();
            // Cloned per task, which clones the `Arc`: the label set must be **one** value,
            // or two connections could disagree about whether a tenant is named.
            let tenant_labels = Arc::clone(&tenant_labels);

            // Allocated here, on the acceptor, so the id is fixed before the task
            // starts and two connections can never share one — not even if the
            // scheduler runs the tasks in an unexpected order.
            let trace = trace_counter.next_trace();

            // The accept bound, honoured **after** the connection has been served.
            //
            // Signalling here — on the acceptor, immediately after the spawn — was the first
            // version and it was wrong: the spawned task had not read a byte yet, so it saw a
            // signalled shutdown on its first poll, drained, and closed without answering.
            // Every request against `--accept-limit 1` returned nothing at all, which is what
            // the integration tests in `qqq-run/tests/serve_policy.rs` caught.
            //
            // The count is of connections *accepted*, and it is read inside the task so the
            // signal lands after the last connection has been served rather than before it
            // has been read.
            let accepted = Arc::clone(&accepted);
            let shutdown_for_task = task_shutdown.clone();
            let limit = accept_limit;
            accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

            tokio::spawn(async move {
                let id = ConnectionId::new(peer, trace);
                {
                    let mut l = ledger.lock().await;
                    if !l.admit(&id.tenant) {
                        // Refused before reading a byte. Reading a request the
                        // server will not answer spends the attacker's cost on
                        // the defender, which is the wrong way round.
                        drop(l);
                        let _ = close_immediately(stream, 503).await;
                        // A refusal is still an **accept**: the counter on the
                        // acceptor was incremented for it before this task was
                        // spawned, deliberately, because the bound counts
                        // connections accepted rather than requests answered.
                        //
                        // Returning without this left the count at the bound with
                        // nothing to signal it -- and a burst of connection
                        // attempts is both the load that produces refusals and the
                        // load a bound exists for, so the two arrive together. The
                        // server then ran on past its bound indefinitely, which is
                        // the defect `tests/accept_bound.rs` pins.
                        stop_after_the_bound(limit, &accepted, &shutdown_for_task);
                        return;
                    }
                }

                if let Some(m) = metrics.as_deref() {
                    m.connection_opened();
                }

                let ctx = ConnectionContext {
                    id: &id,
                    shutdown: &local_shutdown,
                    logger: &logger,
                    cors: cors.as_deref(),
                    auth: auth.as_ref(),
                    // `ConnectionConfig` holds a plain `Duration` (a connection always has
                    // one); the context holds an `Option` because a WebSocket may
                    // legitimately want none — a long-lived socket with its own heartbeat
                    // should not be closed by a deadline the server invented. The HTTP
                    // default is what applies here.
                    idle_timeout: Some(connection_config.idle_timeout),
                    metrics: metrics.as_ref(),
                    metrics_path: metrics_path.as_deref(),
                    limits: limits.as_ref(),
                    tenant_labels: &tenant_labels,
                };
                let served = serve_connection(
                    stream,
                    &table,
                    &dispatch,
                    // Dereferenced from the `Arc`: the function borrows the
                    // config, and passing the `Arc` would force it to know about
                    // how the caller shares it.
                    connection_config.as_ref(),
                    &ctx,
                )
                .await;

                // --- One close, with how it ended -------------------------
                //
                // Reported **after** the ledger releases, so the open count and the close
                // count describe the same windows. A close recorded before the release
                // would briefly show one more connection open than the ledger admits.
                if let Some(m) = metrics.as_deref() {
                    m.connection_closed(metric_outcome_of(served));
                }

                let mut l = ledger.lock().await;
                l.release(&id.tenant);
                drop(l);

                // Now that this connection is finished, honour the bound.
                //
                // Signalling the shared shutdown rather than breaking out of the acceptor is
                // deliberate: the drain path already exists, is tested, and lets the other
                // connections in flight finish. A `break` would be a second way to stop a
                // server, and the second way is the one that forgets to drain.
                stop_after_the_bound(limit, &accepted, &shutdown_for_task);
            });
        })
        .await;

    result.map_err(|e: AcceptError| {
        Error::new(
            ErrorCode::ListenerBindFailed,
            "the accept loop stopped with an error",
        )
        .with_cause(e.to_string())
    })
}

/// The per-tenant connection ceilings declared by the manifest.
///
/// Read from `config.limits` rather than from a second field on the config, so one
/// manifest key has one home: a parallel ceilings map would be a second authority on
/// the same policy and the two would drift. `ServerConfig::connections_per_tenant`
/// remains the fallback, so naming one tenant does not change the ceiling for every
/// other.
///
/// Extracted from `serve` rather than inlined, because `serve` is at its line budget
/// without it — which is what clippy's `too_many_lines` asked for.
#[must_use]
fn connection_ceilings(config: &ServerConfig) -> Vec<(String, u32)> {
    config
        .limits
        .as_ref()
        .map_or_else(Vec::new, |l| l.connections_by_tenant())
}

/// The `manifest_rev` this layer reports, because it has no manifest.
///
/// §10.3 requires the field on every line; `qqq-serve` does not load manifests, so
/// the honest value is the word `unknown` rather than a revision it cannot know.
/// Exported so the host can compare against it and substitute the real revision when
/// it has one, instead of both layers writing the literal and drifting.
pub const MANIFEST_REV_UNKNOWN: &str = "unknown";

/// The tenant a peer address belongs to.
///
/// The peer's IP, because there is no authentication at this layer. Named as a
/// function rather than inlined so that when `default_auth` arrives (`SRV-008`),
/// the change is here and every caller inherits it.
fn tenant_of(peer: SocketAddr) -> String {
    peer.ip().to_string()
}

/// The `QQQ-XXXX` code carried in a response's body, if it has one.
///
/// Read out of the rendered error rather than threaded through `Response` as a
/// field: a code on the response would be a second authority on what the body
/// says, and the two would eventually disagree — the same objection the
/// keep-alive comment below makes about a `keep_alive` flag.
///
/// Scans for the first `QQQ-` followed by four digits. Deliberately simple: the
/// only producer is `Error::render`, whose format is fixed by the error model, and
/// a parser that tried to understand more would need updating whenever that format
/// changed.
fn error_code_of(response: &response::Response) -> Option<String> {
    let body = std::str::from_utf8(&response.body).ok()?;
    let start = body.find("QQQ-")?;
    let digits: String = body[start + 4..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    if digits.len() == 4 {
        Some(format!("QQQ-{digits}"))
    } else {
        None
    }
}

/// The level a status code is recorded at.
///
/// # Why this is a named function and not an `if` at the call site
///
/// The rule is the whole operational value of the level field: an operator setting
/// `warn` sees failures and not traffic, and `grep '"level":"error"'` is only useful
/// if 5xx is the only thing that produces it. Inline, the rule had no name, so no test
/// could state it; named, `the_record_level_follows_the_status_the_client_saw` pins it
/// and a change to the boundaries has to be deliberate.
///
/// Public because the boundary is a contract with operators, not an implementation
/// detail — an integration test asserting the rule should call this rather than
/// restate it, so the two cannot disagree.
#[must_use]
pub fn level_of(status: u16) -> Level {
    if status >= 500 {
        Level::Error
    } else if status >= 400 {
        Level::Warn
    } else {
        Level::Info
    }
}

/// Build the access record for a completed request.
///
/// # Why this is separate from `emit_record`
///
/// The record's *content* and its *sink* are independently wrong things. Extracted,
/// the content is testable without a socket or a captured stdout, and the sink stays
/// the one `println!` it should be. It also keeps `serve_connection` under the line
/// limit honestly, rather than by suppressing the lint — the body was 113 lines and
/// the extraction is what the lint was asking for.
///
/// # `manifest_rev` is `"unknown"` here, deliberately
///
/// The manifest revision belongs to the host, which is the layer that loaded the
/// manifest. `qqq-serve` never sees one, and §10.3 permits a placeholder. Writing a
/// plausible-looking value would be worse than writing the truth: a log line claiming
/// a revision that did not serve the request is a false lead during an incident.
///
/// Public so an integration test asserts on the record the server actually builds —
/// the addressable half of `SRV-013` — instead of a hand-written copy that would go
/// stale the first time a field changed.
#[must_use]
pub fn access_record(
    head: &RequestHead,
    path: &str,
    response: &response::Response,
    tenant: &str,
    trace: u64,
    span: u64,
) -> Record {
    let status = response.status;
    let rec = Record::new(
        level_of(status),
        // **Server-wide**, not per-connection. Measured before the fix: with the trace
        // id derived from a per-connection counter, the first request on *every*
        // concurrent connection carried `00000000000000000000000000000001` — so the
        // "trace id" was a request ordinal, not an identifier, and correlating two
        // lines from different connections was impossible. The caller supplies a
        // counter taken from the accept loop, which is unique for the process.
        TraceId::from_counter(trace),
        // The span is the request *within* the connection: ordered for a keep-alive
        // conversation, which is what a span means. It stays per-connection.
        TraceId::span(&format!("{span:016x}"))
            // Unreachable: the format is exactly 16 hex digits. The fallback exists
            // because a logger must not be able to take the server down, and
            // `unwrap` here would make a logging bug a denial of service.
            .unwrap_or_else(|_| TraceId::from_counter(span)),
        tenant,
        "qqq-serve",
        MANIFEST_REV_UNKNOWN,
        format!("{} {} {}", head.method.as_str(), head.target, status),
    )
    .with_field("method", head.method.as_str())
    .with_field("path", path)
    .with_field("status", status.to_string());

    match error_code_of(response) {
        Some(c) => rec.with_code(c),
        None => rec,
    }
}

/// Write one record to stdout, ignoring a write failure.
///
/// # Why not `println!`
///
/// `println!` **panics** when stdout cannot be written — a closed pipe, a full
/// filesystem, a redirected descriptor below the write end. In `serve_connection` that
/// panic happens inside a spawned task, so a deployment problem with the log sink would
/// abort the task handling the request, turning a lost log line into a dropped
/// connection. A logger must never fail a request; that is the whole point of the
/// function.
///
/// So the write goes through `io::Write` on a locked stdout handle and the result is
/// discarded. Locking per line rather than holding a guard across the request matters:
/// stdout is process-global, so a held guard would serialize every connection's logging
/// against one lock for the life of a keep-alive conversation.
///
/// The failure is silent by necessity — there is nowhere left to report it that would
/// not be the same broken sink. What is *not* silent is the panic this removes.
fn emit_record(logger: &Logger, record: Record) {
    use std::io::Write as _;

    if let Some(line) = logger.emit(record) {
        // `let _` rather than `unwrap`: see above. `writeln!` adds the newline the
        // access-log contract requires — one record per line.
        let _ = writeln!(std::io::stdout().lock(), "{line}");
    }
}

/// Write a buffered response, returning an outcome when the connection ends here.
///
/// `None` means the connection may be reused and the caller should read the next request.
/// `Some(..)` means it is finished, for one of two reasons — and they are different, which
/// is why this returns an `Option` rather than a `bool`.
///
/// # The rule this function exists to hold
///
/// **Whether a connection may be reused is the state machine's decision, and the question
/// to ask it is `will_keep_alive`, not `is_open`.**
///
/// `is_open` answers "has this connection been closed?" — `true` for the whole of a
/// request that is about to be the last one. Using it here advertised
/// `Connection: keep-alive` on the very response that closed the connection, which is how
/// an HTTP/1.0 request came back with keep-alive after a correct encoder and a correct
/// state machine.
///
/// The response carries no opinion of its own: a `keep_alive` flag on `Response` would be
/// a second authority on the same answer, and the two would eventually disagree in exactly
/// this way.
///
/// # Why the close is a half-close
///
/// `shutdown` sends the FIN rather than dropping the socket, so the response is not
/// discarded by a RST before the client has read it. Dropping a `TcpStream` with unread
/// data in flight is how a client receives a connection reset instead of a body.
async fn write_flat_response(
    stream: &mut TcpStream,
    conn: &mut Connection,
    head: &RequestHead,
    response: &Response,
) -> Option<Served> {
    let keep_alive = conn.will_keep_alive(false);
    let bytes = response::write_response(response, head.version, keep_alive, is_head(head));
    if stream.write_all(&bytes).await.is_err() || stream.flush().await.is_err() {
        // A write failure is the client's problem, not the server's: it disconnected
        // before reading the response.
        return Some(Served::ClientClosed);
    }

    conn.on_response_sent(Instant::now(), !keep_alive);
    if keep_alive {
        return None;
    }
    let _ = stream.shutdown().await;
    Some(Served::HandlerClosed)
}

/// Ask the state machine what to do, returning an outcome when it says to close.
///
/// # The rule this function holds
///
/// **This is the only authority on the deadlines.** `poll` decides whether the connection
/// is idle, past its header deadline, at its request ceiling or draining — and it is
/// re-evaluated every iteration and on every read timeout inside `read_head`.
///
/// An earlier draft threaded a `last_activity` instant into `read_head` as well, which
/// made the read loop a *second* authority on the idle deadline. The compiler reported
/// the duplication as an unused assignment, which is the correct diagnosis: two places
/// deciding the same thing is how a connection ends up held past its deadline by one and
/// closed early by the other.
///
/// Returning `Option<Served>` keeps "close now" distinguishable from "carry on", which a
/// `bool` or a sentinel outcome would not.
fn act_on_poll(conn: &mut Connection, now: Instant) -> Option<Served> {
    match conn.poll(now) {
        Action::Close(reason) => Some(outcome_of(reason)),
        // `WriteResponse` means the previous iteration wrote and the machine is ready
        // for the next read; both it and `ReadRequest` lead to reading, and the
        // distinction matters only to a caller that interleaves other work between them.
        Action::ReadRequest | Action::WriteResponse => None,
    }
}

/// Start a graceful drain when shutdown is signalled, returning an outcome if the
/// connection is already finished.
///
/// # The rule
///
/// **A shutdown stops *reading*; it does not cut off an in-flight response.** The
/// request above this point has already been answered, so a client is never left
/// mid-response — and the drain deadline from `ConnectionConfig` is what bounds how long
/// the server waits for the connection to end on its own rather than closing it.
///
/// Extracted so the rule has a name, and because `serve_connection` had grown past the
/// line limit. Returning `Option<Served>` rather than the outcome directly keeps the
/// "not yet finished" case distinguishable from "finished cleanly" — the two would be
/// the same value if this returned `Served`.
fn begin_drain_if_signalled(conn: &mut Connection, shutdown: &Shutdown) -> Option<Served> {
    if !shutdown.is_signalled() {
        return None;
    }
    conn.begin_drain(Instant::now());
    match conn.poll(Instant::now()) {
        Action::Close(reason) => Some(outcome_of(reason)),
        Action::ReadRequest | Action::WriteResponse => None,
    }
}

/// Whether this request used `HEAD`.
///
/// # Why a named function rather than an inline comparison
///
/// Four call sites need it, and a HEAD response has a specific contract
/// (`RFC 9110` §9.3.2: the same header fields as GET, no body). Naming it means the rule
/// has a name a test can state, and a fifth caller cannot quietly pass `false` because
/// the expression looked obvious.
#[must_use]
fn is_head(head: &RequestHead) -> bool {
    head.method == crate::route::Method::Head
}

/// Answer a request whose body was malformed or over the cap, and close.
///
/// # Why this is a named function
///
/// Extracted so the rule it encodes has a name a test and a reader can refer to, and
/// because `serve_connection` had grown past the line limit. The rule:
///
/// > **The body is capped while it arrives, and a breach is answered before the
/// > handler runs.**
///
/// `SRV-005`. A first version dispatched first and drained afterwards, so a 3 MiB
/// chunked body against a 2 MiB cap was answered **200 OK** — the guest ran, the
/// response was written, and only then did the drain discover the body was too large.
/// The client was told the request succeeded. Found by
/// `a_chunked_body_past_the_cap_is_cut_off` in `tests/socket.rs`.
///
/// The connection closes because the framing offset is no longer knowable: the decoder
/// stopped mid-body, so where the next request would begin is unknown.
async fn reject_body(stream: &mut TcpStream, head: &RequestHead) -> Served {
    let resp = response::error_response(
        &Error::new(
            ErrorCode::RequestBodyTooLarge,
            "the request body exceeded max_request_bytes while arriving",
        ),
        false,
    );
    let bytes = response::write_response(
        &response::from_error(&resp),
        head.version,
        false,
        is_head(head),
    );
    let _ = stream.write_all(&bytes).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
    Served::BodyRejected
}

/// Serve a request that arrived on a WebSocket route.
///
/// # Two outcomes, and why both are needed
///
/// A WebSocket route can be reached two ways, and they are different protocols:
///
/// - **With an upgrade** (§4.2.1): the connection becomes a WebSocket and stays open.
///   `serve_websocket` owns it from the handshake onward.
/// - **Without one**: it is an ordinary HTTP request that happened to match the route. It
///   gets a `400` naming the missing header. Answering it with a `101` would put the
///   connection into frame mode for a client still speaking HTTP.
///
/// Extracted because `serve_connection` is the connection's life cycle and this is a
/// whole protocol transition happening in the middle of it — and because inlining it
/// pushed that function past the line limit, which is the extraction the lint asked for.
async fn serve_ws_route(
    stream: &mut TcpStream,
    head: &RequestHead,
    handler: &dyn crate::ws_conn::WebSocketHandler,
    ctx: &ConnectionContext<'_>,
    tenant: &str,
    span: u64,
    leftover: Vec<u8>,
) -> Served {
    if !crate::ws_conn::is_upgrade_request(head) {
        let refusal = crate::ws_conn::not_an_upgrade();
        if stream.write_all(&refusal).await.is_err() || stream.flush().await.is_err() {
            return Served::ClientClosed;
        }
        let _ = stream.shutdown().await;
        return Served::HandlerClosed;
    }

    let ws_ctx = crate::ws_conn::WsContext {
        peer: ctx.id.peer,
        tenant,
        logger: ctx.logger,
        trace: ctx.id.trace,
        span,
        // An upgraded connection must still observe both. See `WsContext` for what
        // happens when it does not: a graceful restart hangs on one idle client, because a
        // WebSocket read blocks forever and nothing else can end it.
        shutdown: ctx.shutdown,
        idle_timeout: ctx.idle_timeout,
    };
    let outcome =
        crate::ws_conn::serve_websocket(stream, head, handler, None, leftover, &ws_ctx).await;
    match outcome {
        crate::ws_conn::WsOutcome::ProtocolError => Served::ClientClosed,
        _ => Served::HandlerClosed,
    }
}

/// Answer a request whose head could not be parsed, and close.
///
/// # The rule
///
/// **A malformed request is the client's fault, and a 500 says otherwise.** A first
/// version routed the parse error through `ParseError::to_error`, which produced
/// `ManifestSchemaViolation` and a **500** for a client's bad request line -- the error
/// taxonomy had no client-error class at all until a test found that.
///
/// `parse_error_response` rather than `error_response` for the same reason: a malformed
/// request has no truthful `ErrorCode`, and inventing one would put a code in the log
/// naming a defect in QQQ rather than in the request.
///
/// The connection closes because the framing offset is no longer knowable -- the parser
/// stopped mid-head, so where the next request would begin is unknown.
async fn reject_parse_error(
    stream: &mut TcpStream,
    conn: &mut Connection,
    err: &ParseError,
) -> Served {
    conn.on_parse_error(err);
    // `false`, and the reason is structural rather than incidental: this runs when the
    // head could **not be parsed**, so there is no method to inspect. A request whose head
    // is unreadable cannot be a well-formed HEAD, so the question does not arise.
    let body = response::write_response(
        &response::from_error(&response::parse_error_response(&err.to_string())),
        Version::Http11,
        false,
        false,
    );
    let _ = stream.write_all(&body).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
    Served::BadRequest
}

/// Convert a router match into the `RouteMatch` a handler receives.
///
/// # Why this is a function rather than two inline conversions
///
/// The same conversion appeared in the flat path and the streaming path, which is two
/// places to keep right for a value the handler's signature depends on. `crate::route::Match`
/// and `RouteMatch` are deliberately different types — the router's carries the trie's own
/// view, and the handler's is the minimal thing a handler needs — so the conversion has to
/// exist; it does not have to exist twice.
///
/// `params` is copied rather than borrowed because `RouteMatch` is owned: a handler may
/// hold it for the length of an `await`, and a borrow into the router would tie the
/// handler's lifetime to the table.
fn route_match_of(m: &crate::route::Match) -> RouteMatch {
    RouteMatch {
        handler: m.handler.clone(),
        pattern: m.pattern.clone(),
        params: m
            .params
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
    }
}

/// Answer a request through the flat handler, or refuse it.
///
/// # The rule
///
/// **A path with no route but a known method set gets a 405 with the allowance; a
/// genuinely unknown path gets 404.** The distinction is what lets a client recover: a
/// 404 says "try another path", a 405 says "this path exists and you used the wrong
/// method" and names the ones that work.
///
/// `table.allows` is asked rather than the route table being guessed at, so the allowance
/// is the router's own answer and cannot drift from what it actually matches.
///
/// Extracted because `serve_connection` is the connection's life cycle — reading heads,
/// tracking deadlines, deciding keep-alive — and *choosing a response* is a different job
/// that happens to occur in the middle of it.
/// Route a request and answer it with a flat or body-aware handler.
///
/// # Why the handler name decides, not a field on the route
///
/// The route's `handler` is a name the dispatcher resolves, which is the same rule
/// `Dispatch`'s own docs give for streaming and WebSocket handlers: the router is not
/// the authority on how a guest is invoked. It also means a route whose name has no
/// body-aware entry falls through to `flat`, so a server that registers none behaves
/// exactly as it did before this parameter existed.
///
/// # Why the body is passed by reference
///
/// A `Response` is produced synchronously and the body is not consumed, so borrowing it
/// avoids a copy on every request. The lifetime is the caller's stack frame, which is
/// exactly the handler's duration.
fn dispatch_flat(
    table: &RouteTable,
    dispatch: &Dispatch,
    head: &RequestHead,
    path: &str,
    body: &crate::body_bytes::BodyBytes,
) -> Response {
    if let Some(m) = table.match_route(head.method, path) {
        let matched = route_match_of(&m);
        // A body-aware handler wins when one is registered for this name; otherwise the
        // flat handler answers, which is every caller that predates this distinction.
        if let Some(handler) = dispatch.body_for(&matched.handler) {
            return handler(head, body);
        }
        return (dispatch.flat)(head, &matched);
    }
    let allowed = table.allows(path);
    if allowed.is_empty() {
        response::not_found()
    } else {
        response::method_not_allowed(&allowed)
    }
}

/// Apply the cross-origin policy to a buffered response.
///
/// # Why this is applied to *every* response, not only to successes
///
/// CORS is enforced by the **browser**, not the server: the headers tell the browser
/// whether script on another origin may read the response. A 404 or a 405 is exactly
/// the kind of answer a client most needs to be able to read — without the grant, the
/// browser reports an opaque network failure and the developer sees nothing about the
/// status the server actually chose.
///
/// The one exception is a request with no `Origin` header at all: a same-origin browser
/// request never sends one, so there is nothing to decide and nothing to add. That is
/// reported as `NotACorsRequest` and carries no `Vary`, because a response that does not
/// depend on the origin must not be cached per-origin.
///
/// # A denied origin
///
/// The response is still sent, unchanged, with only `Vary: Origin`. There is no status a
/// server can return that means "CORS refused" — a 403 would be read by the browser as
/// the *application* refusing, which is a different fact — so the refusal is expressed
/// by the **absence** of `Access-Control-Allow-Origin`, which is what the browser
/// checks.
fn apply_cors(
    mut response: Response,
    head: &RequestHead,
    cors: Option<&crate::cors::Cors>,
) -> Response {
    let Some(cors) = cors else {
        return response;
    };
    let decision = cors.simple(head.header("origin"));
    for (name, value) in decision.headers() {
        response.set_header(name, value);
    }
    response
}

/// Answer a CORS preflight.
///
/// # What a preflight is, and why the answer is not the real response
///
/// An `OPTIONS` carrying `Access-Control-Request-Method` is the browser asking whether
/// it may send a request with that method and those headers. The reply carries **no
/// body** and a different header set from the real response: answering it with the
/// route's own headers would advertise methods the route will not accept.
///
/// The decision is [`crate::cors::Cors::preflight`], which *checks* the requested method
/// and headers against the configuration rather than echoing them. A preflight that
/// echoes is not a policy — it grants every method on demand.
///
/// The status is `204 No Content` on a grant and `403 Forbidden` on a refusal. The
/// refusal status is safe to use here, unlike on a simple request, because a preflight
/// has no application semantics: the browser is not calling the route, so there is no
/// handler decision to misreport.
/// Serve the metrics path when this request is for it — `OBS-013`.
///
/// # Why this is its own function
///
/// Because `serve_special_route` is a dispatch chain whose *order* is the part that matters — the
/// docs above it explain why a `101` cannot follow a body and why a preflight must precede routing —
/// and a branch that only decides *whether* to answer is a different kind of thing from the three
/// that decide *how*.
///
/// Returns `None` when the request is not for the metrics path, so the caller falls through
/// unchanged.
async fn maybe_serve_metrics(
    stream: &mut TcpStream,
    head: &RequestHead,
    path: &str,
    ctx: &ConnectionContext<'_>,
    tenant: &str,
    span_seq: &mut u64,
) -> Option<Served> {
    let metrics_path = ctx.metrics_path?;
    let metrics = ctx.metrics?;
    if path != metrics_path {
        return None;
    }
    // `HEAD` as well as `GET`: a scraper may probe with it, and `write_response` strips the body
    // for a head request, so the length still reports what a `GET` would have returned.
    if !matches!(
        head.method,
        crate::route::Method::Get | crate::route::Method::Head
    ) {
        return None;
    }
    *span_seq += 1;
    Some(serve_metrics(stream, head, path, metrics, ctx, tenant, *span_seq).await)
}

/// Serve the Prometheus exposition — `OBS-013`.
///
/// # Why the body is rendered here rather than cached
///
/// Because a scrape is a snapshot: a cached body would report whatever was true when it was built,
/// and reading the registry is the cheapest thing in this function.
///
/// # Why the content type names a version
///
/// `text/plain; version=0.0.4` is the exposition format's own identifier. A scraper uses it to
/// decide how to parse the body, so omitting it makes the response unparseable by the tools this
/// endpoint exists for — reachable and useless.
async fn serve_metrics(
    stream: &mut TcpStream,
    head: &RequestHead,
    path: &str,
    metrics: &crate::metrics::HttpMetrics,
    ctx: &ConnectionContext<'_>,
    tenant: &str,
    span: u64,
) -> Served {
    let mut response = Response::text(200, metrics.render_prometheus());
    response.set_header("content-type", "text/plain; version=0.0.4; charset=utf-8");

    emit_record(
        ctx.logger,
        access_record(head, path, &response, tenant, ctx.id.trace, span),
    );

    // Closed after the response, like the preflight: a scrape is one request, and keeping the
    // connection alive would let an unauthenticated reader hold one open per scrape.
    let keep_alive = false;
    let bytes = response::write_response(&response, head.version, keep_alive, is_head(head));
    if stream.write_all(&bytes).await.is_err() || stream.flush().await.is_err() {
        return Served::ClientClosed;
    }
    let _ = stream.shutdown().await;
    Served::HandlerClosed
}

async fn serve_preflight(
    stream: &mut TcpStream,
    head: &RequestHead,
    path: &str,
    policy: PreflightRequest<'_>,
    ctx: &ConnectionContext<'_>,
    tenant: &str,
    span: u64,
) -> Served {
    let decision = policy.cors.preflight(
        head.header("origin"),
        Some(policy.requested_method),
        policy.requested_headers,
    );

    let mut response = Response::status(if decision.is_granted() { 204 } else { 403 });
    for (name, value) in decision.headers() {
        response.set_header(name, value);
    }

    emit_record(
        ctx.logger,
        access_record(head, path, &response, tenant, ctx.id.trace, span),
    );

    let keep_alive = false;
    let bytes = response::write_response(&response, head.version, keep_alive, is_head(head));
    if stream.write_all(&bytes).await.is_err() || stream.flush().await.is_err() {
        return Served::ClientClosed;
    }
    let _ = stream.shutdown().await;
    Served::HandlerClosed
}

/// Serve one request through a streaming handler.
///
/// # Why this is separate from `serve_connection`
///
/// A streaming exchange has a different shape from a buffered one: it writes its own
/// head, it owns the socket until the handler returns, it terminates the body itself,
/// and it **closes the connection** rather than returning to the request loop. Mixing
/// that into the loop made one function do two things and pushed it past the line limit;
/// separating them makes each readable and is what the lint was asking for.
///
/// # The commit point
///
/// `StreamWriter::begin` is where the status goes on the wire. Before it, a failure can
/// still produce a normal error response; after it, the only honest signal left is the
/// log — which is why [`crate::stream::StreamOutcome`] distinguishes a handler that
/// failed *mid-body* from one that completed.
#[allow(clippy::too_many_arguments)]
async fn serve_streaming(
    stream: &mut TcpStream,
    stream_handler: &crate::stream::StreamingHandler,
    head: &RequestHead,
    path: &str,
    matched: &RouteMatch,
    ctx: &ConnectionContext<'_>,
    tenant: &str,
    span: u64,
) -> Served {
    // The status is not on the wire until the handler writes a head, so a handler that
    // fails before `begin` could still produce an error response. `begin` is the commit.
    let streaming_response = Response::status(200);
    let Ok(mut writer) =
        crate::stream::StreamWriter::begin(stream, &streaming_response, head.version).await
    else {
        // The client was already gone, or the socket failed before anything was
        // committed. Nothing to log beyond the connection outcome.
        return Served::ClientClosed;
    };

    // Scoped so the mutable borrow of `writer` ends before `finish` needs it.
    // `StreamingHandler` takes `&'s mut StreamWriter<'w>` and returns a future borrowing
    // it, so the borrow spans the whole call; capturing only the `Result` releases it.
    let handler_result = stream_handler(head, matched, &mut writer).await;
    let outcome = match handler_result {
        Ok(()) => match writer.finish().await {
            Ok(()) => crate::stream::StreamOutcome::Completed,
            Err(_) => crate::stream::StreamOutcome::HandlerFailed,
        },
        Err(crate::stream::StreamError::Transport(_)) => crate::stream::StreamOutcome::ClientClosed,
        Err(crate::stream::StreamError::Handler(_)) => crate::stream::StreamOutcome::HandlerFailed,
    };
    let written = writer.written();

    crate::stream::emit_stream_record(
        ctx.logger,
        &crate::stream::StreamRecord {
            head,
            path,
            status: streaming_response.status,
            outcome,
            written,
            tenant,
            peer: ctx.id.peer,
            trace: ctx.id.trace,
            span,
        },
    );

    // A stream ends when the client disconnects or the handler returns, and at that point
    // the connection is in a state the request loop has no way to reason about — a
    // half-consumed body may still be in flight. `StreamWriter::begin` already forces
    // `Connection: close` for the same reason.
    let _ = stream.shutdown().await;
    match outcome {
        crate::stream::StreamOutcome::Completed | crate::stream::StreamOutcome::ClientClosed => {
            Served::HandlerClosed
        }
        crate::stream::StreamOutcome::HandlerFailed => Served::ClientClosed,
    }
}

/// What a preflight is asking for.
///
/// Three values that are meaningless apart: the policy decides, and the two
/// `Access-Control-Request-*` headers are what it decides *about*. Passing them
/// positionally invited transposing the method and the headers -- both `&str`-shaped, and
/// the resulting grant would name the wrong method.
pub struct PreflightRequest<'a> {
    /// The policy to evaluate against.
    pub cors: &'a crate::cors::Cors,
    /// The value of `Access-Control-Request-Method`.
    pub requested_method: &'a str,
    /// The value of `Access-Control-Request-Headers`, when present.
    pub requested_headers: Option<&'a str>,
}

/// Everything one connection's handler needs to log, run and answer.
///
/// # Why this exists, and why it is the third type of its kind
///
/// `serve_connection`, `serve_streaming` and `serve_preflight` were each at eight to ten
/// positional parameters, and every one of them was there for the same reason: the
/// shutdown handle, the logger and the connection's identity are *connection-scoped*
/// values, threaded individually because there was nowhere else to put them.
///
/// The same grouping has now been needed three times — [`ConnectionId`] for identity,
/// [`crate::stream::StreamRecord`] for a streaming request's record, and this — which is
/// the point at which a convention should become a type. It also makes the signatures
/// readable: a reader can see at a glance which arguments vary per *request* and which
/// are fixed for the life of the connection.
///
/// Borrowed rather than cloned: the context lives for one connection and is passed down
/// by reference.
pub struct ConnectionContext<'a> {
    /// The connection's identity: peer, tenant and trace id.
    pub id: &'a ConnectionId,
    /// The accept loop's shutdown signal.
    pub shutdown: &'a Shutdown,
    /// Where records go.
    pub logger: &'a Logger,
    /// The cross-origin policy, or `None` when the manifest declared none.
    pub cors: Option<&'a crate::cors::Cors>,
    /// The path the registry is exposed on, or `None` — `OBS-013`.
    pub metrics_path: Option<&'a str>,
    /// The per-route authentication policy, or `None` when the caller installed none.
    ///
    /// Borrowed from the `Arc` the accept loop cloned, so every connection consults the
    /// **same** policy: a per-connection copy would let two connections disagree about
    /// whether a route is public, which is the class of bug the shared `Arc` on `metrics`
    /// and `limits` exists to prevent.
    pub auth: Option<&'a Arc<crate::auth::AuthPolicy>>,
    /// How long the connection may be idle before the server closes it.
    ///
    /// Carried into an upgraded connection too: a WebSocket has no natural end, so the
    /// idle deadline is the only thing that reclaims a half-open one. Without it a
    /// client that vanishes without a FIN holds a connection for the process's life.
    pub idle_timeout: Option<std::time::Duration>,
    /// Where per-request counters go, or `None` to record nothing.
    ///
    /// `None` rather than an always-present registry: a caller that does not want metrics
    /// should not pay three mutex operations per request, and making absence expressible
    /// keeps each recording site one `if let` rather than a flag consulted inside the
    /// registry. A test asserting "one request was recorded" owns its registry, so two
    /// servers in one process cannot see each other's counts.
    pub metrics: Option<&'a Arc<crate::metrics::HttpMetrics>>,
    /// The per-tenant limits, or `None` when the manifest declared none.
    ///
    /// Borrowed rather than cloned, like every other field here: one `Arc` shared by every
    /// connection is what makes a tenant's allowance **per tenant** rather than per
    /// connection.
    pub limits: Option<&'a Arc<crate::limits::TenantLimits>>,
    /// The bounded set of tenant labels that may appear in a metric.
    ///
    /// # Why this is not optional even when metrics are off
    ///
    /// The tenant today is the **peer IP address** (`tenant_of`), so recording it directly
    /// would create one time series per client — the §10.2 cardinality violation in its
    /// worst form, because an attacker chooses the value. `TenantLabels` bounds it at 64
    /// distinct names and collapses the rest into one `other` series.
    ///
    /// Carried even when `metrics` is `None`, because the mapping is a property of the
    /// metric label space rather than of whether metrics are recorded, and threading it
    /// conditionally would make the recording site depend on two options agreeing.
    pub tenant_labels: &'a Arc<crate::metrics::TenantLabels>,
}

/// Allocates a trace id per accepted connection.
///
/// # Why a type rather than a bare `AtomicU64` in `serve`
///
/// The correctness requirement is *"no two connections share a trace id"*, and the
/// accept loop is not the only place that could try. A named type gives that
/// requirement one implementation with one test, instead of an `fetch_add` inlined in a
/// closure that nothing can call directly — which is how the original defect survived:
/// there was no function to test, so no test was written.
///
/// A random id would satisfy uniqueness more cheaply, and is rejected because `§10.5`
/// requires a deterministic run to produce identical logs: a random trace id makes
/// every run's output differ, and logs are something a run produces.
///
/// `Relaxed` is deliberate and sufficient. The only requirement is that concurrent
/// allocations get distinct values, which `fetch_add` guarantees irrespective of
/// ordering; a stronger ordering would cost a fence and buy nothing, because the counter
/// publishes no other data.
///
/// # Why the first id is `1`, not `0`
///
/// **An all-zero trace id is not a trace id.** The W3C Trace Context specification
/// reserves `00000000000000000000000000000000` to mean *invalid/absent*, and a tracing
/// backend that receives it treats the record as having no trace at all. Starting the
/// counter at zero — which `AtomicU64::default()` does — handed exactly that value to
/// the **first connection the server ever accepted**, so the one request an operator is
/// most likely to look at while starting up was the one they could not correlate.
///
/// It is the same class of mistake as the per-connection counter this type replaced:
/// both produce a *value that looks like an identifier and is not one*. Found by
/// external review (`§O-125`), after my own tests passed — because they asserted that
/// ids were *distinct*, and `0` is distinct from `1`.
#[derive(Debug)]
pub struct TraceCounter {
    next: std::sync::atomic::AtomicU64,
}

impl Default for TraceCounter {
    /// A counter whose first allocation is `1`.
    ///
    /// Hand-written rather than derived: `#[derive(Default)]` would give `0`, which is
    /// the reserved all-zero id. A derived `Default` on this type is a defect, so the
    /// implementation is explicit and `0` cannot be reached through it.
    fn default() -> Self {
        Self::new()
    }
}

impl TraceCounter {
    /// A counter whose first allocation is `1`.
    ///
    /// `1` because `0` is reserved to mean "no trace"; see the type's documentation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// The trace id for one connection. Unique for the life of the process, and never
    /// the reserved all-zero value.
    pub fn next_trace(&self) -> u64 {
        self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

/// Everything a connection needs to know about *who and where it is*.
///
/// # Why this is a struct and not three parameters
///
/// `peer`, the tenant derived from it, and the trace id all answer the same question —
/// "which connection is this?" — and they are only meaningful together: the tenant is a
/// function of the peer, and the trace id is what ties this connection's records to each
/// other. Threading them as separate arguments is what pushed `serve_connection` past
/// the argument limit, and the honest response to that limit is to group the things
/// that belong together rather than to add an `#[allow]` and leave eight loose
/// parameters.
///
/// It also collapses a latent bug: the tenant was computed twice, once in the acceptor
/// (for the ledger) and once in `serve_connection`. One type, one derivation.
#[derive(Debug, Clone)]
pub struct ConnectionId {
    /// The client's address.
    pub peer: SocketAddr,
    /// The tenant the peer belongs to, derived once from `peer`.
    pub tenant: String,
    /// The process-wide trace id, allocated by [`TraceCounter`].
    pub trace: u64,
}

impl ConnectionId {
    /// Derive a connection's identity from its peer and its allocated trace id.
    #[must_use]
    pub fn new(peer: SocketAddr, trace: u64) -> Self {
        Self {
            peer,
            tenant: tenant_of(peer),
            trace,
        }
    }
}

/// Serve one connection until it closes, for any reason.
///
/// The config is taken by reference and cloned into the `Connection`, which owns
/// it: the shared `Arc` cannot be moved into a value that outlives the borrow,
/// and `ConnectionConfig` is four small fields, so the clone costs less than the
/// indirection that would avoid it.
async fn serve_connection(
    mut stream: TcpStream,
    table: &RouteTable,
    dispatch: &Dispatch,
    config: &ConnectionConfig,
    ctx: &ConnectionContext<'_>,
) -> Served {
    let mut conn = Connection::new(config.clone());
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    // One counter per connection: this is the **span**, the request's ordinal within
    // the conversation, so a keep-alive exchange stays ordered.
    //
    // It is not the trace id. Deriving the trace from this value was a defect — every
    // connection starts at zero, so the first request on all of them shared a trace
    // id. `id.trace` is the process-wide counter and is what correlates records across
    // connections; see `access_record`.
    let mut span_seq: u64 = 0;
    let tenant = ctx.id.tenant.clone();

    loop {
        // Which action does the state machine want? `act_on_poll` holds the rule that
        // it is the **only** authority on the deadlines, and why a second one existed
        // once.
        let now = Instant::now();
        if let Some(served) = act_on_poll(&mut conn, now) {
            return served;
        }

        if let Some(served) = begin_drain_if_signalled(&mut conn, ctx.shutdown) {
            return served;
        }

        conn.begin_request(now);

        // --- Read a complete head -----------------------------------------
        //
        // Extracted so the failure taxonomy has a name: `reject_parse_error` states which
        // outcomes are the *client's* fault and which are the server's, and why a
        // malformed request line must not become a 500.
        let head = match read_head(&mut stream, &mut buf, config).await {
            Ok(h) => h,
            Err(ReadOutcome::ClientClosed) => return Served::ClientClosed,
            Err(ReadOutcome::HeaderTimeout) => return Served::HeaderTimeout,
            Err(ReadOutcome::BadRequest(err)) => {
                return reject_parse_error(&mut stream, &mut conn, &err).await;
            }
        };

        let (path, _query) = split_target(&head.target);
        let client_wants_keep_alive = wants_keep_alive(&head);
        conn.on_request_parsed(client_wants_keep_alive);

        // The instant the head finished parsing, which is where the service-time clock
        // starts. **After** the head, deliberately: the time spent waiting for a slow
        // client to send its request line is the client's, and folding it into the
        // latency histogram would make the metric measure the network and call it the
        // handler. The idle deadline already governs that wait — see `act_on_poll`.
        let request_started = Instant::now();

        // --- Route and respond --------------------------------------------
        //
        // The idle clock starts **after** the head is read, not before it: the
        // time spent waiting for a client to send a request is what the idle
        // deadline measures, and the time spent parsing and answering is not.
        // Starting it earlier would cut off a slow-but-progressing client for
        // the server's own think time.

        // --- The two gates that must run before anything is read ------------
        //
        // Extracted so the ordering rule lives in one named place rather than in the middle
        // of a hundred-line function where a later edit can move it without noticing. The
        // extraction is also what the line-count lint was asking for.
        if let Some(served) =
            refuse_before_reading(&mut stream, &head, path, table, &tenant, ctx, &mut span_seq)
                .await
        {
            return served;
        }

        // --- Preflight, WebSocket, or streaming: three ways off the HTTP path ----
        //
        // `serve_special_route` owns all three, and the ordering inside it is the rule:
        // a preflight before routing, then an upgrade before a response, then a stream.
        // Each is a case where answering with an ordinary HTTP response would commit the
        // connection to something the client did not ask for.
        //
        // **Before `drain_body`, and that ordering is the point of this block.** None of
        // the three reads the request body: `StreamingHandler` and the WebSocket handler
        // are both called with the head and the route match and no body at all, and a
        // preflight has none by definition. Draining first buffered a body nothing would
        // ever read — the cost `SRV-004`'s *"a cap, not a buffer"* exists to avoid — and
        // it made `drain_body`'s own documentation false, since that function stated a
        // streaming route *"is dispatched before this function runs"* while the call sat
        // below it. Two halves of one rule, disagreeing.
        //
        // All three branches close the connection — `serve_streaming` and
        // `serve_preflight` force `Connection: close` and shut the socket down, and the
        // WebSocket loop owns it from the handshake on — so leaving the body unread cannot
        // leave the request loop parsing the next request from mid-body.
        //
        // # What is not lost by not draining
        //
        // * The per-tenant **declared-length** cap is checked above, before this block.
        // * The absolute `max_request_bytes` cap is enforced by the **parser** on a
        //   declared `Content-Length` (`http1`), which runs before any of this.
        //
        // A *chunked* body past the absolute cap on a streaming or WebSocket route is
        // therefore no longer refused with `413` — and it is not read either, because
        // nothing reads it and the connection closes. That is the one behaviour change in
        // this ordering, and it is stated here rather than left to be discovered.
        if let Some(served) = serve_special_route(
            &mut stream,
            &head,
            path,
            table,
            dispatch,
            ctx,
            &tenant,
            &mut buf,
            &mut span_seq,
        )
        .await
        {
            return served;
        }

        // --- The body, now that the request is known to be an ordinary one ------
        //
        // **Consume the body before dispatching.** `reject_body` states why the ordering
        // is the rule rather than a preference.
        //
        // The count is kept for the metric: `body_bytes` must be the bytes that crossed the
        // socket, not the head's declared length. `reject_body` records the refusal itself,
        // because a body over the cap is precisely the case `SRV-020` wants counted and no
        // response is produced for it here.
        let Some((body, body_bytes)) = drain_body(&mut stream, &mut buf, &head).await else {
            if let Some(m) = ctx.metrics {
                // The refusal is counted because a body over the cap is exactly the case
                // `SRV-020` asks about, and no `record_request` runs for it: the connection
                // closes without a completed request.
                let label = ctx.tenant_labels.label(&tenant);
                m.record_body_limit(label.as_str());
            }
            return reject_body(&mut stream, &head).await;
        };

        let response = dispatch_flat(table, dispatch, &head, path, &body);

        let response = apply_cors(response, &head, ctx.cors);

        // --- One record per request, `SRV-013` -----------------------------
        //
        // Emitted **after** the handler and **before** the response is written:
        // the status is known by then, and a write failure is reported by the
        // return code rather than by a missing log line. Logging first would mean
        // a record for a request whose response never left the server.
        span_seq += 1;
        emit_record(
            ctx.logger,
            access_record(&head, path, &response, &tenant, ctx.id.trace, span_seq),
        );

        // --- The same request, as a metric --------------------------------
        //
        // `record_metrics` holds the reasoning: why it sits beside the access record, and
        // why the label is bounded rather than the tenant itself.
        if let Some(metrics) = ctx.metrics {
            record_metrics(
                metrics,
                ctx.tenant_labels,
                &head,
                &response,
                request_started,
                &tenant,
                body_bytes,
            );
        }

        // `None` means the connection may be reused, so the loop reads the next
        // request. The body was consumed **before** the handler ran, so the connection
        // is already positioned at it — there is deliberately no drain here, because a
        // second consumer of the same body would either read the next request as this
        // request's body or block on bytes already accounted for.
        if let Some(served) = write_flat_response(&mut stream, &mut conn, &head, &response).await {
            return served;
        }
    }
}

/// Serve a request that is not an ordinary HTTP request, if it is one of the three.
///
/// Returns `None` when the request is ordinary, which is the common case: the caller then
/// dispatches it normally. `Some` means the connection has left the HTTP path entirely and
/// the caller must return the outcome.
///
/// # The ordering, which is the whole content of this function
///
/// 1. **A CORS preflight first**, and **before routing**, because it names a path the route
///    table may have no `OPTIONS` handler for — the browser is asking *about* the path, not
///    calling it. A 404 here would make the browser refuse a request the server would serve.
/// 2. **A WebSocket upgrade next**, before any response is produced, because a `101` cannot
///    be sent after a body: answering an upgrade with an ordinary response commits the
///    connection to HTTP and makes the upgrade impossible.
/// 3. **A streaming route last**, because it *does* produce a response — it just writes the
///    body in pieces afterwards, so it needs the routing decision but not the buffered
///    writer.
///
/// `span_seq` is passed by reference rather than read and returned: every branch consumes a
/// span number, and a caller that had to thread the value back through an `Option` would be
/// able to forget.
#[allow(clippy::too_many_arguments)]
async fn serve_special_route(
    stream: &mut TcpStream,
    head: &RequestHead,
    path: &str,
    table: &RouteTable,
    dispatch: &Dispatch,
    ctx: &ConnectionContext<'_>,
    tenant: &str,
    buf: &mut Vec<u8>,
    span_seq: &mut u64,
) -> Option<Served> {
    // §10.2's scrape endpoint — `OBS-013`.
    //
    // **First**, before CORS and before routing, because this is a *server*-owned path: the
    // application's CORS policy, auth policy and route table are about the application's routes,
    // and `serve::prepare` refuses a `--metrics-path` that collides with a declared one. Putting it
    // after routing would make it reachable only where the table happened to have no entry, which
    // is the opposite of owning it.
    if let Some(served) = maybe_serve_metrics(stream, head, path, ctx, tenant, span_seq).await {
        return Some(served);
    }

    if head.method == crate::route::Method::Options {
        if let Some(requested) = head.header("access-control-request-method") {
            if let Some(cors) = ctx.cors {
                *span_seq += 1;
                return Some(
                    serve_preflight(
                        stream,
                        head,
                        path,
                        PreflightRequest {
                            cors,
                            requested_method: requested,
                            requested_headers: head.header("access-control-request-headers"),
                        },
                        ctx,
                        tenant,
                        *span_seq,
                    )
                    .await,
                );
            }
        }
    }

    let m = table.match_route(head.method, path)?;

    if let Some(ws_handler) = dispatch.websocket_for(&m.handler) {
        *span_seq += 1;
        // The buffer may hold **more than the head**: a client is entitled to coalesce its
        // first frame with the handshake, and discarding the remainder would silently drop
        // that frame. Taken by value because the WebSocket loop owns the read buffer from
        // here on.
        let leftover = std::mem::take(buf);
        return Some(
            serve_ws_route(
                stream,
                head,
                ws_handler.as_ref(),
                ctx,
                tenant,
                *span_seq,
                leftover,
            )
            .await,
        );
    }

    if let Some(stream_handler) = dispatch.streaming_for(&m.handler) {
        *span_seq += 1;
        let matched = route_match_of(&m);
        return Some(
            serve_streaming(
                stream,
                stream_handler,
                head,
                path,
                &matched,
                ctx,
                tenant,
                *span_seq,
            )
            .await,
        );
    }

    None
}

/// Stop accepting once `limit` connections have been accepted.
///
/// # Why this is a function
///
/// The reasoning is four times the length of the code, and inside the connection task it was
/// one more thing to read past on the way to the request loop. Extracted, the whole rule —
/// *count accepts, signal after the last one is served, signal the shared shutdown so the
/// existing drain path runs* — is in one place with its history.
///
/// # The bug it records
///
/// The first version signalled on the acceptor immediately after the spawn. The spawned task
/// had not read a byte, so it saw a signalled shutdown on its first poll, drained, and closed
/// without answering: every request against `--accept-limit 1` returned nothing at all. The
/// integration tests in `qqq-run/tests/serve_policy.rs` caught it. Signalling is therefore
/// read here, **after** `serve_connection` returns, which is why this takes the counter and
/// the shutdown rather than only the limit.
fn stop_after_the_bound(
    limit: Option<u64>,
    accepted: &std::sync::atomic::AtomicU64,
    shutdown: &Shutdown,
) {
    if let Some(limit) = limit {
        if accepted.load(std::sync::atomic::Ordering::SeqCst) >= limit {
            shutdown.signal();
        }
    }
}

/// The two gates that must run **before the server reads a byte of the request**.
///
/// Returns `Some` when the request was refused, which is the caller's signal to return
/// without dispatching. `None` means the request passed both gates and may proceed.
///
/// # Why this is one function and not two blocks in `serve_connection`
///
/// The ordering is the security property, and it has three parts that must all hold:
///
/// 1. **Both gates run before `drain_body`.** A request that will be refused must cost the
///    server as little as possible, and the body is the part a client controls the size of.
///    A check after the body was read has already paid for the thing the cap exists to
///    prevent.
/// 2. **Both gates run before `serve_special_route`**, for the upgrade and stream branches.
///    Each is a way of committing the connection to something, so granting either to a route
///    the manifest refused would let a caller reach a handler the manifest said no to.
///
///    **A preflight is the exception, and this doc said otherwise until §O-188.**
///    `serve_special_route` answers an `OPTIONS` request naming
///    `access-control-request-method` from the *path* alone, before `table.match_route` is
///    called at all -- deliberately, because a browser is asking *about* the path rather
///    than calling it, and a `404` would make the browser refuse a request the server would
///    serve. So a preflight is answered for a path whose route is denied, and for a path
///    with no route at all. The claim that a denied route's preflight is refused was stated
///    as policy and was never what the code did.
///
///    **That is not a bypass**, and the reason is worth stating precisely: the preflight
///    carries no body and reaches no handler, and the actual request that follows it passes
///    through this function like any other, so the auth gate still decides whether the route
///    is served. What a preflight discloses is that a path is *considered* by the route
///    table, which a `404` on a real request already discloses.
/// 3. **A path that matches no route is not refused here.** It is a 404 from the dispatcher,
///    and answering 403 for it would tell an unauthenticated caller which paths exist.
///
/// Held in the middle of a hundred-line function, that rule is one careless edit away from
/// being broken in a way no test notices — which is exactly what happened to the ordering of
/// `serve_special_route` and `drain_body` (`§O-184`). As a named function called from one
/// place, it can be read in full.
#[allow(clippy::too_many_arguments)]
async fn refuse_before_reading(
    stream: &mut TcpStream,
    head: &RequestHead,
    path: &str,
    table: &RouteTable,
    tenant: &str,
    ctx: &ConnectionContext<'_>,
    span_seq: &mut u64,
) -> Option<Served> {
    // --- Per-tenant limits -------------------------------------------------
    //
    // The rate check is `check_and_record`, which consumes the allowance as a side effect:
    // a separate `check` and `record` would let a caller check without recording, which is a
    // limiter that never limits. The refusal is recorded as a metric so an operator can see
    // it, and answered with 429 -- the status that means "you are sending too often",
    // distinct from 413 for "you are sending too much".
    if let Some(limits) = ctx.limits {
        // The **declared** length first. A client understating it is caught by the streaming
        // count in `drain_body`; a client stating it honestly pays nothing to find out.
        if let Some(declared) = head.content_length {
            if limits.check_body(tenant, declared).is_err() {
                if let Some(m) = ctx.metrics {
                    let label = ctx.tenant_labels.label(tenant);
                    m.record_body_limit(label.as_str());
                }
                return Some(
                    refuse_limits(stream, head, path, tenant, ctx, *span_seq + 1, false).await,
                );
            }
        }
        if limits.check_and_record(tenant, Instant::now()).is_err() {
            *span_seq += 1;
            return Some(refuse_limits(stream, head, path, tenant, ctx, *span_seq, true).await);
        }
    }

    // --- The route's authentication policy ---------------------------------
    if let Some(policy) = ctx.auth {
        if let Some(matched) = table.match_route(head.method, path) {
            if let crate::auth::Decision::Refuse { mode } = policy.decide(&matched) {
                *span_seq += 1;
                return Some(refuse_auth(stream, head, path, tenant, ctx, *span_seq, mode).await);
            }
        }
    }

    None
}

/// Answer a request that a per-tenant limit refused.
///
/// # Why the two refusals have different statuses
///
/// `413 Content Too Large` and `429 Too Many Requests` are different facts with different
/// remedies: the first says "this payload is too big", the second says "you are sending too
/// often, come back later". A client that received one status for both would retry a body it
/// can never send, or shrink a payload when it should have waited. The distinction costs one
/// `bool` and saves a support ticket.
///
/// # Why the access record is emitted here
///
/// Every other early return in `serve_connection` emits one, and a refusal an operator cannot
/// see in the log is indistinguishable from a request that vanished. The record carries the
/// status the client actually received, so a denial and a success are told apart by the same
/// field a successful request uses.
///
/// # Why `Connection: close`
///
/// The body was **not** consumed -- that is the point of checking first -- so the connection
/// is positioned mid-request and the framing offset is unknowable. Keeping it alive would
/// mean the next request is read as this one's body.
/// Refuse a request the manifest's authentication policy denied.
///
/// # Why `403` and not `401`
///
/// `401` means "authenticate and try again", and it obliges the server to name a scheme in
/// `WWW-Authenticate` (RFC 9110 §15.5.2). For `deny` there is no scheme to name and no
/// credential that would help — the route is refused for everyone, by configuration. `403`
/// is the status that says "understood, and no".
///
/// The three authenticating modes are refused with the same status for a different reason:
/// there is no authenticator in this crate yet, so a request to a `bearer-jwt` route cannot
/// be *proved* to carry a valid token. Answering `401` would invite a retry that could
/// never succeed; answering `403` says the route is closed, which is true until an
/// authenticator exists. Serving it would be the one answer that is never acceptable.
///
/// # Why the body names the mode
///
/// The manifest author's next action is to edit the route that asked for this, and the
/// deployment's next action is to notice that it asked for something the runtime cannot do.
/// A bare `403` tells neither of them which line to look at. The mode is in the body and in
/// the `X-QQQ-Error` header so a human and a script each get it in the form they read.
async fn refuse_auth(
    stream: &mut TcpStream,
    head: &RequestHead,
    path: &str,
    tenant: &str,
    ctx: &ConnectionContext<'_>,
    span: u64,
    mode: &'static str,
) -> Served {
    let body = format!("this route is not served: its manifest entry requires `auth = \"{mode}\"`");
    let mut response = crate::response::Response::text(403, body);
    response.set_header("X-QQQ-Error", "unauthenticated");
    response.set_header("X-QQQ-Auth-Mode", mode);

    emit_record(
        ctx.logger,
        access_record(head, path, &response, tenant, ctx.id.trace, span),
    );

    let bytes = response::write_response(&response, head.version, false, is_head(head));
    if stream.write_all(&bytes).await.is_err() || stream.flush().await.is_err() {
        return Served::ClientClosed;
    }
    Served::Unauthorized
}

async fn refuse_limits(
    stream: &mut TcpStream,
    head: &RequestHead,
    path: &str,
    tenant: &str,
    ctx: &ConnectionContext<'_>,
    span: u64,
    rate: bool,
) -> Served {
    let (status, reason) = if rate {
        (429u16, "Too Many Requests")
    } else {
        (413, "Content Too Large")
    };
    let body = if rate {
        "this tenant has exceeded its request limit"
    } else {
        "this tenant's request body exceeded its limit"
    };
    let response = crate::response::Response::text(status, body);

    emit_record(
        ctx.logger,
        access_record(head, path, &response, tenant, ctx.id.trace, span),
    );

    let bytes = response::write_response(&response, head.version, false, is_head(head));
    if stream.write_all(&bytes).await.is_err() || stream.flush().await.is_err() {
        return Served::ClientClosed;
    }
    let _ = reason;
    // Two variants, not one: the consequence for the *connection* is identical -- the body was
    // not read, so it cannot be reused -- but an operator reading the log needs to know which
    // limit fired, and the status alone requires them to remember the mapping.
    if rate {
        Served::Refused
    } else {
        Served::BodyRejected
    }
}

/// Record one completed request, from the same facts the access record uses.
///
/// # Why it lives beside the access record rather than somewhere of its own
///
/// The two answer the same question, and a divergence between them is undetectable from
/// the outside: a log line saying `200` next to a counter saying `5xx` would be read as two
/// facts rather than as one bug. Emitting them from one place with one set of inputs is
/// what makes that impossible rather than merely unlikely.
///
/// # Why the label is bounded and not the tenant
///
/// The tenant is the **peer IP address** (`tenant_of`), so recording it directly creates
/// one time series per client — §10.2's cardinality violation in its worst form, because
/// the value is entirely attacker-chosen. `TenantLabels` bounds it at 64 distinct names and
/// collapses the rest into one `other` series, and the exact per-tenant facts stay in the
/// access record, which is not aggregated.
///
/// # Why the latency excludes the request line
///
/// `started` is taken **after** the head is parsed, so the histogram measures the server's
/// own service time. Folding in the time spent waiting for a slow client would make the
/// metric measure the network and call it the handler.
fn record_metrics(
    metrics: &crate::metrics::HttpMetrics,
    tenant_labels: &crate::metrics::TenantLabels,
    head: &RequestHead,
    response: &crate::response::Response,
    started: Instant,
    tenant: &str,
    body_bytes: u64,
) {
    let label = tenant_labels.label(tenant);
    // Saturating rather than a raw cast: `as_micros` returns `u128`, and a saturating
    // conversion states that the ceiling is unreachable rather than silently truncating a
    // value that a overflowed `Instant` difference could in principle produce.
    let micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    metrics.record_request(
        crate::metrics::Method::parse(head.method.as_str()),
        response.status,
        micros,
        label.as_str(),
        body_bytes,
        response.body.len() as u64,
    );
}

/// Map a connection's ending to its metric label.
///
/// # Why this is a mapping and not a `From` impl
///
/// [`Served`] has more variants than the metric's closed set, and the excess is the point:
/// the metric label space is bounded by §10.2's cardinality discipline, so `BadRequest`,
/// `BodyTooLarge` and `ProtocolError` all collapse into one `ProtocolError` series. The
/// distinction is not lost — the **access log** keeps the exact outcome per connection, and
/// a log is not aggregated. A metric that grew a series per failure mode would be the
/// failure §10.2's rule exists to prevent.
///
/// Written as an exhaustive match rather than a `matches!` chain so that adding a `Served`
/// variant is a **compile error** here. A `_ =>` arm would silently classify the new
/// variant as whatever the fallback is, and the person adding it would have no reason to
/// look.
fn metric_outcome_of(served: Served) -> crate::metrics::Outcome {
    use crate::metrics::Outcome;
    match served {
        Served::HandlerClosed => Outcome::Ok,
        Served::ClientClosed => Outcome::ClientClosed,
        // Both deadlines: the *server* ended the connection on a timer, which is a
        // different operational fact from the peer violating the protocol.
        Served::IdleTimeout | Served::HeaderTimeout => Outcome::Timeout,
        // The server refused to continue -- a request ceiling, a graceful drain, a
        // per-tenant limit, or the route's authentication policy. None is the client's
        // protocol mistake and none is a success, so all four land in one series.
        //
        // Merged into one arm rather than written as two arms with the same body: clippy's
        // `match_same_arms` is right, and the distinction that matters is already carried by
        // the access record's status and body (`Served::Unauthorized`, `refuse_auth`), not
        // by the metric series. A second arm saying `Outcome::Refused` again would imply the
        // metric distinguishes them, and it does not.
        Served::RequestLimit | Served::Drained | Served::Refused | Served::Unauthorized => {
            Outcome::Refused
        }
        // The two client mistakes collapse into one series. See this function's
        // documentation for why the distinction lives in the log rather than the metric.
        Served::BadRequest | Served::BodyRejected => Outcome::ProtocolError,
    }
}

/// Why a head read stopped.
///
/// There is deliberately **no `IdleTimeout` variant**. An idle connection is
/// closed by `Connection::poll` before this function is entered, so a variant
/// for it here would be unreachable — and an unreachable variant is how a second
/// authority on the idle deadline would start: someone constructs it, the two
/// checks disagree, and a connection is held past its deadline by one path while
/// the other closes it early.
///
/// The compiler reported it as a dead variant, which is the correct diagnosis.
enum ReadOutcome {
    /// The client closed between requests, which is normal for HTTP/1.0.
    ClientClosed,
    /// Bytes arrived but the head did not complete within its deadline.
    ///
    /// Kept here rather than in `Connection` because it is a property of the
    /// *read* rather than of the connection: the state machine does not know how
    /// many bytes have arrived.
    HeaderTimeout,
    /// The request was malformed.
    BadRequest(ParseError),
}

/// How long to sleep between timeout checks while waiting for bytes.
///
/// A poll interval rather than a `select!` on a timer, because the deadlines
/// live in `Connection` and this must not become a second authority on them.
/// 10 ms is well below the smallest documented deadline (10 s) and costs one
/// wakeup per idle connection per interval.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Read until a complete request head is available.
///
/// # Why the read is incremental
///
/// A single `read` may return any prefix: half a request line, a header split
/// across two TCP segments, or everything plus the start of the body. The parser
/// is asked only once `head_end` finds the terminator, so `parse_head` never has
/// to handle a truncated buffer — and it is the parser that owns the decision
/// about what a complete head is, so the check lives in one place.
///
/// # Why this does **not** clear the buffer on entry
///
/// It did, and that was a real defect — caught by
/// `tests/socket.rs::a_body_is_drained_so_the_next_request_parses`, which is the
/// only test that sends a second request behind a body.
///
/// The parser keeps the bytes after the head, because they are the start of the
/// body and the kernel has already delivered them (`buf.drain(..end)` below).
/// `buf` is owned by the connection loop and outlives one call to this function,
/// so a `buf.clear()` here threw that retained prefix away — **making the
/// preservation above pointless.** `drain_body` then read the body from the
/// *socket*, but those bytes were no longer there: they had been consumed by the
/// first `read` into `buf` and then discarded. The connection was left five
/// bytes ahead of where it believed it was, so the next request line began
/// mid-body and parsed as `400 Bad Request`.
///
/// The failure is worth the paragraph because of where it hid: every unit test
/// passed, the first request on the connection was answered correctly, and the
/// damage appeared only on the second request — one layer away from the code
/// that caused it. Two individually correct halves, the preserve and the drain,
/// disagreed about **who owns the buffered bytes**, which is `§O-045a`'s shape
/// again.
///
/// The buffer is now cleared exactly once, by `drain_body`, at the point where
/// its remaining contents are genuinely consumed. That is the only place that
/// knows how many bytes the body still owes.
async fn read_head(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    config: &ConnectionConfig,
) -> std::result::Result<RequestHead, ReadOutcome> {
    let mut header_started: Option<Instant> = None;

    loop {
        if let Some(end) = http1::head_end(buf) {
            return match http1::parse_head(&buf[..end]) {
                Ok((head, _consumed)) => {
                    // Keep the remainder: it is the start of the body and must
                    // not be discarded, or the next read would re-fetch bytes
                    // the kernel has already delivered.
                    buf.drain(..end);
                    Ok(head)
                }
                Err(e) => Err(ReadOutcome::BadRequest(e)),
            };
        }

        // Two deadlines, and they measure different failures — but only one of
        // them is checked here.
        //
        //   * Past `idle_timeout` with nothing read — decided by
        //     `Connection::poll`, which the caller runs before entering this
        //     function and this loop runs again on each poll tick. Not
        //     re-checked here, because a second authority on the same deadline
        //     is how one path holds a connection past it while the other closes
        //     early.
        //   * Past `header_timeout` with bytes read — a client mid-request that
        //     stalled. `Connection` does not model this, because it is a
        //     property of the *read* rather than of the connection, so the
        //     deadline is kept here.
        if let Some(started) = header_started {
            if Instant::now().duration_since(started) >= config.header_timeout {
                return Err(ReadOutcome::HeaderTimeout);
            }
        }

        let mut chunk = [0u8; 8192];
        let read = tokio::select! {
            biased;
            // The poll interval lets the deadlines above be re-checked while a
            // read is pending. It is far below the smallest documented timeout,
            // so it costs one wakeup per idle connection per interval and never
            // fires early enough to matter.
            () = tokio::time::sleep(POLL_INTERVAL) => continue,
            r = stream.read(&mut chunk) => r,
        };

        match read {
            // A zero-length read and a read error both mean the peer is gone.
            // Merged rather than kept apart because the handling is identical,
            // and two arms that must stay in step are two places to forget.
            Ok(0) | Err(_) => return Err(ReadOutcome::ClientClosed),
            Ok(n) => {
                header_started.get_or_insert(Instant::now());
                buf.extend_from_slice(&chunk[..n]);
                // The head ceiling is enforced by the *parser*, not here: it is
                // the parser that knows the limit and that a body may legally
                // exceed it. Duplicating the check would give two limits, and a
                // smuggled request is what the gap between two limits looks
                // like.
                if buf.len() > http1::MAX_HEAD_BYTES + 1 {
                    return match http1::parse_head(buf) {
                        Ok((head, _)) => Ok(head),
                        Err(e) => Err(ReadOutcome::BadRequest(e)),
                    };
                }
            }
        }
    }
}

/// Consume a body so the next request parses from the right offset.
///
/// Returns `false` when the body could not be consumed, which means the
/// connection cannot be reused.
///
/// # Why this is built on the streaming decoder
///
/// The body may be **partly or wholly already in the buffer**: `read_head` stops
/// at the head terminator and keeps whatever followed it, and a client that
/// wrote a small request in one segment delivers head and body together. Reading
/// only from the socket would therefore skip those bytes and leave the
/// connection advanced past the body by exactly the amount already buffered —
/// the desync that produced a 400 on the second request (`§O-047a`).
///
/// A first version of this function hand-rolled the two framing cases and
/// returned `false` for a `chunked` body, ending the connection, because
/// reading-and-discarding chunked framing without decoding it leaves the offset
/// at a place only a decoder knows — a request-smuggling shape.
///
/// `qqq_serve::body::BodyReader` is that decoder (`SRV-004`), so this now
/// delegates: the framing knowledge lives in one place, and a chunked body no
/// longer costs a connection. It also means the **cap is enforced during the
/// drain** (`SRV-005`) rather than only at parse time, so a body that declares a
/// length under the cap but streams more cannot be drained without bound.
///
/// # The buffered prefix, which is the only thing this function still owns
///
/// `BodyReader` reads from anything `AsyncRead`. The bytes already in `buf` are
/// ahead of the socket, so they are fed to the decoder through a chained reader:
/// a cursor over the buffer first, then the socket. That is the whole trick —
/// the decoder sees one continuous stream, and the buffer is empty afterwards,
/// so the connection's framing offset is exactly right.
/// Returns the body's bytes and the count that crossed the socket, or `None` when the
/// framing is no longer trustworthy.
///
/// # Why it returns both
///
/// The count is what the `body_bytes` metric must report -- the bytes that actually
/// arrived, not the head's declared length, which disagree for a truncated request. The
/// bytes are what a handler must receive. Returning one and reading the other from
/// `reader` afterwards would work too, but a single return value cannot be partially
/// ignored by mistake.
///
/// # Why collecting here does not weaken `SRV-004`
///
/// A route with a `StreamingHandler` is dispatched **before** this function runs, so a
/// streaming route never buffers. This path serves a flat or body-aware handler, and both
/// produce one `Response` -- which requires the whole body in memory by construction.
/// The cap is enforced by `BodyReader` *during* the read either way, so collecting cannot
/// be used to exhaust memory.
///
/// # The paragraph above was false for a while, and the shape is worth keeping
///
/// It said exactly this while the call to `serve_special_route` sat **below** the call to
/// this function, so a streaming route's body was fully buffered before the streaming
/// handler was ever considered -- the opposite of the claim, in the one function that made
/// it. Nothing failed: the handler ignores the body, so the output was right and only the
/// cost was wrong, and no test asserted on what was *not* read.
///
/// That is `§O-045a`'s shape a third time: a documented invariant, a call order that
/// contradicted it, and no test that could tell the two apart. The order is now the one
/// the paragraph describes, and two tests drive it:
/// `a_streaming_route_does_not_read_the_request_body` and its control, both in
/// `tests/streaming_route.rs`. The control matters because the streaming handler ignores
/// the body, so "the body was not read" is only observable against a route that is not
/// streaming — which the first version of this comment did not say.
async fn drain_body(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    head: &RequestHead,
) -> Option<(crate::body_bytes::BodyBytes, u64)> {
    // No body declared: anything buffered is the start of the **next** request —
    // a pipelined one. It must be preserved, not cleared, or a client that
    // pipelines loses its second request.
    if !head.chunked && head.content_length.is_none_or(|n| n == 0) {
        // No framing header at all is `Absent`; an explicit `Content-Length: 0` is an
        // empty body. The two are distinguishable on the wire and mean different things
        // to an application, so they are not collapsed here.
        let body = if head.content_length == Some(0) {
            crate::body_bytes::BodyBytes::Buffered(Vec::new())
        } else {
            crate::body_bytes::BodyBytes::Absent
        };
        return Some((body, 0));
    }

    let Ok(mut reader) = crate::body::BodyReader::from_head(head, config_max_request_bytes())
    else {
        // `from_head` refuses a head declaring both framings. `http1` already
        // rejects that at parse time, so reaching here means the two disagree,
        // and the connection is not trustworthy.
        return None;
    };

    // Take the buffered prefix out, leaving `buf` empty for the next request.
    let prefix = std::mem::take(buf);
    let mut combined = std::io::Cursor::new(prefix).chain(stream);

    // A malformed body or one past the cap both mean the framing offset is no
    // longer trustworthy, so the connection closes — and the caller's `None`
    // is what expresses that. The two cases are not distinguished *here*
    // because the caller's action is identical either way; the reason is
    // reported by `BodyReader` to a caller that wants it.
    //
    // The bytes are **collected** rather than discarded. `discard` read them and threw
    // them away, which is why every write route in the reference application answered
    // as though its body were empty: the bytes had crossed the socket and been dropped.
    //
    // The count comes from the reader's own accounting rather than from summing here,
    // so the metric and the reader cannot drift: the declared length and the received
    // count agree for a well-formed request and disagree for a truncated one, and a
    // metric reporting the declaration would claim bytes that never arrived.
    let mut body = Vec::new();
    loop {
        match reader.poll_chunk(&mut combined, 8 * 1024).await {
            Ok(crate::body::BodyChunk::Data(chunk)) => body.extend_from_slice(&chunk),
            Ok(crate::body::BodyChunk::End) => {
                let received = reader.bytes_read();
                return Some((crate::body_bytes::BodyBytes::Buffered(body), received));
            }
            // Malformed or over the cap. The connection closes, and the body is
            // deliberately **not** returned: a handler must never see a truncated body
            // it believes is complete.
            Err(_) => return None,
        }
    }
}

/// The `max_request_bytes` a drained body is held to.
///
/// The parser (`http1`) enforces the same cap on a *declared* length, and this
/// is the streaming enforcement for what actually arrives. It reads the shared
/// constant rather than holding a second number, because two limits is how the
/// ground between them becomes a smuggle window.
fn config_max_request_bytes() -> u64 {
    http1::MAX_REQUEST_BYTES
}

/// Split a request target into path and query.
///
/// The query is returned but unused today: routing matches on the path, and a
/// handler that wants the query reads it from `RequestHead::target`. Splitting
/// here rather than in the router keeps the router's contract — "match a path" —
/// honest, since a route pattern never contains a query.
fn split_target(target: &str) -> (&str, Option<&str>) {
    match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    }
}

/// Whether the client asked to keep the connection open.
///
/// HTTP/1.1 defaults to keep-alive; HTTP/1.0 does not. Getting this backwards
/// either closes every connection after one request — making HTTP/1.1 slower
/// than 1.0 — or keeps a 1.0 connection alive that the client will not reuse,
/// holding a slot until the idle timeout.
fn wants_keep_alive(head: &RequestHead) -> bool {
    let connection_header = head
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .map(|(_, value)| value.to_ascii_lowercase());

    match connection_header.as_deref() {
        Some(v) if v.contains("close") => false,
        Some(v) if v.contains("keep-alive") => true,
        // No header: the version decides.
        _ => head.version == Version::Http11,
    }
}

/// Close a connection immediately with a status and no body.
///
/// Used when the ledger refuses a connection: sending a full error response
/// would spend more of the server's budget on a peer that is already over it.
async fn close_immediately(mut stream: TcpStream, status: u16) -> std::io::Result<()> {
    let text = format!(
        "HTTP/1.1 {status} {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        if status == 503 {
            "Service Unavailable"
        } else {
            "Error"
        }
    );
    // Drain what the client has already sent, **before** writing the refusal.
    //
    // # Why this is not optional
    //
    // The refusal path deliberately reads nothing, so at this point the client's request
    // is sitting unread in the receive buffer. Closing a socket with unread data makes the
    // stack send an RST rather than a FIN, and the RST discards whatever the peer has not
    // yet read -- including the refusal written below. Measured on Windows: a client that
    // connected and read without writing received the full 74-byte 503; a client that sent
    // a request first received **nothing at all**. Every real client sends a request, so
    // every real client saw a reset instead of a status.
    //
    // The cost bound is what keeps the original property: this reads at most
    // `REFUSAL_DRAIN_BYTES` with a short deadline, so a peer that sends a large body still
    // spends almost nothing on the defender, and no body is ever parsed.
    drain_for_refusal(&mut stream).await;
    stream.write_all(text.as_bytes()).await?;
    stream.flush().await
}

/// How many bytes are drained from a refused connection before closing.
///
/// Large enough for a request head, small enough that a peer streaming a body gains
/// nothing: the point of refusing before reading is that the refused side pays.
const REFUSAL_DRAIN_BYTES: usize = 8192;

/// How long the drain waits for the client's request to arrive.
///
/// A client that connects and says nothing must not hold the task open. Long enough for a
/// request already in flight on a local or LAN connection, short enough that an idle
/// attacker's connections free their tasks quickly.
const REFUSAL_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

/// Read and discard the client's pending bytes so the close is orderly.
///
/// Errors are ignored: this is a courtesy to the stack, and a refusal whose drain fails is
/// still a refusal.
async fn drain_for_refusal(stream: &mut TcpStream) {
    let mut buf = [0u8; 1024];
    let mut total = 0usize;
    while total < REFUSAL_DRAIN_BYTES {
        let read = tokio::time::timeout(REFUSAL_DRAIN_TIMEOUT, stream.read(&mut buf)).await;
        match read {
            // Nested rather than three flat alternatives, which is what clippy's
            // `unnested_or_patterns` asks for: `Ok` wraps both the byte count and the
            // read error, so the two share one arm.
            Ok(Ok(0) | Err(_)) | Err(_) => break,
            Ok(Ok(n)) => total += n,
        }
    }
}

/// Map a close reason to the reported outcome.
///
/// `ClientRequested` and `ServerRequested` collapse to `ClientClosed` and
/// `HandlerClosed`, because who *asked* is not what an operator needs — what
/// they need is whether the server chose to close or the peer did.
const fn outcome_of(reason: CloseReason) -> Served {
    match reason {
        CloseReason::IdleTimeout => Served::IdleTimeout,
        CloseReason::HeaderTimeout => Served::HeaderTimeout,
        CloseReason::RequestLimit => Served::RequestLimit,
        // A protocol error and a drain deadline both end in a closed
        // connection; they are reported as the bad request and the drain they
        // were, rather than as "something closed".
        CloseReason::ProtocolError => Served::BadRequest,
        CloseReason::DrainDeadline | CloseReason::ShutdownIdle => Served::Drained,
        CloseReason::ClientRequested => Served::ClientClosed,
        CloseReason::ServerRequested => Served::HandlerClosed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::Method;

    fn head(version: Version, headers: &[(&str, &str)]) -> RequestHead {
        RequestHead {
            method: Method::Get,
            target: "/".to_owned(),
            version,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            content_length: None,
            chunked: false,
        }
    }

    /// HTTP/1.1 keeps alive by default; HTTP/1.0 does not.
    ///
    /// Getting this backwards either closes every 1.1 connection after one
    /// request, or holds a 1.0 connection open that the client will never reuse.
    #[test]
    fn the_version_decides_keep_alive_when_no_header_is_present() {
        assert!(wants_keep_alive(&head(Version::Http11, &[])));
        assert!(
            !wants_keep_alive(&head(Version::Http10, &[])),
            "HTTP/1.0 defaults to close"
        );
    }

    /// An explicit `Connection` header overrides the version, both ways.
    #[test]
    fn an_explicit_connection_header_overrides_the_version() {
        assert!(!wants_keep_alive(&head(
            Version::Http11,
            &[("Connection", "close")]
        )));
        assert!(wants_keep_alive(&head(
            Version::Http10,
            &[("Connection", "keep-alive")]
        )));
    }

    /// The header name and value are matched case-insensitively.
    ///
    /// A client sending `CONNECTION: Close` is stating the same thing, and a
    /// case-sensitive match would keep the connection alive against its wish.
    #[test]
    fn connection_header_matching_is_case_insensitive() {
        assert!(!wants_keep_alive(&head(
            Version::Http11,
            &[("CONNECTION", "Close")]
        )));
        assert!(wants_keep_alive(&head(
            Version::Http10,
            &[("connection", "Keep-Alive")]
        )));
    }

    #[test]
    fn a_target_splits_into_path_and_query() {
        assert_eq!(split_target("/a/b"), ("/a/b", None));
        assert_eq!(split_target("/a/b?x=1"), ("/a/b", Some("x=1")));
        // An empty query is present, not absent. `/a?` and `/a` differ, and
        // collapsing them loses what the client actually sent.
        assert_eq!(split_target("/a?"), ("/a", Some("")));
    }

    #[test]
    fn a_target_with_no_leading_slash_is_returned_as_is() {
        // Not a valid origin-form target, and normalising it here would hide
        // that from the parser that should reject it.
        assert_eq!(split_target("a/b"), ("a/b", None));
    }

    #[test]
    fn a_tenant_is_the_peer_ip() {
        let peer: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        assert_eq!(tenant_of(peer), "203.0.113.7");
    }
}
