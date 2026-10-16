// SPDX-License-Identifier: Apache-2.0

//! Hyper-backed HTTP/1.1 serving for flat routes (`F-16` Option A).
//!
//! One connection in, the QQQ pipeline around it: the request head is
//! mapped from hyper's parse to the same [`RequestHead`] the in-house
//! path produces, the same pre-reading gates run in the same order
//! (loopback `Host`, process budget, tenant limits, auth), the body is
//! collected through the same [`BodyReader`], dispatch reuses
//! [`dispatch_off_thread`], and rendering validates through
//! [`validate_outbound`] before hyper frames it. Policy lives in exactly
//! one place; this module is the second transport that calls it.
//!
//! # What this serves, stated plainly
//!
//! Flat routes, the metrics path, and CORS preflights — as ordinary
//! responses through hyper's HTTP/1.1 driver. WebSocket and streaming
//! routes answer `501` here, loudly: the upgrade and stream loops still
//! belong to the in-house path until the parity commit wires them to
//! hyper's upgrade and streaming bodies. A silent 404 for those routes
//! would be a fork; the 501 names the transport gap instead.
//!
//! # Where the behaviours differ from the in-house path, and why
//!
//! * Hyper parses the head itself, so malformed heads hyper rejects
//!   (bad header syntax, obs-fold, over-count/size lines) close the
//!   connection instead of answering `400`/`431`. Anything hyper *does*
//!   parse gets the in-house refusal taxonomy byte-for-byte, because the
//!   refusal is built by the same constructors from the same
//!   [`ParseError`]. The direction is safe: nothing hyper accepts is
//!   refused in-house, and the differential suite pins every row.
//! * Header names arrive lowercased (hyper normalises); the in-house
//!   path preserves case. Routing, CORS, and limits all match
//!   case-insensitively, so the difference is representation, not
//!   policy — except for a handler that reflects header names, which
//!   the differential echo test pins.
//! * The idle bound accrues between requests, mirroring `Connection`:
//!   every answered request stamps an activity clock and holds a
//!   flight guard while it runs, and the drivers close only when no
//!   flight is held and nothing arrived within the bound. Response
//!   sends stamp per body poll; polls cluster per write quantum, so
//!   a trickle slower than quantum-per-bound under a tiny bound can
//!   still reclaim mid-send (stated in `HyperLimits::idle_timeout`).
//!   Codec-level traffic (`PING`s) does not count.
//! * A request past the per-connection ceiling is answered `503`: on
//!   HTTP/1 with `Connection: close` (the connection is still
//!   reclaimed; the status tells the client why), on HTTP/2
//!   persisting while the client reconnects for service.
//! * A `1xx` handler response becomes `500`: a flat response is final,
//!   and `1xx` has no final meaning. Handlers never emit one; the
//!   branch exists so a future one cannot desynchronise the stream.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_core::Stream as _;
use http_body_util::{BodyExt as _, BodyStream};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use qqq_host::tenant::TenantKey;
use qqq_io::listener::Shutdown;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::access_log::Logger;
use crate::auth::AuthPolicy;
use crate::body::{BodyChunk, BodyReader};
use crate::body_bytes::BodyBytes;
use crate::cors::Cors;
use crate::http1::{MAX_REQUEST_BYTES, MAX_TARGET_BYTES, ParseError, RequestHead, Version};
use crate::limits::{GlobalBucket, TenantLimits};
use crate::metrics::{HttpMetrics, TenantLabels};
use crate::response::{self, Response, validate_outbound};
use crate::route::{Method, RouteTable};
use crate::server::{
    ConnectionContext, Dispatch, RouteMatch, Served, apply_cors, config_max_request_bytes,
    dispatch_off_thread, emit_record, emit_span_sampled, is_head, micros_since, record_metrics,
    split_target,
};
use crate::span::Sampler;
use crate::transport::HyperLimits;
use crate::ws::loopback_host_allowed;
use tokio_rustls::TlsAcceptor;

/// What serving one TLS connection produced: the transport outcome
/// plus what the handshake established.
///
/// The three travel together because they describe one connection:
/// splitting them across return values would let a caller serve on
/// one handshake's bytes while reporting another's identity.
#[derive(Debug)]
pub struct TlsServed {
    /// How the connection ended, same taxonomy as the plaintext drivers.
    pub served: Served,
    /// Version, cipher suite, and ALPN the handshake negotiated.
    pub negotiated: crate::tls::Negotiated,
    /// Who the peer proved to be, when client authentication was
    /// required and a certificate verified. `None` is not anonymous —
    /// it is the absence of authentication, distinct from any identity.
    pub peer: Option<crate::tls::PeerIdentity>,
}

/// Serve one TCP connection through TLS, then hyper.
///
/// Handshake with the given `rustls::ServerConfig` (built by
/// [`crate::tls::TlsConfig::build`], so the cipher policy, versions,
/// and client-auth mode are the documented ones, not adhoc), then
/// route by negotiated ALPN: `h2` to the HTTP/2 driver, anything
/// else to HTTP/1.1 — the same default
/// [`crate::tls::Negotiated::http_version`] makes, so the routing
/// cannot disagree with the reported version. The encrypted stream
/// flows through the generic drivers; this function is the only
/// place that knows a socket was involved at all.
///
/// # Errors
///
/// Handshake failures surface as I/O errors: a client that cannot
/// complete the handshake gets no response, and the accept loop
/// logs the error rather than serving plaintext by accident — a
/// fallback to cleartext on handshake failure would be a silent
/// downgrade, which is worse than a refused connection.
///
/// ```
/// use qqq_serve::tls::Negotiated;
///
/// // The routing rule this function implements: `h2` means the
/// // HTTP/2 driver, anything else the HTTP/1.1 driver.
/// let negotiated = Negotiated {
///     version: "TLSv1.3".to_owned(),
///     cipher_suite: "TLS13_AES_256_GCM_SHA384".to_owned(),
///     alpn: Some("h2".to_owned()),
/// };
/// assert_eq!(negotiated.http_version(), "HTTP/2");
/// assert_eq!(
///     Negotiated {
///         alpn: None,
///         ..negotiated.clone()
///     }
///     .http_version(),
///     "HTTP/1.1"
/// );
/// ```
pub async fn serve_hyper_tls(
    stream: tokio::net::TcpStream,
    tls: Arc<rustls::ServerConfig>,
    table: Arc<RouteTable>,
    dispatch: Dispatch,
    limits: HyperLimits,
    ctx: &ConnectionContext<'_>,
) -> std::io::Result<TlsServed> {
    let acceptor = TlsAcceptor::from(tls);
    let stream = acceptor.accept(stream).await?;
    let (_, connection) = stream.get_ref();
    let negotiated = crate::tls::Negotiated::of(connection);
    let peer = crate::tls::PeerIdentity::from_verified(connection.peer_certificates());
    let served = match negotiated.http_version() {
        "HTTP/2" => serve_hyper_h2(stream, table, dispatch, limits, ctx).await,
        _ => serve_hyper_h1(stream, table, dispatch, limits, ctx).await,
    };
    Ok(TlsServed {
        served,
        negotiated,
        peer,
    })
}

/// Serve one connection through hyper's HTTP/1.1 driver.
///
/// Any byte stream, not just a socket: the driver only polls the
/// stream through `TokioIo`, so a server-side `TlsStream` flows
/// exactly where a `TcpStream` or test duplex flows. `Send` is for
/// the callers that serve each connection on its own task; `Unpin`
/// is what lets the driver poll without pinning ceremony.
///
/// The accept loop calls this exactly where it calls the in-house
/// `serve_connection`: after ledger admission, with the same context.
/// Ledger release, metrics, and the accept bound stay the caller's job,
/// because they describe the accept, not the transport.
pub async fn serve_hyper_h1<S>(
    stream: S,
    table: Arc<RouteTable>,
    dispatch: Dispatch,
    limits: HyperLimits,
    ctx: &ConnectionContext<'_>,
) -> Served
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = Arc::new(State {
        table,
        dispatch,
        limits,
        ctx: OwnedCtx::capture(ctx),
        served: Arc::new(AtomicU64::new(0)),
        protocol: Protocol::H1,
        watch: Arc::new(IdleWatch::new()),
        ws_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
        stream_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    crate::transport::apply_http1(&mut builder, &state.limits);
    let service = service_fn({
        let state = Arc::clone(&state);
        move |request: hyper::Request<Incoming>| {
            let state = Arc::clone(&state);
            async move { answer(request, &state).await }
        }
    });
    let connection = builder
        .serve_connection(TokioIo::new(stream), service)
        // Upgrades are opt-in on HTTP/1: without this, a `101`
        // completes the connection and the upgrade future resolves
        // to an error that looks exactly like a vanished peer.
        // With it, the handshake hands the IO to whoever called
        // `upgrade::on`. HTTP/2 has no upgrade dance here
        // (extended-CONNECT is a separate unit), so its driver
        // stays on the plain connection.
        .with_upgrades();
    let idle = state.limits.idle_timeout;
    let drain = state.limits.drain_timeout;
    let shutdown = state.ctx.shutdown.clone();
    // Poll the inactivity bound instead of sleeping it once: an
    // absolute sleep kills active connections (a slow flood, a
    // long-lived multiplexed session) exactly like idle ones, which
    // the in-house `Connection` never does. Ticks subdivide the
    // bound so a short test bound still fires near it.
    let check_every = (idle / 10).max(Duration::from_millis(1));
    let mut ticker = tokio::time::interval(check_every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(connection);
    // Every exit drains upgraded WebSocket loops first: the h1
    // connection future completes at the `101` handoff, so the
    // driver returning here would release the ledger slot while
    // frames still flow. The loops observe shutdown and idle
    // themselves, so the drain cannot hang past them — and a
    // task that panicked yields its `JoinError` to the base
    // outcome rather than inventing one.
    let base = loop {
        tokio::select! {
            result = &mut connection => {
                // The connection ended. Per-request outcomes already went to
                // the access log; this is the connection's. A hyper-side
                // header timeout is its own outcome; anything else is the
                // client going away.
                break match result {
                    Ok(()) => Served::ClientClosed,
                    Err(error) if error.is_timeout() => Served::HeaderTimeout,
                    Err(_error) => Served::ClientClosed,
                };
            }
            () = shutdown.wait() => {
                connection.as_mut().graceful_shutdown();
                let _ = tokio::time::timeout(drain, &mut connection).await;
                break Served::Drained;
            }
            _ = ticker.tick() => {
                if state.watch.is_idle(idle) {
                    break Served::IdleTimeout;
                }
            }
        }
    };
    abort_stream_tasks(&state).await;
    drain_ws_tasks(&state, base).await
}

/// Abandon streaming handlers at connection end.
///
/// The mirror of the accept loop's `JoinSet` abandon at the drain
/// deadline: in-house ends a parked handler by ending its
/// connection task, and hyper must end the detached equivalent.
/// Abort, not await — a parked handler has nothing to wake for —
/// and no record: the abandon never reaches the emit in-house
/// either, so a record here would be a behaviour the oracle does
/// not have. The await after each abort only reaps the teardown,
/// so a test observing handler drops is deterministic.
async fn abort_stream_tasks(state: &State) {
    let handles: Vec<_> = std::mem::take(
        &mut state
            .stream_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    for handle in handles {
        handle.abort();
        let _ = handle.await;
    }
}

/// Await upgraded WebSocket loops and fold the outcome in.
/// No upgrades — the common case — costs one lock and one empty
/// check. With upgrades, the last loop's outcome maps exactly as
/// `serve_ws_route` maps it, so the two transports report one
/// taxonomy; a panicked loop keeps the base outcome rather than
/// upgrading a task failure into a protocol verdict.
async fn drain_ws_tasks(state: &State, base: Served) -> Served {
    let handles: Vec<_> = std::mem::take(
        &mut state
            .ws_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    if handles.is_empty() {
        return base;
    }
    let mut served = base;
    for handle in handles {
        if let Ok(outcome) = handle.await {
            served = match outcome {
                crate::ws_conn::WsOutcome::ProtocolError => Served::ClientClosed,
                _ => Served::HandlerClosed,
            };
        }
    }
    served
}

/// Serve one connection through hyper's HTTP/2 driver, prior
/// knowledge (no upgrade dance): the tests speak raw h2, and TLS/ALPN
/// selection lands with the TLS commit.
///
/// Any byte stream, like [`serve_hyper_h1`]: same bounds for the
/// same reasons.
///
/// Same pipeline as [`serve_hyper_h1`] through the shared `answer`,
/// with two transport differences: per-request `Connection: close`
/// headers are stripped (connection headers are forbidden on h2 —
/// hyper would fail the stream), and the driver is otherwise
/// identical (idle bound, drain bound, graceful shutdown).
pub async fn serve_hyper_h2<S>(
    stream: S,
    table: Arc<RouteTable>,
    dispatch: Dispatch,
    limits: HyperLimits,
    ctx: &ConnectionContext<'_>,
) -> Served
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = Arc::new(State {
        table,
        dispatch,
        limits,
        ctx: OwnedCtx::capture(ctx),
        served: Arc::new(AtomicU64::new(0)),
        protocol: Protocol::H2,
        watch: Arc::new(IdleWatch::new()),
        ws_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
        stream_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
    });
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    crate::transport::apply_http2(&mut builder, &state.limits);
    let service = service_fn({
        let state = Arc::clone(&state);
        move |request: hyper::Request<Incoming>| {
            let state = Arc::clone(&state);
            async move { answer_h2(request, state).await }
        }
    });
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    let idle = state.limits.idle_timeout;
    let drain = state.limits.drain_timeout;
    let shutdown = state.ctx.shutdown.clone();
    // Same inactivity poll as the HTTP/1 driver: the bound accrues
    // between requests, never on an active connection.
    let check_every = (idle / 10).max(Duration::from_millis(1));
    let mut ticker = tokio::time::interval(check_every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(connection);
    let base = loop {
        tokio::select! {
            result = &mut connection => {
                // h2 has no per-request read timeouts, so every connection
                // error is the connection's outcome, not a request's.
                break match result {
                    Ok(()) => Served::ClientClosed,
                    Err(_error) => Served::ClientClosed,
                };
            }
            () = shutdown.wait() => {
                connection.as_mut().graceful_shutdown();
                let _ = tokio::time::timeout(drain, &mut connection).await;
                break Served::Drained;
            }
            _ = ticker.tick() => {
                if state.watch.is_idle(idle) {
                    break Served::IdleTimeout;
                }
            }
        }
    };
    // h2 upgrades are refused, so `ws_tasks` is always empty here —
    // the tail stays shared so the next transport cannot forget it.
    abort_stream_tasks(&state).await;
    drain_ws_tasks(&state, base).await
}

/// Connection context owned by the serving task.
///
/// `ConnectionContext` borrows everything, which the HTTP/1 driver can
/// hold (it never spawns) but the HTTP/2 driver cannot (streams run on
/// the executor, so the service must be `'static`). This snapshot
/// clones the shared handles once per connection — every `Arc` inside
/// is a clone of the accept loop's, so one tenant's allowance stays
/// per tenant rather than per connection — and copies the small
/// values. Both drivers build it the same way, so neither transport
/// can disagree about policy.
#[derive(Debug, Clone)]
pub(crate) struct OwnedCtx {
    /// The tenant the peer belongs to, derived once from the peer.
    pub tenant: TenantKey,
    /// The tenant's label for logs, metrics, and audit.
    pub tenant_label: String,
    /// The process-wide trace id for this connection.
    pub trace: u64,
    /// The accept loop's shutdown signal.
    pub shutdown: Shutdown,
    /// Where records go.
    pub logger: Logger,
    /// The cross-origin policy, or `None` when the manifest declared none.
    pub cors: Option<Cors>,
    /// The metrics path, or `None` to expose nothing.
    pub metrics_path: Option<String>,
    /// The trace sampler, or `None` to emit no spans.
    pub sampler: Option<Sampler>,
    /// The per-route authentication policy, or `None` when none installed.
    pub auth: Option<Arc<AuthPolicy>>,
    /// Where per-request counters go, or `None` to record nothing.
    pub metrics: Option<Arc<HttpMetrics>>,
    /// The per-tenant limits, or `None` when the manifest declared none.
    pub limits: Option<Arc<TenantLimits>>,
    /// The process-wide request budget, or `None` when disabled.
    pub global_requests: Option<Arc<GlobalBucket>>,
    /// The loopback host names beside the built-in set.
    pub ws_extra_hosts: Vec<String>,
    /// Whether this listener is loopback, hence under the allow-list.
    pub loopback_only: bool,
    /// The bounded tenant labels for metrics.
    pub tenant_labels: Arc<TenantLabels>,
    /// The peer's socket address, for upgraded-connection records.
    ///
    /// Flat responses never name it (the access record carries the
    /// tenant, not the socket), but a WebSocket outlives its
    /// handshake and its record is written when it ends — by which
    /// time nothing else remembers who it was.
    pub peer: std::net::SocketAddr,
    /// The WebSocket policy: origins, limits, buffer caps.
    pub ws: crate::ws::WsConfig,
    /// The process-wide WebSocket buffer budget.
    pub ws_buffer: Arc<tokio::sync::Semaphore>,
    /// How long a connection may idle; upgraded connections inherit it.
    pub idle_timeout: Option<Duration>,
}

impl OwnedCtx {
    /// Snapshot the borrowed context for a `'static` service.
    pub(crate) fn capture(ctx: &ConnectionContext<'_>) -> Self {
        Self {
            tenant: ctx.id.tenant,
            tenant_label: ctx.id.tenant_label.clone(),
            trace: ctx.id.trace,
            shutdown: ctx.shutdown.clone(),
            logger: ctx.logger.clone(),
            cors: ctx.cors.cloned(),
            metrics_path: ctx.metrics_path.map(str::to_owned),
            sampler: ctx.sampler,
            auth: ctx.auth.cloned(),
            metrics: ctx.metrics.cloned(),
            limits: ctx.limits.cloned(),
            global_requests: ctx.global_requests.cloned(),
            ws_extra_hosts: ctx.ws.extra_hosts.clone(),
            loopback_only: ctx.loopback_only,
            tenant_labels: Arc::clone(ctx.tenant_labels),
            peer: ctx.id.peer,
            ws: ctx.ws.clone(),
            ws_buffer: Arc::clone(ctx.ws_buffer),
            idle_timeout: ctx.idle_timeout,
        }
    }
}

/// Everything one connection shares, owned so both drivers' services
/// can hold it — including across the executor spawns HTTP/2 needs.
#[derive(Clone)]
struct State {
    table: Arc<RouteTable>,
    dispatch: Dispatch,
    limits: HyperLimits,
    ctx: OwnedCtx,
    served: Arc<AtomicU64>,
    protocol: Protocol,
    watch: Arc<IdleWatch>,
    /// WebSocket loops upgraded on this connection, owned by the
    /// driver past the `101`: the h1 connection future completes
    /// at the handshake handoff, so without this the ledger slot
    /// would release while frames still flow — the slot must last
    /// as long as the connection does, exactly as in-house, where
    /// `serve_connection` owns the loop. Drained when the driver
    /// returns, mapping the loop outcome to `Served` the way
    /// `serve_ws_route` does.
    ws_tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<crate::ws_conn::WsOutcome>>>>,
    /// Streaming handlers running on this connection, abandoned
    /// when the driver returns: the task owns the handler future,
    /// so dropping the connection without them leaks a parked
    /// handler the way nothing in-house can (there the handler
    /// runs inline on the connection task, and the accept loop's
    /// `JoinSet` abandon is what ends it at the drain deadline).
    /// Aborted, never awaited: a parked handler has no reason to
    /// wake, and the connection is over either way. Silence
    /// matches the abandon — no record fires for a stream the
    /// server cut, exactly as none fires in-house.
    stream_tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

/// Service-observable activity for the idle bound, mirroring
/// `Connection`'s idle rule: idleness accrues between requests, never
/// mid-request, and never from connect.
///
/// Every `answer()` entry stamps activity and holds a flight guard;
/// the guard's `Drop` releases it, so cancellation (hyper dropping a
/// reset stream's future before it answers) cannot wedge the count.
/// The drivers close only when no flight is held AND no activity
/// happened within the bound. Response sends stamp per body poll,
/// and polls cluster per hyper's write quantum — so the bound holds
/// for active work at sane ratios and the residual (trickle slower
/// than quantum-per-bound under a tiny bound) lives in
/// `HyperLimits::idle_timeout`, not here.
///
/// What this observes is requests reaching the service, not socket
/// bytes: hyper owns the bytes, so codec-level traffic (`PING`s,
/// `WINDOW_UPDATE`s) does not reset the bound, exactly as `Connection`
/// ignores non-request traffic for idleness. The head-arrival window
/// is covered by `header_read_timeout` on HTTP/1; on HTTP/2 it rides
/// with the scheduled header-phase hardening (the field doc says so).
struct IdleWatch {
    in_flight: AtomicU64,
    last_activity: std::sync::Mutex<Instant>,
}

impl IdleWatch {
    fn new() -> Self {
        Self {
            in_flight: AtomicU64::new(0),
            last_activity: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Stamp activity and hold a flight: released by `Drop` on every
    /// exit, including cancellation. The stamp lands under the same
    /// mutex the idle decision takes, so a decision either sees this
    /// request (count or stamp) or precedes it entirely — never half.
    fn hold(&self) -> Flight<'_> {
        let mut slot = self
            .last_activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = Instant::now();
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        Flight { watch: self }
    }

    /// Stamp activity without holding a flight: response-send polls.
    fn touch(&self) {
        *self
            .last_activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
    }

    /// Idle only when nothing is flying and nothing arrived recently.
    /// The mutex is taken BEFORE reading the count, linearizing with
    /// `hold`: a concurrent hold either completes first (count seen,
    /// not idle) or lands after (stamp seen next tick) — a decision
    /// never observes a half-started request as an idle connection.
    fn is_idle(&self, bound: Duration) -> bool {
        let slot = self
            .last_activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.in_flight.load(Ordering::SeqCst) == 0 && slot.elapsed() >= bound
    }
}

/// A held request flight: `Drop` releases it, so every `answer()`
/// exit — response, refusal, or hyper cancelling a reset stream —
/// unholds exactly once.
struct Flight<'a> {
    watch: &'a IdleWatch,
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        // Stamp completion: without it, a slow handler's answer leaves
        // idleness measured from request arrival, so a short bound
        // could close the connection before an empty (HEAD, 204, 304)
        // response is even sent. Stamp BEFORE releasing the count: the
        // reverse order lets an idle tick observe zero flights with an
        // expired stamp and close a connection mid-drop.
        // (Red-proven: disabling the stamp fails
        // `flight_drop_stamps_activity`; see `red-drop-stamp-w8b.log`.)
        self.watch.touch();
        self.watch.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Response body that stamps service activity on every send poll.
///
/// Hyper sends the response after `answer()` returns, when no flight
/// is held — without this, a stalled send looks idle and the bound
/// reclaims a connection still doing work (the in-house path never
/// idle-closes mid-write). The body travels as ≤16KB frames and every
/// `poll_frame` stamps the watch, so the stamps track the send while
/// polls recur; a fully stalled send (no polls at all) still
/// reclaims, and the quantum-paced corner is stated in
/// `HyperLimits::idle_timeout` rather than promised away here.
///
/// The chunking is load-bearing, not cosmetic: hyper polls a
/// single-frame body exactly once no matter its size (the h1 write
/// buffer then drains silently), so one stamp per response would
/// cover only the send's start. 16KB aligns with the h2 DATA frame
/// ceiling — no fragmentation waste — and sits well under h1's
/// 64KB buffer quantum, so polls recur as the socket drains.
/// `size_hint` stays exact and `is_end_stream` mirrors `Full`, so
/// framing decisions see the same body hyper would.
struct WatchBody {
    inner: WatchBodyInner,
    watch: Arc<IdleWatch>,
}

/// What a hyper response body carries.
enum WatchBodyInner {
    /// One complete body, sent in ≤16KB frames.
    Full { data: Bytes, pos: usize },
    /// A streaming body: frames arrive from the handler as it
    /// writes them, and the body ends when the sender is dropped.
    /// The stamps still track the send — a stalled stream (no
    /// polls at all) reclaims like a stalled send.
    Stream {
        rx: tokio::sync::mpsc::Receiver<Bytes>,
    },
}

/// Largest single frame the watch body yields: the h2 DATA ceiling.
const WATCH_FRAME_BYTES: usize = 16 * 1024;

impl WatchBody {
    fn new(body: Bytes, watch: &Arc<IdleWatch>) -> Self {
        Self {
            inner: WatchBodyInner::Full { data: body, pos: 0 },
            watch: Arc::clone(watch),
        }
    }

    /// A streaming body fed by a handler through `StreamWriter::channel`.
    fn streaming(rx: tokio::sync::mpsc::Receiver<Bytes>, watch: &Arc<IdleWatch>) -> Self {
        Self {
            inner: WatchBodyInner::Stream { rx },
            watch: Arc::clone(watch),
        }
    }
}

impl http_body::Body for WatchBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match &mut this.inner {
            WatchBodyInner::Full { data, pos } => {
                if *pos >= data.len() {
                    return Poll::Ready(None);
                }
                this.watch.touch();
                let end = (*pos + WATCH_FRAME_BYTES).min(data.len());
                let chunk = data.slice(*pos..end);
                *pos = end;
                Poll::Ready(Some(Ok(http_body::Frame::data(chunk))))
            }
            WatchBodyInner::Stream { rx } => match rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    this.watch.touch();
                    Poll::Ready(Some(Ok(http_body::Frame::data(chunk))))
                }
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            WatchBodyInner::Full { data, pos } => *pos >= data.len(),
            // Unknown until the sender drops: saying `true` early
            // would let hyper end the body while the handler still
            // holds it.
            WatchBodyInner::Stream { .. } => false,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.inner {
            WatchBodyInner::Full { data, pos } => {
                http_body::SizeHint::with_exact((data.len() - pos) as u64)
            }
            WatchBodyInner::Stream { .. } => http_body::SizeHint::default(),
        }
    }
}

/// The per-connection ceiling refusal, rendered and recorded.
///
/// Extracted so `answer` stays a pipeline: the rule is count first
/// (every attempt, including reset streams), refuse past the ceiling
/// with a `503` the client can read, and record it whenever the head
/// maps — an answer without a record is a refusal the operator cannot
/// see fire. Heads that do not map stay silent, mirroring
/// `reject_parse_error`.
fn refuse_ceiling(
    state: &State,
    request: &hyper::Request<Incoming>,
    served: u64,
    started: Instant,
) -> Option<hyper::Response<WatchBody>> {
    if ceiling_for(served, state.limits.max_requests_per_connection) != Ceiling::Refuse {
        return None;
    }
    let response = Response::text(503, "this connection reached its request ceiling");
    let mapped = match state.protocol {
        Protocol::H1 => map_head(request),
        Protocol::H2 => map_head_h2(request),
    };
    Some(match mapped {
        Ok(head) => {
            let (path, _query) = split_target(&head.target);
            close_after(render_recorded(
                state,
                Some((&head, path)),
                &response,
                0,
                started,
            ))
        }
        Err(_) => close_after(render_validated(
            &response,
            false,
            &state.limits,
            &state.watch,
        )),
    })
}

/// The pre-reading gates, in `refuse_before_reading` order.
///
/// Returns the refusal — rendered and recorded — when a gate fires, so
/// `answer` stays a pipeline rather than growing past the line budget.
/// Same order, same shapes, same records as the in-house path: loopback
/// `Host`, process budget, tenant limits, auth.
fn refuse_early(
    state: &State,
    head: &RequestHead,
    path: &str,
    span: u64,
    started: Instant,
) -> Option<hyper::Response<WatchBody>> {
    let ctx = &state.ctx;
    if ctx.loopback_only {
        let host = head.header("host").unwrap_or("");
        if !loopback_host_allowed(host, &ctx.ws_extra_hosts) {
            let response = Response::text(421, "misdirected request");
            return Some(close_after(render_recorded(
                state,
                Some((head, path)),
                &response,
                0,
                started,
            )));
        }
    }
    if let Some(budget) = ctx.global_requests.as_ref()
        && !budget.admit(Instant::now())
    {
        if let Some(metrics) = ctx.metrics.as_ref() {
            metrics.record_global_request_refusal();
        }
        let mut response = Response::text(
            503,
            "the server is at its process-wide admission budget; retry shortly",
        );
        response.set_header("retry-after", "1");
        return Some(close_after(render_recorded(
            state,
            Some((head, path)),
            &response,
            0,
            started,
        )));
    }
    if let Some(response) = refuse_tenant_limits(state, head, path, span, started) {
        return Some(response);
    }
    if let Some(response) = refuse_auth_policy(state, head, path, span, started) {
        return Some(response);
    }
    None
}

/// Render a refusal: record it, map it, mark the connection to close.
fn render_refusal(
    state: &State,
    head: &RequestHead,
    path: &str,
    response: &Response,
    started: Instant,
) -> hyper::Response<WatchBody> {
    close_after(render_recorded(
        state,
        Some((head, path)),
        response,
        0,
        started,
    ))
}

/// The tenant gates: declared body cap, then the rate window.
///
/// Returns the rendered refusal when a gate fires. Spans fire on both
/// outcomes (step 8), mirroring the in-house path: a check that passed
/// is a stage that ran.
fn refuse_tenant_limits(
    state: &State,
    head: &RequestHead,
    path: &str,
    span: u64,
    started: Instant,
) -> Option<hyper::Response<WatchBody>> {
    let ctx = &state.ctx;
    let tenant_key = ctx.tenant;
    let tenant: &str = &ctx.tenant_label;
    let limits = ctx.limits.as_ref()?;
    if let Some(declared) = head.content_length
        && limits.check_body(tenant_key, declared).is_err()
    {
        if let Some(metrics) = ctx.metrics.as_ref() {
            let label = ctx.tenant_labels.label(tenant);
            metrics.record_body_limit(label.as_str());
        }
        let response = Response::text(413, "this tenant's request body exceeded its limit");
        return Some(render_refusal(state, head, path, &response, started));
    }
    let limit_started = Instant::now();
    let over = limits.check_and_record(tenant_key, Instant::now()).is_err();
    emit_span_sampled(
        &ctx.logger,
        ctx.sampler,
        ctx.trace,
        tenant,
        8,
        span,
        micros_since(limit_started),
        over,
    );
    if over {
        let response = Response::text(429, "this tenant has exceeded its request limit");
        return Some(render_refusal(state, head, path, &response, started));
    }
    None
}

/// The route's authentication policy.
///
/// Returns the rendered refusal on `Refuse`, with step 5 spanned on
/// both outcomes like the in-house path.
fn refuse_auth_policy(
    state: &State,
    head: &RequestHead,
    path: &str,
    span: u64,
    started: Instant,
) -> Option<hyper::Response<WatchBody>> {
    let ctx = &state.ctx;
    let tenant: &str = &ctx.tenant_label;
    let policy = ctx.auth.as_ref()?;
    let matched = state.table.match_route(head.method, path)?;
    let policy_started = Instant::now();
    let decision = policy.decide(&matched);
    let refused = matches!(decision, crate::auth::Decision::Refuse { .. });
    emit_span_sampled(
        &ctx.logger,
        ctx.sampler,
        ctx.trace,
        tenant,
        5,
        span,
        micros_since(policy_started),
        refused,
    );
    if let crate::auth::Decision::Refuse { mode } = decision {
        let body =
            format!("this route is not served: its manifest entry requires `auth = \"{mode}\"`");
        let mut response = Response::text(403, body);
        response.set_header("X-QQQ-Error", "unauthenticated");
        response.set_header("X-QQQ-Auth-Mode", mode);
        return Some(render_refusal(state, head, path, &response, started));
    }
    None
}

/// Metrics path and preflight.
///
/// Returns the response — rendered and recorded — when the request is
/// not an ordinary flat one. Upgrades, streaming routes, and the
/// metrics path never reach the 501 below: their arms run first in
/// `answer`, and what remains here is metrics, preflight, and the
/// h2-upgrade gap.
fn serve_special(
    state: &State,
    head: &RequestHead,
    path: &str,
    started: Instant,
) -> Option<hyper::Response<WatchBody>> {
    let ctx = &state.ctx;
    if let Some(metrics_path) = ctx.metrics_path.as_deref()
        && path == metrics_path
        && let Some(metrics) = ctx.metrics.as_ref()
    {
        let mut response = Response::text(200, metrics.render_prometheus());
        response.set_header("content-type", "text/plain; version=0.0.4; charset=utf-8");
        return Some(close_after(render_recorded(
            state,
            Some((head, path)),
            &response,
            0,
            started,
        )));
    }
    if head.method == Method::Options
        && let Some(requested) = head.header("access-control-request-method")
        && let Some(cors) = ctx.cors.as_ref()
    {
        if head.chunked || head.content_length.is_some_and(|n| n > 0) {
            let response = response::from_error(&response::parse_error_response(
                "special routes do not accept an HTTP request body; send the body to an ordinary route",
            ));
            return Some(close_after(render_recorded(
                state,
                Some((head, path)),
                &response,
                0,
                started,
            )));
        }
        let decision = cors.preflight(
            head.header("origin"),
            Some(requested),
            head.header("access-control-request-headers"),
        );
        let mut response = Response::status(if decision.is_granted() { 204 } else { 403 });
        for (name, value) in decision.headers() {
            response.set_header(name, value);
        }
        return Some(close_after(render_recorded(
            state,
            Some((head, path)),
            &response,
            0,
            started,
        )));
    }
    // The last 501: h2 upgrade requests need extended-CONNECT, a
    // mechanism this path does not implement yet. Streaming over
    // both protocols and h1 upgrades are served by their arms in
    // `answer`, which run before this function.
    if state.protocol == Protocol::H2
        && let Some(matched) = state.table.match_route(head.method, path)
        && state.dispatch.websocket_for(&matched.handler).is_some()
    {
        let mut response = Response::text(
            501,
            "this route needs an h2 extended-CONNECT upgrade, which the hyper path does not serve yet",
        );
        response.set_header("X-QQQ-Error", "hyper-transport-gap");
        return Some(render_refusal(state, head, path, &response, started));
    }
    None
}

/// A hyper upgrade as a tokio stream: the bridge the frame loop needs.
///
/// hyper 1.x speaks its own `rt::Read`/`Write` on `Upgraded`
/// (cursor-based reads, not tokio's `ReadBuf`), so the loop —
/// written against tokio traits — cannot poll it directly. This
/// delegates each poll across the boundary: writes, flushes, and
/// shutdowns map one-to-one, and reads stage through a stack
/// buffer the cursor fills before the bytes advance the tokio
/// buffer. Pinned-boxed inside, so `Unpin` holds whatever the
/// inner type does.
struct HyperUpgraded(std::pin::Pin<Box<hyper::upgrade::Upgraded>>);

impl HyperUpgraded {
    fn new(upgraded: hyper::upgrade::Upgraded) -> Self {
        Self(Box::pin(upgraded))
    }
}

impl tokio::io::AsyncRead for HyperUpgraded {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Scoped so the hyper buffer's borrow of `buf` ends
        // before `advance`: `filled` counts from the fresh
        // `ReadBuf`, so its length is exactly what this poll
        // staged — never bytes a previous poll advanced past.
        let staged = {
            let inner = buf.initialize_unfilled();
            let mut read_buf = hyper::rt::ReadBuf::new(inner);
            let cursor = read_buf.unfilled();
            match <hyper::upgrade::Upgraded as hyper::rt::Read>::poll_read(
                self.0.as_mut(),
                cx,
                cursor,
            ) {
                std::task::Poll::Ready(Ok(())) => read_buf.filled().len(),
                std::task::Poll::Ready(Err(error)) => {
                    return std::task::Poll::Ready(Err(error));
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        };
        buf.advance(staged);
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for HyperUpgraded {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        <hyper::upgrade::Upgraded as hyper::rt::Write>::poll_write(self.0.as_mut(), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        <hyper::upgrade::Upgraded as hyper::rt::Write>::poll_flush(self.0.as_mut(), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        <hyper::upgrade::Upgraded as hyper::rt::Write>::poll_shutdown(self.0.as_mut(), cx)
    }
}

/// The upgrade route, if this request targets one on HTTP/1.
///
/// Split out so `answer` stays under its line budget: the match
/// (route table plus handler registry) is the only part of the
/// upgrade decision that belongs to routing rather than to the
/// handshake that follows it.
fn upgrade_route(
    state: &State,
    head: &RequestHead,
    path: &str,
) -> Option<Arc<dyn crate::ws_conn::WebSocketHandler>> {
    if state.protocol != Protocol::H1 {
        return None;
    }
    let matched = state.table.match_route(head.method, path)?;
    state.dispatch.websocket_for(&matched.handler).cloned()
}

/// Serve a WebSocket upgrade on HTTP/1: validate, answer `101`, run
/// the frame loop on the upgraded connection.
///
/// Refusal order mirrors `serve_ws_route` exactly — not-an-upgrade,
/// origin, handshake — because a client that cannot tell which
/// check failed it cannot fix its request, and because the two
/// transports answering differently would be a fork. Every refusal
/// is recorded through `render_refusal` like every other hyper
/// answer (an invisible refusal is one the operator cannot see)
/// and closes, like in-house: an upgrade that will not happen
/// must not linger as keep-alive.
///
/// On success the `101` goes back through hyper while the frame
/// loop runs on a spawned task over the upgraded IO; the driver
/// awaits it at connection end (see `drain_ws_tasks`), so the
/// ledger slot lasts as long as the frames do. The loop's record
/// and `on_close` fire inside the task, which is why the audit
/// trail does not depend on the driver outliving the connection.
async fn serve_upgrade(
    state: &State,
    request: hyper::Request<Incoming>,
    head: RequestHead,
    ws_handler: Arc<dyn crate::ws_conn::WebSocketHandler>,
    span: u64,
    started: Instant,
) -> Result<hyper::Response<WatchBody>, hyper::Error> {
    // A chunked body on an upgrade route is refused before the
    // handshake, like in-house: committing to frames with bytes
    // in flight bypasses the body cap. The drain is async, which
    // is what makes this function async while nothing else in it
    // awaits.
    if crate::server::special_route_has_body(&head) {
        return Ok(refuse_special_body(state, request, &head, started).await);
    }
    // Not an upgrade at all: answered as ordinary HTTP, never hijacked.
    if !crate::ws_conn::is_upgrade_request(&head) {
        return Ok(upgrade_refusal(
            state,
            &head,
            400,
            &crate::ws::HandshakeError::NotAnUpgrade.to_string(),
            &[],
            started,
        ));
    }
    // Origin before the handshake: past the `101` the connection
    // speaks frames, and a refusal must not arrive framed.
    if !crate::ws::upgrade_origin_allowed(
        &state.ctx.ws.origins,
        head.header("origin"),
        head.header("host").unwrap_or(""),
    ) {
        return Ok(upgrade_refusal(state, &head, 403, "", &[], started));
    }
    let handshake = match crate::ws::Handshake::parse(head.method.as_str(), |name| {
        head.header(name).map(str::to_owned)
    }) {
        Ok(handshake) => handshake,
        // 426 names the retry version; anything else is a 400.
        // Same split as `ws::write_refusal`, minus the status
        // line hyper owns.
        Err(error) => {
            let status = match error {
                crate::ws::HandshakeError::UnsupportedVersion { .. } => 426u16,
                _ => 400u16,
            };
            let mut extra = Vec::new();
            if status == 426 {
                extra.push(("Sec-WebSocket-Version", crate::ws::VERSION.to_owned()));
            }
            return Ok(upgrade_refusal(
                state,
                &head,
                status,
                &error.to_string(),
                &extra,
                started,
            ));
        }
    };
    let upgrade = hyper::upgrade::on(request);
    let mut builder = hyper::Response::builder().status(hyper::StatusCode::SWITCHING_PROTOCOLS);
    for (name, value) in crate::ws::accept_headers(&handshake, None) {
        builder = builder.header(name, value);
    }
    let response = builder
        .body(WatchBody::new(Bytes::new(), &state.watch))
        .unwrap_or_else(|_| {
            hyper::Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(WatchBody::new(Bytes::new(), &state.watch))
                .unwrap_or_else(|_| {
                    hyper::Response::new(WatchBody::new(Bytes::new(), &state.watch))
                })
        });
    let ws_ctx = crate::ws_conn::WsContext {
        peer: state.ctx.peer,
        tenant: state.ctx.tenant_label.clone(),
        logger: state.ctx.logger.clone(),
        trace: state.ctx.trace,
        span,
        shutdown: state.ctx.shutdown.clone(),
        idle_timeout: state.ctx.idle_timeout,
        limits: state.ctx.ws.limits,
        buffer: Arc::clone(&state.ctx.ws_buffer),
    };
    let handle = tokio::spawn(async move {
        let outcome = match upgrade.await {
            Ok(upgraded) => {
                let mut stream = HyperUpgraded::new(upgraded);
                crate::ws_conn::run_frames(&mut stream, ws_handler.as_ref(), Vec::new(), &ws_ctx)
                    .await
            }
            // The handshake succeeded but the peer vanished
            // before the upgrade completed: gone, not broken.
            Err(_) => crate::ws_conn::WsOutcome::ClientGone,
        };
        crate::ws_conn::emit_ws_record(&ws_ctx, &head, outcome);
        ws_handler.on_close(outcome);
        outcome
    });
    state
        .ws_tasks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(handle);
    Ok(response)
}

/// Render an upgrade refusal: recorded like every hyper answer,
/// closed like every in-house upgrade refusal.
fn upgrade_refusal(
    state: &State,
    head: &RequestHead,
    status: u16,
    body: &str,
    extra: &[(&str, String)],
    started: Instant,
) -> hyper::Response<WatchBody> {
    let (path, _query) = split_target(&head.target);
    let mut response = Response::text(status, body.to_owned());
    for (name, value) in extra {
        response.set_header(name, value.as_str());
    }
    close_after(render_refusal(state, head, path, &response, started))
}

/// Drain a refused chunked body, bounded like in-house.
///
/// Same bound, same deadline, same silence on failure as
/// `drain_for_refusal`: closing with an unread body resets the
/// connection and discards the refusal, so the drain is courtesy,
/// and a courtesy that can hang is not one.
async fn drain_hyper_body(body: hyper::body::Incoming) {
    let mut remaining = crate::server::REFUSAL_DRAIN_BYTES;
    let mut body = body;
    let deadline = tokio::time::sleep(crate::server::REFUSAL_DRAIN_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        if remaining == 0 {
            break;
        }
        tokio::select! {
            () = &mut deadline => break,
            frame = body.frame() => {
                match frame {
                    None | Some(Err(_)) => break,
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            remaining = remaining.saturating_sub(data.len());
                        }
                    }
                }
            }
        }
    }
}

/// Refuse a chunked body on a special route, mirroring
/// `reject_special_route_body`: drained first, then the same 400
/// message, recorded and closed. Shared by the upgrade and
/// streaming arms, which is exactly the sharing in-house gets
/// from checking before dispatch.
async fn refuse_special_body(
    state: &State,
    request: hyper::Request<Incoming>,
    head: &RequestHead,
    started: Instant,
) -> hyper::Response<WatchBody> {
    drain_hyper_body(request.into_body()).await;
    let (path, _query) = split_target(&head.target);
    let response = response::from_error(&response::parse_error_response(
        crate::server::SPECIAL_ROUTE_BODY_MESSAGE,
    ));
    close_after(render_recorded(
        state,
        Some((head, path)),
        &response,
        0,
        started,
    ))
}

/// Serve a streaming route: head now, body as the handler writes it.
///
/// The handler runs on a spawned task against a channel writer;
/// the response carries the receiving end, so the first event
/// leaves while the handler is still parked — a buffered path
/// would deadlock the gated test, not merely fail it. The head
/// mirrors `write_stream_head` minus framing (status, no
/// content-length/connection/transfer-encoding — hyper frames
/// DATA itself), and h1 closes after the body like in-house
/// shuts the socket down. The record fires in the task with the
/// outcome and the bytes written, so per-request audit does not
/// depend on the driver outliving the stream.
#[allow(clippy::too_many_arguments)]
async fn serve_streaming_hyper(
    state: &State,
    request: hyper::Request<Incoming>,
    head: RequestHead,
    matched: RouteMatch,
    stream_handler: crate::stream::StreamingHandler,
    span: u64,
) -> Result<hyper::Response<WatchBody>, hyper::Error> {
    use crate::stream::{StreamError, StreamOutcome};
    if crate::server::special_route_has_body(&head) {
        return Ok(refuse_special_body(state, request, &head, Instant::now()).await);
    }
    let (mut writer, rx) = crate::stream::StreamWriter::channel();
    let builder = hyper::Response::builder().status(hyper::StatusCode::OK);
    // No content headers: hyper owns framing, and a declared
    // length would disagree with a body whose end only the
    // handler's return provides.
    let response = builder
        .body(WatchBody::streaming(rx, &state.watch))
        .unwrap_or_else(|_| {
            hyper::Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(WatchBody::new(Bytes::new(), &state.watch))
                .unwrap_or_else(|_| {
                    hyper::Response::new(WatchBody::new(Bytes::new(), &state.watch))
                })
        });
    let response = match state.protocol {
        Protocol::H1 => close_after(response),
        Protocol::H2 => response,
    };
    let tenant = state.ctx.tenant_label.clone();
    let peer = state.ctx.peer;
    let trace = state.ctx.trace;
    let logger = state.ctx.logger.clone();
    let (path, _query) = split_target(&head.target);
    let path = path.to_owned();
    let task = tokio::spawn(async move {
        let handler_result = stream_handler(&head, &matched, &mut writer).await;
        let outcome = match handler_result {
            Ok(()) => match writer.finish().await {
                Ok(()) => StreamOutcome::Completed,
                Err(_) => StreamOutcome::HandlerFailed,
            },
            Err(StreamError::Transport(_)) => StreamOutcome::ClientClosed,
            Err(StreamError::Handler(_)) => StreamOutcome::HandlerFailed,
        };
        let written = writer.written();
        crate::stream::emit_stream_record(
            &logger,
            &crate::stream::StreamRecord {
                head: &head,
                path: &path,
                status: 200,
                outcome,
                written,
                tenant: &tenant,
                peer,
                trace,
                span,
            },
        );
    });
    // Tracked so the driver abandons it at connection end, and
    // pruned so a long multiplexed connection does not collect
    // finished handles: a slot per stream is the ledger's shape,
    // not a log.
    let mut tasks = state
        .stream_tasks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    tasks.retain(|handle| !handle.is_finished());
    tasks.push(task);
    drop(tasks);
    Ok(response)
}

/// The per-connection ceiling decision for one request start.
///
/// `served` is the count before this request (the `fetch_add` return),
/// mirroring `Connection`'s `RequestLimit`: serve while under, warn on
/// the response that reaches the ceiling, refuse past it. The refuse
/// arm is unreachable over sequential HTTP/1 — hyper closes after the
/// warned response before reading another — and exists for multiplexed
/// HTTP/2, where a second stream can start past the ceiling mid-flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ceiling {
    /// Serve normally.
    Serve,
    /// Serve, but this response must say the connection ends here.
    Warn,
    /// Do not serve: answer `503` and close.
    Refuse,
}

fn ceiling_for(served: u64, max: u32) -> Ceiling {
    if served >= u64::from(max) {
        Ceiling::Refuse
    } else if u64::from(max) == served + 1 {
        Ceiling::Warn
    } else {
        Ceiling::Serve
    }
}

/// Which hyper driver serves the connection: per-request close
/// signalling differs (see `close_after`), everything else is shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    /// HTTP/1.1: `Connection: close` ends the connection after a response.
    H1,
    /// HTTP/2: connection headers are forbidden on the wire, and
    /// per-stream framing stays sound without closing — so refusals
    /// answer without a close signal, and the over-ceiling answer is a
    /// persisting `503` (the client reconnects for service) rather than
    /// a bare close.
    H2,
}
///
/// Answer one h2 request: the shared pipeline, minus the
/// `Connection: close` marker.
///
/// `close_after` marks h1 closes; on h2 the header itself is a protocol
/// violation, so it comes off before hyper sees it. A named function
/// rather than an inline async block, because the block borrows the
/// connection state in a way the service lifetime rejects while the
/// named future borrows it at the call — exactly the shape the h1
/// closure already proves.
async fn answer_h2(
    request: hyper::Request<Incoming>,
    state: Arc<State>,
) -> Result<hyper::Response<WatchBody>, hyper::Error> {
    let mut response = answer(request, &state).await?;
    response.headers_mut().remove(hyper::header::CONNECTION);
    Ok(response)
}

/// Answer one request: the QQQ pipeline, ending in a hyper response.
///
/// Recording (access log, metrics, spans) happens inside, at the same
/// points the in-house path records, because a hyper request invisible
/// in the log is a request the operator cannot see refused. The result
/// never errors: every failure below has a response, so the connection
/// always gets an answer rather than an abort.
async fn answer(
    request: hyper::Request<Incoming>,
    state: &State,
) -> Result<hyper::Response<WatchBody>, hyper::Error> {
    // Service-level activity first: this request is work the
    // connection did, so the idle bound restarts here. The guard's
    // `Drop` unholds on every exit — response, refusal, or hyper
    // cancelling a reset stream mid-answer.
    let _flight = state.watch.hold();
    let ctx = &state.ctx;
    let tenant: &str = &ctx.tenant_label;
    let request_started = Instant::now();

    // The per-connection ceiling first, mirroring `Connection`'s
    // `RequestLimit`: the in-house path checks before reading, so a
    // request past the ceiling is never served. Here it is answered
    // `503` rather than closed bare, so the client learns why.
    let served = state.served.fetch_add(1, Ordering::SeqCst);
    if let Some(refusal) = refuse_ceiling(state, &request, served, request_started) {
        return Ok(refusal);
    }

    // --- The head, mapped to the in-house taxonomy ----------------------
    //
    // No access record on this path, mirroring `reject_parse_error`: an
    // unreadable head has no method or path worth logging.
    let mapped = match state.protocol {
        Protocol::H1 => map_head(&request),
        Protocol::H2 => map_head_h2(&request),
    };
    let head = match mapped {
        Ok(head) => head,
        Err(error) => {
            let response =
                response::from_error(&response::parse_error_response(&error.to_string()));
            return Ok(close_after(render_validated(
                &response,
                false,
                &state.limits,
                &state.watch,
            )));
        }
    };
    let (path, _query) = split_target(&head.target);
    let span = state.served.load(Ordering::SeqCst);

    // --- The gates that must run before anything is read -----------------
    //
    // Same order as `refuse_before_reading`: loopback `Host`, process
    // budget, tenant limits, auth. Same shapes, same records.
    if let Some(refusal) = refuse_early(state, &head, path, span, request_started) {
        return Ok(refusal);
    }

    // --- Metrics path, preflight, upgrades: off the flat path ------------
    //
    // WebSocket upgrades on HTTP/1 take the upgrade arm, which owns
    // the raw request for the handshake handoff; streaming routes
    // take the streaming arm, which owns it for the channel handoff;
    // everything else falls through to `serve_special` (metrics,
    // preflight, h2 upgrades).
    if let Some(ws_handler) = upgrade_route(state, &head, path) {
        return serve_upgrade(state, request, head, ws_handler, span, request_started).await;
    }
    if let Some(matched) = state.table.match_route(head.method, path)
        && let Some(stream_handler) = state.dispatch.streaming_for(&matched.handler)
    {
        // Same position as in-house (after the gates, before the
        // flat path): a streaming route commits the connection to
        // a body without a length, so it must not reach the
        // buffered body reader, which would wait for an end that
        // only the handler's return provides.
        let stream_handler = stream_handler.clone();
        let matched = crate::server::route_match_of(&matched);
        return serve_streaming_hyper(state, request, head, matched, stream_handler, span).await;
    }
    if let Some(special) = serve_special(state, &head, path, request_started) {
        return Ok(special);
    }

    // --- The body, through the shared reader ------------------------------
    //
    // `request` is consumed here; every head fact needed below was
    // extracted above the move.
    let collected = match state.protocol {
        Protocol::H1 => collect_body(request.into_body(), &head).await,
        Protocol::H2 => collect_h2_body(request.into_body(), &head).await,
    };
    let Some((body, body_bytes)) = collected else {
        if let Some(metrics) = ctx.metrics.as_ref() {
            let label = ctx.tenant_labels.label(tenant);
            metrics.record_body_limit(label.as_str());
        }
        let response = response::from_error(&response::error_response(
            &qqq_core::Error::new(
                qqq_core::ErrorCode::RequestBodyTooLarge,
                "the request body exceeded max_request_bytes while arriving",
            ),
            false,
        ));
        return Ok(close_after(render_recorded(
            state,
            Some((&head, path)),
            &response,
            0,
            request_started,
        )));
    };

    // --- Dispatch, CORS, record, render ------------------------------------
    let route_started = Instant::now();
    let response =
        dispatch_off_thread(&state.table, &state.dispatch, &head, path, &body, tenant).await;
    emit_span_sampled(
        &ctx.logger,
        ctx.sampler,
        ctx.trace,
        tenant,
        3,
        span,
        micros_since(route_started),
        false,
    );
    let response = apply_cors(response, &head, ctx.cors.as_ref());
    let rendered = render_recorded(
        state,
        Some((&head, path)),
        &response,
        body_bytes,
        request_started,
    );
    // The ceiling warning, mirroring `Connection`: on HTTP/1 the
    // response that reaches the ceiling says the connection ends here.
    // On HTTP/2 there is no per-response close signal (connection
    // headers are forbidden), so the warned response serves plainly and
    // the over-ceiling answer stays a persisting `503` — a GOAWAY-based
    // warning is drain-commit work, and the budget holds either way.
    if ceiling_for(served, state.limits.max_requests_per_connection) == Ceiling::Warn
        && state.protocol == Protocol::H1
    {
        return Ok(close_after(rendered));
    }
    Ok(rendered)
}

/// Render a QQQ response for a recorded request: validate, map to hyper,
/// emit the access record and the metric — the same facts from the same
/// inputs, so the log and the counters cannot drift.
fn render_recorded(
    state: &State,
    known: Option<(&RequestHead, &str)>,
    response: &Response,
    body_bytes: u64,
    started: Instant,
) -> hyper::Response<WatchBody> {
    let ctx = &state.ctx;
    let tenant: &str = &ctx.tenant_label;
    // Resolved BEFORE recording: the record must describe the wire
    // bytes, so a handler 200 past the body budget is recorded as the
    // 500 the client receives, never as a success. Recording the
    // pre-validation response split the log from the wire — a 200 in
    // the log for a 500 on the socket.
    let effective = effective_response(response, &state.limits);
    if let Some((head, path)) = known {
        let span = state.served.load(Ordering::SeqCst);
        emit_record(
            &ctx.logger,
            crate::server::access_record(head, path, &effective, tenant, ctx.trace, span),
        );
        if let Some(metrics) = ctx.metrics.as_ref() {
            record_metrics(
                metrics,
                &ctx.tenant_labels,
                head,
                &effective,
                started,
                tenant,
                body_bytes,
            );
        }
        render_inner(&effective, is_head(head), &state.watch)
    } else {
        render_inner(&effective, false, &state.watch)
    }
}

/// Mark a rendered response to close the connection after it.
///
/// The in-house path closes the socket for every one of these cases
/// (unread body, untrustworthy framing, one-shot routes); hyper closes
/// on the header instead.
fn close_after(mut response: hyper::Response<WatchBody>) -> hyper::Response<WatchBody> {
    response.headers_mut().insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );
    response
}

/// Validate a response and map it to hyper's framing.
///
/// `validate_outbound` is the F-02 gate: a bad handler response becomes
/// `500`, never a split stream. Framing headers stay hyper's, exactly as
/// the in-house writer owns them: a caller cannot contradict the
/// framing. `head_request` strips the body but keeps the real length,
/// mirroring `response_body_for_wire`.
fn render_validated(
    response: &Response,
    head_request: bool,
    limits: &HyperLimits,
    watch: &Arc<IdleWatch>,
) -> hyper::Response<WatchBody> {
    let effective = effective_response(response, limits);
    render_inner(&effective, head_request, watch)
}

/// Resolve the response the wire gets: the handler's, unless the F-02
/// gate or the no-`1xx` rule replaces it with a valid-by-construction
/// 500. Shared by the recording and silent render paths so both map
/// the same bytes the record describes.
fn effective_response<'a>(
    response: &'a Response,
    limits: &HyperLimits,
) -> std::borrow::Cow<'a, Response> {
    match validate_outbound(response, limits.max_response_body_bytes) {
        Ok(()) if response.status >= 200 => std::borrow::Cow::Borrowed(response),
        Ok(()) => std::borrow::Cow::Owned(Response::text(
            500,
            "response failed validation: no final meaning",
        )),
        Err(refusal) => std::borrow::Cow::Owned(refusal.replacement()),
    }
}

/// Map a validated response onto hyper types.
///
/// Unreachable-by-construction fallbacks (`500`) cover the mapping
/// errors validation already excluded: returning hyper's error type
/// would abort the connection with no response at all, which answers
/// less than a loud 500.
fn render_inner(
    response: &Response,
    head_request: bool,
    watch: &Arc<IdleWatch>,
) -> hyper::Response<WatchBody> {
    let status = hyper::StatusCode::from_u16(response.status)
        .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = hyper::Response::builder().status(status);
    for (name, value) in &response.headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        // Lowercased: HTTP/2 forbids uppercase names outright (RFC 9113
        // §8.2.2), and HTTP/1 names are case-insensitive — so one
        // canonical form serves both, and a handler that set
        // `Content-Type` cannot fail a stream. The QQQ `Response` keeps
        // its case; only the wire form normalises.
        let name = name.to_ascii_lowercase();
        let Ok(header_name) = name.parse::<hyper::header::HeaderName>() else {
            return render_inner(
                &Response::text(500, "response failed validation: bad header"),
                head_request,
                watch,
            );
        };
        let Ok(header_value) = value.parse::<hyper::header::HeaderValue>() else {
            return render_inner(
                &Response::text(500, "response failed validation: bad header"),
                head_request,
                watch,
            );
        };
        builder = builder.header(header_name, header_value);
    }
    let real_len = response.body.len();
    let body = if crate::response::forbids_body(response.status) || head_request {
        Bytes::new()
    } else {
        Bytes::copy_from_slice(&response.body)
    };
    // `Content-Length` always describes the real body, even when the
    // bytes are omitted — mirroring the in-house writer, so a HEAD
    // response does not claim the representation is empty.
    builder = builder.header(hyper::header::CONTENT_LENGTH, real_len.to_string());
    builder
        .body(WatchBody::new(body, watch))
        .unwrap_or_else(|_| {
            hyper::Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(WatchBody::new(Bytes::new(), watch))
                .unwrap_or_else(|_| hyper::Response::new(WatchBody::new(Bytes::new(), watch)))
        })
}

/// The framing a request declares: headers plus what they say about
/// the body. Shared by both maps, because the rules are the transport's
/// only when the transport parses them — and both hyper drivers parse
/// the same way.
struct Framing {
    headers: Vec<(String, String)>,
    content_length: Option<u64>,
    chunked: bool,
}

/// Read the framing headers out of hyper's parsed map, enforcing the
/// `parse_head` rules: single `Content-Length` under the cap, one
/// `Transfer-Encoding` naming `chunked` at most, single `Host`, never
/// both framings. Anything hyper already rejected (bad syntax,
/// obs-fold, over-count/size) never reaches here — those close below
/// the service, which the differential suite pins per row.
fn framing_of(headers: &hyper::HeaderMap) -> Result<Framing, ParseError> {
    let mut out = Vec::new();
    let mut content_length = None;
    let mut chunked = false;
    let mut seen_transfer_encoding = false;
    let mut seen_host = false;
    // `HeaderMap` iteration yields multi-valued keys once per value, so
    // a doubled header is seen twice here exactly as the parser sees
    // two lines. Names arrive lowercased — hyper normalises — where the
    // in-house path preserves case; routing, CORS, and limits all match
    // case-insensitively, so the difference is representation.
    for (name, value) in headers {
        let name = name.as_str();
        let value = value.to_str().map_err(|_| ParseError::InvalidUtf8)?.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(ParseError::DuplicateContentLength);
            }
            let n: u64 = value
                .parse()
                .map_err(|_| ParseError::InvalidContentLength {
                    value: truncate_head(value, 64),
                })?;
            if n > MAX_REQUEST_BYTES {
                return Err(ParseError::BodyTooLarge {
                    declared: n,
                    limit: MAX_REQUEST_BYTES,
                });
            }
            content_length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if seen_transfer_encoding {
                return Err(ParseError::DuplicateTransferEncoding);
            }
            seen_transfer_encoding = true;
            if value.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else {
                return Err(ParseError::UnsupportedTransferEncoding {
                    value: truncate_head(value, 64),
                });
            }
        } else if name.eq_ignore_ascii_case("host") {
            if seen_host {
                return Err(ParseError::DuplicateHost);
            }
            seen_host = true;
        }
        out.push((name.to_owned(), value.to_owned()));
    }
    if chunked && content_length.is_some() {
        return Err(ParseError::ConflictingFraming);
    }
    Ok(Framing {
        headers: out,
        content_length,
        chunked,
    })
}
/// Map hyper's parsed HTTP/1.1 head to the in-house taxonomy.
///
/// Every refusal reuses [`ParseError`], so the status and the body come
/// from the same constructors the in-house path uses — identical by
/// construction, not by parallel code.
fn map_head<B>(request: &hyper::Request<B>) -> Result<RequestHead, ParseError> {
    let method =
        Method::parse(request.method().as_str()).ok_or_else(|| ParseError::UnknownMethod {
            method: truncate_head(request.method().as_str(), 32),
        })?;
    let version = match request.version() {
        hyper::Version::HTTP_11 => Version::Http11,
        hyper::Version::HTTP_10 => Version::Http10,
        other => {
            return Err(ParseError::UnsupportedVersion {
                version: truncate_head(&format!("{other:?}"), 16),
            });
        }
    };
    // Origin-form carries path and query; asterisk-form is the `OPTIONS *`
    // exception; anything else (absolute- or authority-form) is not a
    // target this server routes, mirroring `TargetNotAbsolute`. The
    // scheme check comes first because hyper normalises absolute-form
    // to origin-form below — without it, a proxy-style request would
    // route as the path it names.
    let target = if request.uri().scheme().is_some() {
        return Err(ParseError::TargetNotAbsolute {
            target: truncate_head(&request.uri().to_string(), 64),
        });
    } else if method == Method::Options && request.uri().path() == "*" {
        "*".to_owned()
    } else if let Some(path_query) = request.uri().path_and_query() {
        path_query.as_str().to_owned()
    } else {
        return Err(ParseError::TargetNotAbsolute {
            target: truncate_head(&request.uri().to_string(), 64),
        });
    };
    let target = check_target(&target, method)?;
    let framing = framing_of(request.headers())?;
    Ok(RequestHead {
        method,
        target,
        version,
        headers: framing.headers,
        content_length: framing.content_length,
        chunked: framing.chunked,
    })
}

/// Map hyper's parsed HTTP/2 head to the in-house taxonomy.
///
/// Pseudo-headers arrive decoded: `:method` and `:path` through
/// hyper's method/URI, `:scheme` ignored (any scheme reaches dispatch;
/// routing never sees it), `:authority` synthesised as the `host`
/// header the loopback check and handlers read. Framing rules are the
/// shared ones. A `te` announcement (e.g. `trailers`) passes through
/// as an ordinary header on both protocols — the flat path has no
/// trailer contract, matching the in-house reader, which never sees
/// them either — and `chunked` never sets: h2 has no chunked framing,
/// and bodies without `Content-Length` stream to the cap (see
/// `collect_body`).
fn map_head_h2<B>(request: &hyper::Request<B>) -> Result<RequestHead, ParseError> {
    let method =
        Method::parse(request.method().as_str()).ok_or_else(|| ParseError::UnknownMethod {
            method: truncate_head(request.method().as_str(), 32),
        })?;
    let target = if let Some(path_query) = request.uri().path_and_query() {
        path_query.as_str().to_owned()
    } else {
        return Err(ParseError::TargetNotAbsolute {
            target: truncate_head(&request.uri().to_string(), 64),
        });
    };
    let target = check_target(&target, method)?;
    let framing = framing_of(request.headers())?;
    let mut headers = framing.headers;
    // `:authority` is the h2 host: it sorts first, like a request line
    // the client actually addressed to us. A `host` header beside it
    // must agree (RFC 9110 §7.2) — differing is two hosts disagreeing,
    // which is what `DuplicateHost` already means.
    if let Some(authority) = request.uri().authority() {
        let authority = authority.as_str();
        if headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("host") && v != authority)
        {
            return Err(ParseError::DuplicateHost);
        }
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
        headers.insert(0, ("host".to_owned(), authority.to_owned()));
    }
    Ok(RequestHead {
        method,
        target,
        version: Version::Http2,
        headers,
        content_length: framing.content_length,
        chunked: framing.chunked,
    })
}

/// Check a request target's length, bytes, and shape — the rules
/// `parse_request_line` owns for HTTP/1, shared here so both maps
/// refuse the same targets.
fn check_target(target: &str, method: Method) -> Result<String, ParseError> {
    if target.len() > MAX_TARGET_BYTES {
        return Err(ParseError::TargetTooLong {
            bytes: target.len(),
            limit: MAX_TARGET_BYTES,
        });
    }
    if !target.is_ascii() {
        return Err(ParseError::BadRequestLine {
            detail: "non-ASCII byte in the request line".to_owned(),
        });
    }
    let is_asterisk = target == "*" && method == Method::Options;
    if !is_asterisk && !target.starts_with('/') {
        return Err(ParseError::TargetNotAbsolute {
            target: truncate_head(target, 64),
        });
    }
    Ok(target.to_owned())
}

/// Truncate for an error detail without splitting UTF-8, mirroring the
/// private `http1::truncate`: an unbounded method or target must not
/// become an unbounded log line.
fn truncate_head(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}…", &s[..end])
}

/// Collect a hyper body with the shared caps.
///
/// Two framings, two readers — deliberately, because hyper delivers
/// them differently. A `Content-Length` body arrives as raw bytes, so
/// it goes through the shared [`BodyReader`] (same streaming counts,
/// same refusals as the in-house path). A decoded stream — HTTP/1
/// chunked after hyper strips it, or HTTP/2 DATA with no declared
/// length — goes through [`collect_streamed`], counted frame by frame
/// against the same cap. Returns the body with the byte count, so the
/// metric cannot drift from what arrived.
async fn collect_body(incoming: Incoming, head: &RequestHead) -> Option<(BodyBytes, u64)> {
    if !head.chunked && head.content_length.is_none_or(|n| n == 0) {
        let body = if head.content_length == Some(0) {
            BodyBytes::Buffered(Vec::new())
        } else {
            BodyBytes::Absent
        };
        return Some((body, 0));
    }
    // Chunked arrives decoded (hyper strips the framing), so it streams
    // through the counter; declared lengths go through the shared
    // reader with identical counts and refusals.
    if head.chunked {
        return collect_streamed(incoming).await;
    }
    collect_framed(incoming, head).await
}

/// Collect an HTTP/2 body: declared lengths go through the shared
/// reader; lengths the client never declared stream to the cap.
///
/// HTTP/2 has no chunked framing, so a body without `Content-Length`
/// is an unframed stream — refusing it would demand `411`, and
/// ignoring it would lose bytes. Counting it against the shared cap
/// keeps both promises, and an empty stream still reports `Absent`
/// (not an empty buffer), preserving the distinction dispatch relies
/// on without sniffing the method.
async fn collect_h2_body(incoming: Incoming, head: &RequestHead) -> Option<(BodyBytes, u64)> {
    match head.content_length {
        Some(0) => Some((BodyBytes::Buffered(Vec::new()), 0)),
        Some(_) => collect_framed(incoming, head).await,
        None => {
            let (body, received) = collect_streamed(incoming).await?;
            if received == 0 {
                return Some((BodyBytes::Absent, 0));
            }
            Some((body, received))
        }
    }
}

/// Collect through the shared [`BodyReader`]: caps, chunked decoding,
/// and refusal shapes identical to the in-house path.
async fn collect_framed(incoming: Incoming, head: &RequestHead) -> Option<(BodyBytes, u64)> {
    let Ok(mut reader) = BodyReader::from_head(head, config_max_request_bytes()) else {
        return None;
    };
    let mut transport = IncomingReader::new(incoming);
    let mut body = Vec::new();
    loop {
        match reader.poll_chunk(&mut transport, 8 * 1024).await {
            Ok(BodyChunk::Data(chunk)) => body.extend_from_slice(&chunk),
            Ok(BodyChunk::End) => {
                let received = reader.bytes_read();
                return Some((BodyBytes::Buffered(body), received));
            }
            Err(_) => return None,
        }
    }
}

/// Collect a decoded stream frame by frame against the shared cap:
/// HTTP/1 chunked after hyper strips it, or HTTP/2 DATA with no
/// declared length. Hyper guarantees the framing; QQQ guarantees the
/// bound. A body past the cap, a transport error, or a truncation all
/// refuse the same way the shared reader refuses: no partial body ever
/// reaches a handler.
async fn collect_streamed(incoming: Incoming) -> Option<(BodyBytes, u64)> {
    let cap = config_max_request_bytes();
    let mut stream = BodyStream::new(incoming);
    let mut body = Vec::new();
    loop {
        let Some(next) = stream.frame().await else {
            let received = body.len() as u64;
            return Some((BodyBytes::Buffered(body), received));
        };
        let Ok(frame) = next else {
            return None;
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let received = body.len() as u64 + data.len() as u64;
        if received > cap {
            return None;
        }
        body.extend_from_slice(&data);
    }
}

/// Adapt hyper's body stream to the [`AsyncRead`] the shared
/// [`BodyReader`] polls.
///
/// Data frames become read bytes; trailer and informational frames are
/// skipped (the flat path has no trailer contract, matching the
/// in-house reader, which never sees them); transport end becomes EOF,
/// which the reader interprets — truncated bodies fail there, not here.
///
/// Soundness of the manual `Unpin`: the struct owns its pinned body
/// through a `Box`, so moving the adapter moves the pointer, never the
/// body. The leftover bytes move freely.
struct IncomingReader {
    body: Pin<Box<BodyStream<Incoming>>>,
    leftover: Option<Bytes>,
}

impl Unpin for IncomingReader {}

impl IncomingReader {
    fn new(incoming: Incoming) -> Self {
        Self {
            body: Box::pin(BodyStream::new(incoming)),
            leftover: None,
        }
    }
}

impl AsyncRead for IncomingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if let Some(rest) = this.leftover.take() {
            let n = rest.len().min(buf.remaining());
            let take = rest.slice(..n);
            buf.put_slice(&take);
            if n < rest.len() {
                this.leftover = Some(rest.slice(n..));
            }
            return Poll::Ready(Ok(()));
        }
        match this.body.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    this.leftover = Some(data);
                }
                // Through the leftover path for data, or back to the
                // transport for trailers: one place fills the buffer.
                self.poll_read(cx, buf)
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(std::io::Error::other(format!(
                "hyper body failed: {error}"
            )))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head<B>(request: &hyper::Request<B>) -> Result<RequestHead, ParseError> {
        map_head(request)
    }

    fn get(target: &str, headers: &[(&str, &str)]) -> hyper::Request<()> {
        let mut builder = hyper::Request::builder().method("GET").uri(target);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap_or_else(|_| hyper::Request::new(()))
    }

    /// Every send poll stamps activity — and polls recur across the
    /// whole send, not just its start: backdate the watch past the
    /// bound before EACH poll of a 40KB body (16K + 16K + 8K + end)
    /// and every poll revives it. A single-frame wrapper would stamp
    /// once and go silent for the rest of a slow send; the chunking
    /// exists so the stamps track send progress to the last byte.
    /// Red before `WatchBody` exists (it names the type and its
    /// constructor); red at runtime if any poll stops stamping.
    #[tokio::test]
    async fn watch_body_stamps_on_poll() {
        use http_body::Body as _;

        fn backdate(watch: &IdleWatch) {
            let mut slot = watch.last_activity.lock().expect("test mutex held");
            *slot = Instant::now()
                .checked_sub(Duration::from_secs(120))
                .expect("backdate within clock range");
        }

        let watch = Arc::new(IdleWatch::new());
        let bound = Duration::from_secs(60);
        let mut body = WatchBody::new(Bytes::from(vec![b'z'; 40 * 1024]), &watch);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut pinned = std::pin::Pin::new(&mut body);
        let mut bytes = 0usize;
        for (n, want) in [16 * 1024, 16 * 1024, 8 * 1024].into_iter().enumerate() {
            backdate(&watch);
            assert!(watch.is_idle(bound), "poll {n}: backdated watch reads idle");
            match pinned.as_mut().poll_frame(&mut cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    let data = frame.into_data().expect("data frame");
                    assert_eq!(data.len(), want, "poll {n}: frame carries its chunk");
                    assert!(data.iter().all(|&b| b == b'z'), "poll {n}: bytes unchanged");
                    bytes += data.len();
                }
                other => panic!("poll {n}: DATA frame expected, got {other:?}"),
            }
            assert!(
                !watch.is_idle(bound),
                "poll {n}: a send poll stamps activity like a request"
            );
        }
        assert_eq!(bytes, 40 * 1024);
        backdate(&watch);
        match pinned.as_mut().poll_frame(&mut cx) {
            Poll::Ready(None) => {}
            other => panic!("end of body expected, got {other:?}"),
        }
        assert!(
            watch.is_idle(bound),
            "the terminal poll carries no bytes, so it stamps nothing"
        );
    }

    /// Dropping a flight stamps completion: backdate past the bound
    /// while held (invisible — the flight blocks idleness), drop, and
    /// the watch is alive. Without the drop stamp, a slow handler's
    /// answer would leave idleness measured from request arrival.
    #[test]
    fn flight_drop_stamps_activity() {
        let watch = Arc::new(IdleWatch::new());
        let bound = Duration::from_secs(60);
        let flight = watch.hold();
        {
            let mut slot = watch.last_activity.lock().expect("test mutex held");
            *slot = Instant::now()
                .checked_sub(Duration::from_secs(120))
                .expect("backdate within clock range");
        }
        drop(flight);
        assert!(
            !watch.is_idle(bound),
            "completion stamps like arrival and polling"
        );
    }

    /// The smuggling rows refuse with the in-house taxonomy, not a guess.
    #[test]
    fn conflicting_and_doubled_framing_refuse() {
        let both = hyper::Request::builder()
            .method("POST")
            .uri("/a")
            .header("content-length", "5")
            .header("transfer-encoding", "chunked")
            .body(())
            .unwrap_or_else(|_| hyper::Request::new(()));
        assert!(matches!(head(&both), Err(ParseError::ConflictingFraming)));
        let dup = hyper::Request::builder()
            .method("POST")
            .uri("/a")
            .header("content-length", "5")
            .header("content-length", "6")
            .body(())
            .unwrap_or_else(|_| hyper::Request::new(()));
        assert!(matches!(
            head(&dup),
            Err(ParseError::DuplicateContentLength)
        ));
        let dup_host = get("/a", &[("host", "x"), ("host", "y")]);
        assert!(matches!(head(&dup_host), Err(ParseError::DuplicateHost)));
    }

    /// Absolute-form is not routable: a scheme means a proxy wrote this.
    #[test]
    fn absolute_form_refuses() {
        let absolute = hyper::Request::builder()
            .method("GET")
            .uri("http://x/b")
            .body(())
            .unwrap_or_else(|_| hyper::Request::new(()));
        assert!(matches!(
            head(&absolute),
            Err(ParseError::TargetNotAbsolute { .. })
        ));
    }

    /// Unknown methods refuse; known ones map, case-insensitively like the parser.
    #[test]
    fn methods_map_like_the_parser() {
        let known = get("/a", &[]);
        assert_eq!(head(&known).expect("GET maps").method, Method::Get);
        let unknown = hyper::Request::builder()
            .method("FROBNICATE")
            .uri("/a")
            .body(())
            .unwrap_or_else(|_| hyper::Request::new(()));
        assert!(matches!(
            head(&unknown),
            Err(ParseError::UnknownMethod { .. })
        ));
    }

    /// The ceiling decides serve, warn, and refuse on the count before
    /// the request — mirroring `Connection`'s `RequestLimit`, including
    /// the zero-ceiling edge that refuses everything.
    #[test]
    fn ceiling_decides_serve_warn_and_refuse() {
        assert_eq!(ceiling_for(0, 2), Ceiling::Serve);
        assert_eq!(ceiling_for(1, 2), Ceiling::Warn);
        assert_eq!(ceiling_for(2, 2), Ceiling::Refuse);
        assert_eq!(ceiling_for(9, 2), Ceiling::Refuse);
        assert_eq!(ceiling_for(0, 0), Ceiling::Refuse);
        assert_eq!(ceiling_for(0, 1), Ceiling::Warn);
    }

    fn h2_get(uri: &str, headers: &[(&str, &str)]) -> hyper::Request<()> {
        let mut builder = hyper::Request::builder().method("GET").uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap_or_else(|_| hyper::Request::new(()))
    }

    /// The h2 map synthesises `host` from `:authority` first, like a
    /// request line the client addressed to us — and a `host` header
    /// disagreeing with it is two hosts disagreeing (`DuplicateHost`).
    #[test]
    fn h2_authority_synthesis_and_conflicts() {
        let headed = map_head_h2(&h2_get("http://localhost/hello", &[])).expect("authority maps");
        assert_eq!(headed.version, Version::Http2);
        assert_eq!(headed.target, "/hello");
        assert_eq!(
            headed.headers.first(),
            Some(&("host".to_owned(), "localhost".to_owned()))
        );
        let agreeing = map_head_h2(&h2_get("http://localhost/hello", &[("host", "localhost")]))
            .expect("agreeing host maps");
        let hosts: Vec<_> = agreeing
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
            .collect();
        assert_eq!(
            hosts,
            [("host".to_owned(), "localhost".to_owned())]
                .iter()
                .collect::<Vec<_>>(),
            "one host survives, the authority first"
        );
        assert!(matches!(
            map_head_h2(&h2_get("http://localhost/hello", &[("host", "other")]),),
            Err(ParseError::DuplicateHost)
        ));
    }

    /// The shared target rules hold on h2: over-long refuses, and a
    /// target that does not start at `/` is not routable.
    #[test]
    fn h2_targets_refuse_like_h1() {
        let long = format!("http://localhost/{}", "a".repeat(MAX_TARGET_BYTES));
        assert!(matches!(
            map_head_h2(&h2_get(&long, &[])),
            Err(ParseError::TargetTooLong { .. })
        ));
    }
}
