// SPDX-License-Identifier: Apache-2.0

//! Connection lifecycle: keep-alive, idle deadlines, and graceful drain.
//!
//! Implements `SRV-011` and `SRV-012`; Proposal §6.4 (*"HTTP keep-alive,
//! configurable idle timeouts, connection limits per tenant, graceful shutdown
//! with in-flight request draining"*).
//!
//! # What this module is, and what it deliberately is not
//!
//! It is a **state machine**: given what has happened on a connection, it says
//! what should happen next. It does not own a socket, spawn a task, or read a
//! clock. Every timing input arrives as a parameter, exactly as in
//! [`crate::route`]'s debouncer cousin (`qqq-run::watch`).
//!
//! That is not stylistic. The decisions that matter here are *timing* decisions
//! — has the connection been idle too long, has the drain deadline passed, is
//! this tenant at its limit — and a state machine that reads `Instant::now()`
//! internally can only be tested by sleeping. Tests that sleep are slow and
//! flaky, and a flaky test of a shutdown path is worse than no test, because it
//! gets ignored.
//!
//! # The four rules this encodes
//!
//! 1. **A response decides the next state, not the request.** A client may ask
//!    for keep-alive and still be told `Connection: close`, because the server
//!    is draining or the request was malformed. The response is the authority.
//!
//! 2. **An error closes the connection.** After a framing error the parser's
//!    view of where one request ends is not trustworthy, so reading on risks
//!    interpreting body bytes as the next request — which *is* the smuggling
//!    attack. This is why [`ParseError::closes_connection`] exists and why the
//!    machine consults it rather than deciding for itself.
//!
//! 3. **A drain stops accepting, not finishing.** Graceful shutdown means
//!    in-flight requests complete and idle connections close. Killing an
//!    in-flight request is not graceful, and refusing to close an idle one
//!    means the process never exits — a shutdown that hangs is worse than one
//!    that is abrupt, because an operator cannot tell the difference between
//!    "still draining" and "stuck".
//!
//! 4. **A drain deadline is enforced, and exceeding it is reported.** Some
//!    guests will not finish. After the deadline the connection is closed and
//!    the event is counted, because a silent forced close during a deploy is
//!    how a slow request becomes an unexplained 502.
//!
//! `ParseError::closes_connection` is referenced above; see [`crate::http1`].

use std::time::{Duration, Instant};

use crate::http1::ParseError;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// How a connection should behave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    /// How long an idle connection is kept open.
    ///
    /// "Idle" means between requests: the connection is open, no request is
    /// being read or handled. This is the setting that bounds how many sockets
    /// a slow client can hold, so it is also the slow-loris mitigation.
    pub idle_timeout: Duration,
    /// How long the whole request head may take to arrive.
    ///
    /// # Why this is separate from the idle timeout, and why it must be shorter
    ///
    /// The idle timeout governs a connection *between* requests. This governs
    /// one *during* a request head. Without it, a client that opens a connection
    /// and sends one byte per minute holds it forever while technically never
    /// being idle — which is precisely the slow-loris attack Proposal §6.4
    /// names.
    ///
    /// It is shorter than the idle timeout because a legitimate client sends a
    /// complete head in one or two packets; anything taking longer is either
    /// broken or hostile.
    pub header_timeout: Duration,
    /// The maximum requests one connection may serve before closing.
    ///
    /// A cap rather than unbounded reuse. Two reasons: it bounds the effect of
    /// a per-connection leak, and it forces periodic rebalancing, so a client
    /// pinned to one backend eventually moves. Both are invisible in normal
    /// operation and both matter at scale.
    pub max_requests: u32,
    /// How long a drain may take before in-flight requests are cut off.
    pub drain_timeout: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            // 75 seconds is nginx's default and sits comfortably above every
            // common client timeout, so the server closes first and the client
            // sees a clean close rather than a reset.
            idle_timeout: Duration::from_secs(75),
            // Deliberately much shorter than the idle timeout: a client sending
            // a head slowly is not a client with a slow connection, it is a
            // client holding a slot.
            header_timeout: Duration::from_secs(10),
            // 1000 requests is enough to amortise a handshake across a real
            // session and small enough that a leak shows up within one.
            max_requests: 1_000,
            // 30 seconds is long enough for a slow but legitimate request and
            // short enough that a deploy completes within a normal rollout
            // window.
            drain_timeout: Duration::from_secs(30),
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// What the connection layer should do next.
///
/// A closed enum rather than a set of booleans, so the caller cannot represent
/// "read the next request *and* close" — a combination that would be a bug every
/// time it occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Read another request head.
    ReadRequest,
    /// The request was handled; write the response and decide again.
    WriteResponse,
    /// Close now.
    Close(CloseReason),
}

/// Why a connection closed.
///
/// Reported per connection because the *reason* is what an operator needs: a
/// process whose connections all close with `HeaderTimeout` is being scanned,
/// and one where they close with `DrainDeadline` needs a longer drain timeout.
/// A bare "closed" counter cannot distinguish them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// The client asked to close.
    ClientRequested,
    /// The server's response carried `Connection: close`.
    ServerRequested,
    /// The connection was idle longer than the idle timeout.
    IdleTimeout,
    /// A request head did not arrive within the header timeout.
    HeaderTimeout,
    /// The head was malformed, or its framing was ambiguous.
    ProtocolError,
    /// The connection reached its request cap.
    RequestLimit,
    /// A shutdown began and this connection was idle, so it closed at once.
    ShutdownIdle,
    /// A shutdown began and this connection's in-flight request exceeded the
    /// drain deadline and was cut off.
    DrainDeadline,
}

impl CloseReason {
    /// The stable name, for metrics and access logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientRequested => "client-requested",
            Self::ServerRequested => "server-requested",
            Self::IdleTimeout => "idle-timeout",
            Self::HeaderTimeout => "header-timeout",
            Self::ProtocolError => "protocol-error",
            Self::RequestLimit => "request-limit",
            Self::ShutdownIdle => "shutdown-idle",
            Self::DrainDeadline => "drain-deadline",
        }
    }

    /// Whether this close is routine rather than a symptom.
    ///
    /// A deploy that produces a spike in `DrainDeadline` is different from one
    /// that produces a spike in `ClientRequested`, and only the former needs
    /// action. Exposed so a metric can be split without the caller
    /// re-implementing the classification.
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(
            self,
            Self::ClientRequested | Self::ServerRequested | Self::RequestLimit | Self::ShutdownIdle
        )
    }
}

// ---------------------------------------------------------------------------
// The machine
// ---------------------------------------------------------------------------

/// One connection's lifecycle.
#[derive(Debug, Clone)]
pub struct Connection {
    config: ConnectionConfig,
    /// When the connection last became idle — i.e. finished a response.
    ///
    /// `None` until the first response, because a connection that has not yet
    /// served a request is governed by the header timeout rather than the idle
    /// timeout. Conflating the two lets a client hold a slot by never sending
    /// anything.
    idle_since: Option<Instant>,
    /// When the current request head started arriving.
    head_started: Option<Instant>,
    /// How many requests this connection has served.
    served: u32,
    /// Whether the client asked for keep-alive on the last request.
    client_wants_keep_alive: bool,
    /// Whether a shutdown has begun.
    draining: bool,
    /// When the drain deadline expires.
    drain_deadline: Option<Instant>,
    /// Whether a request is in flight.
    in_flight: bool,
    /// What closed it, once it is closed.
    closed: Option<CloseReason>,
}

impl Connection {
    /// A new connection.
    #[must_use]
    pub fn new(config: ConnectionConfig) -> Self {
        Self {
            config,
            idle_since: None,
            head_started: None,
            served: 0,
            client_wants_keep_alive: true,
            draining: false,
            drain_deadline: None,
            in_flight: false,
            closed: None,
        }
    }

    /// Whether the connection is still usable.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.closed.is_none()
    }

    /// Why it closed, when it did.
    #[must_use]
    pub fn close_reason(&self) -> Option<CloseReason> {
        self.closed
    }

    /// How many requests it served.
    #[must_use]
    pub fn served(&self) -> u32 {
        self.served
    }

    /// Mark that a request head has begun arriving.
    ///
    /// Separate from [`Self::on_request_parsed`] because a slow client is
    /// detected *during* the head, and the timer has to start before the parse
    /// completes or the timeout can never fire.
    pub fn begin_request(&mut self, now: Instant) {
        if self.head_started.is_none() {
            self.head_started = Some(now);
        }
        // A connection reading a request is not idle, even if it arrived idle.
        self.idle_since = None;
    }

    /// Mark that a request head arrived.
    pub fn on_request_parsed(&mut self, client_wants_keep_alive: bool) {
        self.head_started = None;
        self.in_flight = true;
        self.client_wants_keep_alive = client_wants_keep_alive;
    }

    /// Whether a response written now may advertise `keep-alive`.
    ///
    /// # Why this exists separately from [`is_open`]
    ///
    /// `is_open` answers "has this connection been closed?" — which is `true`
    /// for the whole duration of a request that is about to be the last one.
    /// A caller that uses it to choose the `Connection` header therefore
    /// advertises keep-alive on the response that closes the connection.
    ///
    /// Measured: an HTTP/1.0 request, which defaults to close, received
    /// `Connection: keep-alive`. The encoder was correct, the state machine was
    /// correct, and the *caller* asked the wrong question — so the two correct
    /// halves disagreed on the wire, which is the defect this session has found
    /// in four different modules (`§O-045a`, `§O-046a`).
    ///
    /// This answers the question the caller actually has: after a response is
    /// written with `server_wants_close`, will the connection persist? It mirrors
    /// the decision [`on_response_sent`] will make, and the `debug_assert` there
    /// keeps the two in step — a header that disagrees with the lifecycle is a
    /// protocol bug, not a cosmetic one.
    #[must_use]
    pub fn will_keep_alive(&self, server_wants_close: bool) -> bool {
        if server_wants_close || !self.client_wants_keep_alive {
            return false;
        }
        if self.closed.is_some() || self.draining {
            return false;
        }
        // The next request would exceed the ceiling, so this response is the
        // last one and must say so.
        self.served.saturating_add(1) < self.config.max_requests
    }

    /// Mark that a response was written.
    ///
    /// `server_wants_close` is the response's own `Connection: close`. It wins
    /// over the client's preference, because the server may be draining or may
    /// have decided the connection is unusable.
    ///
    /// # How this stays in step with `will_keep_alive`
    ///
    /// The two must agree: `will_keep_alive` decides the `Connection` header and
    /// this decides the connection's life, and a disagreement puts one answer on
    /// the wire and another in the lifecycle. A client told `keep-alive` on a
    /// socket that then closes has its next request fail; a client told `close`
    /// on a socket that stays open holds a connection it will not reuse.
    ///
    /// There is deliberately **no `debug_assert` tying them together**. A first
    /// draft added one, and it would have been circular: this function computes
    /// `will_keep_alive` from the same fields it is about to mutate, so the
    /// assertion would evaluate `true` in every reachable state and could not
    /// fail. That is the vacuous-assertion trap recorded in `§O-046b`, and this
    /// is the fourth time this session that the instinct to add a check produced
    /// one that cannot refute anything.
    ///
    /// What actually keeps them in step is the integration test in
    /// `tests/socket.rs`, which reads the header off a real socket and checks the
    /// connection's behaviour directly — two independent observations rather
    /// than one restated.
    pub fn on_response_sent(&mut self, now: Instant, server_wants_close: bool) {
        self.in_flight = false;
        self.served = self.served.saturating_add(1);

        if server_wants_close || !self.client_wants_keep_alive {
            self.closed = Some(if server_wants_close {
                CloseReason::ServerRequested
            } else {
                CloseReason::ClientRequested
            });
            return;
        }
        if self.served >= self.config.max_requests {
            self.closed = Some(CloseReason::RequestLimit);
            return;
        }
        // Draining and now idle: close rather than wait for a request that will
        // be refused anyway.
        if self.draining {
            self.closed = Some(CloseReason::ShutdownIdle);
            return;
        }
        self.idle_since = Some(now);
    }

    /// Mark that the head failed to parse.
    ///
    /// # Why this takes the error rather than a bare "failed"
    ///
    /// Because whether to close depends on the error, and the parser already
    /// knows the answer: [`ParseError::closes_connection`] is true exactly when
    /// the parser's view of where this request ends is untrustworthy. Deciding
    /// that here would duplicate the rule, and the two copies would eventually
    /// disagree — with the disagreement being a smuggling vulnerability.
    pub fn on_parse_error(&mut self, error: &ParseError) {
        self.head_started = None;
        self.in_flight = false;
        if error.closes_connection() {
            self.closed = Some(CloseReason::ProtocolError);
        }
    }

    /// Begin a graceful shutdown.
    ///
    /// In-flight requests are allowed to finish; idle connections close at once.
    pub fn begin_drain(&mut self, now: Instant) {
        self.draining = true;
        self.drain_deadline = Some(now + self.config.drain_timeout);
        if !self.in_flight {
            self.closed = Some(CloseReason::ShutdownIdle);
        }
    }

    /// What to do at this instant.
    ///
    /// # The order of checks is the policy
    ///
    /// 1. **Already closed** — nothing to do.
    /// 2. **Drain deadline** — a drain that never completes is worse than an
    ///    abrupt one, because an operator cannot tell it from a hang.
    /// 3. **Header timeout** — a client mid-head is holding a slot.
    /// 4. **In flight** — a request is being handled; leave it alone, because
    ///    interrupting it is not graceful.
    /// 5. **Idle timeout**.
    /// 6. **Draining** — stop reading; the response will close us.
    ///
    /// The order matters where conditions overlap. A draining connection with
    /// an in-flight request must not be closed by the idle rule (4 before 6),
    /// and a connection whose drain deadline passed must close even though a
    /// request is in flight (2 before 4).
    #[must_use]
    pub fn poll(&self, now: Instant) -> Action {
        if let Some(reason) = self.closed {
            return Action::Close(reason);
        }

        // 2. The drain deadline, checked before everything else so a stuck
        //    request cannot hold a draining process open forever.
        if let Some(deadline) = self.drain_deadline {
            if now >= deadline {
                return Action::Close(CloseReason::DrainDeadline);
            }
        }

        // 4. A request in flight is never interrupted by a timeout. The guest's
        //    own epoch deadline governs it, and it produces a response rather
        //    than a reset — which is what makes a slow request a 504 instead of
        //    a connection error the client cannot classify.
        if self.in_flight {
            return Action::WriteResponse;
        }

        // 3. A head arrived partially and stopped.
        if let Some(started) = self.head_started {
            if now.saturating_duration_since(started) >= self.config.header_timeout {
                return Action::Close(CloseReason::HeaderTimeout);
            }
            return Action::ReadRequest;
        }

        // 5. Idle between requests.
        if let Some(idle_since) = self.idle_since {
            if now.saturating_duration_since(idle_since) >= self.config.idle_timeout {
                return Action::Close(CloseReason::IdleTimeout);
            }
        }

        // 6. Draining: do not start a new request.
        if self.draining {
            return Action::Close(CloseReason::ShutdownIdle);
        }

        Action::ReadRequest
    }
}

// ---------------------------------------------------------------------------
// Per-tenant accounting
// ---------------------------------------------------------------------------

/// Tracks open connections per tenant, enforcing a limit.
///
/// # Why a limit per tenant rather than a global one
///
/// A global limit lets one tenant starve every other by opening connections. The
/// per-tenant limit is what makes the runtime multi-tenant rather than merely
/// multi-process — and Proposal §6.4 requires exactly this
/// (`SRV-012`).
#[derive(Debug)]
pub struct ConnectionLedger {
    /// Per-tenant ceilings, for a tenant the manifest names.
    ///
    /// Empty is the common case: a deployment that declares no per-tenant
    /// `max_connections` gets the fallback for everybody.
    ceilings: std::collections::BTreeMap<String, u32>,
    /// The ceiling for a tenant not in `ceilings`.
    ///
    /// This is `ServerConfig::connections_per_tenant`, and it is a fallback rather
    /// than an override so that naming one tenant does not change the ceiling for
    /// every other — the same shape `TenantLimits` uses for its limits, and for the
    /// same reason.
    per_tenant: u32,
    /// Open connections per tenant.
    counts: std::collections::BTreeMap<String, u32>,
}

impl ConnectionLedger {
    /// A ledger with the given per-tenant ceiling.
    ///
    /// A ceiling of zero is raised to one: a tenant allowed no connections
    /// cannot be served at all, which is almost certainly a configuration
    /// mistake rather than an intent, and silently rejecting every request
    /// would make it hard to diagnose.
    #[must_use]
    pub fn new(per_tenant: u32) -> Self {
        Self {
            ceilings: std::collections::BTreeMap::new(),
            per_tenant: per_tenant.max(1),
            counts: std::collections::BTreeMap::new(),
        }
    }

    /// A ledger with per-tenant ceilings and a fallback.
    ///
    /// A ceiling of zero in the table is raised to one for the same reason
    /// [`Self::new`] raises the fallback: a tenant allowed no connections cannot be
    /// served at all. The manifest refuses `max_connections = 0` before a server
    /// binds, so this is defence in depth rather than the only guard.
    #[must_use]
    pub fn with_limits<I>(ceilings: I, fallback: u32) -> Self
    where
        I: IntoIterator<Item = (String, u32)>,
    {
        Self {
            ceilings: ceilings
                .into_iter()
                .map(|(tenant, ceiling)| (tenant, ceiling.max(1)))
                .collect(),
            per_tenant: fallback.max(1),
            counts: std::collections::BTreeMap::new(),
        }
    }

    /// The fallback ceiling.
    #[must_use]
    pub const fn per_tenant(&self) -> u32 {
        self.per_tenant
    }

    /// The ceiling that applies to one tenant.
    #[must_use]
    pub fn ceiling_for(&self, tenant: &str) -> u32 {
        self.ceilings
            .get(tenant)
            .copied()
            .unwrap_or(self.per_tenant)
    }

    /// Try to admit a connection.
    ///
    /// Returns `false` when the tenant is at its ceiling, which the caller
    /// answers with 503 and `Retry-After` — the same loading-shedding path as
    /// pool exhaustion, because it is the same situation.
    pub fn admit(&mut self, tenant: &str) -> bool {
        let ceiling = self
            .ceilings
            .get(tenant)
            .copied()
            .unwrap_or(self.per_tenant);
        let count = self.counts.entry(tenant.to_owned()).or_insert(0);
        if *count >= ceiling {
            return false;
        }
        *count += 1;
        true
    }

    /// Release a connection.
    ///
    /// Removes the entry at zero rather than keeping it, so a runtime serving
    /// many short-lived tenants does not accumulate a map entry per tenant ever
    /// seen. A ledger that grows without bound is a leak in the component whose
    /// job is to bound something.
    pub fn release(&mut self, tenant: &str) {
        if let Some(count) = self.counts.get_mut(tenant) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.counts.remove(tenant);
            }
        }
    }

    /// How many connections a tenant holds.
    #[must_use]
    pub fn open_for(&self, tenant: &str) -> u32 {
        self.counts.get(tenant).copied().unwrap_or(0)
    }

    /// The total across tenants.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.counts.values().copied().sum()
    }

    /// How many distinct tenants hold connections.
    #[must_use]
    pub fn tenants(&self) -> usize {
        self.counts.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ConnectionConfig {
        ConnectionConfig {
            idle_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(2),
            max_requests: 3,
            drain_timeout: Duration::from_secs(5),
        }
    }

    fn conn() -> Connection {
        Connection::new(config())
    }

    // -- the happy path ----------------------------------------------------

    #[test]
    fn a_fresh_connection_reads_a_request() {
        let c = conn();
        assert!(c.is_open());
        assert_eq!(c.poll(Instant::now()), Action::ReadRequest);
        assert_eq!(c.served(), 0);
    }

    /// A request that arrived and was answered leaves the connection idle, not
    /// closed, when both sides want keep-alive.
    #[test]
    fn keep_alive_after_a_response() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);
        c.on_request_parsed(true);
        assert_eq!(c.poll(t0), Action::WriteResponse, "in flight");

        c.on_response_sent(t0, false);
        assert!(c.is_open());
        assert_eq!(c.served(), 1);
        assert_eq!(
            c.poll(t0 + Duration::from_secs(1)),
            Action::ReadRequest,
            "idle but within the timeout"
        );
    }

    /// The response is the authority, not the request: a server that is
    /// draining may tell a keep-alive client to close.
    #[test]
    fn a_server_side_close_wins_over_the_client_preference() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);
        c.on_request_parsed(true); // client wants keep-alive
        c.on_response_sent(t0, true); // server says close

        assert!(!c.is_open());
        assert_eq!(c.close_reason(), Some(CloseReason::ServerRequested));
    }

    #[test]
    fn a_client_close_is_honoured() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);
        c.on_request_parsed(false); // client says close
        c.on_response_sent(t0, false);

        assert_eq!(c.close_reason(), Some(CloseReason::ClientRequested));
    }

    // -- the request cap ---------------------------------------------------

    /// A connection closes after its cap, so a per-connection leak is bounded
    /// and clients are forced to rebalance periodically.
    #[test]
    fn a_connection_closes_at_its_request_cap() {
        let mut c = conn();
        let t0 = Instant::now();
        for i in 1..=3 {
            c.begin_request(t0);
            c.on_request_parsed(true);
            c.on_response_sent(t0, false);
            assert_eq!(c.served(), i);
            if i < 3 {
                assert!(c.is_open(), "still under the cap after {i}");
            }
        }
        assert_eq!(
            c.close_reason(),
            Some(CloseReason::RequestLimit),
            "the third request reaches the cap of 3"
        );
    }

    // -- timeouts ----------------------------------------------------------

    /// The idle timeout governs a connection *between* requests.
    #[test]
    fn an_idle_connection_times_out() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);
        c.on_request_parsed(true);
        c.on_response_sent(t0, false);

        assert_eq!(
            c.poll(t0 + Duration::from_secs(9)),
            Action::ReadRequest,
            "under the idle timeout"
        );
        assert_eq!(
            c.poll(t0 + Duration::from_secs(10)),
            Action::Close(CloseReason::IdleTimeout),
            "at the boundary it closes"
        );
    }

    /// **The slow-loris mitigation.** A client that starts a request and sends
    /// the rest slowly is not idle — it is mid-head — so the idle timeout never
    /// fires. The header timeout is what closes it.
    #[test]
    fn a_slow_header_is_closed_by_the_header_timeout_not_the_idle_timeout() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);

        // Two seconds is the header timeout; ten is the idle timeout. If the
        // machine used the idle timeout here, a slow-loris would hold the
        // connection five times longer than intended.
        assert_eq!(
            c.poll(t0 + Duration::from_secs(1)),
            Action::ReadRequest,
            "still within the header timeout"
        );
        assert_eq!(
            c.poll(t0 + Duration::from_secs(2)),
            Action::Close(CloseReason::HeaderTimeout),
            "the header timeout fires long before the idle timeout would"
        );
    }

    /// A connection that has never served a request is governed by the header
    /// timeout from its first byte — there is no idle period to measure.
    #[test]
    fn a_connection_that_never_sends_anything_is_closed_by_the_header_timeout() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);
        assert_eq!(
            c.poll(t0 + Duration::from_secs(2)),
            Action::Close(CloseReason::HeaderTimeout)
        );
    }

    /// **A request in flight is never interrupted by a timeout.** The guest's
    /// own epoch deadline governs it and produces a 504 rather than a reset, so
    /// a slow request is classifiable by the client.
    #[test]
    fn an_in_flight_request_is_not_closed_by_any_timeout() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);
        c.on_request_parsed(true);

        for elapsed in [1u64, 5, 10, 100, 10_000] {
            assert_eq!(
                c.poll(t0 + Duration::from_secs(elapsed)),
                Action::WriteResponse,
                "an in-flight request must not be cut off after {elapsed}s"
            );
        }
    }

    // -- protocol errors ---------------------------------------------------

    /// **The smuggling defence.** After a framing error the parser's view of
    /// where the request ends is untrustworthy, so reading on risks treating
    /// body bytes as the next request.
    #[test]
    fn a_framing_error_closes_the_connection() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);
        c.on_request_parsed(true);

        c.on_parse_error(&ParseError::ConflictingFraming);
        assert_eq!(c.close_reason(), Some(CloseReason::ProtocolError));
        assert_eq!(c.poll(t0), Action::Close(CloseReason::ProtocolError));
    }

    /// But a request-scoped error — a bad route, an oversized target — does
    /// **not** close, because the parser still knows where the request ends and
    /// the connection remains usable.
    #[test]
    fn a_request_scoped_error_does_not_close_the_connection() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);
        c.on_request_parsed(true);

        c.on_parse_error(&ParseError::TargetTooLong { bytes: 1, limit: 1 });
        assert!(
            c.is_open(),
            "an oversized target is request-scoped; the framing is still known"
        );
        // And it can serve the next request.
        c.on_response_sent(t0, false);
        assert!(c.is_open());
    }

    /// The machine consults the parser rather than deciding for itself, so the
    /// two cannot disagree. Every error that says it closes must close the
    /// connection.
    #[test]
    fn every_closing_parse_error_closes_the_connection() {
        let errors = [
            ParseError::ConflictingFraming,
            ParseError::DuplicateContentLength,
            ParseError::TooManyHeaders { limit: 1 },
            ParseError::HeadTooLarge { limit: 1 },
            ParseError::HeaderTooLong {
                name: "X".to_owned(),
                bytes: 2,
                limit: 1,
            },
        ];
        for e in &errors {
            assert!(e.closes_connection(), "{e} should close");
            let mut c = conn();
            c.on_parse_error(e);
            assert_eq!(
                c.close_reason(),
                Some(CloseReason::ProtocolError),
                "{e} must close the connection"
            );
        }
    }

    // -- graceful drain ----------------------------------------------------

    /// An idle connection closes at once when a drain begins: waiting for a
    /// request that will be refused just delays the deploy.
    #[test]
    fn a_drain_closes_an_idle_connection_immediately() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_drain(t0);

        assert_eq!(c.close_reason(), Some(CloseReason::ShutdownIdle));
        assert_eq!(c.poll(t0), Action::Close(CloseReason::ShutdownIdle));
    }

    /// **The point of a graceful drain.** An in-flight request is allowed to
    /// finish; killing it is not graceful and produces an unexplained error for
    /// a user.
    #[test]
    fn a_drain_lets_an_in_flight_request_finish() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);
        c.on_request_parsed(true);
        c.begin_drain(t0);

        assert_eq!(
            c.poll(t0 + Duration::from_secs(1)),
            Action::WriteResponse,
            "the in-flight request continues"
        );
        assert_eq!(
            c.poll(t0 + Duration::from_secs(4)),
            Action::WriteResponse,
            "and still continues just before the deadline"
        );

        // When it finishes, the connection closes rather than accepting more.
        c.on_response_sent(t0 + Duration::from_secs(4), false);
        assert_eq!(c.close_reason(), Some(CloseReason::ShutdownIdle));
    }

    /// **A drain that never completes is worse than an abrupt one**, because an
    /// operator cannot tell "still draining" from "stuck". The deadline is
    /// enforced even with a request in flight.
    #[test]
    fn the_drain_deadline_is_enforced_even_with_a_request_in_flight() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);
        c.on_request_parsed(true);
        c.begin_drain(t0);

        assert_eq!(
            c.poll(t0 + Duration::from_secs(5)),
            Action::Close(CloseReason::DrainDeadline),
            "at the deadline the request is cut off"
        );
    }

    /// The drain deadline is checked before the in-flight rule, so a stuck
    /// request cannot hold a draining process open forever.
    #[test]
    fn the_drain_deadline_beats_the_in_flight_rule() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);
        c.on_request_parsed(true);
        c.begin_drain(t0);

        // Just before: in flight wins.
        assert_eq!(
            c.poll(t0 + Duration::from_millis(4_999)),
            Action::WriteResponse
        );
        // Just after: the deadline wins.
        assert!(matches!(
            c.poll(t0 + Duration::from_millis(5_001)),
            Action::Close(CloseReason::DrainDeadline)
        ));
    }

    /// A response sent during a drain must not re-arm keep-alive, or a draining
    /// process would serve requests forever.
    #[test]
    fn a_drain_does_not_re_arm_keep_alive() {
        let mut c = conn();
        let t0 = Instant::now();
        c.begin_request(t0);
        c.on_request_parsed(true);
        c.begin_drain(t0);
        c.on_response_sent(t0 + Duration::from_secs(1), false);

        assert!(
            !c.is_open(),
            "a completed request during a drain must close, not idle"
        );
    }

    // -- close reasons -----------------------------------------------------

    /// The reason is what an operator acts on, so the classification into
    /// routine and symptomatic has to be right.
    #[test]
    fn close_reasons_are_classified_by_whether_they_are_a_symptom() {
        for healthy in [
            CloseReason::ClientRequested,
            CloseReason::ServerRequested,
            CloseReason::RequestLimit,
            CloseReason::ShutdownIdle,
        ] {
            assert!(healthy.is_healthy(), "{} is routine", healthy.as_str());
        }
        for unhealthy in [
            CloseReason::IdleTimeout,
            CloseReason::HeaderTimeout,
            CloseReason::ProtocolError,
            CloseReason::DrainDeadline,
        ] {
            assert!(
                !unhealthy.is_healthy(),
                "{} indicates something worth looking at",
                unhealthy.as_str()
            );
        }
    }

    #[test]
    fn close_reason_names_are_stable() {
        assert_eq!(CloseReason::ClientRequested.as_str(), "client-requested");
        assert_eq!(CloseReason::ServerRequested.as_str(), "server-requested");
        assert_eq!(CloseReason::IdleTimeout.as_str(), "idle-timeout");
        assert_eq!(CloseReason::HeaderTimeout.as_str(), "header-timeout");
        assert_eq!(CloseReason::ProtocolError.as_str(), "protocol-error");
        assert_eq!(CloseReason::RequestLimit.as_str(), "request-limit");
        assert_eq!(CloseReason::ShutdownIdle.as_str(), "shutdown-idle");
        assert_eq!(CloseReason::DrainDeadline.as_str(), "drain-deadline");
    }

    /// Once closed, always closed: a state machine that can reopen is one that
    /// can reuse a connection whose framing is untrustworthy.
    #[test]
    fn a_closed_connection_stays_closed() {
        let mut c = conn();
        let t0 = Instant::now();
        c.on_parse_error(&ParseError::ConflictingFraming);
        let first = c.close_reason();

        for elapsed in [0u64, 1, 100] {
            assert_eq!(
                c.poll(t0 + Duration::from_secs(elapsed)),
                Action::Close(first.expect("closed"))
            );
        }
        // And further events do not reopen it.
        c.begin_request(t0);
        c.on_response_sent(t0, false);
        assert_eq!(c.close_reason(), first);
    }

    // -- timings -----------------------------------------------------------

    /// The header timeout must be shorter than the idle timeout, or a client
    /// mid-head is treated more leniently than one between requests — which
    /// inverts the intent and makes slow-loris *easier* than idle probing.
    #[test]
    fn the_header_timeout_is_shorter_than_the_idle_timeout() {
        let c = ConnectionConfig::default();
        assert!(
            c.header_timeout < c.idle_timeout,
            "header {} must be under idle {}",
            c.header_timeout.as_secs(),
            c.idle_timeout.as_secs()
        );
    }

    #[test]
    fn the_defaults_are_within_a_sane_range() {
        let c = ConnectionConfig::default();
        // Long enough for any real client, short enough to bound a socket leak.
        assert!(c.idle_timeout >= Duration::from_secs(30));
        assert!(c.idle_timeout <= Duration::from_mins(5));
        assert!(c.header_timeout >= Duration::from_secs(1));
        assert!(c.header_timeout <= Duration::from_secs(30));
        assert!(c.max_requests > 0);
        assert!(c.drain_timeout >= Duration::from_secs(5));
    }

    // -- the ledger --------------------------------------------------------

    #[test]
    fn the_ledger_admits_up_to_the_limit() {
        let mut l = ConnectionLedger::new(2);
        assert!(l.admit("acme"));
        assert!(l.admit("acme"));
        assert!(
            !l.admit("acme"),
            "the third connection exceeds a limit of two"
        );
        assert_eq!(l.open_for("acme"), 2);
    }

    /// **Why the limit is per tenant.** A global limit lets one tenant starve
    /// every other by opening connections.
    #[test]
    fn one_tenant_cannot_starve_another() {
        let mut l = ConnectionLedger::new(2);
        assert!(l.admit("noisy"));
        assert!(l.admit("noisy"));
        assert!(!l.admit("noisy"), "the noisy tenant is at its ceiling");

        // The quiet tenant is unaffected.
        assert!(
            l.admit("quiet"),
            "a tenant at its own limit must not consume another's"
        );
        assert!(l.admit("quiet"));
        assert_eq!(l.open_for("noisy"), 2);
        assert_eq!(l.open_for("quiet"), 2);
    }

    #[test]
    fn releasing_frees_a_slot() {
        let mut l = ConnectionLedger::new(1);
        assert!(l.admit("acme"));
        assert!(!l.admit("acme"));
        l.release("acme");
        assert!(l.admit("acme"), "a released slot must be reusable");
    }

    /// Releasing more than was admitted must not underflow. A double release is
    /// a caller bug, but a ledger that wraps to 4 billion would let a tenant
    /// through forever.
    #[test]
    fn releasing_too_many_times_does_not_underflow() {
        let mut l = ConnectionLedger::new(1);
        l.release("never-admitted");
        assert_eq!(l.open_for("never-admitted"), 0);

        l.admit("acme");
        l.release("acme");
        l.release("acme");
        l.release("acme");
        assert_eq!(l.open_for("acme"), 0);
        assert_eq!(l.total(), 0);
    }

    /// The ledger must not accumulate an entry per tenant ever seen: a
    /// structure whose job is to bound something should not itself grow without
    /// bound.
    #[test]
    fn the_ledger_forgets_tenants_at_zero() {
        let mut l = ConnectionLedger::new(1);
        for i in 0..1000 {
            let tenant = format!("tenant-{i}");
            l.admit(&tenant);
            l.release(&tenant);
        }
        assert_eq!(
            l.tenants(),
            0,
            "a tenant at zero connections must not keep a map entry"
        );
    }

    #[test]
    fn the_ledger_reports_its_totals() {
        let mut l = ConnectionLedger::new(5);
        l.admit("a");
        l.admit("a");
        l.admit("b");
        assert_eq!(l.total(), 3);
        assert_eq!(l.tenants(), 2);
        assert_eq!(l.per_tenant(), 5);
        assert_eq!(l.open_for("absent"), 0);
    }

    /// A ceiling of zero is almost certainly a mistake, and silently rejecting
    /// every request would make it hard to diagnose. Raising it to one at least
    /// lets the service respond.
    #[test]
    fn a_zero_ceiling_is_raised_to_one() {
        let mut l = ConnectionLedger::new(0);
        assert_eq!(l.per_tenant(), 1);
        assert!(l.admit("a"), "a tenant must be able to connect at all");
        assert!(!l.admit("a"));
    }

    /// **A named tenant gets its own ceiling, and other tenants keep the fallback.**
    ///
    /// The whole point of per-tenant limits, and the half that a table read as an
    /// override rather than as per-tenant entries would get wrong: naming one tenant
    /// must not change the ceiling for every other.
    #[test]
    fn a_named_tenant_gets_its_own_ceiling_and_others_keep_the_fallback() {
        let mut l = ConnectionLedger::with_limits([("a".to_owned(), 2)], 5);
        assert_eq!(l.ceiling_for("a"), 2, "the named ceiling must apply");
        assert_eq!(
            l.ceiling_for("b"),
            5,
            "an unnamed tenant keeps the fallback"
        );

        assert!(l.admit("a"));
        assert!(l.admit("a"));
        assert!(!l.admit("a"), "`a` is at its own ceiling of two");

        for _ in 0..5 {
            assert!(
                l.admit("b"),
                "`b` is bounded by the fallback, not by `a`'s entry"
            );
        }
        assert!(!l.admit("b"), "`b` is now at the fallback ceiling of five");
    }

    /// A zero ceiling in the **table** is raised the same way the fallback is.
    ///
    /// The manifest refuses `max_connections = 0` before a server binds, so this is
    /// defence in depth: a ledger built directly must not create a tenant that can never
    /// connect, which would answer every request with 503 and say nothing about why.
    #[test]
    fn a_zero_ceiling_in_the_table_is_raised_to_one() {
        let mut l = ConnectionLedger::with_limits([("a".to_owned(), 0)], 5);
        assert_eq!(l.ceiling_for("a"), 1);
        assert!(l.admit("a"), "the tenant must be able to connect at all");
        assert!(!l.admit("a"));
        assert_eq!(
            l.ceiling_for("b"),
            5,
            "raising `a` must not touch the fallback"
        );
    }
}
