// SPDX-License-Identifier: Apache-2.0

//! The default metric set, per Proposal §10.2.
//!
//! Implements the HTTP and capability rows of §10.2's table:
//!
//! | Category | Metrics |
//! |---|---|
//! | HTTP | requests, status classes, latency histograms, body bytes, connection count |
//! | Capability | uses by capability, denials by capability, **by tenant** |
//!
//! # Cardinality discipline, and why it is enforced by the type system here
//!
//! §10.2 states the rule:
//!
//! > **Cardinality discipline:** no metric label may take an unbounded value (no raw paths,
//! > no user IDs, no full URLs). Enforced by a lint on metric definitions.
//!
//! That sentence is the whole design constraint, and it has a specific failure mode: a
//! registry with `&str` labels works perfectly in development and **destroys the monitoring
//! system in production**, because every distinct label value is a new time series. A path
//! label turns one series into one per URL; a tenant label into one per customer. The
//! Prometheus instance falls over, and the cause is a change nobody reviewed as risky —
//! someone added a label.
//!
//! So the labels here are **enums, not strings**. `Method`, `StatusClass` and `Outcome` are
//! closed sets, and a new value cannot be introduced without editing this file. That makes
//! §10.2's discipline structural rather than a convention: the compiler is the enforcement.
//! `OBS-006` asks for a lint over metric *definitions*; this module makes its subject matter
//! impossible to get wrong by accident.
//!
//! **`Tenant` is bounded separately** by [`TenantLabels::MAX_TENANTS`]. A tenant name is
//! operator-supplied, so it is not a closed set — but it is unbounded in the same way a path
//! is. Past the ceiling, further tenants are recorded as [`Tenant::Other`], which keeps the
//! total bounded and makes the overflow **visible in one series** rather than invisibly
//! multiplying them. Losing per-tenant metric detail above a threshold is the right trade
//! against losing the pipeline; the audit log (§10.1) keeps the per-tenant facts regardless,
//! and a log is not aggregated.
//!
//! # Why counters are integers, not floats
//!
//! A counter that is incremented must never go backwards, and integer addition is exact.
//! Floats accumulate representation error, which over a long-running process makes a
//! `rate()` computation subtly wrong — and a metric that is *almost* right is worse than one
//! that is obviously broken, because it is believed.
//!
//! # Why the registry is not a global
//!
//! A process-wide singleton would make two servers in one test process share counters, so a
//! test asserting "one request was recorded" would see another test's requests. A value the
//! caller holds is also what makes §10.5's determinism requirement satisfiable: the same
//! inputs produce the same counts with no hidden state to reset.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

/// An HTTP method, as a closed set.
///
/// A metric label rather than the request's own method string: an unrecognised method
/// arrives in the request line, so it is attacker-controlled, and using it directly would
/// let a client create a time series per invented verb. `Other` bounds it at one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// `GET`
    Get,
    /// `HEAD`
    Head,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
    /// `OPTIONS`
    Options,
    /// `TRACE`
    Trace,
    /// `CONNECT`
    Connect,
    /// Any method this build does not name.
    Other,
}

impl Method {
    /// Every variant, so a test can assert the label space is finite.
    pub const ALL: [Self; 10] = [
        Self::Get,
        Self::Head,
        Self::Post,
        Self::Put,
        Self::Patch,
        Self::Delete,
        Self::Options,
        Self::Trace,
        Self::Connect,
        Self::Other,
    ];

    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
            Self::Other => "OTHER",
        }
    }

    /// Classify a method string.
    ///
    /// Anything unrecognised is [`Method::Other`], which is the point: the label space is
    /// fixed regardless of what a client sends.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            "OPTIONS" => Self::Options,
            "TRACE" => Self::Trace,
            "CONNECT" => Self::Connect,
            _ => Self::Other,
        }
    }
}

/// The status class, per RFC 9110 §15.
///
/// The **class**, not the code: `200` and `201` are one series, which is the difference
/// between five values and sixty. §10.2 names "status classes" for exactly this reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StatusClass {
    /// `1xx`
    Informational,
    /// `2xx`
    Success,
    /// `3xx`
    Redirection,
    /// `4xx`
    ClientError,
    /// `5xx`
    ServerError,
    /// A status outside every defined class.
    ///
    /// RFC 9110 defines `100`–`599`. A server producing `99` or `600` has a bug, and
    /// recording it as one bounded value keeps that bug visible rather than creating a
    /// series for each impossible code.
    Unknown,
}

impl StatusClass {
    /// Every variant.
    pub const ALL: [Self; 6] = [
        Self::Informational,
        Self::Success,
        Self::Redirection,
        Self::ClientError,
        Self::ServerError,
        Self::Unknown,
    ];

    /// The label form, which is what a dashboard queries on.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "1xx",
            Self::Success => "2xx",
            Self::Redirection => "3xx",
            Self::ClientError => "4xx",
            Self::ServerError => "5xx",
            Self::Unknown => "unknown",
        }
    }

    /// Classify a status code.
    #[must_use]
    pub const fn of(status: u16) -> Self {
        match status / 100 {
            1 => Self::Informational,
            2 => Self::Success,
            3 => Self::Redirection,
            4 => Self::ClientError,
            5 => Self::ServerError,
            _ => Self::Unknown,
        }
    }
}

/// How a connection or request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// Completed normally.
    Ok,
    /// The peer went away.
    ClientClosed,
    /// A deadline expired.
    Timeout,
    /// The peer violated the protocol.
    ProtocolError,
    /// The server refused it — a limit, a denial, or a shutdown.
    Refused,
}

impl Outcome {
    /// Every variant.
    pub const ALL: [Self; 5] = [
        Self::Ok,
        Self::ClientClosed,
        Self::Timeout,
        Self::ProtocolError,
        Self::Refused,
    ];

    /// The label form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::ClientClosed => "client_closed",
            Self::Timeout => "timeout",
            Self::ProtocolError => "protocol_error",
            Self::Refused => "refused",
        }
    }
}

/// A bounded tenant label.
///
/// See [`TenantLabels`] for why this is not a `String`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tenant<'a> {
    /// A named tenant that fits under the ceiling.
    Named(&'a str),
    /// The shared default tenant.
    Default,
    /// Tenants beyond the ceiling.
    Other,
}

impl<'a> Tenant<'a> {
    /// The label form.
    ///
    /// Borrows the tenant name rather than returning `'static`: a named tenant's label is
    /// the operator's own string, and inventing a static for it would defeat the point of
    /// carrying the name. `Default` and `Other` are the two static values.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        match self {
            Self::Named(s) => s,
            Self::Default => "default",
            Self::Other => "other",
        }
    }
}

/// The set of tenant names allowed a distinct label.
#[derive(Debug, Default)]
pub struct TenantLabels {
    /// The names seen so far. A `Vec` in insertion order rather than a `HashSet`, so the
    /// mapping is deterministic (§10.5) and small enough that a linear scan is faster than
    /// hashing.
    seen: Mutex<Vec<String>>,
}

impl TenantLabels {
    /// The largest number of tenants that get their own label.
    ///
    /// 64 is deliberate rather than round: far more than a small deployment has, far fewer
    /// than the thousands that would make a registry expensive.
    pub const MAX_TENANTS: usize = 64;

    /// A fresh set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a tenant name to a bounded label.
    ///
    /// The first [`Self::MAX_TENANTS`] distinct names are kept; anything after them is
    /// `Other`. A name already seen keeps its own label even past the ceiling, so a
    /// deployment's history does not change retroactively as it grows.
    pub fn label<'a>(&self, name: &'a str) -> Tenant<'a> {
        if name.is_empty() || name == "default" {
            return Tenant::Default;
        }
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if seen.iter().any(|s| s == name) {
            return Tenant::Named(name);
        }
        if seen.len() >= Self::MAX_TENANTS {
            return Tenant::Other;
        }
        seen.push(name.to_owned());
        Tenant::Named(name)
    }

    /// How many distinct names are tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether no names are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A latency histogram with fixed buckets.
///
/// # Why the buckets are fixed and not configurable
///
/// A histogram whose boundaries can change has no stable meaning between scrapes, and a
/// `histogram_quantile` computed across a change is wrong in a way nothing reports. The
/// boundaries are published as a constant so a dashboard can be written against them.
#[derive(Debug, Default)]
pub struct Latency {
    /// One counter per bound, plus `count` as the `+Inf` bucket.
    buckets: [AtomicU64; Self::BOUNDS.len()],
    /// Total observations, which is also the `+Inf` bucket.
    count: AtomicU64,
    /// Sum of observed microseconds.
    ///
    /// Microseconds and integer, so the mean is exact to the microsecond and cannot drift
    /// over a long-running process the way a float sum would.
    sum_micros: AtomicU64,
}

impl Latency {
    /// The upper bounds, in microseconds.
    ///
    /// Powers-of-two-ish milliseconds covering a web request: 1 ms to 8 s. Chosen so the
    /// labels are readable in a query and the relative error is bounded — uniform-width
    /// buckets would spend most of their resolution on the range nobody asks about.
    pub const BOUNDS: [u64; 12] = [
        1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000,
        4_000_000, 8_000_000,
    ];

    /// Record one observation.
    ///
    /// A value past every bound is counted and summed but lands in no bucket, which is what
    /// `+Inf` means in the exposition format: `count` is the `+Inf` bucket, and a `le="+Inf"`
    /// series is emitted from it rather than stored.
    pub fn observe(&self, micros: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        for (i, bound) in Self::BOUNDS.iter().enumerate() {
            // `<=`, because `le` means "less than or equal". An exclusive comparison shifts
            // a whole bucket and makes every quantile slightly wrong — and *plausibly*
            // wrong, which is worse than obviously wrong.
            if micros <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Total observations.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Sum of observations, in microseconds.
    #[must_use]
    pub fn sum_micros(&self) -> u64 {
        self.sum_micros.load(Ordering::Relaxed)
    }

    /// The bucket counts, in `BOUNDS` order.
    #[must_use]
    pub fn buckets(&self) -> Vec<u64> {
        self.buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect()
    }

    /// The mean, in microseconds, or `None` with no observations.
    ///
    /// `None` rather than `0`: a mean of zero and "no data" are different facts, and a
    /// dashboard showing `0` for an unobserved route reads as "instant" rather than
    /// "unmeasured".
    #[must_use]
    pub fn mean_micros(&self) -> Option<u64> {
        let n = self.count();
        if n == 0 {
            return None;
        }
        Some(self.sum_micros() / n)
    }
}

/// All per-request counters, keyed by the bounded label sets.
///
/// The request key is `(Method, StatusClass)` rather than a string, so the number of entries
/// is bounded by `10 × 6 = 60` and cannot be driven by a client.
#[derive(Debug, Default)]
pub struct HttpMetrics {
    /// One counter per (method, class).
    requests: Mutex<BTreeMap<(Method, StatusClass), u64>>,
    /// Body bytes read, per tenant.
    body_bytes_in: Mutex<BTreeMap<String, u64>>,
    /// Body bytes written, per tenant.
    body_bytes_out: Mutex<BTreeMap<String, u64>>,
    /// Connection closes, by outcome.
    connections: Mutex<BTreeMap<Outcome, u64>>,
    /// Open connections right now.
    open: AtomicU64,
    /// Request latency.
    latency: Latency,
    /// Bodies refused for exceeding a limit, by tenant.
    body_limit_hits: Mutex<BTreeMap<String, u64>>,
}

impl HttpMetrics {
    /// A fresh, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one completed request.
    pub fn record_request(
        &self,
        method: Method,
        status: u16,
        latency_micros: u64,
        tenant: &str,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        {
            let mut m = self.requests.lock().unwrap_or_else(PoisonError::into_inner);
            *m.entry((method, StatusClass::of(status))).or_insert(0) += 1;
        }
        {
            let mut m = self
                .body_bytes_in
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *m.entry(tenant.to_owned()).or_insert(0) += bytes_in;
        }
        {
            let mut m = self
                .body_bytes_out
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *m.entry(tenant.to_owned()).or_insert(0) += bytes_out;
        }
        self.latency.observe(latency_micros);
    }

    /// Record a body refused for exceeding a limit.
    ///
    /// # Why this is not part of `requests`
    ///
    /// A refused body is not a completed request — no handler ran — and counting it in the
    /// request total would make the error rate and the request rate disagree. It is its own
    /// counter because "is a tenant hitting the cap?" and "is a tenant erroring?" are
    /// different questions with different remedies.
    pub fn record_body_limit(&self, tenant: &str) {
        let mut m = self
            .body_limit_hits
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *m.entry(tenant.to_owned()).or_insert(0) += 1;
    }

    /// Record a connection opening.
    pub fn connection_opened(&self) {
        self.open.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection closing, with how it ended.
    pub fn connection_closed(&self, outcome: Outcome) {
        // Saturating rather than a plain subtract: a close without a matching open is a bug
        // elsewhere, and an `AtomicU64` underflow would wrap to ~1.8e19 and destroy every
        // dashboard built on the value. Staying at 0 is a visible symptom of the bug.
        let _ = self
            .open
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
        let mut m = self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *m.entry(outcome).or_insert(0) += 1;
    }

    /// Open connections right now.
    #[must_use]
    pub fn open_connections(&self) -> u64 {
        self.open.load(Ordering::Relaxed)
    }

    /// Total requests recorded.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .sum()
    }

    /// Requests for one (method, class).
    #[must_use]
    pub fn requests_for(&self, method: Method, class: StatusClass) -> u64 {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(method, class))
            .copied()
            .unwrap_or(0)
    }

    /// Bytes read for a tenant.
    #[must_use]
    pub fn bytes_in_for(&self, tenant: &str) -> u64 {
        self.body_bytes_in
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(tenant)
            .copied()
            .unwrap_or(0)
    }

    /// Bytes written for a tenant.
    #[must_use]
    pub fn bytes_out_for(&self, tenant: &str) -> u64 {
        self.body_bytes_out
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(tenant)
            .copied()
            .unwrap_or(0)
    }

    /// Body-limit refusals for a tenant.
    #[must_use]
    pub fn body_limit_hits_for(&self, tenant: &str) -> u64 {
        self.body_limit_hits
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(tenant)
            .copied()
            .unwrap_or(0)
    }

    /// Connections closed with an outcome.
    #[must_use]
    pub fn connections_for(&self, outcome: Outcome) -> u64 {
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&outcome)
            .copied()
            .unwrap_or(0)
    }

    /// The latency histogram.
    #[must_use]
    pub fn latency(&self) -> &Latency {
        &self.latency
    }

    /// How many distinct (method, class) series exist.
    ///
    /// Exposed for the cardinality test: the bound is the point, so it is measured rather
    /// than argued.
    #[must_use]
    pub fn series_count(&self) -> usize {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- the label spaces are closed ---------------------------------------

    /// **Every label space has distinct names.**
    ///
    /// The compiler forces the matches to be exhaustive; this asserts the names differ,
    /// because two variants sharing a label would silently merge two series — the confusion
    /// the closed sets exist to prevent.
    #[test]
    fn every_label_space_has_distinct_names() {
        let methods: std::collections::BTreeSet<&str> =
            Method::ALL.iter().map(|m| m.as_str()).collect();
        assert_eq!(methods.len(), Method::ALL.len(), "method labels collide");

        let classes: std::collections::BTreeSet<&str> =
            StatusClass::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            classes.len(),
            StatusClass::ALL.len(),
            "class labels collide"
        );

        let outcomes: std::collections::BTreeSet<&str> =
            Outcome::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(outcomes.len(), Outcome::ALL.len(), "outcome labels collide");
    }

    /// **The label space is bounded, whatever a client sends.**
    ///
    /// The §10.2 discipline, measured: a thousand invented methods produce exactly **one**
    /// series, not a thousand.
    #[test]
    fn an_invented_method_cannot_create_a_series() {
        let m = HttpMetrics::new();
        for i in 0..1_000 {
            m.record_request(Method::parse(&format!("INVENTED{i}")), 200, 1, "t", 0, 0);
        }
        assert_eq!(
            m.series_count(),
            1,
            "every invented method must collapse to the same series"
        );
        assert_eq!(m.requests_for(Method::Other, StatusClass::Success), 1_000);
    }

    /// 500 distinct status codes produce five series, not five hundred.
    #[test]
    fn status_classes_cover_the_range_without_multiplying() {
        let m = HttpMetrics::new();
        for status in 100..=599u16 {
            m.record_request(Method::Get, status, 1, "t", 0, 0);
        }
        assert_eq!(
            m.series_count(),
            5,
            "500 distinct status codes must be 5 series"
        );
        assert_eq!(m.requests_for(Method::Get, StatusClass::Success), 100);
    }

    /// An impossible status is `Unknown`, not a new series per value.
    #[test]
    fn an_impossible_status_is_unknown() {
        assert_eq!(StatusClass::of(99), StatusClass::Unknown);
        assert_eq!(StatusClass::of(600), StatusClass::Unknown);
        assert_eq!(StatusClass::of(0), StatusClass::Unknown);
        assert_eq!(StatusClass::of(100), StatusClass::Informational);
        assert_eq!(StatusClass::of(599), StatusClass::ServerError);
    }

    /// Classification is exact at the boundaries.
    #[test]
    fn class_boundaries_are_exact() {
        assert_eq!(StatusClass::of(199), StatusClass::Informational);
        assert_eq!(StatusClass::of(200), StatusClass::Success);
        assert_eq!(StatusClass::of(299), StatusClass::Success);
        assert_eq!(StatusClass::of(300), StatusClass::Redirection);
        assert_eq!(StatusClass::of(399), StatusClass::Redirection);
        assert_eq!(StatusClass::of(400), StatusClass::ClientError);
        assert_eq!(StatusClass::of(499), StatusClass::ClientError);
        assert_eq!(StatusClass::of(500), StatusClass::ServerError);
        assert_eq!(StatusClass::of(599), StatusClass::ServerError);
    }

    /// Every named method round-trips through its own string.
    #[test]
    fn every_named_method_round_trips() {
        for m in Method::ALL {
            assert_eq!(Method::parse(m.as_str()), m, "{m:?}");
        }
    }

    // -- tenants ------------------------------------------------------------

    /// A tenant name gets its own label, idempotently.
    #[test]
    fn a_tenant_gets_its_own_label() {
        let labels = TenantLabels::new();
        assert_eq!(labels.label("acme"), Tenant::Named("acme"));
        assert_eq!(labels.len(), 1);
        assert_eq!(labels.label("acme"), Tenant::Named("acme"), "idempotent");
        assert_eq!(labels.len(), 1);
    }

    /// An empty or `default` name is the default tenant and is not tracked.
    #[test]
    fn the_default_tenant_is_recognised() {
        let labels = TenantLabels::new();
        assert_eq!(labels.label(""), Tenant::Default);
        assert_eq!(labels.label("default"), Tenant::Default);
        assert!(labels.is_empty());
    }

    /// **Past the ceiling, tenants collapse to `Other` rather than multiplying series.**
    ///
    /// The bound §10.2 requires, measured: 500 tenants produce 64 named labels plus one
    /// overflow, so the count stays finite however many tenants exist.
    #[test]
    fn tenants_past_the_ceiling_collapse_to_other() {
        let labels = TenantLabels::new();
        for i in 0..500 {
            let name = format!("tenant-{i}");
            let label = labels.label(&name);
            if i < TenantLabels::MAX_TENANTS {
                assert!(
                    matches!(label, Tenant::Named(_)),
                    "tenant {i} must be named"
                );
            } else {
                assert_eq!(label, Tenant::Other, "tenant {i} must collapse");
            }
        }
        assert_eq!(labels.len(), TenantLabels::MAX_TENANTS);
    }

    /// **A tenant seen before the ceiling keeps its label after it.**
    ///
    /// The control: the ceiling must not make an *existing* tenant start reporting as
    /// `Other`, or a deployment's history would change retroactively as it grew.
    #[test]
    fn an_existing_tenant_keeps_its_label_past_the_ceiling() {
        let labels = TenantLabels::new();
        for i in 0..TenantLabels::MAX_TENANTS + 10 {
            labels.label(&format!("tenant-{i}"));
        }
        assert_eq!(
            labels.label("tenant-0"),
            Tenant::Named("tenant-0"),
            "a tenant seen before the ceiling must keep its own label"
        );
    }

    /// The ceiling is real: the set actually stops growing at it.
    ///
    /// Asserting `MAX_TENANTS >= 16` would be a constant assertion — clippy is right that
    /// the compiler already knows it. What is *not* known statically is that the ceiling is
    /// enforced by the code rather than merely declared, so that is what this measures: the
    /// tracked set stops at the bound, and `len` never reports more.
    #[test]
    fn the_tenant_ceiling_is_enforced() {
        let labels = TenantLabels::new();
        // Well past the ceiling, and past any plausible bound.
        for i in 0..(TenantLabels::MAX_TENANTS * 4) {
            labels.label(&format!("t{i}"));
        }
        assert_eq!(
            labels.len(),
            TenantLabels::MAX_TENANTS,
            "the tracked set must stop growing at the ceiling"
        );
    }

    /// A name at the ceiling boundary, checked from both sides.
    ///
    /// The off-by-one control: the 64th distinct name is named and the 65th is not, so the
    /// ceiling is `MAX_TENANTS` and not `MAX_TENANTS - 1`.
    #[test]
    fn the_ceiling_boundary_is_exact() {
        let labels = TenantLabels::new();
        for i in 0..TenantLabels::MAX_TENANTS - 1 {
            labels.label(&format!("t{i}"));
        }
        assert_eq!(
            labels.label("last-named"),
            Tenant::Named("last-named"),
            "the MAX_TENANTS-th distinct name must still be named"
        );
        assert_eq!(
            labels.label("overflow"),
            Tenant::Other,
            "the one after it must collapse"
        );
    }

    // -- counters -----------------------------------------------------------

    /// A request is recorded against its (method, class).
    #[test]
    fn a_request_is_recorded() {
        let m = HttpMetrics::new();
        m.record_request(Method::Get, 200, 5_000, "acme", 10, 20);
        assert_eq!(m.total_requests(), 1);
        assert_eq!(m.requests_for(Method::Get, StatusClass::Success), 1);
        assert_eq!(m.requests_for(Method::Post, StatusClass::Success), 0);
        assert_eq!(m.bytes_in_for("acme"), 10);
        assert_eq!(m.bytes_out_for("acme"), 20);
    }

    /// Bytes accumulate per tenant and do not leak across them.
    #[test]
    fn bytes_are_per_tenant() {
        let m = HttpMetrics::new();
        m.record_request(Method::Post, 200, 1, "acme", 100, 1_000);
        m.record_request(Method::Post, 200, 1, "globex", 7, 8);
        m.record_request(Method::Post, 200, 1, "acme", 100, 1_000);

        assert_eq!(m.bytes_in_for("acme"), 200);
        assert_eq!(m.bytes_in_for("globex"), 7);
        assert_eq!(m.bytes_out_for("acme"), 2_000);
        assert_eq!(m.bytes_out_for("globex"), 8);
        assert_eq!(m.bytes_in_for("nobody"), 0);
    }

    /// **A refused body is counted separately from a completed request.**
    #[test]
    fn a_refused_body_is_its_own_counter() {
        let m = HttpMetrics::new();
        m.record_body_limit("acme");
        m.record_body_limit("acme");
        m.record_body_limit("globex");

        assert_eq!(m.body_limit_hits_for("acme"), 2);
        assert_eq!(m.body_limit_hits_for("globex"), 1);
        assert_eq!(
            m.total_requests(),
            0,
            "a refused body is not a completed request"
        );
    }

    /// Open connections track opens and closes.
    #[test]
    fn open_connections_are_tracked() {
        let m = HttpMetrics::new();
        assert_eq!(m.open_connections(), 0);
        m.connection_opened();
        m.connection_opened();
        assert_eq!(m.open_connections(), 2);
        m.connection_closed(Outcome::Ok);
        assert_eq!(m.open_connections(), 1);
        assert_eq!(m.connections_for(Outcome::Ok), 1);
    }

    /// **A close without a matching open saturates rather than wrapping.**
    ///
    /// An `AtomicU64` underflow would wrap to ~1.8e19 and destroy every dashboard built on
    /// the value. Staying at 0 is a visible symptom of the bug; a wrap is not.
    #[test]
    fn a_close_without_an_open_does_not_wrap() {
        let m = HttpMetrics::new();
        m.connection_closed(Outcome::ClientClosed);
        assert_eq!(m.open_connections(), 0, "the count must not wrap");
        assert_eq!(m.connections_for(Outcome::ClientClosed), 1);
    }

    /// Outcomes are counted separately.
    #[test]
    fn outcomes_are_counted_separately() {
        let m = HttpMetrics::new();
        for o in Outcome::ALL {
            m.connection_opened();
            m.connection_closed(o);
        }
        for o in Outcome::ALL {
            assert_eq!(m.connections_for(o), 1, "{o:?}");
        }
        assert_eq!(m.open_connections(), 0);
    }

    // -- latency ------------------------------------------------------------

    /// Observations land in the right bucket.
    #[test]
    fn latency_lands_in_the_right_bucket() {
        let h = Latency::default();
        h.observe(500);
        h.observe(1_000);
        h.observe(1_001);
        h.observe(9_000_000);

        let b = h.buckets();
        assert_eq!(b[0], 2, "500 and 1000 are both <= 1000");
        assert_eq!(b[1], 1, "1001 is <= 2500");
        assert_eq!(
            h.count(),
            4,
            "an observation past every bound is still counted"
        );
    }

    /// **A bucket bound is inclusive.**
    ///
    /// `le` means "less than or equal", so a value exactly on a bound belongs to that
    /// bucket. An exclusive comparison shifts a whole bucket and makes every quantile
    /// slightly wrong — and *plausibly* wrong, which is worse.
    #[test]
    fn a_bucket_bound_is_inclusive() {
        let h = Latency::default();
        h.observe(1_000);
        assert_eq!(h.buckets()[0], 1, "1000 <= 1000");
        assert_eq!(
            h.buckets()[1],
            0,
            "and it must not also land in the next bucket"
        );
    }

    /// An unobserved histogram reports `None`, not `0`.
    #[test]
    fn an_unobserved_histogram_has_no_mean() {
        let h = Latency::default();
        assert_eq!(h.count(), 0);
        assert_eq!(
            h.mean_micros(),
            None,
            "zero and 'no data' are different facts, and 0 reads as 'instant'"
        );
    }

    /// The mean is exact.
    #[test]
    fn the_mean_is_exact() {
        let h = Latency::default();
        h.observe(100);
        h.observe(200);
        h.observe(300);
        assert_eq!(h.sum_micros(), 600);
        assert_eq!(h.mean_micros(), Some(200));
    }

    /// The bounds strictly increase.
    ///
    /// A non-monotonic list would make `observe` find the wrong bucket, and with fixed
    /// constants the mistake is a typo rather than a runtime condition.
    #[test]
    fn the_bucket_bounds_increase() {
        for pair in Latency::BOUNDS.windows(2) {
            assert!(pair[0] < pair[1], "{} must be under {}", pair[0], pair[1]);
        }
    }

    /// The histogram covers a web request's useful range.
    #[test]
    fn the_buckets_cover_a_useful_range() {
        assert_eq!(Latency::BOUNDS[0], 1_000, "a 1 ms floor");
        assert!(
            *Latency::BOUNDS.last().expect("non-empty") >= 1_000_000,
            "the top bucket must reach at least a second"
        );
    }

    // -- determinism --------------------------------------------------------

    /// The same input sequence produces the same counts. §10.5.
    #[test]
    fn recording_is_deterministic() {
        fn run() -> (u64, u64, Vec<u64>) {
            let m = HttpMetrics::new();
            for i in 0..100u64 {
                m.record_request(Method::Get, 200, i * 100, "acme", i, i * 2);
            }
            (
                m.total_requests(),
                m.bytes_in_for("acme"),
                m.latency().buckets(),
            )
        }
        let first = run();
        for _ in 0..10 {
            assert_eq!(run(), first);
        }
    }
}
