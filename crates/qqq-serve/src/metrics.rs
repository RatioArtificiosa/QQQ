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

    /// Resolve a tenant name to a **bounded numeric key** — §10.2's cardinality discipline.
    ///
    /// # Why a number and not the name
    ///
    /// Because a `BTreeMap<String, _>` keyed by a name is *unbounded as a type*, and the bound is
    /// then a property of the constructor that no reader — and no lint — can check. Three maps in
    /// [`HttpMetrics`] were keyed that way, with values coming from `tenant_of`, which returns the
    /// **peer IP address**: an attacker chose the key, and `§O-306` records that
    /// `tools/check_metric_cardinality.py` is what found it.
    ///
    /// A `u16` in `0..=MAX_TENANTS + 1` is bounded by its own type, so the lint can prove it and a
    /// reviewer can see it. The name is still recoverable from [`Self::name_of`] for rendering.
    ///
    /// The mapping is the same one [`Self::label`] uses, and it is **stable for the life of the
    /// set**: a name already seen keeps its index even past the ceiling, so a series does not
    /// change identity as a deployment grows.
    ///
    /// # Example
    ///
    /// The key space is bounded by the type, and the past-the-ceiling bucket is shared:
    ///
    /// ```
    /// use qqq_serve::metrics::TenantLabels;
    ///
    /// let labels = TenantLabels::new();
    /// assert_eq!(labels.index("default"), 0, "the shared default is reserved, not allocated");
    /// assert_eq!(labels.index("acme"), 1);
    /// assert_eq!(labels.index("acme"), 1, "and the mapping is stable");
    /// assert_eq!(labels.index("globex"), 2);
    ///
    /// // Every index is inside a space the type bounds, which is the whole point.
    /// assert!(labels.index("anything at all") <= TenantLabels::MAX_TENANTS as u16 + 1);
    /// ```
    #[must_use]
    pub fn index(&self, name: &str) -> u16 {
        // 0 is the shared default, 1..=MAX_TENANTS are named, MAX_TENANTS + 1 is everything past
        // the ceiling. Reserved rather than allocated, so the space is bounded by construction.
        if name.is_empty() || name == "default" {
            return 0;
        }
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(i) = seen.iter().position(|s| s == name) {
            return u16::try_from(i).unwrap_or(u16::MAX).saturating_add(1);
        }
        if seen.len() >= Self::MAX_TENANTS {
            return u16::try_from(Self::MAX_TENANTS).unwrap_or(u16::MAX) + 1;
        }
        seen.push(name.to_owned());
        u16::try_from(seen.len()).unwrap_or(u16::MAX)
    }

    /// The name behind an [`Self::index`], for rendering a series back to something readable.
    ///
    /// `None` for the past-the-ceiling bucket, whose members deliberately share one label.
    ///
    /// # Example
    ///
    /// ```
    /// use qqq_serve::metrics::TenantLabels;
    ///
    /// let labels = TenantLabels::new();
    /// let acme = labels.index("acme");
    /// assert_eq!(labels.name_of(acme).as_deref(), Some("acme"));
    /// assert_eq!(labels.name_of(0).as_deref(), Some("default"));
    ///
    /// // An index past the ceiling names nobody, because its members share one label.
    /// let past = u16::try_from(TenantLabels::MAX_TENANTS).expect("the ceiling fits u16") + 1;
    /// assert_eq!(labels.name_of(past), None);
    /// ```
    #[must_use]
    pub fn name_of(&self, index: u16) -> Option<String> {
        if index == 0 {
            return Some("default".to_owned());
        }
        let seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let i = usize::from(index).checked_sub(1)?;
        seen.get(i).cloned()
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
    /// Resolves a tenant name to a bounded index. The three per-tenant maps below key on that
    /// index rather than on the name, which is what makes their size a property of the type.
    tenants: TenantLabels,
    /// Body bytes read, per tenant **index**.
    body_bytes_in: Mutex<BTreeMap<u16, u64>>,
    /// Body bytes written, per tenant **index**.
    body_bytes_out: Mutex<BTreeMap<u16, u64>>,
    /// Connection closes, by outcome.
    connections: Mutex<BTreeMap<Outcome, u64>>,
    /// Open connections right now.
    open: AtomicU64,
    /// Request latency.
    latency: Latency,
    /// Bodies refused for exceeding a limit, per tenant **index**.
    body_limit_hits: Mutex<BTreeMap<u16, u64>>,
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
            *m.entry(self.tenants.index(tenant)).or_insert(0) += bytes_in;
        }
        {
            let mut m = self
                .body_bytes_out
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *m.entry(self.tenants.index(tenant)).or_insert(0) += bytes_out;
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
        *m.entry(self.tenants.index(tenant)).or_insert(0) += 1;
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
            .get(&self.tenants.index(tenant))
            .copied()
            .unwrap_or(0)
    }

    /// Bytes written for a tenant.
    #[must_use]
    pub fn bytes_out_for(&self, tenant: &str) -> u64 {
        self.body_bytes_out
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&self.tenants.index(tenant))
            .copied()
            .unwrap_or(0)
    }

    /// Body-limit refusals for a tenant.
    #[must_use]
    pub fn body_limit_hits_for(&self, tenant: &str) -> u64 {
        self.body_limit_hits
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&self.tenants.index(tenant))
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
    /// The registry in the Prometheus text exposition format — `OBS-013`.
    ///
    /// # Why the renderer lives here and not in a script
    ///
    /// Because every number must come from the **same** source the recording path writes to, and a
    /// second derivation would be a second answer to one question — the defect this repository
    /// keeps recording. The label values are the bounded enums' own `as_str`, so the exposition
    /// inherits §10.2's cardinality discipline rather than restating it: **a series cannot appear
    /// here that the registry would refuse to hold.**
    ///
    /// # The three rules that are easy to get wrong
    ///
    /// 1. **Durations are seconds.** Prometheus' convention is `_seconds` and the registry counts
    ///    **microseconds**. Converting at the edge keeps the internal unit exact and the exported
    ///    one conventional; exporting micros under a `_seconds` name is a wrong number that looks
    ///    right.
    /// 2. **Histogram buckets are cumulative.** `le` means *less than or equal*, and
    ///    [`Latency::buckets`] returns **per-bucket** counts. Exporting those directly produces a
    ///    histogram that appears to decrease — which a server either rejects or, worse, accepts and
    ///    renders as nonsense.
    /// 3. **Label values are escaped.** A tenant name is operator-supplied and may contain a quote
    ///    or a backslash; unescaped it does not merely look wrong, it **forges a new label** in the
    ///    exposition. Same class as log injection, which §10.3's redaction exists to prevent in its
    ///    own domain.
    ///
    /// # What is deliberately absent
    ///
    /// **No `tenant` label on the request counters.** Their key is `(method, class)`, and adding a
    /// tenant dimension would multiply that space by the tenant ceiling for a question nobody
    /// asks. The per-tenant series are the byte and refusal counters, which are the ones §10.2's
    /// table names *"by tenant"*.
    ///
    /// A series with no observation is **omitted, not exported as zero**: absent means "not
    /// observed" and zero is a claim that it was.
    ///
    /// # Example
    ///
    /// ```
    /// use qqq_serve::metrics::{HttpMetrics, Method};
    ///
    /// let m = HttpMetrics::new();
    /// m.record_request(Method::Get, 200, 2_500_000, "acme", 10, 20);
    ///
    /// let text = m.render_prometheus();
    /// assert!(text.contains("qqq_http_requests_total{method=\"GET\",class=\"2xx\"} 1"));
    /// // Durations are SECONDS, and the registry counts microseconds.
    /// assert!(text.contains("qqq_http_request_duration_seconds_sum 2.500000"));
    /// // Every sample is a name, a value, and nothing else on the line.
    /// assert!(text.contains("qqq_http_request_body_bytes_total{tenant=\"acme\"} 10"));
    /// ```
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        write_request_counters(self, &mut out);
        write_latency_histogram(self, &mut out);
        write_connection_gauges(self, &mut out);
        write_tenant_counters(self, &mut out);
        out
    }
}

/// -- requests, by (method, class) -----------------------------------
fn write_request_counters(m: &HttpMetrics, out: &mut String) {
    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "# HELP qqq_http_requests_total Total HTTP requests, by method and status class."
    );
    let _ = writeln!(out, "# TYPE qqq_http_requests_total counter");
    for method in Method::ALL {
        for class in StatusClass::ALL {
            let n = m.requests_for(method, class);
            if n == 0 {
                continue;
            }
            let _ = writeln!(
                out,
                "qqq_http_requests_total{{method=\"{}\",class=\"{}\"}} {n}",
                prometheus_escape(method.as_str()),
                prometheus_escape(class.as_str())
            );
        }
    }
}

/// -- latency, a CUMULATIVE histogram in seconds ---------------------
fn write_latency_histogram(m: &HttpMetrics, out: &mut String) {
    use std::fmt::Write as _;
    let latency = m.latency();
    let _ = writeln!(
        out,
        "# HELP qqq_http_request_duration_seconds Request latency."
    );
    let _ = writeln!(out, "# TYPE qqq_http_request_duration_seconds histogram");
    let per_bucket = latency.buckets();
    let mut cumulative: u64 = 0;
    for (i, upper_micros) in Latency::BOUNDS.iter().enumerate() {
        cumulative += per_bucket.get(i).copied().unwrap_or(0);
        let _ = writeln!(
            out,
            "qqq_http_request_duration_seconds_bucket{{le=\"{}\"}} {cumulative}",
            micros_as_seconds(*upper_micros)
        );
    }
    // `+Inf` is every observation, which is the histogram's own count -- not a leftover, since
    // a finite bucket's count is only ever an upper bound on what it holds.
    let _ = writeln!(
        out,
        "qqq_http_request_duration_seconds_bucket{{le=\"+Inf\"}} {}",
        latency.count()
    );
    let _ = writeln!(
        out,
        "qqq_http_request_duration_seconds_sum {}",
        micros_as_seconds(latency.sum_micros())
    );
    let _ = writeln!(
        out,
        "qqq_http_request_duration_seconds_count {}",
        latency.count()
    );
}

/// -- connections ----------------------------------------------------
fn write_connection_gauges(m: &HttpMetrics, out: &mut String) {
    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "# HELP qqq_http_connections_total Connections closed, by outcome."
    );
    let _ = writeln!(out, "# TYPE qqq_http_connections_total counter");
    for outcome in Outcome::ALL {
        let n = m.connections_for(outcome);
        if n == 0 {
            continue;
        }
        let _ = writeln!(
            out,
            "qqq_http_connections_total{{outcome=\"{}\"}} {n}",
            prometheus_escape(outcome.as_str())
        );
    }
    let _ = writeln!(
        out,
        "# HELP qqq_http_connections_open Connections open right now."
    );
    let _ = writeln!(out, "# TYPE qqq_http_connections_open gauge");
    let _ = writeln!(out, "qqq_http_connections_open {}", m.open_connections());
}

/// -- per tenant, walked BY INDEX so the bound is the output's ------
fn write_tenant_counters(m: &HttpMetrics, out: &mut String) {
    use std::fmt::Write as _;
    //
    // The index space is what the registry bounds, so walking it is what makes "at most
    // MAX_TENANTS + 2 series" true of the exposition rather than merely intended. `name_of`
    // returns `None` for the shared past-the-ceiling bucket, which is labelled `other` -- the
    // same collapse `Tenant::Other` performs, so a flood of client addresses produces ONE
    // series here too.
    let ceiling = u16::try_from(TenantLabels::MAX_TENANTS).unwrap_or(u16::MAX);
    for (name, help, read) in [
        (
            "qqq_http_request_body_bytes_total",
            "Request body bytes read, by tenant.",
            0usize,
        ),
        (
            "qqq_http_response_body_bytes_total",
            "Response body bytes written, by tenant.",
            1,
        ),
        (
            "qqq_http_body_limit_hits_total",
            "Bodies refused for exceeding a limit, by tenant.",
            2,
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} counter");
        for index in 0..=ceiling + 1 {
            let label = m
                .tenants
                .name_of(index)
                .unwrap_or_else(|| "other".to_owned());
            let n = match read {
                0 => m.body_bytes_in.lock(),
                1 => m.body_bytes_out.lock(),
                _ => m.body_limit_hits.lock(),
            }
            .map_or(0, |m| m.get(&index).copied().unwrap_or(0));
            if n == 0 {
                continue;
            }
            let _ = writeln!(
                out,
                "{name}{{tenant=\"{}\"}} {n}",
                prometheus_escape(&label)
            );
        }
    }
}

/// Microseconds as the seconds a Prometheus `_seconds` metric carries.
///
/// Six decimal places, which is the microsecond resolution exactly: coarser would round a
/// sub-millisecond latency to zero, and finer would invent precision the registry does not have.
fn micros_as_seconds(micros: u64) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

/// Escape a label value for the exposition format.
///
/// # Why this is not optional
///
/// A tenant name is operator-supplied and may contain `"`, `\` or a newline. Unescaped, it does not
/// merely look wrong -- it **forges a new label** in the exposition, or splits one metric line into
/// two. That is the same class as log injection, which §10.3's host-side redaction exists to
/// prevent in its own domain.
fn prometheus_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- the Prometheus exposition -- OBS-013 ---------------------------------

    /// **Histogram buckets are CUMULATIVE in the exposition.**
    ///
    /// `le` means *less than or equal*, and `Latency::buckets` returns **per-bucket** counts.
    /// Exporting those directly produces a histogram whose buckets appear to decrease, which a
    /// Prometheus server either rejects or, worse, accepts and renders as nonsense. This is the
    /// rule the format makes easiest to get wrong, so it is the first thing asserted.
    #[test]
    fn the_exposition_histogram_is_cumulative() {
        let m = HttpMetrics::new();
        // One observation in the first bucket and one in the last, so a non-cumulative export
        // would produce a sequence that goes up then down.
        m.record_request(Method::Get, 200, 1, "t", 0, 0);
        m.record_request(Method::Get, 200, 60_000_000, "t", 0, 0);

        let text = m.render_prometheus();
        let mut previous = 0u64;
        let mut seen = 0;
        for line in text.lines() {
            let Some(rest) = line.strip_prefix("qqq_http_request_duration_seconds_bucket{le=\"")
            else {
                continue;
            };
            let (label, value) = rest.split_once("\"} ").expect("a bucket line has a value");
            let value: u64 = value.parse().expect("a bucket count is an integer");
            assert!(
                value >= previous,
                "bucket `le={label}` holds {value}, below the previous bucket's {previous}: the \
                 export is per-bucket rather than cumulative"
            );
            previous = value;
            seen += 1;
        }
        assert!(
            seen > 2,
            "the histogram must export its finite buckets: {text}"
        );
        assert_eq!(
            previous, 2,
            "the last finite bucket is not necessarily every observation, so check the count line"
        );
        assert!(
            text.contains("qqq_http_request_duration_seconds_count 2"),
            "the count line must carry the total: {text}"
        );
        assert!(
            text.contains("le=\"+Inf\"} 2"),
            "and `+Inf` is every observation: {text}"
        );
    }

    /// **Durations are exported in SECONDS, and the conversion is exact.**
    ///
    /// The registry counts microseconds; Prometheus' convention is `_seconds`. Exporting micros
    /// under a `_seconds` name is a wrong number that looks right — off by six orders of magnitude,
    /// in the direction that makes every latency look catastrophic.
    #[test]
    fn the_exposition_converts_micros_to_seconds() {
        assert_eq!(micros_as_seconds(0), "0.000000");
        assert_eq!(micros_as_seconds(1), "0.000001");
        assert_eq!(micros_as_seconds(1_500_000), "1.500000");
        assert_eq!(micros_as_seconds(60_000_000), "60.000000");

        let m = HttpMetrics::new();
        m.record_request(Method::Get, 200, 2_500_000, "t", 0, 0);
        let text = m.render_prometheus();
        assert!(
            text.contains("qqq_http_request_duration_seconds_sum 2.500000"),
            "the sum must be in seconds: {text}"
        );
    }

    /// **A tenant name containing a quote is ESCAPED, not interpolated.**
    ///
    /// Unescaped, it does not merely look wrong — it **forges a new label** in the exposition, or
    /// splits one metric line into two. Same class as log injection, which §10.3's redaction exists
    /// to prevent in its own domain.
    #[test]
    fn the_exposition_escapes_a_tenant_label() {
        assert_eq!(prometheus_escape("plain"), "plain");
        assert_eq!(prometheus_escape("a\"b"), "a\\\"b");
        assert_eq!(prometheus_escape("a\\b"), "a\\\\b");
        assert_eq!(prometheus_escape("a\nb"), "a\\nb");

        let m = HttpMetrics::new();
        // A name with a quote and a backslash, recorded as a real tenant would be.
        m.record_request(Method::Get, 200, 1, "evil\" tenant", 5, 0);
        let text = m.render_prometheus();
        assert!(
            !text.contains("tenant=\"evil\" tenant\""),
            "an unescaped quote would forge a label: {text}"
        );
        assert!(
            text.contains("tenant=\"evil\\\" tenant\""),
            "the quote must be escaped: {text}"
        );
        // And every metric line must still have exactly one label list.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            assert_eq!(
                line.matches('{').count(),
                line.matches('}').count(),
                "a line with unbalanced braces is a forged label: {line}"
            );
        }
    }

    /// **The exposition's per-tenant series are bounded by the ceiling, like the registry's.**
    ///
    /// The renderer walks the *index* space rather than the names, which is what makes "at most
    /// `MAX_TENANTS + 2` series" true of the output rather than merely intended — the same property
    /// `a_flood_of_tenant_names_cannot_grow_the_per_tenant_maps` asserts one layer down.
    #[test]
    fn the_exposition_bounds_its_tenant_series() {
        let m = HttpMetrics::new();
        for i in 0..(TenantLabels::MAX_TENANTS * 10) {
            let name = format!("10.0.{}.{}", i / 256, i % 256);
            m.record_request(Method::Get, 200, 1, &name, 1, 1);
        }
        let text = m.render_prometheus();
        let series = text
            .lines()
            .filter(|l| l.starts_with("qqq_http_request_body_bytes_total{"))
            .count();
        assert!(
            series <= TenantLabels::MAX_TENANTS + 2,
            "the exposition emitted {series} tenant series for {} names",
            TenantLabels::MAX_TENANTS * 10
        );
        assert!(
            text.contains("tenant=\"other\"}"),
            "and the past-the-ceiling names share ONE series labelled `other`: {text}"
        );
    }

    /// **Every non-comment line is a well-formed exposition sample.**
    ///
    /// The format is line-oriented and positional, so a malformed line is not a rendering blemish —
    /// a scraper rejects the whole payload.
    #[test]
    fn every_exposition_line_is_well_formed() {
        let m = HttpMetrics::new();
        m.record_request(Method::Get, 200, 1_000, "acme", 10, 20);
        m.record_body_limit("acme");
        m.connection_opened();
        m.connection_closed(Outcome::ClientClosed);

        let text = m.render_prometheus();
        let mut samples = 0;
        for line in text.lines() {
            if line.starts_with('#') {
                assert!(
                    line.starts_with("# HELP ") || line.starts_with("# TYPE "),
                    "only HELP and TYPE are comments in this exposition: {line}"
                );
                continue;
            }
            assert!(!line.is_empty(), "a blank line is not a sample");
            let (_, value) = line
                .rsplit_once(' ')
                .unwrap_or_else(|| panic!("a sample line is `name value`: {line}"));
            assert!(
                value.parse::<f64>().is_ok() || value == "+Inf",
                "the value must be a number: {line}"
            );
            samples += 1;
        }
        assert!(samples >= 6, "the registry holds several series: {text}");
        assert!(
            text.contains("# TYPE qqq_http_request_duration_seconds histogram"),
            "and the histogram declares its type: {text}"
        );
    }

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
    /// **A flood of distinct tenant names cannot grow the per-tenant maps — `OBS-006`.**
    ///
    /// This is the property `tools/check_metric_cardinality.py` exists to keep, asserted at the
    /// level a reader can act on. The values come from `tenant_of`, which returns the **peer IP
    /// address**, so the names below stand in for an attacker opening connections from many
    /// addresses: before the fix, each one added an entry to three `BTreeMap<String, _>`s, which
    /// is §10.2's violation *"in its worst form, because an attacker chooses the value"*.
    ///
    /// The assertion is not *"the map has N entries"* but *"the map cannot exceed the ceiling plus
    /// the two reserved buckets"* — a count alone would pass for a small flood and say nothing
    /// about the next one.
    #[test]
    fn a_flood_of_tenant_names_cannot_grow_the_per_tenant_maps() {
        let m = HttpMetrics::new();

        // Ten times the ceiling, each name distinct -- every one a different "client address".
        for i in 0..(TenantLabels::MAX_TENANTS * 10) {
            let name = format!("10.0.{}.{}", i / 256, i % 256);
            m.record_request(Method::Get, 200, 1, &name, 1, 1);
            m.record_body_limit(&name);
        }

        // The space is the ceiling, plus `default` (index 0) and the shared past-the-ceiling
        // bucket -- two reserved entries, not one per name.
        let ceiling = TenantLabels::MAX_TENANTS + 2;
        let in_ = m.body_bytes_in.lock().expect("lock").len();
        let out = m.body_bytes_out.lock().expect("lock").len();
        let hits = m.body_limit_hits.lock().expect("lock").len();
        assert!(
            in_ <= ceiling,
            "body_bytes_in holds {in_} entries for {} distinct names; the ceiling is {ceiling}",
            TenantLabels::MAX_TENANTS * 10
        );
        assert!(out <= ceiling, "body_bytes_out holds {out} entries");
        assert!(hits <= ceiling, "body_limit_hits holds {hits} entries");

        // And the flood was actually recorded rather than dropped: the past-the-ceiling bucket is
        // non-zero, so the test would notice a "fix" that bounded the maps by refusing to count.
        let past = u16::try_from(TenantLabels::MAX_TENANTS).expect("the ceiling fits u16") + 1;
        assert!(
            m.body_limit_hits
                .lock()
                .expect("lock")
                .get(&past)
                .copied()
                .unwrap_or(0)
                > 0,
            "the names past the ceiling must share one bucket that is actually counted"
        );
    }

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
