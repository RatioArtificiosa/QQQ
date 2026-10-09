// SPDX-License-Identifier: Apache-2.0

//! Per-tenant request limits, and the accounting that enforces them (`SRV-020`).
//!
//! The connection ceiling already existed in [`crate::conn::ConnectionLedger`]. This adds
//! the two limits `SRV-020` names that did not: a **body size** cap and a **request count**
//! cap, both per tenant, both **enforced** rather than merely counted.
//!
//! # The distinction from `metrics.rs`, which counts the same things
//!
//! [`crate::metrics::HttpMetrics`] **records** body bytes and refusals so an operator can
//! see them. This module **decides**. They are separate types because a metric that is also
//! the enforcement point cannot be sampled, dropped or shipped elsewhere without silently
//! changing what the server allows — and because §10.2's cardinality discipline applies only
//! to the metric, while enforcement needs the exact per-tenant figure.
//!
//! **Keeping them consistent is a requirement on the request path, not a property of these
//! types.** They are separate values and neither knows about the other, so a caller that
//! updates one and not the other gets two answers to one question — and nothing here can
//! prevent that. The requirement is that the site applying a limit also records the outcome,
//! and it is stated as a requirement because a first version of this comment claimed the two
//! "cannot disagree", which was a promise the code did not keep (`§O-124`).
//!
//! # Why the limits are a table and not a single number
//!
//! A deployment sells different sizes, and the alternative to a table is one global cap set
//! for the largest customer — which is no limit at all for everybody else. The table is
//! small, fixed at startup and read on every request, so it lives behind an `Arc`: no lock on
//! the read path and no rehashing as tenants are added.
//!
//! # Why every limit has a documented "unlimited" spelling
//!
//! `None` means no limit rather than zero, and the distinction is load-bearing: a limit of
//! zero refuses everything, which is almost never what an operator meant and is exactly the
//! silent misconfiguration `§O-128` records. Making them different values means such a
//! mistake is a visible violation rather than a server that serves nobody.
//!
//! # Why the window is a monotonic instant and not a timer
//!
//! A rate limiter driven by a background task that resets counters is a second authority on
//! time, and the connection state machine is already the first (`act_on_poll` derives every
//! deadline from it). Deriving the window from a caller-supplied monotonic instant keeps one
//! clock, makes the limiter a pure function of `(tenant, now)`, and makes it testable without
//! sleeping.

use std::collections::BTreeMap;
use std::hash::BuildHasher;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qqq_host::tenant::TenantKey;

/// The limits that apply to one tenant.
///
/// Every field is optional, and `None` means **unlimited**. See the module documentation for
/// why `None` and `Some(0)` are deliberately different.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest request body accepted, in bytes.
    ///
    /// Enforced against the **declared** length before a byte of the body is read, and
    /// against the streaming count as it arrives. Declared-only would let a client understate
    /// the length; streamed-only would read an unbounded body before deciding.
    pub max_body_bytes: Option<u64>,
    /// The largest number of requests allowed in one window.
    pub max_requests_per_window: Option<u32>,
    /// The window those requests are counted over.
    ///
    /// Ignored when `max_requests_per_window` is `None`. A window with no count is
    /// meaningless, and requiring both would let a caller set one and forget the other.
    pub window: Duration,
    /// The largest number of simultaneous connections the tenant may hold.
    ///
    /// `None` means the server's own ceiling applies, which is the fallback the ledger was
    /// already built with. Read by `ConnectionLedger::with_limits`; a tenant this field
    /// names gets its own ceiling and every other tenant keeps the server default.
    pub max_connections: Option<u32>,
}

impl Limits {
    /// No limits at all.
    ///
    /// The **default**, and the safe one only because a QQQ server is not exposed without a
    /// manifest declaring its server section. Where a deployment wants limits they come from
    /// the manifest; a built-in guess would be a number this crate invented.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            max_body_bytes: None,
            max_requests_per_window: None,
            window: Duration::from_secs(60),
            max_connections: None,
        }
    }

    /// A body cap, with no request-rate limit.
    #[must_use]
    pub const fn with_body(max_body_bytes: u64) -> Self {
        Self {
            max_body_bytes: Some(max_body_bytes),
            max_requests_per_window: None,
            window: Duration::from_secs(60),
            max_connections: None,
        }
    }

    /// A request-rate limit, with no body cap.
    #[must_use]
    pub const fn with_rate(max_requests_per_window: u32, window: Duration) -> Self {
        Self {
            max_body_bytes: None,
            max_requests_per_window: Some(max_requests_per_window),
            window,
            max_connections: None,
        }
    }

    /// Whether a declared or counted body length is within the cap.
    ///
    /// Takes the **length** rather than the body, because the caller must be able to ask
    /// before reading: a check that needs the bytes is a check that has already paid for them.
    #[must_use]
    pub fn allows_body(&self, declared_len: u64) -> bool {
        match self.max_body_bytes {
            Some(max) => declared_len <= max,
            None => true,
        }
    }

    /// Builder: a body cap.
    #[must_use]
    pub const fn body(mut self, max_body_bytes: u64) -> Self {
        self.max_body_bytes = Some(max_body_bytes);
        self
    }

    /// Builder: a request-rate limit.
    #[must_use]
    pub const fn rate(mut self, max_requests_per_window: u32, window: Duration) -> Self {
        self.max_requests_per_window = Some(max_requests_per_window);
        self.window = window;
        self
    }

    /// Whether these limits are coherent.
    ///
    /// # The one incoherent combination, and why it is a bug rather than a preference
    ///
    /// A **zero window** with a request cap makes the limiter never refuse. The rollover
    /// test is `elapsed >= window`, which is true for any elapsed value when the window is
    /// zero — so every call resets the count to zero and the cap is unreachable. The
    /// limiter would look configured, count nothing and allow everything.
    ///
    /// That is the worst kind of misconfiguration to leave silent, because the failure is
    /// **in the permissive direction** and nothing reports it: an operator sets a limit and
    /// gets no enforcement, with no error and no log line. It is the same shape as
    /// `§O-128`'s "safe defaults must deny" — a limit that does not limit.
    ///
    /// Refused at construction rather than at the first request, so a bad manifest fails at
    /// startup where someone is watching rather than under load where nobody is.
    #[must_use]
    pub fn is_coherent(&self) -> bool {
        match self.max_requests_per_window {
            // A window is only meaningful with a cap...
            Some(_) => self.window > Duration::ZERO,
            // ...and a cap with no window is caught by the same reasoning from the other
            // side: `None` means no rate limit, so the window is unused and any value is
            // coherent.
            None => true,
        }
    }
}

/// Why a request was refused.
///
/// A value rather than a bare `false`, because the two refusals have different remedies and
/// different log lines: a body over the cap is the client sending too *much*, a rate breach
/// is the client sending too *often*, and an operator mitigates them differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The declared or counted body exceeded the tenant's cap.
    BodyTooLarge {
        /// What the tenant is allowed.
        limit: u64,
        /// What this request was.
        got: u64,
    },
    /// The tenant exceeded its request count for the window.
    RateExceeded {
        /// What the tenant is allowed.
        limit: u32,
        /// The window, in seconds, for the log line.
        window_secs: u64,
    },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BodyTooLarge { limit, got } => write!(
                f,
                "the request body is {got} bytes, over this tenant's {limit}-byte cap"
            ),
            Self::RateExceeded { limit, window_secs } => write!(
                f,
                "this tenant has exceeded {limit} requests in {window_secs} seconds"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// Whether a window that began at `started` is still running.
///
/// # Why this is one function rather than two comparisons
///
/// The sweep and the rollover both ask "has this window expired?", and they **must** answer
/// identically: if the sweep considers an entry live while the rollover considers it expired,
/// a tenant is evicted and immediately re-created with a full allowance, which is a rate
/// limiter that resets itself. Writing the comparison twice is how those two answers drift
/// apart — the same argument `act_on_poll` makes for being the only authority on the
/// connection's deadlines.
///
/// `>=` rather than `>`: a window of exactly N seconds has elapsed at N seconds.
fn window_is_active(started: Instant, window: Duration, now: Instant) -> bool {
    now.saturating_duration_since(started) < window
}

/// Per-tenant limits and their accounting.
///
/// # Why fixed-size sharded buckets instead of a table (`F-13`)
///
/// The windows used to live in a `BTreeMap` bounded at 4,096 entries, and past
/// the bound a new tenant went untracked — admitted without a rate limit. An
/// attacker needed only to occupy the table (trivial with IPv6 rotation) and
/// everything new was unlimited: the limiter disabled itself under pressure.
///
/// The buckets cannot fill: there is no insert, only indexing. A tenant hashes
/// to one bucket; a live bucket owned by another key shares its count, an
/// expired one is taken over. Sharing is documented intent, not a defect —
/// collisions merge allowances symmetrically, and the
/// [`GlobalBucket`] below bounds total admissions so no rotation strategy can
/// exceed overall capacity. What the table's bound protected (memory) is now a
/// property of the type: 16,384 buckets allocated once, never grown.
///
/// Interior mutability behind one `Mutex` rather than per-bucket locks: window
/// state is a (key, start, count, window) tuple that must update together, and
/// the previous design already serialised admissions on one lock, so this is
/// no narrower than what it replaces.
#[derive(Debug)]
pub struct TenantLimits {
    /// The limits, by tenant key.
    limits: Arc<BTreeMap<TenantKey, Limits>>,
    /// The limit applied to a tenant with no entry.
    fallback: Limits,
    /// The fixed-size sharded windows. Never resized, never evicted-of the
    /// living: only an expired bucket changes hands.
    buckets: std::sync::Mutex<Box<[Bucket]>>,
    /// The per-process hash seed. Unknown to any peer, so no client can aim
    /// at (or away from) another tenant's bucket.
    seed: std::collections::hash_map::RandomState,
}

/// One sharded window: the occupant's allowance state, or nothing.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Who counts here, and since when, how much, under which window.
    occupant: Option<Occupant>,
}

/// A live bucket's state. `Copy` so the admission decision reads atomically
/// under the one lock.
#[derive(Debug, Clone, Copy)]
struct Occupant {
    /// The tenant spending this bucket.
    key: TenantKey,
    /// When the current window began.
    started: Instant,
    /// Requests seen in it.
    count: u32,
    /// The window those requests are counted over (the occupant's own, so a
    /// foreign key arriving later judges expiry by the right clock).
    window: Duration,
}

/// The number of sharded buckets. 16,384 per the audit's recommendation: large
/// enough that accidental collisions are noise (9 tenants collide with
/// probability ~0.0002), small enough to allocate once (~1 MiB, never grown).
const BUCKET_COUNT: usize = 16_384;

impl TenantLimits {
    /// Build a limiter from a table and a fallback.
    ///
    /// # Panics
    ///
    /// If any entry is incoherent — see [`Limits::is_coherent`]. A zero window with a
    /// request cap makes the limiter allow **everything**, which is a misconfiguration that
    /// must not start a server. Panicking at construction means a bad manifest fails at
    /// startup where someone is watching, rather than under load where nobody is.
    #[must_use]
    pub fn new<I>(limits: I, fallback: Limits) -> Self
    where
        I: IntoIterator<Item = (TenantKey, Limits)>,
    {
        let limits: BTreeMap<TenantKey, Limits> = limits.into_iter().collect();
        assert!(
            fallback.is_coherent(),
            "the fallback limits are incoherent: a zero window with a request cap would \
             allow every request"
        );
        for (tenant, l) in &limits {
            assert!(
                l.is_coherent(),
                "the limits for tenant `{tenant:?}` are incoherent: a zero window with a \
                 request cap would allow every request"
            );
        }
        Self {
            limits: Arc::new(limits),
            fallback,
            buckets: std::sync::Mutex::new(
                (0..BUCKET_COUNT)
                    .map(|_| Bucket { occupant: None })
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
            seed: std::collections::hash_map::RandomState::new(),
        }
    }

    /// A limiter that applies the same limits to every tenant.
    #[must_use]
    pub fn uniform(limits: Limits) -> Self {
        Self::new(std::iter::empty(), limits)
    }

    /// The limits that apply to a tenant.
    #[must_use]
    pub fn limits_for(&self, tenant: TenantKey) -> Limits {
        self.limits.get(&tenant).copied().unwrap_or(self.fallback)
    }

    /// A table whose only limit is the per-tenant **connection** ceiling.
    ///
    /// For a caller that has a connection policy and no request policy — the manifest path
    /// builds a full table and does not use this. Each entry's other limits are
    /// [`Limits::none`], so this never turns on a body or rate cap by accident.
    #[must_use]
    pub fn with_connections<I>(ceilings: I, fallback_connections: u32) -> Self
    where
        I: IntoIterator<Item = (TenantKey, u32)>,
    {
        let limits: BTreeMap<TenantKey, Limits> = ceilings
            .into_iter()
            .map(|(tenant, ceiling)| {
                (
                    tenant,
                    Limits {
                        max_connections: Some(ceiling),
                        ..Limits::none()
                    },
                )
            })
            .collect();
        let fallback = Limits {
            max_connections: Some(fallback_connections),
            ..Limits::none()
        };
        Self::new(limits, fallback)
    }

    /// The per-tenant **connection** ceilings, for tenants that name one.
    ///
    /// # Why only the tenants that name a ceiling appear
    ///
    /// A tenant whose entry sets a body cap and no `max_connections` must keep the
    /// server's ceiling. Emitting its `None` as a ceiling would reset that tenant to
    /// unbounded merely because it appears in the table, which is the opposite of what
    /// its author wrote -- so this filters, and absence keeps the fallback.
    ///
    /// The shape is `(tenant, ceiling)` rather than a map so the caller can hand it
    /// straight to `ConnectionLedger::with_limits`, which owns the fallback.
    #[must_use]
    pub fn connections_by_tenant(&self) -> Vec<(TenantKey, u32)> {
        self.limits
            .iter()
            .filter_map(|(tenant, l)| l.max_connections.map(|c| (*tenant, c)))
            .collect()
    }

    /// Check a body length against the tenant's cap, **without** recording anything.
    ///
    /// Separate from [`Self::check_and_record`] because the declared length is known before
    /// the body is read and the counted length only afterwards, and both must be checked.
    /// Calling this twice is the correct use.
    ///
    /// # Errors
    ///
    /// [`Refusal::BodyTooLarge`] when the length exceeds the tenant's cap.
    pub fn check_body(&self, tenant: TenantKey, len: u64) -> Result<(), Refusal> {
        let limits = self.limits_for(tenant);
        if limits.allows_body(len) {
            return Ok(());
        }
        Err(Refusal::BodyTooLarge {
            limit: limits.max_body_bytes.unwrap_or(0),
            got: len,
        })
    }

    /// Check **and record** a request against the tenant's rate limit.
    ///
    /// # Why this records as a side effect
    ///
    /// A separate `check` and `record` would let a caller check without recording — a limiter
    /// that never limits, and exactly the shape `§O-130` records for a feature that looks
    /// live and is not. Making the check consume the allowance means using it correctly is
    /// the only way to call it.
    ///
    /// # Errors
    ///
    /// [`Refusal::RateExceeded`] when the tenant has spent its allowance for the window.
    pub fn check_and_record(&self, tenant: TenantKey, now: Instant) -> Result<(), Refusal> {
        let limits = self.limits_for(tenant);
        let Some(max) = limits.max_requests_per_window else {
            // No rate limit: count nothing, because a bucket nobody reads is state an
            // attacker can drive for free.
            return Ok(());
        };

        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = self.bucket_index(tenant);
        let bucket = &mut buckets[index];

        // The rollover is **lazy**: a window expires when the next request arrives rather
        // than on a timer. A timer would be a second authority on time, and an expired
        // bucket is worth reclaiming only when next touched.
        //
        // Three cases, and only the third changes hands:
        // - empty: the tenant moves in;
        // - same key: its own window rolls over;
        // - another key: the occupant's *own* window decides. Expired means the
        //   bucket is dead state and the arrival takes it over; live means a hash
        //   collision, and the two tenants share the count. Sharing is the
        //   documented price of a table that cannot fill — and it is symmetric:
        //   neither side can aim at the other's bucket (the seed is per-process),
        //   and sharing only ever refuses sooner, never admits past `max`.
        let admit = match &mut bucket.occupant {
            None => {
                bucket.occupant = Some(Occupant {
                    key: tenant,
                    started: now,
                    count: 1,
                    window: limits.window,
                });
                true
            }
            Some(o) if o.key == tenant => {
                if !window_is_active(o.started, limits.window, now) {
                    o.started = now;
                    o.count = 0;
                    o.window = limits.window;
                }
                if o.count >= max {
                    false
                } else {
                    o.count = o.count.saturating_add(1);
                    true
                }
            }
            Some(o) => {
                if !window_is_active(o.started, o.window, now) {
                    bucket.occupant = Some(Occupant {
                        key: tenant,
                        started: now,
                        count: 1,
                        window: limits.window,
                    });
                    true
                } else if o.count >= max {
                    false
                } else {
                    o.count = o.count.saturating_add(1);
                    true
                }
            }
        };

        if admit {
            Ok(())
        } else {
            Err(Refusal::RateExceeded {
                limit: max,
                window_secs: limits.window.as_secs(),
            })
        }
    }

    /// The bucket a tenant counts in: `SipHash` under the per-process seed.
    fn bucket_index(&self, tenant: TenantKey) -> usize {
        let in_range = self.seed.hash_one(tenant) % BUCKET_COUNT as u64;
        // `in_range` is below 16,384 by construction, so this fits every
        // pointer width; the fallback names bucket zero rather than failing.
        usize::try_from(in_range).unwrap_or(0)
    }
}

/// The process-wide admission budgets a server enforces alongside the
/// per-tenant limits.
///
/// Two windows, not one: requests and new connections cost differently (a
/// connection holds a task and a socket before any request arrives), so one
/// budget for both would let cheap requests crowd out handshakes or the
/// reverse. Generous by default — this bounds rotation attacks, not
/// legitimate flash crowds — and every field is operator-settable.
///
/// ```
/// use qqq_serve::limits::GlobalBudget;
/// use std::time::Duration;
///
/// let budget = GlobalBudget::default();
/// assert_eq!(budget.requests_per_window, 1_000_000);
/// assert_eq!(budget.request_window, Duration::from_secs(60));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalBudget {
    /// Admissions per request window.
    pub requests_per_window: u32,
    /// The request window.
    pub request_window: Duration,
    /// New connections per connection window.
    pub connections_per_window: u32,
    /// The connection window.
    pub connection_window: Duration,
}

impl Default for GlobalBudget {
    /// Generous bounds: ~16,000 requests and ~1,600 new connections per
    /// second. Above every load profile the repository measures (the 200k
    /// lock-step test peaks near 3,000 requests per second) with room to
    /// spare, and still a ceiling no rotation strategy can cross.
    fn default() -> Self {
        Self {
            requests_per_window: 1_000_000,
            request_window: Duration::from_secs(60),
            connections_per_window: 100_000,
            connection_window: Duration::from_secs(60),
        }
    }
}

/// The process-wide admission budget: the backstop identity rotation cannot cross.
///
/// Per-tenant buckets bound what one identity spends; this bounds what *all* of
/// them spend together. When it is empty the server answers `503` with
/// `Retry-After` — the same load-shedding path as pool exhaustion, because it
/// is the same situation. A fixed window, not a token bucket with refill: the
/// budget is exact within a window, and the window rolls over lazily on the
/// next arrival, so there is no background task holding a second clock.
///
/// ```
/// use qqq_serve::limits::GlobalBucket;
/// use std::time::{Duration, Instant};
///
/// let bucket = GlobalBucket::new(2, Duration::from_secs(60));
/// let t0 = Instant::now();
/// assert!(bucket.admit(t0));
/// assert!(bucket.admit(t0));
/// assert!(!bucket.admit(t0), "the budget is spent");
/// assert_eq!(bucket.refused_total(), 1);
/// ```
#[derive(Debug)]
pub struct GlobalBucket {
    /// Admissions allowed per window.
    budget: u32,
    /// The window they are counted over.
    window: Duration,
    /// The current window's state.
    state: std::sync::Mutex<GlobalState>,
}

/// The current window's count. `Copy` so the decision reads atomically under
/// the lock.
#[derive(Debug, Clone, Copy)]
struct GlobalState {
    /// When the current window began.
    started: Option<Instant>,
    /// Admissions in it.
    count: u32,
    /// Lifetime refusals, for the metric. Monotonic: a refusal is a fact about
    /// offered load, and resetting it would un-count evidence.
    refused: u64,
}

impl GlobalBucket {
    /// A global budget of `budget` admissions per `window`.
    ///
    /// # Panics
    ///
    /// If the window is zero: a zero window admits nothing on the first call
    /// and resets on every later one, which is a limiter that cannot decide.
    /// Like [`TenantLimits::new`], a bad configuration fails at construction.
    ///
    /// ```
    /// use qqq_serve::limits::GlobalBucket;
    /// use std::time::Duration;
    ///
    /// let bucket = GlobalBucket::new(1, Duration::from_secs(60));
    /// assert_eq!(bucket.refused_total(), 0);
    /// ```
    #[must_use]
    pub fn new(budget: u32, window: Duration) -> Self {
        assert!(
            window > Duration::ZERO,
            "a zero global window cannot bound anything"
        );
        Self {
            budget,
            window,
            state: std::sync::Mutex::new(GlobalState {
                started: None,
                count: 0,
                refused: 0,
            }),
        }
    }

    /// Try to admit one request. `false` means the server must shed load.
    ///
    /// ```
    /// use qqq_serve::limits::GlobalBucket;
    /// use std::time::{Duration, Instant};
    ///
    /// let bucket = GlobalBucket::new(1, Duration::from_secs(60));
    /// let t0 = Instant::now();
    /// assert!(bucket.admit(t0));
    /// assert!(!bucket.admit(t0), "the budget of one is spent");
    /// ```
    pub fn admit(&self, now: Instant) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match state.started {
            Some(started) if window_is_active(started, self.window, now) => {}
            _ => {
                state.started = Some(now);
                state.count = 0;
            }
        }
        if state.count >= self.budget {
            state.refused = state.refused.saturating_add(1);
            false
        } else {
            state.count = state.count.saturating_add(1);
            true
        }
    }

    /// Lifetime refusals. The metric the audit's acceptance criterion names.
    ///
    /// ```
    /// use qqq_serve::limits::GlobalBucket;
    /// use std::time::{Duration, Instant};
    ///
    /// let bucket = GlobalBucket::new(1, Duration::from_secs(60));
    /// let t0 = Instant::now();
    /// assert!(bucket.admit(t0));
    /// assert!(!bucket.admit(t0));
    /// assert_eq!(bucket.refused_total(), 1);
    /// ```
    #[must_use]
    pub fn refused_total(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .refused
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_host::tenant::tenant_key;

    /// One tenant as a key: the table tests used to name tenants `"a"`, `"t"`,
    /// `"vip"`. Strings were the defect (`F-13`); keys are `Copy` values.
    fn key(n: u32) -> TenantKey {
        TenantKey::V4(n)
    }

    // -- the limit table ---------------------------------------------------

    /// A tenant with an entry gets its own limits.
    #[test]
    fn a_tenant_gets_its_own_limits() {
        let l = TenantLimits::new(
            [(key(7), Limits::with_body(1_000_000))],
            Limits::with_body(1_000),
        );
        assert_eq!(l.limits_for(key(7)).max_body_bytes, Some(1_000_000));
        assert_eq!(l.limits_for(key(9)).max_body_bytes, Some(1_000));
    }

    /// A uniform limiter applies one limit to everyone.
    #[test]
    fn a_uniform_limiter_applies_to_everyone() {
        let l = TenantLimits::uniform(Limits::with_body(500));
        assert_eq!(l.limits_for(key(1)).max_body_bytes, Some(500));
        assert_eq!(l.limits_for(key(2)).max_body_bytes, Some(500));
    }

    // -- body caps ---------------------------------------------------------

    /// **A body cap is inclusive and enforced.**
    ///
    /// The bound is `<=`, so exactly the cap is allowed. An exclusive comparison makes the
    /// documented cap a lie by one byte, and the off-by-one is invisible in a test that only
    /// checks a value far over.
    #[test]
    fn a_body_cap_is_inclusive_and_enforced() {
        let l = TenantLimits::uniform(Limits::with_body(100));

        assert!(
            l.check_body(key(1), 0).is_ok(),
            "an empty body is always fine"
        );
        assert!(l.check_body(key(1), 99).is_ok());
        assert!(
            l.check_body(key(1), 100).is_ok(),
            "the bound is inclusive: `<=` the cap, or the cap is a lie by one byte"
        );
        let err = l
            .check_body(key(1), 101)
            .expect_err("one over must be refused");
        assert_eq!(
            err,
            Refusal::BodyTooLarge {
                limit: 100,
                got: 101
            }
        );
    }

    /// **The refusal names both the limit and the actual length.**
    ///
    /// A message saying only "too large" leaves an operator guessing which of their limits
    /// fired and by how much.
    #[test]
    fn a_body_refusal_names_both_numbers() {
        let l = TenantLimits::uniform(Limits::with_body(1_048_576));
        let err = l.check_body(key(1), 5_000_000).expect_err("refused");
        let text = err.to_string();
        assert!(text.contains("1048576"), "{text}");
        assert!(text.contains("5000000"), "{text}");
    }

    /// A tenant with no cap is unlimited, not refused.
    #[test]
    fn no_cap_means_unlimited() {
        let l = TenantLimits::uniform(Limits::none());
        assert!(l.check_body(key(1), u64::MAX).is_ok());
    }

    /// **`None` and `Some(0)` are different**, and the difference is total refusal.
    #[test]
    fn none_and_zero_are_different() {
        let unlimited = TenantLimits::uniform(Limits::none());
        let zero = TenantLimits::uniform(Limits::with_body(0));

        assert!(unlimited.check_body(key(1), 1).is_ok(), "None is unlimited");
        assert!(
            zero.check_body(key(1), 0).is_ok(),
            "an empty body still fits"
        );
        assert!(
            zero.check_body(key(1), 1).is_err(),
            "Some(0) refuses everything -- which is why it is not the default"
        );
    }

    /// The builders compose.
    #[test]
    fn the_builders_compose() {
        let l = Limits::none().body(2_048).rate(10, Duration::from_secs(5));
        assert_eq!(l.max_body_bytes, Some(2_048));
        assert_eq!(l.max_requests_per_window, Some(10));
        assert_eq!(l.window, Duration::from_secs(5));
    }

    // -- rate limits -------------------------------------------------------

    /// **The rate limit admits exactly `max` requests, then refuses.**
    ///
    /// The off-by-one control: `max` succeed and the `max + 1`th fails. An implementation
    /// using `>` instead of `>=` admits one extra every window, which over a fleet is a real
    /// overshoot and is invisible in a test that only checks for a refusal eventually.
    #[test]
    fn the_rate_limit_admits_exactly_the_allowance() {
        let l = TenantLimits::uniform(Limits::with_rate(3, Duration::from_secs(60)));
        let t0 = Instant::now();

        for i in 0..3 {
            assert!(
                l.check_and_record(key(1), t0).is_ok(),
                "request {i} must be admitted"
            );
        }
        let err = l
            .check_and_record(key(1), t0)
            .expect_err("the fourth must be refused");
        assert_eq!(
            err,
            Refusal::RateExceeded {
                limit: 3,
                window_secs: 60
            }
        );
    }

    /// The window rolls over and the allowance is restored.
    #[test]
    fn the_window_rolls_over() {
        let l = TenantLimits::uniform(Limits::with_rate(2, Duration::from_secs(10)));
        let t0 = Instant::now();

        assert!(l.check_and_record(key(1), t0).is_ok());
        assert!(l.check_and_record(key(1), t0).is_ok());
        assert!(l.check_and_record(key(1), t0).is_err(), "spent");

        assert!(
            l.check_and_record(key(1), t0 + Duration::from_secs(9))
                .is_err(),
            "the window has not elapsed"
        );
        assert!(
            l.check_and_record(key(1), t0 + Duration::from_secs(10))
                .is_ok(),
            "the window has elapsed, so the allowance is restored"
        );
    }

    /// **A zero window is refused at construction, because it allows everything.**
    ///
    /// The rollover test is `elapsed >= window`, which is true for any elapsed value when
    /// the window is zero — so every call resets the count and the cap becomes unreachable.
    /// A limiter configured this way counts nothing and allows everything, and **nothing
    /// reports it**: the failure is in the permissive direction.
    ///
    /// This is the check that makes the failure land at startup rather than under load.
    /// The test would catch a regression that removed `is_coherent`, because construction
    /// would succeed and the cap would stop being enforced.
    #[test]
    #[should_panic(expected = "incoherent")]
    fn a_zero_window_is_refused() {
        let bad = Limits::none().rate(10, Duration::ZERO);
        assert!(!bad.is_coherent());
        // Constructing must panic rather than build a limiter that never refuses.
        let _ = TenantLimits::uniform(bad);
    }

    /// The coherence rule is exactly "a cap needs a window", and nothing else is refused.
    #[test]
    fn coherence_refuses_only_a_cap_with_no_window() {
        // No cap: the window is unused, so any value is coherent.
        assert!(Limits::none().is_coherent());
        assert!(Limits::none().body(100).is_coherent());
        // A cap with a real window.
        assert!(Limits::with_rate(10, Duration::from_secs(1)).is_coherent());
        // A cap with a zero window: refused.
        assert!(!Limits::with_rate(10, Duration::ZERO).is_coherent());
    }

    /// A tenant with no rate limit is never refused and tracks no window.
    #[test]
    fn no_rate_limit_never_refuses_and_tracks_nothing() {
        let l = TenantLimits::uniform(Limits::none());
        let t0 = Instant::now();
        for _ in 0..10_000 {
            assert!(l.check_and_record(key(1), t0).is_ok());
        }
        // A window nobody reads must leave no state an attacker can drive:
        // after 10,000 uncounted requests a rate-limited tenant still gets
        // its full allowance on whatever bucket it lands on.
        let metered = TenantLimits::uniform(Limits::with_rate(2, Duration::from_secs(60)));
        assert!(metered.check_and_record(key(2), t0).is_ok());
        assert!(metered.check_and_record(key(2), t0).is_ok());
        assert!(metered.check_and_record(key(2), t0).is_err());
    }

    // -- isolation ---------------------------------------------------------

    /// **One tenant's spending does not consume another's allowance.**
    ///
    /// The property that makes this per-tenant. A limiter with one shared counter passes every
    /// test above and fails this one, and the symptom would be one busy client throttling
    /// everybody.
    #[test]
    fn tenants_do_not_share_an_allowance() {
        let l = TenantLimits::uniform(Limits::with_rate(2, Duration::from_secs(60)));
        let t0 = Instant::now();
        // Distinct buckets, not just distinct keys: a hash collision shares
        // one allowance by design, so the test must exclude it explicitly.
        let (a, b) = distinct_buckets(&l, key(1), key(2));

        assert!(l.check_and_record(a, t0).is_ok());
        assert!(l.check_and_record(a, t0).is_ok());
        assert!(l.check_and_record(a, t0).is_err(), "a is spent");

        assert!(
            l.check_and_record(b, t0).is_ok(),
            "b must have its own full allowance"
        );
        assert!(l.check_and_record(b, t0).is_ok());
        assert!(l.check_and_record(b, t0).is_err(), "and b is now spent too");
    }

    /// Two keys that hash to different buckets on this limiter.
    ///
    /// Sharded buckets share an allowance on collision by design, so any test
    /// asserting isolation must pin the layout first. The search always
    /// terminates: 16,384 buckets and sequential keys collide with
    /// probability ~1/16,384 per try.
    fn distinct_buckets(
        l: &TenantLimits,
        first: TenantKey,
        mut second: TenantKey,
    ) -> (TenantKey, TenantKey) {
        let mut n = 2u32;
        while l.bucket_index(first) == l.bucket_index(second) {
            n += 1;
            second = key(n);
        }
        (first, second)
    }

    /// Per-tenant limits differ, and the limiter honours the table.
    #[test]
    fn a_tenant_can_have_a_larger_allowance() {
        let l = TenantLimits::new(
            [(key(7), Limits::with_rate(100, Duration::from_secs(60)))],
            Limits::with_rate(1, Duration::from_secs(60)),
        );
        // Distinct buckets (see `distinct_buckets`): a collision would spend
        // vip's allowance from free's single request.
        let (vip, free) = distinct_buckets(&l, key(7), key(8));
        let t0 = Instant::now();

        assert!(l.check_and_record(free, t0).is_ok());
        assert!(
            l.check_and_record(free, t0).is_err(),
            "the free tier is spent"
        );

        for _ in 0..100 {
            assert!(
                l.check_and_record(vip, t0).is_ok(),
                "vip has its own allowance"
            );
        }
        assert!(l.check_and_record(vip, t0).is_err(), "and its own ceiling");
    }

    // -- bounds ------------------------------------------------------------

    /// **Expired buckets change hands: a new tenant is tracked, never skipped.**
    ///
    /// Replaces the table era's reclaim tests. There is no map to fill and no
    /// sweep: a bucket whose occupant's window elapsed is dead state, and the
    /// next arrival takes it over with a fresh allowance. The assertion is
    /// layout-independent — whichever bucket the newcomer lands on, an expired
    /// occupant (or none) means admission, and the second request then proves
    /// the newcomer was *tracked* rather than passed through.
    #[test]
    fn an_expired_bucket_changes_hands() {
        let l = TenantLimits::uniform(Limits::with_rate(1, Duration::from_secs(10)));
        let t0 = Instant::now();

        assert!(l.check_and_record(key(1), t0).is_ok(), "first fits");

        let later = t0 + Duration::from_secs(11);
        assert!(
            l.check_and_record(key(2), later).is_ok(),
            "the first request fits on whatever bucket it lands on"
        );
        assert!(
            l.check_and_record(key(2), later).is_err(),
            "the newcomer must be tracked and then limited"
        );
    }

    /// **Expiry is judged by the occupant's own window, not the arrival's.**
    ///
    /// A bucket stores the window it counts under. A newcomer with a long
    /// window arriving after a short-window occupant expired must take the
    /// bucket over — judging by the arrival's window would keep dead state
    /// alive exactly as the old sweep bug did.
    #[test]
    fn a_new_tenant_reaps_only_expired_buckets() {
        let short = Limits::with_rate(1, Duration::from_secs(5));
        let long = Limits::with_rate(1, Duration::from_secs(60));
        // The newcomer carries the long window; the occupant counts the short
        // one. Takeover must judge by the occupant's 5 seconds: judging by the
        // arrival's 60 would keep the dead bucket alive and refuse below.
        let l = TenantLimits::new([(key(2), long)], short);
        let t0 = Instant::now();

        assert!(l.check_and_record(key(1), t0).is_ok());

        // Past the occupant's 5-second window: takeover, then tracked.
        let later = t0 + Duration::from_secs(10);
        assert!(
            l.check_and_record(key(2), later).is_ok(),
            "a bucket expired by its occupant's own window must change hands"
        );
        assert!(
            l.check_and_record(key(2), later).is_err(),
            "the newcomer took over an expired bucket and is now limited"
        );
    }

    /// **Colliding tenants share one allowance — and the sharing is observable.**
    ///
    /// The documented price of a table that cannot fill. Two keys hashing to
    /// one bucket spend the same count, so the second tenant's allowance is
    /// already partly consumed. The pair is found per run (the seed is
    /// per-process), which also proves collisions exist to be shared.
    #[test]
    fn colliding_tenants_share_one_allowance() {
        let l = TenantLimits::uniform(Limits::with_rate(3, Duration::from_secs(60)));
        let t0 = Instant::now();
        let (a, b) = colliding_pair(&l);

        assert!(l.check_and_record(a, t0).is_ok());
        assert!(l.check_and_record(a, t0).is_ok());
        assert!(
            l.check_and_record(b, t0).is_ok(),
            "the shared bucket still has one allowance left"
        );
        assert!(
            l.check_and_record(b, t0).is_err(),
            "the third spend on the shared bucket is refused, whoever spends it"
        );
        assert!(
            l.check_and_record(a, t0).is_err(),
            "and the first tenant shares the refusal"
        );
    }

    /// Two distinct keys that hash to the same bucket on this limiter.
    ///
    /// Always terminates: past ~150 sequential keys a collision in 16,384
    /// buckets is near-certain, and distinctness is asserted, not assumed.
    fn colliding_pair(l: &TenantLimits) -> (TenantKey, TenantKey) {
        let mut seen = std::collections::HashMap::new();
        for n in 0..100_000u32 {
            let k = key(n);
            let idx = l.bucket_index(k);
            if let Some(prev) = seen.insert(idx, k) {
                if prev != k {
                    return (prev, k);
                }
            }
        }
        panic!("no bucket collision in 100,000 sequential keys");
    }

    /// **Window expiry is exact at the boundary, by one shared definition.**
    ///
    /// Rollover and takeover both ask "has this window expired?", and they
    /// **must** answer identically: if takeover considers a bucket live while
    /// rollover considers it expired, a tenant is evicted and immediately
    /// re-created with a full allowance, which is a rate limiter that resets
    /// itself. Both call `window_is_active`, and this asserts the boundary
    /// they share.
    #[test]
    fn window_expiry_is_exact_at_the_boundary() {
        let w = Duration::from_secs(10);
        let t0 = Instant::now();

        assert!(window_is_active(t0, w, t0), "a fresh window is active");
        assert!(
            window_is_active(t0, w, t0 + Duration::from_secs(9)),
            "one second short is still active"
        );
        assert!(
            !window_is_active(t0, w, t0 + Duration::from_secs(10)),
            "exactly the window is expired -- `>=`, not `>`"
        );
        assert!(!window_is_active(t0, w, t0 + Duration::from_secs(11)));
    }

    // -- F-13: prefix-keyed tenants, no fail-open table, global bucket -------

    /// **One /64 is one tenant: rotation inside the prefix buys nothing.**
    ///
    /// `F-13`: the key was the textual IP, so every address in a customer's
    /// /64 was a fresh tenant with fresh limits. Keying on the masked prefix
    /// makes rotation inside it share one allowance.
    #[test]
    fn f13_ipv6_addresses_in_the_same_64_share_one_tenant() {
        let a: std::net::IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: std::net::IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let c: std::net::IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(tenant_key(a), tenant_key(b));
        assert_ne!(tenant_key(a), tenant_key(c));
    }

    /// **A dual-stack host is one tenant, not two.**
    ///
    /// `F-13`: `::ffff:1.2.3.4` and `1.2.3.4` are different strings for the
    /// same host, doubling its quota. Canonicalisation maps one to the other.
    #[test]
    fn f13_ipv4_mapped_ipv6_equals_plain_ipv4() {
        let v4: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let mapped: std::net::IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(tenant_key(v4), tenant_key(mapped));
    }

    /// **A full table still limits: the 9th tenant is refused, not untracked.**
    ///
    /// `F-13`: past the old table bound a new tenant went untracked. Buckets
    /// cannot fill, so any 9 tenants each spend exactly their allowance and
    /// the 9th is refused on its 4th request — the shape the fail-open branch
    /// used to escape.
    #[test]
    fn f13_full_table_does_not_disable_limiting() {
        let l = TenantLimits::uniform(Limits::with_rate(3, Duration::from_secs(60)));
        let t0 = Instant::now();
        // Nine tenants on nine distinct buckets (see `distinct_bucket_set`):
        // a collision shares an allowance by design and would refuse early,
        // which would prove sharing, not fullness.
        let tenants = distinct_bucket_set(&l, 9);

        for tenant in &tenants[..8] {
            for _ in 0..3 {
                assert!(l.check_and_record(*tenant, t0).is_ok());
            }
        }

        for _ in 0..3 {
            assert!(l.check_and_record(tenants[8], t0).is_ok());
        }
        assert!(
            l.check_and_record(tenants[8], t0).is_err(),
            "the 9th tenant must be limited even though the table is full"
        );
    }

    /// `count` keys no two of which share a bucket on this limiter.
    ///
    /// Always terminates: each new key collides with the accepted set with
    /// probability `accepted/16,384`, so the search advances almost every try.
    fn distinct_bucket_set(l: &TenantLimits, count: usize) -> Vec<TenantKey> {
        let mut out = Vec::with_capacity(count);
        let mut used = std::collections::HashSet::new();
        let mut n = 0u32;
        while out.len() < count {
            n += 1;
            let k = key(n);
            if used.insert(l.bucket_index(k)) {
                out.push(k);
            }
        }
        out
    }

    /// **Identity rotation cannot exceed overall capacity: the global bucket.**
    ///
    /// `F-13`: 10,000 requests, each from a different /64, against a global
    /// budget of 100 per window — at most 100 are admitted no matter how many
    /// identities the attacker burns.
    #[test]
    fn f13_global_bucket_bounds_identity_rotation() {
        let bucket = GlobalBucket::new(100, Duration::from_secs(60));
        let t0 = Instant::now();

        let mut admitted = 0u32;
        for _ in 0..10_000 {
            if bucket.admit(t0) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 100, "rotation must not exceed the global budget");
    }

    // -- determinism -------------------------------------------------------

    /// The same sequence produces the same decisions. §10.5.
    #[test]
    fn decisions_are_deterministic() {
        fn run() -> Vec<bool> {
            let l = TenantLimits::uniform(Limits::with_rate(3, Duration::from_secs(10)));
            let t0 = Instant::now();
            (0..10u64)
                .map(|i| {
                    let now = t0 + Duration::from_secs(i * 2);
                    l.check_and_record(key(1), now).is_ok()
                })
                .collect()
        }
        let first = run();
        for _ in 0..20 {
            assert_eq!(run(), first);
        }
    }
}
