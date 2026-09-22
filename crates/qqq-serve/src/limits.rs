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
//! The two are updated at the same site, so they cannot disagree about what happened; they
//! are simply not the same value.
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
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        }
    }

    /// A body cap, with no request-rate limit.
    #[must_use]
    pub const fn with_body(max_body_bytes: u64) -> Self {
        Self {
            max_body_bytes: Some(max_body_bytes),
            max_requests_per_window: None,
            window: Duration::from_secs(60),
        }
    }

    /// A request-rate limit, with no body cap.
    #[must_use]
    pub const fn with_rate(max_requests_per_window: u32, window: Duration) -> Self {
        Self {
            max_body_bytes: None,
            max_requests_per_window: Some(max_requests_per_window),
            window,
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

/// One tenant's rolling window.
#[derive(Debug, Clone, Copy)]
struct Window {
    /// When the current window began.
    started: Instant,
    /// Requests seen in it.
    count: u32,
}

/// Per-tenant limits and their accounting.
///
/// Interior mutability behind a `Mutex` rather than atomics: the window is a **pair** of
/// values that must be updated together, and two atomics would let a reader see a new
/// `started` with an old `count` — a torn read that shows an impossible state and, worse,
/// occasionally admits a burst twice the intended size.
#[derive(Debug)]
pub struct TenantLimits {
    /// The limits, by tenant name.
    limits: Arc<BTreeMap<String, Limits>>,
    /// The limit applied to a tenant with no entry.
    fallback: Limits,
    /// The rolling windows, by tenant.
    windows: std::sync::Mutex<BTreeMap<String, Window>>,
    /// The largest number of tenants whose windows are tracked.
    ///
    /// Bounded for the same reason the metric label is (§10.2): the tenant is the peer IP, so
    /// an unbounded map is a memory leak an attacker drives. Past the ceiling a new tenant
    /// falls back to the fallback limits **with no window** — a deliberate choice to fail
    /// open on *rate* rather than allocating without limit. The body cap needs no state and
    /// still applies, and that is the limit which actually protects memory.
    max_tracked: usize,
}

impl TenantLimits {
    /// The default ceiling on tracked windows.
    pub const DEFAULT_MAX_TRACKED: usize = 4096;

    /// Build a limiter from a table and a fallback.
    #[must_use]
    pub fn new<I>(limits: I, fallback: Limits) -> Self
    where
        I: IntoIterator<Item = (String, Limits)>,
    {
        Self {
            limits: Arc::new(limits.into_iter().collect()),
            fallback,
            windows: std::sync::Mutex::new(BTreeMap::new()),
            max_tracked: Self::DEFAULT_MAX_TRACKED,
        }
    }

    /// A limiter that applies the same limits to every tenant.
    #[must_use]
    pub fn uniform(limits: Limits) -> Self {
        Self::new(std::iter::empty(), limits)
    }

    /// The limits that apply to a tenant.
    #[must_use]
    pub fn limits_for(&self, tenant: &str) -> Limits {
        self.limits.get(tenant).copied().unwrap_or(self.fallback)
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
    pub fn check_body(&self, tenant: &str, len: u64) -> Result<(), Refusal> {
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
    pub fn check_and_record(&self, tenant: &str, now: Instant) -> Result<(), Refusal> {
        let limits = self.limits_for(tenant);
        let Some(max) = limits.max_requests_per_window else {
            // No rate limit: count nothing, because a window nobody reads is a map entry an
            // attacker can drive for free.
            return Ok(());
        };

        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // A full map admits no new tenants. Failing open on *rate* is deliberate: the body
        // cap is what protects memory and needs no state, so a new tenant still cannot send
        // an unbounded body. Refusing instead would let an attacker lock out every
        // legitimate new tenant by filling the map.
        if !windows.contains_key(tenant) && windows.len() >= self.max_tracked {
            return Ok(());
        }

        let entry = windows.entry(tenant.to_owned()).or_insert(Window {
            started: now,
            count: 0,
        });

        // The rollover is **lazy**: a window expires when the next request arrives rather
        // than on a timer. A timer would be a second authority on time, and an expired window
        // for a tenant that has gone away is state worth reclaiming only when next touched.
        if now.saturating_duration_since(entry.started) >= limits.window {
            entry.started = now;
            entry.count = 0;
        }

        if entry.count >= max {
            return Err(Refusal::RateExceeded {
                limit: max,
                window_secs: limits.window.as_secs(),
            });
        }
        entry.count = entry.count.saturating_add(1);
        Ok(())
    }

    /// How many tenants have a tracked window.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- the limit table ---------------------------------------------------

    /// A tenant with an entry gets its own limits.
    #[test]
    fn a_tenant_gets_its_own_limits() {
        let l = TenantLimits::new(
            [("big".to_owned(), Limits::with_body(1_000_000))],
            Limits::with_body(1_000),
        );
        assert_eq!(l.limits_for("big").max_body_bytes, Some(1_000_000));
        assert_eq!(l.limits_for("small").max_body_bytes, Some(1_000));
    }

    /// A uniform limiter applies one limit to everyone.
    #[test]
    fn a_uniform_limiter_applies_to_everyone() {
        let l = TenantLimits::uniform(Limits::with_body(500));
        assert_eq!(l.limits_for("a").max_body_bytes, Some(500));
        assert_eq!(l.limits_for("b").max_body_bytes, Some(500));
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

        assert!(l.check_body("t", 0).is_ok(), "an empty body is always fine");
        assert!(l.check_body("t", 99).is_ok());
        assert!(
            l.check_body("t", 100).is_ok(),
            "the bound is inclusive: `<=` the cap, or the cap is a lie by one byte"
        );
        let err = l
            .check_body("t", 101)
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
        let err = l.check_body("t", 5_000_000).expect_err("refused");
        let text = err.to_string();
        assert!(text.contains("1048576"), "{text}");
        assert!(text.contains("5000000"), "{text}");
    }

    /// A tenant with no cap is unlimited, not refused.
    #[test]
    fn no_cap_means_unlimited() {
        let l = TenantLimits::uniform(Limits::none());
        assert!(l.check_body("t", u64::MAX).is_ok());
    }

    /// **`None` and `Some(0)` are different**, and the difference is total refusal.
    #[test]
    fn none_and_zero_are_different() {
        let unlimited = TenantLimits::uniform(Limits::none());
        let zero = TenantLimits::uniform(Limits::with_body(0));

        assert!(unlimited.check_body("t", 1).is_ok(), "None is unlimited");
        assert!(zero.check_body("t", 0).is_ok(), "an empty body still fits");
        assert!(
            zero.check_body("t", 1).is_err(),
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
                l.check_and_record("t", t0).is_ok(),
                "request {i} must be admitted"
            );
        }
        let err = l
            .check_and_record("t", t0)
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

        assert!(l.check_and_record("t", t0).is_ok());
        assert!(l.check_and_record("t", t0).is_ok());
        assert!(l.check_and_record("t", t0).is_err(), "spent");

        assert!(
            l.check_and_record("t", t0 + Duration::from_secs(9))
                .is_err(),
            "the window has not elapsed"
        );
        assert!(
            l.check_and_record("t", t0 + Duration::from_secs(10))
                .is_ok(),
            "the window has elapsed, so the allowance is restored"
        );
    }

    /// A tenant with no rate limit is never refused and tracks no window.
    #[test]
    fn no_rate_limit_never_refuses_and_tracks_nothing() {
        let l = TenantLimits::uniform(Limits::none());
        let t0 = Instant::now();
        for _ in 0..10_000 {
            assert!(l.check_and_record("t", t0).is_ok());
        }
        assert_eq!(
            l.tracked(),
            0,
            "a window nobody reads is a map entry an attacker can drive for free"
        );
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

        assert!(l.check_and_record("a", t0).is_ok());
        assert!(l.check_and_record("a", t0).is_ok());
        assert!(l.check_and_record("a", t0).is_err(), "a is spent");

        assert!(
            l.check_and_record("b", t0).is_ok(),
            "b must have its own full allowance"
        );
        assert!(l.check_and_record("b", t0).is_ok());
        assert!(
            l.check_and_record("b", t0).is_err(),
            "and b is now spent too"
        );
    }

    /// Per-tenant limits differ, and the limiter honours the table.
    #[test]
    fn a_tenant_can_have_a_larger_allowance() {
        let l = TenantLimits::new(
            [(
                "vip".to_owned(),
                Limits::with_rate(100, Duration::from_secs(60)),
            )],
            Limits::with_rate(1, Duration::from_secs(60)),
        );
        let t0 = Instant::now();

        assert!(l.check_and_record("free", t0).is_ok());
        assert!(
            l.check_and_record("free", t0).is_err(),
            "the free tier is spent"
        );

        for _ in 0..100 {
            assert!(
                l.check_and_record("vip", t0).is_ok(),
                "vip has its own allowance"
            );
        }
        assert!(
            l.check_and_record("vip", t0).is_err(),
            "and its own ceiling"
        );
    }

    // -- bounds ------------------------------------------------------------

    /// **The tracked-window map is bounded, and past the bound it fails open.**
    ///
    /// The tenant is the peer IP, so an unbounded map is a memory leak an attacker drives.
    /// Past the ceiling a new tenant gets the fallback limits with **no window** — deliberate:
    /// the body cap needs no state and still applies, so a new tenant cannot send an unbounded
    /// body. Refusing instead would let an attacker lock out every legitimate new tenant by
    /// filling the map.
    #[test]
    fn the_tracked_window_map_is_bounded() {
        let mut l = TenantLimits::uniform(Limits::with_rate(1, Duration::from_secs(60)));
        l.max_tracked = 8;
        let t0 = Instant::now();

        for i in 0..8 {
            assert!(l.check_and_record(&format!("t{i}"), t0).is_ok());
        }
        assert_eq!(l.tracked(), 8);

        assert!(
            l.check_and_record("t8", t0).is_ok(),
            "a tenant past the ceiling fails open on rate"
        );
        assert_eq!(l.tracked(), 8, "and must not grow the map");
    }

    /// **A tenant already tracked keeps being limited past the ceiling.**
    ///
    /// The control: the ceiling must not stop existing tenants being limited, or filling the
    /// map would be a way to disable rate limiting entirely.
    #[test]
    fn a_tracked_tenant_is_still_limited_past_the_ceiling() {
        let mut l = TenantLimits::uniform(Limits::with_rate(1, Duration::from_secs(60)));
        l.max_tracked = 4;
        let t0 = Instant::now();

        assert!(l.check_and_record("t0", t0).is_ok());
        for i in 1..10 {
            let _ = l.check_and_record(&format!("t{i}"), t0);
        }

        assert!(
            l.check_and_record("t0", t0).is_err(),
            "an already-tracked tenant must still be limited"
        );
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
                    l.check_and_record("t", now).is_ok()
                })
                .collect()
        }
        let first = run();
        for _ in 0..20 {
            assert_eq!(run(), first);
        }
    }
}
