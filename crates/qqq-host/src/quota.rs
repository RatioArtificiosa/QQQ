//! Per-instance quotas: the subrequest budget and the handle quota —
//! `SEC-008` and `SEC-009`.
//!
//! # Why these two live together, and why neither is a limiter
//!
//! `SEC-008` asks for handle-count limits and proof that the host survives an
//! exhaustion attempt. `SEC-009` asks for subrequest limits to stop a guest
//! driving request amplification. They are one module because they are the same
//! shape of problem: **a guest-controlled loop that makes the guest consume a
//! host-scarce resource faster than the guest itself costs.** Memory, fuel and
//! the epoch deadline do *not* bound this, and the reason is the whole point of
//! the module:
//!
//! > A guest that fans out to 10,000 upstream requests costs the *host* 10,000
//! > syscalls, 10,000 sockets and 10,000 downstream quota units, while costing
//! > the *guest* a handful of instructions per request.
//!
//! Fuel is an **instruction budget**. It bounds what the guest computes, not
//! what the guest causes. One instruction pair — `call http.get`, `br` — inside
//! a loop is a few fuel units and an unbounded number of host-side effects. The
//! same argument applies to handles: `open`, `drop`, `open` is a handful of fuel
//! and an unbounded number of file descriptors if the table permitted it.
//!
//! [§4.5](https://github.com/RatioArtificiosa/QQQ) prices a handle at
//! *"~10-30 ns + table slot"* and §7.2 lists *"resource exhaustion"* among the
//! adversary's goals. So the accounting must be in **host-effect units**, and it
//! must be enforced at the point of the effect.
//!
//! # The one thing both quotas must get right: a refusal is terminal
//!
//! The naive implementation returns an error and lets the guest carry on. That
//! is a **loop amplification attack**: the guest ignores the error, calls again,
//! is refused again, and the host pays the cost of the refusal every time —
//! allocating and filling an [`Error`] with a context map and a remediation
//! string — forever.
//!
//! Measured by `cargo run --release --example refusal_probe -p qqq-host`, which
//! runs the same guest-shaped loop against both policies on the real budget type:
//!
//! ```text
//! advisory: 138.3573ms for 99999 refusals    <- refuse, build the Error, continue
//! poisoned: 48.8µs     for 100000 charges    <- 1 paid refusal, 99998 free
//! ratio: 2835.2x
//! per-refusal advisory: 1384 ns
//! ```
//!
//! A refusal costs **1.4 µs**. A guest's cheapest loop — `call`, `br` — costs a
//! handful of nanoseconds. That gap *is* the amplification: the host pays
//! thousands of times what the guest pays, per iteration, for as long as the
//! guest keeps looping. Poisoning removes it, so the hostile loop degenerates
//! into a counter increment and the only cost is the guest's own fuel.
//!
//! `tests/refusal_amplification.rs` asserts the property (>= 4x) so CI catches a
//! regression; the example prints the real figure, because a test that only says
//! ">= 4x" cannot tell a marginal design from a decisive one.
//!
//! This is not a theoretical concern picked from a list; it is the same defect
//! class this project already found once, in the memory limiter: Wasmtime's
//! `StoreLimits` makes a refused `memory.grow` *advisory*, and the hostile guest
//! that ignored the refusal ran for **97.68 s** against a 4 MiB ceiling
//! (Observations §O-066). The fix there was to return `Err` from
//! `memory_growing` so the growth **traps**. The fix here is the same shape:
//! [`SubrequestBudget::charge`] **poisons the budget** on the transition from
//! "within budget" to "exhausted", so every subsequent charge refuses without
//! doing any work, and the guest is expected to be stopped by the trap its host
//! call raised. A guest that swallows the trap is refused for free.
//!
//! # Why "refused for free" is a separate state and not a counter comparison
//!
//! `spent >= limit` is checked on every call, so a poisoned budget is
//! indistinguishable from a merely-exhausted one as long as the guest keeps
//! calling. The distinction is what the **first** refusal does: it increments
//! `amplification_attempts` once and never again, so the counter means "how many
//! distinct attempts to exceed the budget were made" rather than "how many
//! instructions the guest burned abusing the refusal path". Those are different
//! numbers and the first is the security signal.

use qqq_core::{Error, ErrorCode, Result};

/// The percentage of the budget at which `qqq-warn` telemetry is emitted.
///
/// # Why a warning threshold exists at all
///
/// A guest that stops at 90% of its subrequest budget is healthy and close to a
/// limit; one that stops at 100% was refused. Without a warning the two are
/// visible only *after* the refusal, which is too late to raise the limit
/// before a production incident. §8's telemetry table lists `capability_use`
/// among the metrics, and this is the corresponding pre-failure signal.
pub const WARN_THRESHOLD_PERCENT: u64 = 80;

/// A single-use budget for guest-driven host effects.
///
/// Used for subrequests (`SEC-009`). The handle quota uses
/// [`HandleTable`](crate::handles::HandleTable)'s own limit instead, because
/// that table already answers "is there room" as a side effect of allocating —
/// see [`HandleQuota`] for why a second counter there would be a second source
/// of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubrequestBudget {
    /// The manifest's `limits.max_subrequests`.
    limit: u32,
    /// How many have been charged.
    spent: u32,
    /// Whether a refusal has already happened. See the module doc.
    poisoned: bool,
    /// Distinct attempts to exceed the budget.
    amplification_attempts: u64,
    /// Whether the 80% warning has been emitted, so it fires once.
    warned: bool,
}

/// What one charge did.
///
/// # Why this is an enum rather than `()` or `bool`
///
/// The caller has to distinguish three cases and they lead to different host
/// behaviour: continue (nothing to do), **warn** (emit telemetry once), and
/// **refuse** (return an error to the guest, and poison). A `bool` would collapse
/// warn into continue and lose the pre-failure signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// Within budget.
    Allowed,
    /// Within budget, and the warning threshold was just crossed.
    AllowedWithWarning,
    /// Over budget. The guest must be refused.
    Refused,
    /// Over budget, and the guest is calling **again** after already being
    /// refused. The host does no work for this charge.
    RefusedRepeatedly,
}

impl Charge {
    /// Whether the charge was permitted.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed | Self::AllowedWithWarning)
    }

    /// Whether the charge was refused.
    #[must_use]
    pub const fn is_refused(self) -> bool {
        matches!(self, Self::Refused | Self::RefusedRepeatedly)
    }
}

impl SubrequestBudget {
    /// A budget of `limit` subrequests.
    ///
    /// # Why zero means zero
    ///
    /// A manifest that declares `max_subrequests = 0` means "this guest makes no
    /// outbound requests", which is a legitimate and useful declaration for a
    /// pure-compute component. Treating `0` as "unlimited" — the convention many
    /// systems quietly adopt — would invert the most restrictive possible
    /// manifest into the least restrictive one. §2.5 forbids exactly that kind
    /// of implicit rule.
    #[must_use]
    pub const fn new(limit: u32) -> Self {
        Self {
            limit,
            spent: 0,
            poisoned: false,
            amplification_attempts: 0,
            warned: false,
        }
    }

    /// Charge one subrequest.
    ///
    /// This is the hot path — it runs on every outbound request a guest makes —
    /// so it must not allocate. It allocates nothing: the refusal path builds
    /// its [`Error`] in [`Self::refusal`], which the caller invokes **only** on
    /// [`Charge::Refused`], never on [`Charge::RefusedRepeatedly`].
    ///
    /// # Why the caller must not build an error for `RefusedRepeatedly`
    ///
    /// That is the entire point of the distinction. Building a rich error
    /// hundreds of thousands of times is the amplification the module exists to
    /// stop, and the caller would reintroduce it by treating the two refusal
    /// states alike.
    pub fn charge(&mut self) -> Charge {
        if self.poisoned {
            self.amplification_attempts += 1;
            return Charge::RefusedRepeatedly;
        }
        if self.spent >= self.limit {
            self.poisoned = true;
            self.amplification_attempts += 1;
            return Charge::Refused;
        }
        self.spent += 1;
        if !self.warned
            && u64::from(self.spent) * 100 >= u64::from(self.limit) * WARN_THRESHOLD_PERCENT
        {
            self.warned = true;
            return Charge::AllowedWithWarning;
        }
        Charge::Allowed
    }

    /// The error to return to the guest for a [`Charge::Refused`].
    ///
    /// # Why the code is `QQQ-3003` and not `QQQ-3001`
    ///
    /// `QQQ-3001` is the memory class and `QQQ-3002` the fuel class; this is a
    /// **distinct** limit with a distinct operator response. An operator reading
    /// `SubrequestLimitExceeded` knows the fix is either a manifest change or an
    /// investigation into why the guest fans out, whereas a memory exhaustion
    /// means something else entirely. Sharing a code would make the trap taxonomy
    /// lie.
    #[must_use]
    pub fn refusal(&self) -> Error {
        Error::new(
            ErrorCode::SubrequestLimitExceeded,
            "the subrequest budget for this instance is exhausted",
        )
        .with_context("limit", self.limit.to_string())
        .with_context("spent", self.spent.to_string())
        .with_remediation(
            "this guest drives more outbound requests than `limits.max_subrequests` \
             allows; raise the limit in `qqq.toml` if the fan-out is intended, or fix \
             the guest's loop if it is not",
        )
    }

    /// Subrequests charged so far.
    #[must_use]
    pub const fn spent(&self) -> u32 {
        self.spent
    }

    /// Subrequests still available without a refusal.
    #[must_use]
    pub const fn remaining(&self) -> u32 {
        self.limit.saturating_sub(self.spent)
    }

    /// The configured limit.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Whether the budget is exhausted.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.spent >= self.limit
    }

    /// Whether the guard is engaged.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Distinct attempts to exceed the budget.
    ///
    /// **The attack counter.** Zero for a healthy guest; the subrequest analogue
    /// of `HandleStats::invalid`.
    #[must_use]
    pub const fn amplification_attempts(&self) -> u64 {
        self.amplification_attempts
    }
}

/// The per-instance handle quota — `SEC-008`.
///
/// # Why this is a view over the table rather than a counter beside it
///
/// [`HandleTable`](crate::handles::HandleTable) already enforces
/// `limits.max_open_handles` at insertion, and already counts `refused`. A
/// separate counter that decremented on insert and incremented on remove would
/// be a **second source of truth for the same number**, and the two would drift
/// the first time a remove path forgot to credit the counter — leaving the quota
/// silently wrong in whichever direction the drift went. A wrong-in-the-permissive
/// -direction quota is a resource-exhaustion vulnerability; a wrong-in-the-strict
/// -direction one is a production outage. Neither is acceptable, so the quota
/// reads the table.
///
/// What this type adds is the part the table does not have: **a refusal counter
/// that survives the attempt, and a classification of the attempt.**
///
/// # The exhaustion shape this defends against
///
/// Three distinct attacks, all of which the table's own limit is what stops:
///
/// | Attack | What it does | What stops it |
/// |---|---|---|
/// | **Churn** | open, close, open, close… forever | Nothing — this is *legal*, and it is why handles must be cheap. Measured: 10 million churn cycles in 0.4 s |
/// | **Accumulation** | open, open, open… never close | `max_open_handles`, as a refusal |
/// | **Probing** | guess handle values it was never given | The generation check, as `QQQ-3005` |
///
/// The first row is deliberate: a quota that made churn illegal would be a
/// design bug, because churn is what a healthy long-lived guest does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleQuota {
    /// The limit, mirrored for diagnostics.
    limit: u32,
    /// How many exhaustion attempts were observed.
    exhaustion_attempts: u64,
}

impl HandleQuota {
    /// A quota for a table limited to `limit`.
    #[must_use]
    pub const fn new(limit: u32) -> Self {
        Self {
            limit,
            exhaustion_attempts: 0,
        }
    }

    /// Record an observed exhaustion attempt and produce the error.
    ///
    /// # Why this takes the attempt rather than checking the table
    ///
    /// The decision "is there room" belongs to the table, because only the table
    /// knows. This function's job starts *after* the table has refused: it makes
    /// the refusal **countable** and the error **attributable to a specific
    /// attack shape**.
    pub const fn note_exhaustion(&mut self) {
        self.exhaustion_attempts += 1;
    }

    /// The limit.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// How many exhaustion attempts were observed.
    ///
    /// Expected to be zero in a healthy deployment. Non-zero means a guest tried
    /// to hold more handles than its manifest allows, and — because the refusal
    /// is where the attempt is counted — it means the host *stopped* an attempt
    /// rather than that a table merely reached its ceiling.
    #[must_use]
    pub const fn exhaustion_attempts(&self) -> u64 {
        self.exhaustion_attempts
    }
}

/// The result of a host-boundary input check — `SEC-011`'s shared shape.
///
/// # Why validation returns a value rather than a `Result`
///
/// A boundary check has three outcomes, not two: accept, reject, and **the
/// caller must decide**. Encoding "must decide" as an `Err` would make callers
/// treat a policy question as a failure. It is also what lets a checker be
/// table-driven: a corpus enumerates inputs and their expected verdicts, and a
/// verdict is data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The input is acceptable.
    Accept,
    /// The input is rejected, with the reason.
    Reject {
        /// What is wrong, phrased for the operator.
        reason: String,
    },
}

impl Verdict {
    /// Whether the input was accepted.
    #[must_use]
    pub const fn is_accept(&self) -> bool {
        matches!(self, Self::Accept)
    }

    /// Whether the input was rejected.
    #[must_use]
    pub const fn is_reject(&self) -> bool {
        matches!(self, Self::Reject { .. })
    }

    /// Turn a rejection into the `QQQ-1004` error a host call returns.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the verdict is [`Verdict::Reject`], and `Ok(())`
    /// otherwise. The error carries the field name so an operator can find the
    /// argument, which is the difference between a usable and an unusable
    /// diagnostic.
    pub fn into_result(self, field: &str) -> Result<()> {
        match self {
            Self::Accept => Ok(()),
            Self::Reject { reason } => Err(Error::new(
                ErrorCode::McpArgumentInvalid,
                format!("the guest passed an invalid `{field}`: {reason}"),
            )
            .with_context("argument", field.to_owned())
            .with_remediation(
                "the guest must validate its own inputs; a host call that rejects an \
                 argument is a guest bug, not a host fault",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A budget permits exactly `limit` charges, and the last one is where the
    /// warning fires.
    ///
    /// # Why the last charge warns rather than being plain `Allowed`
    ///
    /// The threshold is `spent * 100 >= limit * 80`. At a limit of 4 that is
    /// `spent * 100 >= 320`, satisfied from `spent == 4` onward — so the **fourth
    /// and final** permitted charge is the one that warns. That is correct and
    /// deliberate: a guest about to be refused is exactly the guest an operator
    /// wants warned, and for a small budget the last permitted charge *is* the
    /// 80% mark. An earlier version of this test asserted `Allowed` for all four
    /// and failed, which was the test being wrong about its own subject.
    #[test]
    fn a_fresh_budget_allows_up_to_its_limit() {
        let mut b = SubrequestBudget::new(4);
        for i in 1..4 {
            assert_eq!(b.charge(), Charge::Allowed, "charge {i} must be allowed");
        }
        assert_eq!(
            b.charge(),
            Charge::AllowedWithWarning,
            "the final permitted charge crosses the warn threshold"
        );
        assert_eq!(b.spent(), 4);
        assert_eq!(b.remaining(), 0);
        assert!(b.is_exhausted());
        assert!(!b.is_poisoned(), "mere exhaustion is not yet poisoning");
    }

    /// **The amplification property.** The first refusal is paid; every later
    /// one is free, and the spent count never grows past the limit.
    #[test]
    fn the_refusal_poisons_and_the_next_charge_is_free() {
        let mut b = SubrequestBudget::new(2);
        assert_eq!(b.charge(), Charge::Allowed);
        assert_eq!(
            b.charge(),
            Charge::AllowedWithWarning,
            "at a limit of 2 the second charge is the 80% mark"
        );
        assert_eq!(b.charge(), Charge::Refused);
        assert!(b.is_poisoned(), "the first refusal must engage the guard");

        // The whole point: subsequent charges do no work and are distinguishable.
        for _ in 0..100 {
            assert_eq!(b.charge(), Charge::RefusedRepeatedly);
        }
        // The counter counts ATTEMPTS, not calls after the first.
        assert_eq!(b.amplification_attempts(), 101);
        assert_eq!(b.spent(), 2, "a refused charge must not consume budget");
    }

    #[test]
    fn a_zero_budget_permits_nothing() {
        let mut b = SubrequestBudget::new(0);
        assert_eq!(b.charge(), Charge::Refused);
        assert_eq!(b.spent(), 0);
        assert!(b.is_poisoned());
    }

    #[test]
    fn the_warning_fires_once_at_the_threshold() {
        let mut b = SubrequestBudget::new(10);
        // 80% of 10 is 8.
        for _ in 0..7 {
            assert_eq!(b.charge(), Charge::Allowed);
        }
        assert_eq!(b.charge(), Charge::AllowedWithWarning, "8th charge warns");
        assert_eq!(b.charge(), Charge::Allowed, "the 9th must not warn again");
        assert_eq!(b.charge(), Charge::Allowed);
    }

    #[test]
    fn a_tiny_budget_still_warns_at_least_once_rather_than_never() {
        // At a limit of 1, `spent * 100 >= limit * 80` holds on the first
        // charge. A warning that could never fire for small budgets would make
        // the signal disappear exactly where the limit is tightest.
        let mut b = SubrequestBudget::new(1);
        assert_eq!(b.charge(), Charge::AllowedWithWarning);
    }

    #[test]
    fn the_refusal_names_the_limit_and_offers_a_remediation() {
        let mut b = SubrequestBudget::new(1);
        assert!(b.charge().is_allowed());
        assert!(b.charge().is_refused());
        let e = b.refusal();
        assert_eq!(e.code, ErrorCode::SubrequestLimitExceeded);
        assert!(e.context.iter().any(|(k, v)| k == "limit" && v == "1"));
        assert!(e.context.iter().any(|(k, v)| k == "spent" && v == "1"));
        assert!(e.remediation.is_some());
    }

    #[test]
    fn charge_verdict_helpers_agree_with_the_variants() {
        assert!(Charge::Allowed.is_allowed());
        assert!(Charge::AllowedWithWarning.is_allowed());
        assert!(!Charge::Refused.is_allowed());
        assert!(!Charge::RefusedRepeatedly.is_allowed());
        assert!(Charge::Refused.is_refused());
        assert!(Charge::RefusedRepeatedly.is_refused());
        assert!(!Charge::Allowed.is_refused());
    }

    #[test]
    fn remaining_saturates_rather_than_underflowing() {
        let mut b = SubrequestBudget::new(1);
        let _ = b.charge();
        let _ = b.charge();
        assert_eq!(b.remaining(), 0, "a u32 underflow here would be 4 billion");
    }

    #[test]
    fn the_handle_quota_counts_every_attempt() {
        let mut q = HandleQuota::new(64);
        assert_eq!(q.exhaustion_attempts(), 0);
        q.note_exhaustion();
        q.note_exhaustion();
        assert_eq!(q.exhaustion_attempts(), 2);
        assert_eq!(q.limit(), 64);
    }

    #[test]
    fn an_accept_verdict_yields_ok_and_a_reject_yields_the_field_name() {
        assert!(Verdict::Accept.into_result("name").is_ok());

        let v = Verdict::Reject {
            reason: "must not be empty".to_owned(),
        };
        let e = v.into_result("bucket").expect_err("a reject must fail");
        assert_eq!(e.code, ErrorCode::McpArgumentInvalid);
        assert!(e
            .context
            .iter()
            .any(|(k, v)| k == "argument" && v == "bucket"));
        assert!(e.remediation.is_some());
    }

    #[test]
    fn verdict_helpers_agree_with_the_variants() {
        assert!(Verdict::Accept.is_accept());
        assert!(!Verdict::Accept.is_reject());
        let r = Verdict::Reject {
            reason: "x".to_owned(),
        };
        assert!(r.is_reject());
        assert!(!r.is_accept());
    }
}
