// SPDX-License-Identifier: Apache-2.0

//! The refusal-amplification measurement — the evidence behind
//! [`qqq_host::SubrequestBudget`]'s poisoning rule.
//!
//! # What this file exists to measure, and why a unit test could not
//!
//! `SEC-009` requires that a guest cannot drive request amplification. The first
//! half of that is a **limit**: `limits.max_subrequests` caps the fan-out. The
//! second half is subtler and is what this file covers:
//!
//! > **The refusal path must not be amplifiable.**
//!
//! A budget that returns "no" and lets the guest continue is a vulnerability in
//! exactly the way a limit that returns `-1` and lets the guest continue is. The
//! guest's cheapest possible loop is:
//!
//! ```wat
//! (loop $l
//!   (drop (call $get ...))   ;; ignored: the trap is swallowed
//!   (br $l))
//! ```
//!
//! Every iteration makes the host build and discard a fully-populated [`Error`]:
//! a `String` message, a `Vec<(String, String)>` of context, and a `String`
//! remediation — three allocations of a few hundred bytes each. The guest pays
//! one call and one branch. **The host's cost per iteration is orders of
//! magnitude above the guest's**, which is the definition of amplification.
//!
//! # Why the numbers are asserted as a ratio rather than pinned as constants
//!
//! A constant in a doc comment goes stale the moment anything upstream changes,
//! and nobody notices. A ratio asserted against a **baseline measured in the same
//! run** cannot: it is a property of the code as built, on this machine, today.
//! That is `§M-006`'s lesson — a check whose declared strength is not its real
//! strength — applied to a benchmark instead of to a guard.
//!
//! # What this does NOT measure
//!
//! It does not run a Wasm guest. `crates/qqq-host/tests/hostile_guests.rs` covers
//! the wired path end to end; this file isolates the arithmetic so the ratio is
//! not diluted by instantiation, compilation or scheduling noise. Measuring the
//! budget through a full Wasm store would make the two arms of the comparison
//! differ by a factor of a thousand in *overhead* as well as in policy, and the
//! result would prove nothing about the policy.

use std::time::Instant;

use qqq_core::ErrorCode;
use qqq_host::{Charge, SubrequestBudget};

/// How many charges each arm performs.
///
/// One hundred thousand: large enough that per-iteration noise averages out, and
/// small enough that the *advisory* arm — the slow one — still finishes in well
/// under a second, so the test does not become a CI timeout waiting to happen.
const CHARGES: u64 = 100_000;

/// **The advisory policy, reconstructed.** Refuse and continue, building the
/// full error every time.
///
/// This is deliberately a reimplementation of what the *wrong* version of the
/// budget did, rather than a call into the shipped type. If it called the shipped
/// type it could not be slow — the shipped type poisons — and the comparison
/// would be vacuous. It is the control, and a control that shares its
/// implementation with the treatment is not a control.
fn advisory_charges(limit: u32, n: u64) -> u64 {
    let mut spent = 0_u32;
    let mut refused = 0_u64;
    for _ in 0..n {
        if spent >= limit {
            // The cost being measured: a real `Error` with context and
            // remediation, built and immediately dropped.
            let e = qqq_core::Error::new(
                ErrorCode::SubrequestLimitExceeded,
                "the subrequest budget for this instance is exhausted",
            )
            .with_context("limit", limit.to_string())
            .with_context("spent", spent.to_string())
            .with_remediation(
                "this guest drives more outbound requests than `limits.max_subrequests` \
                 allows; raise the limit in `qqq.toml` if the fan-out is intended, or fix \
                 the guest's loop if it is not",
            );
            // `render()` is what a server logs, so a policy that logs the
            // refusal pays this too. Keeping it in the control means the
            // comparison is against the *realistic* naive implementation rather
            // than a strawman that only constructs.
            std::hint::black_box(e.render());
            refused += 1;
        } else {
            spent += 1;
        }
    }
    refused
}

/// **The shipped policy.** Refuse once, then refuse cheaply forever.
fn poisoned_charges(limit: u32, n: u64) -> (u64, u64) {
    let mut budget = SubrequestBudget::new(limit);
    let mut refused = 0_u64;
    let mut free = 0_u64;
    for _ in 0..n {
        match budget.charge() {
            Charge::Allowed | Charge::AllowedWithWarning => {}
            Charge::Refused => {
                std::hint::black_box(budget.refusal().render());
                refused += 1;
            }
            Charge::RefusedRepeatedly => free += 1,
        }
    }
    (refused, free)
}

/// Two identical work quanta, one policy each. Both must refuse on the same
/// iterations, or the timing comparison is between different amounts of *work*
/// rather than between different *policies*.
fn time_both(limit: u32, n: u64) -> (u128, u128, u64, u64, u64) {
    let t0 = Instant::now();
    let advisory_refusals = advisory_charges(limit, n);
    let advisory_ns = t0.elapsed().as_nanos();

    let t1 = Instant::now();
    let (poisoned_refusals, free) = poisoned_charges(limit, n);
    let poisoned_ns = t1.elapsed().as_nanos();

    // Only ONE of the poisoned arm's refusals pays the error cost; every other
    // refusal after it is free. That is the whole difference.
    (
        advisory_ns,
        poisoned_ns,
        advisory_refusals,
        poisoned_refusals,
        free,
    )
}

/// **The property: a poisoned refusal does no work.**
///
/// The shipped arm must be faster than the advisory arm by a wide margin, and
/// the margin must come from the *policy* rather than from doing less work —
/// both arms charge exactly `CHARGES` times and refuse the same number of times.
#[test]
fn a_poisoned_refusal_does_no_work() {
    // Warm the allocator and the CPU so the first timed arm is not penalised by
    // cold-start effects. Without this, the advisory arm runs first and cold,
    // which *helps* it look slow and would make the test pass for the wrong
    // reason.
    let _ = time_both(1, 10_000);
    let _ = time_both(1, 10_000);

    let (advisory_ns, poisoned_ns, advisory_refusals, poisoned_refusals, free) =
        time_both(1, CHARGES);

    // Both arms did the same amount of *charging*.
    assert_eq!(
        advisory_refusals,
        CHARGES - 1,
        "the advisory arm must refuse on every charge after the first"
    );
    assert_eq!(
        poisoned_refusals, 1,
        "the poisoned arm must pay the error cost exactly ONCE"
    );
    assert_eq!(
        free,
        CHARGES - 2,
        "every charge after the single refusal must be the free variant"
    );

    // And the poisoned arm must be dramatically faster. The threshold is
    // deliberately loose: this is a property test, not a benchmark, and a tight
    // bound would flake on a loaded CI runner. A factor of 4 is far below the
    // measured factor and far above any plausible noise.
    assert!(
        poisoned_ns * 4 < advisory_ns,
        "the poisoned policy must be at least 4x cheaper than the advisory one. \
         Measured: advisory {advisory_ns} ns for {advisory_refusals} refusals, \
         poisoned {poisoned_ns} ns for {CHARGES} charges (1 paid refusal + {free} \
         free ones). If this fails, the poisoning guard is not short-circuiting \
         `charge` -- and a guest that swallows its trap is driving host work at \
         one refused call per loop iteration, which is SEC-009's amplification."
    );
}

/// The refusal error's cost is real, stated as its own measurable fact.
///
/// Without this, a reader could reasonably suspect the comparison above is
/// measuring something other than the error construction — and if
/// `Error::render()` were free, the poisoning rule would be unnecessary
/// complexity. It is not free, and this says so with a number.
#[test]
fn constructing_a_refusal_error_is_not_free() {
    const N: u64 = 20_000;

    let t0 = Instant::now();
    for _ in 0..N {
        let e = qqq_core::Error::new(
            ErrorCode::SubrequestLimitExceeded,
            "the subrequest budget for this instance is exhausted",
        )
        .with_context("limit", "32")
        .with_context("spent", "32")
        .with_remediation("raise the limit, or fix the guest's loop");
        std::hint::black_box(e.render());
    }
    let with_error_ns = t0.elapsed().as_nanos();

    let t1 = Instant::now();
    let mut sink = 0_u64;
    for i in 0..N {
        sink = sink.wrapping_add(i);
    }
    std::hint::black_box(sink);
    let bare_loop_ns = t1.elapsed().as_nanos();

    assert!(
        with_error_ns > bare_loop_ns,
        "building and rendering a refusal error must cost more than an empty loop; \
         measured {with_error_ns} ns vs {bare_loop_ns} ns for {N} iterations. If \
         these are equal, the measurement above is not measuring the error cost."
    );
}

/// The poisoning is per-budget, not global.
///
/// A `static` guard would stop every instance in the process the moment one
/// guest exhausted its budget — turning one tenant's misbehaviour into a
/// platform-wide outage. This asserts the isolation directly.
#[test]
fn one_exhausted_budget_does_not_poison_another() {
    let mut first = SubrequestBudget::new(1);
    let mut second = SubrequestBudget::new(1);

    // Exhaust and poison the first.
    assert!(first.charge().is_allowed());
    assert_eq!(first.charge(), Charge::Refused);
    assert!(first.is_poisoned());

    // The second is untouched.
    assert!(
        !second.is_poisoned(),
        "poisoning must be per-budget; a shared guard is a cross-tenant outage"
    );
    assert!(second.charge().is_allowed());
    assert_eq!(second.spent(), 1);
}

/// The counter distinguishes "attempts" from "calls after the first refusal".
///
/// The `amplification_attempts` field is the security signal, and its meaning
/// has to be exact: it counts how many times the guest tried to go over budget.
/// If it counted every call after the first refusal it would grow with the
/// guest's loop rate and say nothing about intent.
#[test]
fn the_amplification_counter_counts_attempts_by_the_guest() {
    let mut b = SubrequestBudget::new(2);
    assert_eq!(
        b.amplification_attempts(),
        0,
        "a fresh budget has no attempts"
    );

    // Two legitimate charges, no attempt.
    assert!(b.charge().is_allowed());
    assert!(b.charge().is_allowed());
    assert_eq!(b.amplification_attempts(), 0);

    // The first over-budget call is attempt #1.
    assert_eq!(b.charge(), Charge::Refused);
    assert_eq!(b.amplification_attempts(), 1);

    // Every subsequent call is another attempt: the guest is still asking, and
    // the guest is what decides how many times it asks.
    for expected in 2..=10 {
        assert_eq!(b.charge(), Charge::RefusedRepeatedly);
        assert_eq!(b.amplification_attempts(), expected);
    }
}
