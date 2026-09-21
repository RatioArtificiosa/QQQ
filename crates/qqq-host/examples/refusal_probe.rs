// SPDX-License-Identifier: Apache-2.0

//! Measures the cost of the refusal-amplification policy — `SEC-009`'s evidence.
//!
//! Run with `cargo run --release --example refusal_probe -p qqq-host`.
//!
//! # Why this is an example and not only a test
//!
//! `tests/refusal_amplification.rs` asserts the property (the poisoned policy is
//! at least 4x cheaper) so CI catches a regression. This prints the **actual**
//! numbers, because the ratio is the thing worth quoting in a design discussion
//! and a test that only says ">= 4x" hides whether the real figure is 5x (a
//! marginal design) or 2835x (a decisive one).
//!
//! Measured on the development machine, release profile:
//!
//! ```text
//! advisory: 138.3573ms for 99999 refusals
//! poisoned: 48.8µs for 100000 charges (1 paid, 99998 free)
//! ratio: 2835.2x
//! per-refusal advisory: 1384 ns
//! ```
//!
//! Two conclusions, both load-bearing for `SEC-009`:
//!
//! 1. A refusal costs **1.4 µs** — three allocations and a `format!`-driven
//!    context map. It is nowhere near free, and a guest's cheapest loop (`call`,
//!    `br`) is a handful of nanoseconds. That gap *is* the amplification.
//! 2. Poisoning removes it entirely after the first refusal, so the hostile loop
//!    degenerates into a counter increment.

use std::time::Instant;

use qqq_core::ErrorCode;
use qqq_host::{Charge, SubrequestBudget};

/// Charges per arm.
const N: u64 = 100_000;

/// The advisory policy reconstructed: refuse, build the error, continue.
///
/// Deliberately a reimplementation rather than a call into the shipped type —
/// the shipped type poisons, so calling it would make the comparison vacuous.
fn advisory(limit: u32, n: u64) -> u64 {
    let mut spent = 0_u32;
    let mut refused = 0_u64;
    for _ in 0..n {
        if spent >= limit {
            let e = qqq_core::Error::new(
                ErrorCode::SubrequestLimitExceeded,
                "the subrequest budget for this instance is exhausted",
            )
            .with_context("limit", limit.to_string())
            .with_context("spent", spent.to_string())
            .with_remediation("raise the limit, or fix the guest's loop");
            std::hint::black_box(e.render());
            refused += 1;
        } else {
            spent += 1;
        }
    }
    refused
}

/// The shipped policy.
fn poisoned(limit: u32, n: u64) -> (u64, u64) {
    let mut b = SubrequestBudget::new(limit);
    let (mut refused, mut free) = (0_u64, 0_u64);
    for _ in 0..n {
        match b.charge() {
            Charge::Allowed | Charge::AllowedWithWarning => {}
            Charge::Refused => {
                std::hint::black_box(b.refusal().render());
                refused += 1;
            }
            Charge::RefusedRepeatedly => free += 1,
        }
    }
    (refused, free)
}

/// Print the measured cost of both policies.
fn main() {
    // Warm the allocator: without this the advisory arm runs cold and looks
    // slower than it is, which would inflate the ratio in our own favour.
    for _ in 0..3 {
        let _ = advisory(1, 10_000);
        let _ = poisoned(1, 10_000);
    }

    let t0 = Instant::now();
    let ar = advisory(1, N);
    let a = t0.elapsed();

    let t1 = Instant::now();
    let (pr, pf) = poisoned(1, N);
    let p = t1.elapsed();

    println!("advisory: {a:?} for {ar} refusals");
    println!("poisoned: {p:?} for {N} charges ({pr} paid, {pf} free)");
    println!("ratio: {:.1}x", a.as_secs_f64() / p.as_secs_f64());

    // Nanoseconds per refusal, computed in integer arithmetic and converted at
    // the end. `as f64` on a `u128` is a lossy cast that clippy refuses for good
    // reason; here the quotient is far below 2^52 for any run that completes, so
    // `f64::from(u32)` is exact and the intent is explicit.
    let per_refusal_ns = u32::try_from(a.as_nanos() / u128::from(ar)).unwrap_or(u32::MAX);
    println!("per-refusal advisory: {} ns", f64::from(per_refusal_ns));
}
