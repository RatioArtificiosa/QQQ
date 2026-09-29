// SPDX-License-Identifier: Apache-2.0

//! Guest-side assertion macros for QQQ components — Checklist `TEST-007`, `TEST-008`.
//!
//! Proposal §6.7's table, which is the specification these two macros implement:
//!
//! > | **Capability assertions** | `assert_caps!` fails a test if the code under test attempts a capability
//! > | the test declared it should not need |
//! > | **Fuel assertions** | `assert_fuel_below!(n)` turns a performance regression into a test failure |
//!
//! # Why this exists as an interface and a macro rather than a library
//!
//! `assert_caps!` has to know **what the code under test attempted**, and a guest cannot see that: the
//! audit stream is the host's, and it is the record of what the guest *did* rather than what it was
//! *given*. So the macro is a thin expansion over `qqq:test/assertions`, and the work is in
//! `qqq-host/src/host_test.rs`.
//!
//! # Why `assert_caps!` does not disclose the capability set
//!
//! The WIT says *"Fail if the code under test **attempts** any capability outside `allowed`"* — attempts,
//! not holds. §2.5's property is *"absent, not denied"*: a guest that cannot import an interface is not
//! told it lacks it. **A guest that asserts `assert_caps!(a, b)` therefore learns what it did, which it
//! already knew, and never what it holds.**
//!
//! # The arity question, answered rather than hidden
//!
//! Proposal's row writes `assert_fuel_below!(n)` — **one** argument — and the host's `assert-fuel-below`
//! needs a **mark** to measure from. A macro cannot span two points in a program, so a one-argument form
//! that marked immediately before asserting would measure zero, be below every limit, and pass forever.
//!
//! **So the one-argument form requires a prior `mark_fuel("block")` and measures from it**, and the
//! two-argument form takes the mark explicitly. The limitation is stated on the macro itself, because
//! *"an assertion that cannot report a problem is an assertion that passes"* is the exact failure this
//! interface was built to prevent, and a silent one-argument shorthand is how it would come back.

wit_bindgen::generate!({
    world: "qqq-test",
    path: "wit",
    // **Without this the macro refuses with `missing \`with\` mapping for the key
    // `qqq:test/assertions@1.0.0``**, which is a confusing sentence for a world that names exactly that
    // import. `examples/orders-api` carries the same line for the same refusal and records the rule:
    // *"that message names `generate_all` as one of its three accepted answers (`§O-147`)."*
    generate_all,
});

// Only what the macros and a caller need. The generated module is public either way, so a caller that
// wants a function this file does not name can reach `qqq::test::assertions` directly.
pub use qqq::test::assertions::{
    assert_caps_only, assert_no_capability, fuel_since, mark_fuel, report,
    // Aliased, because `macro_rules!` puts the macro at the crate root too and two items of one name in
    // one module is a puzzle for a reader even where the namespaces keep them apart.
    assert_fuel_below as fuel_check,
    AssertionError,
};

/// Fail unless the code under test attempted nothing outside the listed capabilities.
///
/// ```ignore
/// assert_caps!("clock.wall", "crypto.random");
/// ```
///
/// # What a failure means, which is two different things
///
/// `assertion-error`'s own documentation separates them and this macro keeps the separation in its
/// messages: **`unknown-capability` is a defect in the test** — *"a typo in a capability name would
/// otherwise assert nothing, and pass. This is the one error here that is almost always a test bug"* —
/// where **`not-assertable` is a defect in the host or the harness.** Collapsing them would make a broken
/// test look like a failing one, and the diagnosis differs entirely.
#[macro_export]
macro_rules! assert_caps {
    ($($cap:expr),* $(,)?) => {{
        let allowed: ::std::vec::Vec<::std::string::String> =
            ::std::vec![$($cap.to_string()),*];
        match $crate::assert_caps_only(&allowed) {
            ::std::result::Result::Ok(()) => {}
            ::std::result::Result::Err($crate::AssertionError::UnknownCapability(name)) => {
                ::std::panic!(
                    "assert_caps!: `{}` is not a capability this runtime knows. \
                     This is almost always a typo in the test -- the assertion checked nothing.",
                    name
                )
            }
            ::std::result::Result::Err(other) => {
                ::std::panic!("assert_caps! could not be evaluated: {:?}", other)
            }
        }
    }};
}

/// Fail if the fuel consumed since `mark` reaches `limit`.
///
/// # The two forms, and why the short one needs a mark
///
/// ```ignore
/// mark_fuel("block");
/// // ... the code whose cost is under test ...
/// assert_fuel_below!(100_000);              // measures from `mark_fuel("block")`
/// assert_fuel_below!("block", 100_000);     // the same, naming the mark
/// ```
///
/// **The one-argument form measures from a mark named `block` and does nothing else.** It cannot measure
/// from "here", because a mark made immediately before the assertion has zero consumption behind it and
/// a zero is below every limit — **it would pass forever, which is worse than failing.** The
/// `no-fuel-baseline` error is what a missing mark produces, and it is deliberately not a pass.
#[macro_export]
macro_rules! assert_fuel_below {
    ($limit:expr $(,)?) => {
        $crate::assert_fuel_below!("block", $limit)
    };
    ($mark:expr, $limit:expr $(,)?) => {{
        let mark: &::std::primitive::str = $mark;
        let limit: ::std::primitive::u64 = $limit;
        match $crate::fuel_check(mark, limit) {
            ::std::result::Result::Ok(()) => {}
            ::std::result::Result::Err($crate::AssertionError::NoFuelBaseline) => {
                ::std::panic!(
                    "assert_fuel_below!: there is no mark named `{}`. \
                     Call `mark_fuel(\"{}\")` before the code under test -- the comparison has \
                     nothing to stand on, and a missing baseline is not a pass.",
                    mark, mark
                )
            }
            ::std::result::Result::Err(other) => {
                ::std::panic!("assert_fuel_below! could not be evaluated: {:?}", other)
            }
        }
    }};
}

/// The component `world qqq-test`'s export is implemented by.
///
/// # Why this exists at all, given the crate is a library of macros
///
/// **Because an import nobody calls does not survive the linker.** With the import declared and nothing
/// referencing it, `wasm-tools component wit` on the built component printed
///
/// ```text
/// world root {
/// }
/// ```
///
/// — **empty.** The `extern` block `generate!` emits is dead code until something uses it, so the
/// artifact could not distinguish "the binding was generated" from "the binding was never generated",
/// and a build that cannot show the import is not evidence that the macros expand.
///
/// `run_assertions` uses them. It is a reference, not an API: what it proves is that the expansion
/// reaches `qqq:test/assertions`, and `wasm-tools component wit` on the artifact is where that is read.
struct Component;

impl Guest for Component {
    fn run_assertions() {
        // A mark first, because the one-argument `assert_fuel_below!` measures from a mark named
        // `block` and a missing baseline is `no-fuel-baseline`, not a pass -- see the macro's own docs.
        //
        // # Why these two take `.expect(..)` and the assertions are macros
        //
        // Every function in this interface returns `result<_, assertion-error>`, and **ignoring one is
        // the defect the interface exists to prevent: an assertion that cannot report a problem is an
        // assertion that passes.** The compiler says so -- *"this `Result` may be an `Err` variant, which
        // should be handled"* -- and it said it for exactly these two calls, which were the only ones not
        // made through a macro.
        //
        // A macro is right for an assertion because it can panic with the *name* that failed. For a
        // call whose only error is `not-assertable` -- which cannot happen while assertion state is
        // attached -- `.expect` with the reason is the honest form, and it fails loudly rather than
        // silently if that ever stops being true.
        mark_fuel("block").expect("mark_fuel cannot fail while assertion state is attached");

        // Called with the capability this reference actually uses, so the assertion passes. An
        // `assert_caps!()` with an empty list would fail here and make the reference a failing guest.
        assert_caps!("clock.wall");

        assert_fuel_below!("block", 1_000_000);

        report(
            true,
            "the macros expanded into calls on this interface",
            None,
        )
        .expect("report cannot fail while assertion state is attached");
    }
}

export!(Component);
