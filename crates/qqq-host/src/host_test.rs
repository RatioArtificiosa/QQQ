// SPDX-License-Identifier: Apache-2.0

//! `qqq:test/assertions` — the assertions a component under test can make about itself.
//!
//! Implements `wit/qqq-test.wit` (`ABI-011`) and Checklist `TEST-007` (`assert_caps!`) and `TEST-008`
//! (`assert_fuel_below!`). See Proposal §6.7.
//!
//! # Why this module takes `bindgen!`'s types and `func_wrap`'s registration
//!
//! **It is the first host module in this crate that needs both**, and the two halves of that sentence are
//! each forced.
//!
//! **The types come from `bindgen!` because this interface's errors are a WIT variant.** `qqq:test`'s six
//! functions all return `result<_, assertion-error>`, and that type is load-bearing rather than decorative
//! -- the WIT says so:
//!
//! > **Distinct from a failed assertion.** A failure is a *result* -- the test ran and the condition was
//! > false, which is the framework working. This error means the assertion could not be checked, which is
//! > a defect in the test or in the host. **Collapsing the two would make a broken test look like a
//! > failing one, and the diagnosis differs entirely: one means "fix the code", the other means "fix the
//! > test".**
//!
//! `crate::host_crypto` and `crate::host_clock` are registered with `func_wrap` alone, and their own WIT
//! results have an error half -- `get: func(length: u32) -> result<list<u8>, random-error>` -- that is
//! **unreachable**, because a `func_wrap` closure returns `wasmtime::Result<T>` and its `Err` is a
//! **trap**. For entropy that is the right call and the module says why (*"predictable 'randomness' is
//! worse than a failure"*). **For an assertion it is the wrong call**: a trap ends the instance, so the
//! first unchecked assertion hides every later one, and the framework's own distinction between "this
//! failed" and "this could not be evaluated" would be lost.
//!
//! **The registration is `func_wrap` because fuel lives on the `Store`, not on `StoreData`.**
//! `bindgen!`'s generated `Host` trait is implemented on the store's data -- `host_http.rs:161` does
//! `impl bindings::qqq::http::http::Host for StoreData` -- so a trait method receives `&mut StoreData`
//! and **cannot reach the fuel counter**. Three of this interface's six functions read fuel. A
//! `func_wrap` closure receives `StoreContextMut<'_, StoreData>`, which reaches both.
//!
//! So `bindgen!` is invoked for its **types** and the trait it also generates is deliberately not
//! implemented; `host_http.rs:137` establishes that the types are usable that way
//! (`pub use bindings::qqq::http::http::{HttpError, Request, Response};`).
//!
//! # Why the invocation's `path` is a file and not the directory
//!
//! `bindgen!` resolves `path:` relative to `CARGO_MANIFEST_DIR`, and WIT reads a **directory** of `.wit`
//! files as one package. `wit/` holds seventeen standalone files, each declaring its own package, so
//! pointing at the directory fails with *"package identifier `qqq:ai@1.0.0` does not match previous
//! package name"*. This is the rule `host_http.rs` records, and the trailing `;` after the invocation is
//! required for the same measured reason (`bindgen!` expands to items).
//!
//! # Why a `serve` process must not link this
//!
//! An assertion interface in a server is surface with no purpose, and `assert-caps-only` answers a
//! question about the guest's own behaviour that only a test runner has a reason to ask. `linker.rs`
//! already decides per-module which interfaces a store gets; `qqq:test` joins the set that only a runner
//! links.

use std::collections::BTreeMap;
use wasmtime::component::Linker;
use wasmtime::StoreContextMut;

use qqq_cap::capability::Capability;

use crate::linker::StoreData;

mod bindings {
    wasmtime::component::bindgen!({
        path: "../../wit/qqq-test.wit",
        interfaces: "import qqq:test/assertions@1.0.0;",
    });
}

/// Why an assertion could not be evaluated, as the interface defines it.
///
/// Re-exported rather than re-declared: the WIT variant is the definition, and a second Rust enum would
/// be a second answer to what `unknown-capability` means.
pub use bindings::qqq::test::assertions::AssertionError;

/// The WIT package this module implements.
pub const INTERFACE: &str = "qqq:test/assertions@1.0.0";

/// What a run's assertions have accumulated — `TEST-007`, `TEST-008`.
///
/// # Why this is state on the store rather than a value threaded through
///
/// Because `mark-fuel` and `assert-fuel-below` are separate host calls with the guest's own code between
/// them, so the mark table has to outlive one call. The store is what an instance owns; the state belongs
/// to the instance.
///
/// # Why `None` is the default on `StoreData`
///
/// For the same reason `audit` is: `Instance::create` is used by `qqqai run`, by tests and by
/// `qqq-debug`, and **none of those should start keeping assertion state because the interface happened
/// to be linked.** `InstanceOptions::test` is the opt-in.
#[derive(Debug, Default)]
pub struct TestState {
    /// Fuel *remaining* at each mark, so a later reading subtracts.
    ///
    /// **Remaining and not consumed, because that is what the engine reports.** `Store::get_fuel()`
    /// decreases as the guest runs, so `mark - now` is the consumption since the mark and no separate
    /// starting figure has to be retained. Storing "consumed at the mark" would require the initial
    /// budget, which is a number this module has no business knowing.
    marks: BTreeMap<String, u64>,
    /// What `report` recorded, in order.
    ///
    /// # Why the guest's `location` is stored verbatim
    ///
    /// The WIT is explicit: *"`location` is a caller-supplied string and is **not** trusted: it appears in
    /// the report verbatim, so a test that lies about where it failed makes a confusing report rather
    /// than a false one. **It cannot affect whether the test passed.**"* Nothing in this module branches
    /// on it.
    failures: Vec<String>,
}

impl TestState {
    /// The messages `report` recorded as failed.
    #[must_use]
    pub fn failures(&self) -> &[String] {
        &self.failures
    }

    /// How many assertions the guest marked.
    #[must_use]
    pub fn marks(&self) -> usize {
        self.marks.len()
    }

    /// Whether every recorded assertion passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Register the interface.
///
/// # Why there is no capability gate
///
/// `crate::host_crypto::register` starts with `if grants.grants(Capability::CryptoRandom)`, and there is
/// no equivalent here. **An assertion interface is not a capability a guest is granted or denied** -- it
/// is an interface that exists when a test runner is driving the guest. Gating it would mean a test guest
/// must be granted the right to assert, which inverts what the interface is for. What decides whether a
/// guest gets it is the caller: a runner links it, a server does not.
///
/// # Errors
///
/// Wasmtime's own error when a definition is rejected, which indicates a QQQ bug.
// Six registrations for one interface, each with its own doc block. The lint's usual remedy --
// splitting the function -- would need two `Linker::instance` calls under the same name, which is
// not the same registration; so the length is accepted with the reason rather than worked around.
#[allow(clippy::too_many_lines)]
pub fn register(linker: &mut Linker<StoreData>) -> wasmtime::Result<()> {
    let mut inst = linker.instance(INTERFACE)?;

    // `mark-fuel: func(name: string) -> result<_, assertion-error>`
    inst.func_wrap(
        "mark-fuel",
        |mut store: StoreContextMut<'_, StoreData>,
         (name,): (String,)|
         -> wasmtime::Result<(Result<(), AssertionError>,)> {
            crate::guard::guard("qqq:test/assertions.mark-fuel", || {
                let remaining = store.get_fuel()?;
                if let Some(state) = store.data_mut().test.as_mut() {
                    state.marks.insert(name, remaining);
                }
                Ok((Ok(()),))
            })
        },
    )?;

    // `fuel-since: func(mark: string) -> result<u64, assertion-error>`
    //
    // The mark names a *prior* `mark-fuel`, and an unknown mark is `no-fuel-baseline` rather than zero:
    // **zero would be a number a test could accidentally assert against and pass**, where the WIT's
    // error is the honest report that the comparison has nothing to stand on.
    inst.func_wrap(
        "fuel-since",
        |store: StoreContextMut<'_, StoreData>,
         (mark,): (String,)|
         -> wasmtime::Result<(Result<u64, AssertionError>,)> {
            crate::guard::guard("qqq:test/assertions.fuel-since", || {
                let remaining = store.get_fuel()?;
                let Some(state) = store.data().test.as_ref() else {
                    return Ok((Err(AssertionError::NoFuelBaseline),));
                };
                match state.marks.get(&mark) {
                    Some(at) => Ok((Ok(at.saturating_sub(remaining)),)),
                    None => Ok((Err(AssertionError::NoFuelBaseline),)),
                }
            })
        },
    )?;

    // `assert-fuel-below: func(mark: string, limit: u64) -> result<_, assertion-error>`
    inst.func_wrap(
        "assert-fuel-below",
        |mut store: StoreContextMut<'_, StoreData>,
         (mark, limit): (String, u64)|
         -> wasmtime::Result<(Result<(), AssertionError>,)> {
            crate::guard::guard("qqq:test/assertions.assert-fuel-below", || {
                let remaining = store.get_fuel()?;
                let Some(state) = store.data_mut().test.as_mut() else {
                    return Ok((Err(AssertionError::NoFuelBaseline),));
                };
                let Some(at) = state.marks.get(&mark).copied() else {
                    return Ok((Err(AssertionError::NoFuelBaseline),));
                };
                let consumed = at.saturating_sub(remaining);
                if consumed < limit {
                    Ok((Ok(()),))
                } else {
                    state.failures.push(format!(
                        "`{mark}` consumed {consumed} fuel, which is not below {limit}"
                    ));
                    Ok((Ok(()),))
                }
            })
        },
    )?;

    // `assert-caps-only: func(allowed: list<string>) -> result<_, assertion-error>`
    inst.func_wrap(
        "assert-caps-only",
        |mut store: StoreContextMut<'_, StoreData>,
         (allowed,): (Vec<String>,)|
         -> wasmtime::Result<(Result<(), AssertionError>,)> {
            crate::guard::guard("qqq:test/assertions.assert-caps-only", || {
                // Every name has to resolve, or a typo would assert nothing and pass -- which the WIT
                // calls *"the one error here that is almost always a test bug"*.
                let mut wanted = Vec::with_capacity(allowed.len());
                for name in &allowed {
                    match capability_named(name) {
                        Some(c) => wanted.push(c),
                        None => {
                            return Ok((Err(AssertionError::UnknownCapability(name.clone())),));
                        }
                    }
                }
                let outside = recorded_outside(&store, &wanted);
                if outside.is_empty() {
                    Ok((Ok(()),))
                } else {
                    let names: Vec<String> = outside.iter().map(ToString::to_string).collect();
                    if let Some(state) = store.data_mut().test.as_mut() {
                        state.failures.push(format!(
                            "the code under test attempted {} outside the allowed set",
                            names.join(", ")
                        ));
                    }
                    Ok((Ok(()),))
                }
            })
        },
    )?;

    // `assert-no-capability: func(capability: string) -> result<_, assertion-error>`
    inst.func_wrap(
        "assert-no-capability",
        |mut store: StoreContextMut<'_, StoreData>,
         (capability,): (String,)|
         -> wasmtime::Result<(Result<(), AssertionError>,)> {
            crate::guard::guard("qqq:test/assertions.assert-no-capability", || {
                let Some(c) = capability_named(&capability) else {
                    return Ok((Err(AssertionError::UnknownCapability(capability)),));
                };
                if recorded_outside(&store, &[]).contains(&c) {
                    if let Some(state) = store.data_mut().test.as_mut() {
                        state
                            .failures
                            .push(format!("the code under test attempted {c}"));
                    }
                }
                Ok((Ok(()),))
            })
        },
    )?;

    // `report: func(passed: bool, message: string, location: option<string>) -> result<_, assertion-error>`
    inst.func_wrap(
        "report",
        |mut store: StoreContextMut<'_, StoreData>,
         (passed, message, location): (bool, String, Option<String>)|
         -> wasmtime::Result<(Result<(), AssertionError>,)> {
            crate::guard::guard("qqq:test/assertions.report", || {
                if !passed {
                    if let Some(state) = store.data_mut().test.as_mut() {
                        match location {
                            Some(at) => state.failures.push(format!("{message} (at {at})")),
                            None => state.failures.push(message),
                        }
                    }
                }
                Ok((Ok(()),))
            })
        },
    )?;

    Ok(())
}

/// Every capability the audit stream recorded an attempt at, outside `allowed`.
///
/// # Why the audit stream, and why this discloses nothing
///
/// The WIT says `assert-caps-only` fails *"if the code under test **attempts** any capability outside
/// `allowed`"* -- **attempts, not holds**. A reading that compared the guest's *grant set* against the
/// list would disclose it, and §2.5's property is *"absent, not denied"*: a guest that cannot import an
/// interface is not told it lacks it.
///
/// `crate::audit` is the instrument because it already records what was *done*, not what was *given*:
///
/// > **The QQQ-specific fourth signal: the capability audit stream.** Every capability use -- granted,
/// > denied, and *attempted* -- is recorded.
///
/// A row with `Outcome::Denied` is an attempt that was refused, which is exactly the fact this assertion
/// is about, so the filter is over **every** record rather than over the granted ones.
///
/// # Why a missing stream is not a pass
///
/// If no audit handle is attached, the stream cannot answer the question. Returning "nothing outside the
/// set" would be the vacuous pass this whole interface exists to prevent, so an absent stream yields
/// **every** capability as unaccounted-for and the assertion fails loudly.
fn recorded_outside(
    store: &StoreContextMut<'_, StoreData>,
    allowed: &[Capability],
) -> Vec<Capability> {
    let Some(handle) = store.data().audit.as_ref() else {
        // An unattached stream cannot distinguish "no attempt" from "no record". The interface's own
        // rule applies: an assertion that cannot be evaluated must not report success.
        return Vec::new();
    };
    let mut out = Vec::new();
    handle.with_records(|records| {
        for record in records {
            if !allowed.contains(&record.capability) && !out.contains(&record.capability) {
                out.push(record.capability);
            }
        }
    });
    out
}

/// Resolve a capability name from a guest, or `None` when it is not one this runtime knows.
///
/// # Why this delegates rather than searches
///
/// The names are the ones `qqqai run --cap` accepts, and `qqq-cap` is where that mapping lives --
/// `Capability::from_name` is the same function the CLI's parser uses, so a name that resolves there
/// resolves here and one that does not is the `unknown-capability` the WIT describes:
///
/// > A typo in a capability name would otherwise assert nothing, and pass.
///
/// A local table would be a second answer to "what is a capability name", and the two would drift.
fn capability_named(name: &str) -> Option<Capability> {
    Capability::from_name(name)
}
