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

/// What a run's assertions accumulate. Private: reached through [`TestState`]'s methods.
#[derive(Debug, Default)]
struct Inner {
    /// Fuel *remaining* at each mark, so a later reading subtracts.
    marks: BTreeMap<String, u64>,
    /// What `report` recorded, in order.
    failures: Vec<String>,
}

/// The assertion state a run accumulates, shared with the caller — `TEST-007`, `TEST-008`.
///
/// # Why this is a handle and not a plain struct
///
/// Because a test runner has to read the result *after* the run, and the state lives inside the store,
/// which lives inside the `Instance`. `crate::audit::AuditHandle` is the precedent: the runner builds a
/// handle over an `Arc<Mutex<..>>`, passes it in, and keeps its own way in. **`Clone` is the mechanism**
/// -- a host function clones the state out of the store before touching the fuel counter, so the two
/// borrows cannot interleave.
#[derive(Debug, Clone, Default)]
pub struct TestState {
    inner: std::sync::Arc<std::sync::Mutex<Inner>>,
}

impl TestState {
    /// The state under the lock.
    ///
    /// # Why a guard rather than `&mut self`
    ///
    /// Because a host function clones the state out of the store and **then** calls
    /// `store.get_fuel()`, which needs `&mut Store`. `&mut self` would require the two borrows to
    /// interleave, and they cannot.
    ///
    /// Poisoning is recovered rather than propagated, for the reason
    /// [`crate::audit::AuditHandle::record`] gives: a host function that has already decided to proceed
    /// must not fail because a previous panic left the lock poisoned.
    fn data(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The messages `report` recorded as failed, copied out from under the lock.
    ///
    /// # Why a copy rather than a slice
    ///
    /// Because a slice would have to outlive the guard that protects it. The failures of a run are a
    /// handful of strings, and a runner wants them after the lock is released.
    #[must_use]
    pub fn failures(&self) -> Vec<String> {
        self.data().failures.clone()
    }

    /// How many assertions the guest marked.
    #[must_use]
    pub fn marks(&self) -> usize {
        self.data().marks.len()
    }

    /// Whether every recorded assertion passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.data().failures.is_empty()
    }
}

/// The WIT package this module implements.
pub const INTERFACE: &str = "qqq:test/assertions@1.0.0";

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
        |store: StoreContextMut<'_, StoreData>,
         (name,): (String,)|
         -> wasmtime::Result<(Result<(), AssertionError>,)> {
            crate::guard::guard("qqq:test/assertions.mark-fuel", || {
                // **An assertion with no state to record into cannot be evaluated.** Returning `Ok`
                // here is the vacuous pass this interface exists to prevent: an assertion that cannot
                // report a problem is an assertion that passes. The WIT has the error for it, and
                // distinguishes it from a failed assertion deliberately -- *"one means 'fix the code',
                // the other means 'fix the test'"*.
                // **An assertion with no state to record into cannot be evaluated.** Returning `Ok`
                // here is the vacuous pass this interface exists to prevent: an assertion that cannot
                // report a problem is an assertion that passes. The WIT has the error for it, and
                // distinguishes it from a failed assertion deliberately -- *"one means 'fix the code',
                // the other means 'fix the test'"*.
                //
                // The clone is what keeps the borrows apart: `store.get_fuel()` below needs
                // `&mut Store`, and writing into the state needs the state. Cloned out first, the two
                // never overlap. **It also removes the dead re-lookups the bodies used to carry** --
                // this guard already established that a state is present, so a body answering
                // `NoFuelBaseline` for a `None` that cannot occur was reporting the wrong error for a
                // case already handled.
                let Some(state) = store.data().test.clone() else {
                    return Ok((Err(AssertionError::NotAssertable(
                        "no assertion state is attached to this store; create the instance with \
                         `InstanceOptions::with_test`"
                            .to_owned(),
                    )),));
                };
                let remaining = store.get_fuel()?;
                state.data().marks.insert(name, remaining);
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
                // **An assertion with no state to record into cannot be evaluated.** Returning `Ok`
                // here is the vacuous pass this interface exists to prevent: an assertion that cannot
                // report a problem is an assertion that passes. The WIT has the error for it, and
                // distinguishes it from a failed assertion deliberately -- *"one means 'fix the code',
                // the other means 'fix the test'"*.
                // **An assertion with no state to record into cannot be evaluated.** Returning `Ok`
                // here is the vacuous pass this interface exists to prevent: an assertion that cannot
                // report a problem is an assertion that passes. The WIT has the error for it, and
                // distinguishes it from a failed assertion deliberately -- *"one means 'fix the code',
                // the other means 'fix the test'"*.
                //
                // The clone is what keeps the borrows apart: `store.get_fuel()` below needs
                // `&mut Store`, and writing into the state needs the state. Cloned out first, the two
                // never overlap. **It also removes the dead re-lookups the bodies used to carry** --
                // this guard already established that a state is present, so a body answering
                // `NoFuelBaseline` for a `None` that cannot occur was reporting the wrong error for a
                // case already handled.
                let Some(state) = store.data().test.clone() else {
                    return Ok((Err(AssertionError::NotAssertable(
                        "no assertion state is attached to this store; create the instance with \
                         `InstanceOptions::with_test`"
                            .to_owned(),
                    )),));
                };
                let remaining = store.get_fuel()?;
                // `.copied()` before the `match`, because the scrutinee's temporary guard would
                // otherwise be dropped while an arm still borrowed from it -- E0597. The same
                // expression is written this way in `assert-fuel-below` below.
                let at = state.data().marks.get(&mark).copied();
                match at {
                    Some(at) => Ok((Ok(at.saturating_sub(remaining)),)),
                    None => Ok((Err(AssertionError::NoFuelBaseline),)),
                }
            })
        },
    )?;

    // `assert-fuel-below: func(mark: string, limit: u64) -> result<_, assertion-error>`
    inst.func_wrap(
        "assert-fuel-below",
        |store: StoreContextMut<'_, StoreData>,
         (mark, limit): (String, u64)|
         -> wasmtime::Result<(Result<(), AssertionError>,)> {
            crate::guard::guard("qqq:test/assertions.assert-fuel-below", || {
                // **An assertion with no state to record into cannot be evaluated.** Returning `Ok`
                // here is the vacuous pass this interface exists to prevent: an assertion that cannot
                // report a problem is an assertion that passes. The WIT has the error for it, and
                // distinguishes it from a failed assertion deliberately -- *"one means 'fix the code',
                // the other means 'fix the test'"*.
                // **An assertion with no state to record into cannot be evaluated.** Returning `Ok`
                // here is the vacuous pass this interface exists to prevent: an assertion that cannot
                // report a problem is an assertion that passes. The WIT has the error for it, and
                // distinguishes it from a failed assertion deliberately -- *"one means 'fix the code',
                // the other means 'fix the test'"*.
                //
                // The clone is what keeps the borrows apart: `store.get_fuel()` below needs
                // `&mut Store`, and writing into the state needs the state. Cloned out first, the two
                // never overlap. **It also removes the dead re-lookups the bodies used to carry** --
                // this guard already established that a state is present, so a body answering
                // `NoFuelBaseline` for a `None` that cannot occur was reporting the wrong error for a
                // case already handled.
                let Some(state) = store.data().test.clone() else {
                    return Ok((Err(AssertionError::NotAssertable(
                        "no assertion state is attached to this store; create the instance with \
                         `InstanceOptions::with_test`"
                            .to_owned(),
                    )),));
                };
                let remaining = store.get_fuel()?;
                let Some(at) = state.data().marks.get(&mark).copied() else {
                    return Ok((Err(AssertionError::NoFuelBaseline),));
                };
                let consumed = at.saturating_sub(remaining);
                if consumed < limit {
                    Ok((Ok(()),))
                } else {
                    state.data().failures.push(format!(
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
        |store: StoreContextMut<'_, StoreData>,
         (allowed,): (Vec<String>,)|
         -> wasmtime::Result<(Result<(), AssertionError>,)> {
            crate::guard::guard("qqq:test/assertions.assert-caps-only", || {
                // **An assertion with no state to record into cannot be evaluated.** Returning `Ok`
                // here is the vacuous pass this interface exists to prevent: an assertion that cannot
                // report a problem is an assertion that passes. The WIT has the error for it, and
                // distinguishes it from a failed assertion deliberately -- *"one means 'fix the code',
                // the other means 'fix the test'"*.
                // **An assertion with no state to record into cannot be evaluated.** Returning `Ok`
                // here is the vacuous pass this interface exists to prevent: an assertion that cannot
                // report a problem is an assertion that passes. The WIT has the error for it, and
                // distinguishes it from a failed assertion deliberately -- *"one means 'fix the code',
                // the other means 'fix the test'"*.
                //
                // The clone is what keeps the borrows apart: `store.get_fuel()` below needs
                // `&mut Store`, and writing into the state needs the state. Cloned out first, the two
                // never overlap. **It also removes the dead re-lookups the bodies used to carry** --
                // this guard already established that a state is present, so a body answering
                // `NoFuelBaseline` for a `None` that cannot occur was reporting the wrong error for a
                // case already handled.
                let Some(state) = store.data().test.clone() else {
                    return Ok((Err(AssertionError::NotAssertable(
                        "no assertion state is attached to this store; create the instance with \
                         `InstanceOptions::with_test`"
                            .to_owned(),
                    )),));
                };
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
                let outside = match recorded_outside(&store, &wanted) {
                    Ok(v) => v,
                    Err(e) => return Ok((Err(e),)),
                };
                if outside.is_empty() {
                    Ok((Ok(()),))
                } else {
                    let names: Vec<String> = outside.iter().map(ToString::to_string).collect();
                    state.data().failures.push(format!(
                        "the code under test attempted {} outside the allowed set",
                        names.join(", ")
                    ));
                    Ok((Ok(()),))
                }
            })
        },
    )?;

    // `assert-no-capability: func(capability: string) -> result<_, assertion-error>`
    inst.func_wrap(
        "assert-no-capability",
        |store: StoreContextMut<'_, StoreData>,
         (capability,): (String,)|
         -> wasmtime::Result<(Result<(), AssertionError>,)> {
            crate::guard::guard("qqq:test/assertions.assert-no-capability", || {
                // **An assertion with no state to record into cannot be evaluated.** Returning `Ok`
                // here is the vacuous pass this interface exists to prevent: an assertion that cannot
                // report a problem is an assertion that passes. The WIT has the error for it, and
                // distinguishes it from a failed assertion deliberately -- *"one means 'fix the code',
                // the other means 'fix the test'"*.
                // **An assertion with no state to record into cannot be evaluated.** Returning `Ok`
                // here is the vacuous pass this interface exists to prevent: an assertion that cannot
                // report a problem is an assertion that passes. The WIT has the error for it, and
                // distinguishes it from a failed assertion deliberately -- *"one means 'fix the code',
                // the other means 'fix the test'"*.
                //
                // The clone is what keeps the borrows apart: `store.get_fuel()` below needs
                // `&mut Store`, and writing into the state needs the state. Cloned out first, the two
                // never overlap. **It also removes the dead re-lookups the bodies used to carry** --
                // this guard already established that a state is present, so a body answering
                // `NoFuelBaseline` for a `None` that cannot occur was reporting the wrong error for a
                // case already handled.
                let Some(state) = store.data().test.clone() else {
                    return Ok((Err(AssertionError::NotAssertable(
                        "no assertion state is attached to this store; create the instance with \
                         `InstanceOptions::with_test`"
                            .to_owned(),
                    )),));
                };
                let Some(c) = capability_named(&capability) else {
                    return Ok((Err(AssertionError::UnknownCapability(capability)),));
                };
                let outside = match recorded_outside(&store, &[]) {
                    Ok(v) => v,
                    Err(e) => return Ok((Err(e),)),
                };
                if outside.contains(&c) {
                    state
                        .data()
                        .failures
                        .push(format!("the code under test attempted {c}"));
                }
                Ok((Ok(()),))
            })
        },
    )?;

    // `report: func(passed: bool, message: string, location: option<string>) -> result<_, assertion-error>`
    inst.func_wrap(
        "report",
        |store: StoreContextMut<'_, StoreData>,
         (passed, message, location): (bool, String, Option<String>)|
         -> wasmtime::Result<(Result<(), AssertionError>,)> {
            crate::guard::guard("qqq:test/assertions.report", || {
                // **An assertion with no state to record into cannot be evaluated.** Returning `Ok`
                // here is the vacuous pass this interface exists to prevent: an assertion that cannot
                // report a problem is an assertion that passes. The WIT has the error for it, and
                // distinguishes it from a failed assertion deliberately -- *"one means 'fix the code',
                // the other means 'fix the test'"*.
                // **An assertion with no state to record into cannot be evaluated.** Returning `Ok`
                // here is the vacuous pass this interface exists to prevent: an assertion that cannot
                // report a problem is an assertion that passes. The WIT has the error for it, and
                // distinguishes it from a failed assertion deliberately -- *"one means 'fix the code',
                // the other means 'fix the test'"*.
                //
                // The clone is what keeps the borrows apart: `store.get_fuel()` below needs
                // `&mut Store`, and writing into the state needs the state. Cloned out first, the two
                // never overlap. **It also removes the dead re-lookups the bodies used to carry** --
                // this guard already established that a state is present, so a body answering
                // `NoFuelBaseline` for a `None` that cannot occur was reporting the wrong error for a
                // case already handled.
                let Some(state) = store.data().test.clone() else {
                    return Ok((Err(AssertionError::NotAssertable(
                        "no assertion state is attached to this store; create the instance with \
                         `InstanceOptions::with_test`"
                            .to_owned(),
                    )),));
                };
                if !passed {
                    match location {
                        Some(at) => state.data().failures.push(format!("{message} (at {at})")),
                        None => state.data().failures.push(message),
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
) -> Result<Vec<Capability>, AssertionError> {
    let handle = stream_of(store.data().audit.as_ref())?;
    let mut out = Vec::new();
    handle.with_records(|records| {
        let attempted: Vec<Capability> = records.iter().map(|r| r.capability).collect();
        out = unaccounted(allowed, &attempted);
    });
    Ok(out)
}

/// The audit stream a capability query reads, or the error for its absence.
///
/// # Why this takes the `Option` rather than a store
///
/// Because the branch it guards is the one the defect lived in, and **a store cannot be constructed in a
/// test** -- `StoreData` has a dozen fields and no test-only constructor. Taking the absence as an
/// argument makes "no stream attached" a value a caller can pass, so the branch that returned a pass
/// instead of a refusal is reachable from a unit test.
///
/// Returning `Ok(&AuditHandle)` from a `&Option<&AuditHandle>` borrows the handle, which is what the
/// caller needs and is why the absent case has to be an error rather than a sentinel.
fn stream_of(
    handle: Option<&crate::audit::AuditHandle>,
) -> Result<&crate::audit::AuditHandle, AssertionError> {
    handle.ok_or_else(|| {
        AssertionError::NotAssertable(
            "no audit stream is attached, so `assert-caps-only` cannot tell an attempt that was not              recorded from one that did not happen"
                .to_owned(),
        )
    })
}

/// Which of `recorded` fall outside `allowed` -- the pure half of the query.
///
/// Ordered by first appearance rather than sorted: the caller reports the names, and an order that
/// matches the guest's own execution is easier to read than an alphabetical one.
fn unaccounted(allowed: &[Capability], recorded: &[Capability]) -> Vec<Capability> {
    let mut out: Vec<Capability> = Vec::new();
    for c in recorded {
        if !allowed.contains(c) && !out.contains(c) {
            out.push(*c);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every assertion must refuse when the store carries no state — the call-site half.
    ///
    /// # Why a source-level test rather than a component
    ///
    /// `host_crypto` records both halves of this. Extracting a helper closes one hole; **"a second
    /// injection — neutering the call site while leaving the helper correct — also left every test
    /// green, because a test that calls the helper directly proves the helper works and proves nothing
    /// about whether the host function uses it."**
    ///
    /// So the property is: **six** `func_wrap` closures, **six** refusals. The count is asserted rather
    /// than a bare `contains`, because a `contains` is satisfied by one guard in one function.
    ///
    /// Whitespace is stripped first, for the reason `registers` gives in `host_crypto`: a test whose
    /// result depends on where a line breaks is not testing the property it names, and `rustfmt` has
    /// already moved this layout once.
    #[test]
    fn every_assertion_refuses_when_the_store_has_no_state() {
        // **The production half only, and the reason is the rule this file has quoted twice.**
        //
        // The first version of this test squeezed the whole file and counted 7 guards for 6
        // registrations, because the pattern it searches for appears in the `matches` call below it.
        // That is a guard matching its own explanation -- the pattern describing the reader rather than
        // the code. `arch012::production_lines` splits at the same marker, for the same reason: a test
        // module is not production, and a checker should not read itself.
        let production = include_str!("host_test.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default();
        let squeezed: String = production.chars().filter(|c| !c.is_whitespace()).collect();
        let guards = squeezed
            .matches("letSome(state)=store.data().test.clone()else{")
            .count();
        let wraps = squeezed.matches("func_wrap(\"").count();
        assert_eq!(
            wraps, 6,
            "this file should register six functions, found {wraps}"
        );
        assert_eq!(
            guards, wraps,
            "every `func_wrap` in this file must refuse when no assertion state is attached; found \
             {guards} guard(s) for {wraps} registration(s). **An assertion that cannot report a problem \
             is an assertion that passes.**"
        );
    }

    /// **And the call site, because a correct helper proves nothing about its use.**
    ///
    /// `host_crypto` records this as its second gap: *"neutering the call site while leaving the helper
    /// correct — also left every test green."* `stream_of`'s own test passes whether or not
    /// `recorded_outside` consults it, and the defect this module was written to remove lived exactly
    /// there — in a branch that returned `Vec::new()` instead of calling anything.
    ///
    /// So the property is asserted where it can be violated: inside `recorded_outside`'s own body.
    #[test]
    fn the_capability_query_consults_the_stream_it_guards() {
        let production = include_str!("host_test.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default();
        let body = production
            .split("fn recorded_outside(")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("recorded_outside must be defined");
        // **The `?` is the property, not the call.** The first version of this assertion asked only
        // whether the body contained `stream_of(`, and an injection that kept the call but answered
        // `Err(_) => return Ok(Vec::new())` sailed through it -- the replacement text contains the
        // call. **What must be present is the propagation**, because an absent stream becoming an
        // empty set is the defect this whole module was written to remove.
        assert!(
            body.contains("stream_of(store.data().audit.as_ref())?"),
            "`recorded_outside` must propagate `stream_of`'s refusal with `?`. Without the `?` the \
             guard is consulted and its answer discarded, so an absent stream becomes an empty set -- \
             which the caller reads as success."
        );
    }

    /// **An absent audit stream is a refusal, not an empty set.**
    ///
    /// This is the branch that read `return Vec::new();` — an empty "outside the allowed set", which the
    /// caller reads as success — while the function's own doc said *"an absent stream yields every
    /// capability as unaccounted-for and the assertion fails loudly."*
    #[test]
    fn an_absent_stream_refuses_rather_than_reporting_nothing_outside() {
        let err = stream_of(None).expect_err("an absent stream must not be a pass");
        assert!(
            matches!(err, AssertionError::NotAssertable(_)),
            "an absent stream is a `not-assertable` -- the assertion could not be evaluated -- and not \
             a failure of the code under test: got {err:?}"
        );
    }

    /// And with a stream present, the comparison is over **attempts**, not grants.
    #[test]
    fn unaccounted_reports_attempts_outside_the_allowed_set() {
        use Capability::{ClockWall, CryptoHash, CryptoRandom};
        // A denied attempt is still an attempt, and that is the whole reason this reads the audit
        // stream: `Outcome::Denied` rows are exactly the fact the assertion is about.
        assert_eq!(
            unaccounted(&[ClockWall], &[ClockWall, CryptoRandom, CryptoRandom]),
            vec![CryptoRandom],
            "an attempt outside the set is reported once, however many times it was made"
        );
        assert_eq!(
            unaccounted(&[ClockWall, CryptoRandom], &[ClockWall, CryptoRandom]),
            Vec::new(),
            "nothing outside the set is an empty report, which is a pass"
        );
        assert_eq!(
            unaccounted(&[], &[CryptoHash]),
            vec![CryptoHash],
            "an empty allowed set permits nothing"
        );
    }

    /// **A clone is a second way in, not a copy.** The whole handle design rests on this.
    ///
    /// `TestState` is handed to `InstanceOptions::with_test`, cloned into `StoreData`, and cloned again by
    /// every guard. **If cloning copied the state, the caller would hold an empty one and every assertion
    /// would record into a value nobody reads** — and the caller would see zero failures whether the guest
    /// passed or failed, which is the vacuous pass this interface exists to prevent, moved into the
    /// plumbing meant to prevent it.
    ///
    /// A unit test cannot reach a `func_wrap` closure, but it can reach this — and this is where the design
    /// would break: not in the host functions and not in the caller, but in the `Arc` between them.
    #[test]
    fn a_cloned_handle_sees_what_its_sibling_recorded() {
        let caller = TestState::default();
        let inside_the_store = caller.clone();
        inside_the_store
            .data()
            .failures
            .push("the guest reported a failure".to_owned());
        inside_the_store
            .data()
            .marks
            .insert("before".to_owned(), 1234);
        assert_eq!(
            caller.failures(),
            vec!["the guest reported a failure".to_owned()],
            "the caller's handle must see what the store's handle recorded"
        );
        assert_eq!(caller.marks(), 1, "the marks are shared too");
        assert!(
            !caller.all_passed(),
            "one recorded failure means the run did not pass"
        );
    }

    /// And the options hold the caller's handle, not a copy of its value.
    ///
    /// The first test never goes through `InstanceOptions`, so it passes even if `with_test` stored a
    /// fresh state. **This one records *before* the options exist**, which only reaches them if they hold
    /// the handle.
    #[test]
    fn with_test_attaches_the_callers_handle() {
        let state = TestState::default();
        let opts = crate::instance::InstanceOptions::default().with_test(state.clone());
        assert!(opts.test.is_some(), "the handle must be attached");
        state
            .data()
            .failures
            .push("recorded before the instance existed".to_owned());
        assert_eq!(
            opts.test.expect("attached").failures(),
            vec!["recorded before the instance existed".to_owned()],
            "the options must share the caller's state"
        );
    }
}
