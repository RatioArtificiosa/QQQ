// SPDX-License-Identifier: Apache-2.0

//! Calling a guest: the edge between the host and an application component.
//!
//! # Why this module is the one the project was missing
//!
//! `qqq-host` had an engine, a pooling allocator, fuel, epochs, a per-grant linker,
//! handle tables, quotas and trap classification. `qqq-serve` had a router, a
//! server loop, TLS, streaming and WebSockets. What neither had was the call
//! between them: nothing in production resolved a guest's
//! `qqq:http/incoming-handler.handle` and passed a request through it. Recorded as
//! `§O-146` after `grep get_typed_func crates/qqq-host/src` returned **fifteen hits,
//! all inside `#[cfg(test)]`**.
//!
//! Without this, `qqqai serve` cannot dispatch to a guest (`CLI-011`), the orders
//! reference app cannot be served (`SRV-018`), and no benchmark in §9.1 can run.
//! Every downstream item was blocked on a call nobody had scheduled, which is what
//! makes this worth building before anything that depends on it.
//!
//! # The export name, measured rather than assumed
//!
//! A component-model export is looked up in **two steps**: the interface is a
//! top-level export, and the method is an export *within* it. `wasm-tools print`
//! on a real guest built against `wit/app/app.wit` gives the authoritative strings:
//!
//! ```text
//!   (export "qqq:http/incoming-handler@1.0.0#handle" (func ...))
//!   (instance $qqq:http/incoming-handler@1.0.0-shim-instance ...)
//! ```
//!
//! So the interface is `qqq:http/incoming-handler@1.0.0` and the method is `handle`.
//! Both are constants here because a typo in either is a lookup that returns `None`
//! at runtime, and a `None` that nobody checks is a request served by nothing.
//!
//! # Why the guest's error type is not the host's error type
//!
//! `handle` returns `result<response, http-error>`. `http-error` is the *guest's*
//! vocabulary — `host-not-allowed`, `request-too-large` and so on — and it describes
//! why the **guest** could not answer. A host-side failure (a trap, a missing export,
//! a fuel exhaustion) is a different thing entirely and must not be flattened into
//! the guest's vocabulary, because an operator reading `request-too-large` would look
//! for a large body when the real cause was a trap. They stay separate: [`Failure`]
//! is the host's, and a guest's `http-error` is returned *as data*.

use wasmtime::component::{ComponentExportIndex, Instance as WasmInstance};
use wasmtime::Store;

use qqq_core::{Error, ErrorCode, Result};

use crate::linker::StoreData;

/// The interface a QQQ application exports.
///
/// Measured from a real component (`wasm-tools print`), not composed from the WIT
/// file's spelling: a component-model export name carries no `interface` prefix.
pub const HANDLER_INTERFACE: &str = "qqq:http/incoming-handler@1.0.0";

/// The method within [`HANDLER_INTERFACE`].
pub const HANDLER_METHOD: &str = "handle";

/// Why a guest call could not be completed **by the host**.
///
/// Deliberately distinct from the guest's own `http-error`, for the reason the module
/// documentation gives: conflating them sends an operator to the wrong cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The component does not export the handler interface.
    ///
    /// The component is not a QQQ application — it was built without
    /// `wit/app/app.wit`, or against a different world. Worth its own variant
    /// because the fix is "rebuild with the right world", not "debug the guest".
    NotAnApplication,
    /// The interface is exported but the method is absent.
    ///
    /// A component built against a **different version** of `qqq:http`. Distinct
    /// from [`Failure::NotAnApplication`] because the fix is a version mismatch,
    /// and an operator told "not an application" would rebuild the wrong thing.
    HandlerMissing,
    /// The stored entry is not the function shape expected.
    ///
    /// The name resolved but the item is not a lifted function. This means the
    /// component and this host disagree about the interface's shape — a real
    /// incompatibility, not a missing piece.
    NotAFunction,
}

impl Failure {
    /// A stable, machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAnApplication => "not_an_application",
            Self::HandlerMissing => "handler_missing",
            Self::NotAFunction => "not_a_function",
        }
    }

    /// The error a caller reports.
    #[must_use]
    pub fn to_error(self, component: &str) -> Error {
        let (code, message, fix) = match self {
            Self::NotAnApplication => (
                ErrorCode::InvalidComponentArtifact,
                format!(
                    "`{component}` does not export `{HANDLER_INTERFACE}`, so it is not a QQQ \
                     application"
                ),
                "build the component against `wit/app/app.wit`, which declares that export",
            ),
            Self::HandlerMissing => (
                ErrorCode::InvalidComponentArtifact,
                format!(
                    "`{component}` exports `{HANDLER_INTERFACE}` but not its `{HANDLER_METHOD}` \
                     method"
                ),
                "the component was built against a different version of `qqq:http`; rebuild \
                 against the version this host implements",
            ),
            Self::NotAFunction => (
                ErrorCode::InvalidComponentArtifact,
                format!(
                    "`{component}` exports `{HANDLER_INTERFACE}.{HANDLER_METHOD}` but it is not \
                     a function"
                ),
                "this is an interface-shape mismatch between the component and this host",
            ),
        };
        Error::new(code, message)
            .with_context("component", component.to_owned())
            .with_remediation(fix)
    }
}

/// The guest's handler, resolved once and callable many times.
///
/// # Why this holds indices rather than a `Func`
///
/// A `wasmtime::component::Func` is bound to a **store**, and QQQ creates one store
/// per request (`§4.2`: per-request isolation is the whole point). A `Func` resolved
/// against request N's store cannot be called against request N+1's — so what travels
/// is the **export index**, which is a property of the compiled component and valid
/// in every store built from it.
///
/// This is the difference between resolving the export once per *component* and once
/// per *request*: the lookup is two hash-map probes, and doing it per request would
/// put them on the hot path for no gain.
#[derive(Debug, Clone)]
pub struct HandlerHandle {
    /// The interface export index.
    interface: ComponentExportIndex,
    /// The method export index within it.
    method: ComponentExportIndex,
    /// The component's name, for diagnostics.
    component: String,
}

impl HandlerHandle {
    /// Resolve a component's handler export.
    ///
    /// # Why this takes a store
    ///
    /// `Instance::get_export_index` needs one to reach the compiled component. Any
    /// store built from the same engine works, including a throwaway one, which is
    /// what the caller does during admission — resolving before the first request
    /// means a component that is not a QQQ application is refused at **admission**
    /// rather than after a request has been read.
    ///
    /// # Errors
    ///
    /// [`Failure`] converted to an [`Error`], naming which of the three states the
    /// component is in. A component that is not a QQQ application must be
    /// distinguishable from one built against the wrong interface version, because
    /// the two have different fixes.
    pub fn resolve(
        store: impl wasmtime::AsContextMut<Data = StoreData>,
        instance: &WasmInstance,
        component: &str,
    ) -> Result<Self> {
        let mut store = store;
        // Step 1: the interface. A component-model export is an *instance* whose
        // methods are exports within it, so the lookup is two probes, not one.
        let (_, interface_index) = instance
            .get_export(&mut store, None, HANDLER_INTERFACE)
            .ok_or_else(|| Failure::NotAnApplication.to_error(component))?;

        // Step 2: the method, looked up *within* the interface.
        //
        // `ComponentItem` is not re-exported by `wasmtime::component` (it is
        // `pub` in `types.rs` but absent from the module's `pub use` list), so the
        // item's kind cannot be matched on directly. The check below is therefore
        // the authoritative one instead of a proxy for it: `Instance::get_func`
        // returns `Some` only for an export that is a **lifted function**, which
        // is exactly the property that matters. Asking Wasmtime the real question
        // beats pattern-matching on a variant that has to be guessed at.
        let index = instance
            .get_export_index(&mut store, Some(&interface_index), HANDLER_METHOD)
            .ok_or_else(|| Failure::HandlerMissing.to_error(component))?;

        if instance.get_func(&mut store, index).is_none() {
            return Err(Failure::NotAFunction.to_error(component));
        }

        Ok(Self {
            interface: interface_index,
            method: index,
            component: component.to_owned(),
        })
    }

    /// The component this handler belongs to.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// The interface export index, for diagnostics and tests.
    #[must_use]
    pub const fn interface_index(&self) -> &ComponentExportIndex {
        &self.interface
    }

    /// The method export index, for diagnostics and tests.
    #[must_use]
    pub const fn method_index(&self) -> &ComponentExportIndex {
        &self.method
    }

    /// Resolve the callable function in one specific store.
    ///
    /// # Errors
    ///
    /// [`Failure::HandlerMissing`] if the store was not built from the component this
    /// handle was resolved against — which is a **programming error**, not a guest
    /// condition, so the message says so rather than blaming the guest.
    pub fn func(
        &self,
        store: &mut Store<StoreData>,
        instance: &WasmInstance,
    ) -> Result<wasmtime::component::Func> {
        instance.get_func(store, self.method).ok_or_else(|| {
            Error::new(
                ErrorCode::InternalInvariantViolated,
                format!(
                    "the resolved method export for `{}` is not present in this store",
                    self.component
                ),
            )
            .with_remediation(
                "this is a QQQ bug: the handle and the instance must come from the same component",
            )
        })
    }
}

impl std::fmt::Display for HandlerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{HANDLER_INTERFACE}.{HANDLER_METHOD}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_export_names_are_the_measured_strings() {
        // These are the exact strings `wasm-tools print` shows in a component built
        // against `wit/app/app.wit`. A change here is a change to the ABI, so the
        // test exists to make it a deliberate edit rather than a typo.
        assert_eq!(HANDLER_INTERFACE, "qqq:http/incoming-handler@1.0.0");
        assert_eq!(HANDLER_METHOD, "handle");
    }

    #[test]
    fn each_failure_has_a_distinct_stable_name() {
        let names = [
            Failure::NotAnApplication.as_str(),
            Failure::HandlerMissing.as_str(),
            Failure::NotAFunction.as_str(),
        ];
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            names.len(),
            "names must be distinct: {names:?}"
        );
    }

    #[test]
    fn a_missing_application_is_not_reported_as_a_missing_method() {
        // The two have different fixes -- rebuild against the world, versus rebuild
        // against a different interface version -- so the messages must not be
        // interchangeable.
        let a = Failure::NotAnApplication.to_error("app.wasm");
        let b = Failure::HandlerMissing.to_error("app.wasm");
        assert_ne!(a.message, b.message);
        assert!(a.message.contains("is not a QQQ application"));
        assert!(b.message.contains("but not its `handle` method"));
        // Both must name the component, because a server hosts more than one.
        for e in [&a, &b] {
            assert!(
                e.context
                    .iter()
                    .any(|(k, v)| k == "component" && v == "app.wasm"),
                "the error must name the component: {e:?}"
            );
        }
    }

    #[test]
    fn every_failure_carries_a_remediation() {
        for f in [
            Failure::NotAnApplication,
            Failure::HandlerMissing,
            Failure::NotAFunction,
        ] {
            let e = f.to_error("app.wasm");
            assert!(
                e.remediation.is_some(),
                "`{}` must say what to do: {e:?}",
                f.as_str()
            );
        }
    }

    #[test]
    fn the_display_form_is_the_fully_qualified_method() {
        // `ComponentExportIndex` has no public constructor, so a `HandlerHandle`
        // cannot be built without a real component. That is a good property -- it
        // means a handle can only ever name an export that exists -- so the display
        // format is asserted against the constants instead, and the integration test
        // in `tests/guest_invocation.rs` covers the handle itself with a real
        // component.
        assert_eq!(
            format!("{HANDLER_INTERFACE}.{HANDLER_METHOD}"),
            "qqq:http/incoming-handler@1.0.0.handle"
        );
    }
}
