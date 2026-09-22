// SPDX-License-Identifier: Apache-2.0

//! Guest invocation, against **real** compiled components.
//!
//! # Why the fixtures are compiled from WAT
//!
//! `§O-141`'s lesson, applied: a fixture I compose can encode the same wrong
//! assumption as the code it tests, and then the two agree with each other and
//! disagree with reality. This module's whole subject is the *export name* of a
//! component-model interface -- a fact about what a compiler emits -- so the
//! fixtures are compiled by Wasmtime from WAT, and the name strings were taken from
//! `wasm-tools print` on a real `wasm32-wasip2` guest (`§O-147`).
//!
//! # The three states, and why they must be distinguishable
//!
//! A component may (1) not export the interface at all, (2) export it but not the
//! `handle` method, or (3) be structurally wrong. Each has a different fix --
//! rebuild against the world, rebuild against a different interface version, or
//! report a host bug -- so the tests below check that the messages do not collapse
//! into one another.

use qqq_cap::manifest::Manifest;
use qqq_cap::resolve::GrantSet;
use qqq_core::Error;
use qqq_host::invoke::{Failure, HandlerHandle, HANDLER_INTERFACE, HANDLER_METHOD};
use qqq_host::{Instance, LimitSet, PreparedComponent};

/// The smallest component that **is** a QQQ application.
///
/// The export shape is the whole point: `qqq:http/incoming-handler@1.0.0` is an
/// *instance* export whose `handle` member is an export *within* it. That two-step
/// shape is what [`HandlerHandle::resolve`] performs, and a single-step lookup
/// would find nothing -- which is the defect this fixture exists to catch.
const AN_APPLICATION: &str = r#"
(component
  (core module $m
    (func (export "handle") (param i32) (result i32) i32.const 0))
  (core instance $i (instantiate $m))
  (func $handle (param "req" u32) (result u32)
    (canon lift (core func $i "handle")))
  (instance $iface (export "handle" (func $handle)))
  (export "qqq:http/incoming-handler@1.0.0" (instance $iface))
)
"#;

/// A component that exports **nothing** -- not a QQQ application.
const NOT_AN_APPLICATION: &str = r#"
(component
  (core module $m (func (export "f") (result i32) i32.const 1))
  (core instance $i (instantiate $m))
)
"#;

/// A component that exports the interface but a **different method name**.
///
/// This stands in for "built against a different version of `qqq:http`". It must
/// not be reported as a non-application: the operator's fix is a version mismatch,
/// not a rebuild against the world.
const WRONG_METHOD: &str = r#"
(component
  (core module $m
    (func (export "handle") (param i32) (result i32) i32.const 0))
  (core instance $i (instantiate $m))
  (func $other (param "req" u32) (result u32)
    (canon lift (core func $i "handle")))
  (instance $iface (export "invoke" (func $other)))
  (export "qqq:http/incoming-handler@1.0.0" (instance $iface))
)
"#;

fn engine() -> wasmtime::Engine {
    let mut cfg = wasmtime::Config::new();
    cfg.wasm_component_model(true);
    cfg.consume_fuel(true);
    cfg.epoch_interruption(true);
    wasmtime::Engine::new(&cfg).expect("engine must build")
}

fn no_grants() -> GrantSet {
    GrantSet::from_manifest(
        &Manifest::parse("[package]\nname = \"invoke\"\nversion = \"0.1.0\"\n")
            .expect("a minimal manifest parses"),
    )
}

fn ordinary_limits() -> LimitSet {
    LimitSet {
        memory_bytes: 16 * 1024 * 1024,
        fuel: 10_000_000,
        epoch_deadline_ms: 5_000,
        max_open_handles: 64,
        max_subrequests: 32,
    }
}

/// Resolve a handler against a WAT fixture.
///
/// Returns the handle's display form on success, or the [`Error`] so a test can
/// assert on the message and remediation.
///
/// # Why the error travels in a slot rather than through the closure's `Result`
///
/// `Instance::run`'s closure returns `Result<T, wasmtime::Error>`, and any `Err`
/// from it is classified as a **trap**: measured, a resolution failure surfaced as
/// `"the guest trapped"`, with the real message discarded. That is correct for the
/// production path -- a failure inside a guest call *is* a trap -- but it means a
/// host-side lookup error cannot be observed through that channel.
///
/// So the error is written to a slot the closure captures, and the closure itself
/// always succeeds at the Wasmtime level. The host's own error then reaches the
/// test intact, which is what lets `a_wrong_method_name_...` assert on the message
/// instead of on the word "trapped".
fn resolve(wat: &str, name: &str) -> Result<String, Error> {
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, wat.as_bytes())
        .expect("the fixture must compile as a component");
    let grants = no_grants();
    let instance = Instance::create(&engine, &prepared, &grants, ordinary_limits())
        .expect("the fixture must instantiate");

    let mut slot: Option<Error> = None;
    let display = instance
        .run(
            |store, wasm| match HandlerHandle::resolve(&mut *store, wasm, name) {
                Ok(handle) => Ok(handle.to_string()),
                Err(e) => {
                    slot = Some(e);
                    // A payload that cannot be mistaken for a resolved handle, so a
                    // closure that swallowed the error would fail the tests below
                    // rather than look like a success.
                    Ok("<resolution failed>".to_owned())
                }
            },
        )
        .expect("the fixture must not trap");

    match slot {
        Some(e) => Err(e),
        None => Ok(display),
    }
}

#[test]
fn a_real_application_resolves_its_handler() {
    let display = resolve(AN_APPLICATION, "app.wasm")
        .expect("a component exporting the interface must resolve");

    assert_eq!(
        display,
        format!("{HANDLER_INTERFACE}.{HANDLER_METHOD}"),
        "the resolved handle must name the fully qualified method"
    );
    assert_eq!(display, "qqq:http/incoming-handler@1.0.0.handle");
}

#[test]
fn a_component_that_is_not_an_application_is_refused_by_name() {
    let err = resolve(NOT_AN_APPLICATION, "not-app.wasm")
        .expect_err("a component with no such export must be refused");

    assert!(
        err.message.contains("is not a QQQ application"),
        "the message must say what the component is not: {}",
        err.message
    );
    assert!(
        err.remediation
            .as_deref()
            .is_some_and(|r| r.contains("wit/app/app.wit")),
        "the fix must name the world to build against: {err:?}"
    );
    assert!(
        err.context
            .iter()
            .any(|(k, v)| k == "component" && v == "not-app.wasm"),
        "the error must name the offending component: {err:?}"
    );
}

#[test]
fn a_wrong_method_name_is_not_reported_as_not_an_application() {
    // The distinction that matters: "rebuild against the world" and "rebuild
    // against a different interface version" are different instructions, and an
    // operator given the wrong one fixes nothing.
    let err = resolve(WRONG_METHOD, "old-version.wasm")
        .expect_err("a component with the wrong method must be refused");

    assert!(
        err.message.contains("but not its `handle` method"),
        "the message must name the missing method: {}",
        err.message
    );
    assert!(
        !err.message.contains("is not a QQQ application"),
        "a version mismatch must not be reported as a non-application: {}",
        err.message
    );
}

/// A control: the positive fixture resolves, and only under the measured name.
///
/// Without this, `a_real_application_resolves_its_handler` would also pass if the
/// lookup accepted any name at all -- and dropping the `@1.0.0` suffix is exactly
/// the tidy-up that would break every real guest.
#[test]
fn the_positive_fixture_resolves_only_under_the_measured_name() {
    let display = resolve(AN_APPLICATION, "app.wasm").expect("the control must itself resolve");
    assert_eq!(display, "qqq:http/incoming-handler@1.0.0.handle");

    assert_ne!(
        HANDLER_INTERFACE, "qqq:http/incoming-handler",
        "the version suffix is part of the export name and must not be dropped"
    );
    assert_ne!(HANDLER_METHOD, "handle_request");
}

#[test]
fn failures_are_named_for_machines() {
    assert_eq!(Failure::NotAnApplication.as_str(), "not_an_application");
    assert_eq!(Failure::HandlerMissing.as_str(), "handler_missing");
    assert_eq!(Failure::NotAFunction.as_str(), "not_a_function");
}
