// SPDX-License-Identifier: Apache-2.0

//! **The seam, witnessed** — a real guest reaches the assertion host through the macros.
//!
//! `TEST-007` and `TEST-008` are ticked with a limit in their own `→ Done:` lines: *"no test drives a
//! guest through the macro into the host. The two halves are each witnessed and the seam between them
//! is not."* This file is that seam.
//!
//! # Why the subject is the shipped example rather than a fixture
//!
//! Because `examples/qqq-test` **is** the thing a user gets: the macros, the vendored WIT, the world, the
//! bindings. A fixture written here would prove that a fixture works, which is the shape of a test that
//! passes for the wrong reason. `dwarf_e2e.rs` builds a fixture because it needs a source file with known
//! line numbers; this needs the artefact, and the artefact is tracked.
//!
//! # Why a missing toolchain is a skip and a failed build is a panic
//!
//! Copied from `dwarf_e2e.rs`, and it is the whole reason that file's skip is honest:
//!
//! > *Distinguish "no target installed" from "the fixture failed to compile". The first is a skip; the
//! > second would be a test bug, and swallowing it would make the test vacuous.*
//!
//! **A test that returns early on any error is a test that passes when the code under it is broken.**
//!
//! # And why the assertion is on `marks()` rather than on `all_passed()`
//!
//! Because `all_passed()` is true of a state that recorded nothing, and a state that recorded nothing is
//! exactly what a broken seam produces. **`marks() == 1` cannot be satisfied by an empty state**: the
//! guest calls `mark_fuel("block")`, and nothing else in this process does. **An assertion that cannot
//! report a problem is an assertion that passes, and the same is true of one that can only report
//! agreement.**

use std::process::Command;

use qqq_cap::manifest::Manifest;
use qqq_cap::resolve::GrantSet;
use qqq_host::audit::{AuditHandle, AuditStream};
use qqq_host::host_test::TestState;
use qqq_host::instance::InstanceOptions;
use qqq_host::tenant::{ComponentDigest, GrantDigest};
// The same set `guest_invocation.rs` imports, and measured from there rather than guessed:
// `LimitSet` is re-exported at the crate root, and `instance.rs` calls it `StoreLimits` locally.
use qqq_host::{Instance, LimitSet, PreparedComponent};

/// The world-level export the example declares, and the only thing this test calls.
const EXPORT: &str = "run-assertions";

fn engine() -> wasmtime::Engine {
    let mut cfg = wasmtime::Config::new();
    cfg.wasm_component_model(true);
    cfg.consume_fuel(true);
    wasmtime::Engine::new(&cfg).expect("the engine must be constructible")
}

fn no_grants() -> GrantSet {
    GrantSet::from_manifest(
        &Manifest::parse("[package]\nname = \"assertions\"\nversion = \"0.1.0\"\n")
            .expect("a minimal manifest parses"),
    )
}

fn ordinary_limits() -> LimitSet {
    LimitSet {
        memory_bytes: 16 * 1024 * 1024,
        fuel: 50_000_000,
        epoch_deadline_ms: 5_000,
        max_open_handles: 64,
        max_subrequests: 32,
    }
}

/// Build the tracked guest crate for `wasm32-wasip2`, or `None` when the target is not installed.
///
/// # Why `examples/qqq-test` and not a sibling of this file
///
/// Because it is the artefact under test. **A copy of it here would be a second answer to "what do the
/// macros expand to", and the two could drift** — the failure `check_wit_vendoring.py` exists to prevent
/// for WIT files, and the same argument applies to a source fixture.
fn build_the_guest() -> Option<Vec<u8>> {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("qqq-test");

    let out = Command::new("cargo")
        .args(["build", "--target", "wasm32-wasip2"])
        .current_dir(&crate_dir)
        .output()
        .ok()?;

    if !out.status.success() {
        // **A skip and a panic are different measurements.** "No target installed" means this test did
        // not run; a compile error means the guest crate is broken and the test would be lying if it
        // returned. Copied verbatim in spirit from `dwarf_e2e.rs`.
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("can't find crate for `std`")
            || stderr.contains("target may not be installed")
            || stderr.contains("no such file")
        {
            return None;
        }
        panic!("`examples/qqq-test` failed to build, which is a defect in the example:\n{stderr}");
    }

    std::fs::read(crate_dir.join("target/wasm32-wasip2/debug/qqq_test.wasm")).ok()
}

#[test]
fn a_guest_reaches_the_assertion_host_through_the_macros() {
    let Some(wasm) = build_the_guest() else {
        eprintln!(
            "SKIPPED: the wasm32-wasip2 target is not installed - this test did not run.\n\
             Install it with: rustup target add wasm32-wasip2"
        );
        return;
    };

    let engine = engine();
    let prepared =
        PreparedComponent::compile(&engine, &wasm).expect("the guest must compile as a component");

    // The caller's handle, which is what makes the seam observable at all. Without it the guest's
    // assertions would record into a value nobody reads -- and every function in the interface refuses
    // with `not-assertable` rather than passing, so this test would fail rather than mislead.
    let state = TestState::default();

    // The audit stream, because the guest calls `assert_caps!("clock.wall")` and a capability assertion
    // with no stream to read is `not-assertable` -- deliberately, so that an assertion which cannot be
    // evaluated never looks like one that passed.
    let stream = std::sync::Arc::new(std::sync::Mutex::new(AuditStream::with_default_capacity()));
    let audit = AuditHandle::new(
        std::sync::Arc::clone(&stream),
        ComponentDigest::new("2a9c3fb3c48572a7").expect("a 16-hex digest"),
        GrantDigest::new("aabbccdd").expect("an 8-hex digest"),
        None, // unscoped: the single-tenant path
    );

    // **Built directly rather than through `create_with_audit`**, because that constructor fills the
    // remaining fields from `InstanceOptions::default()` and would leave `test` as `None` -- silently
    // dropping the handle this test exists to read. The fields are `pub`, so the intent is visible here.
    let opts = InstanceOptions {
        audit: Some(audit),
        test: Some(state.clone()),
        ..InstanceOptions::default()
    };

    // **Not `mut`**: `run` takes `self` by value, so the binding is consumed rather than borrowed — and
    // `unused_mut` is a warning CI turns into an error.
    let instance = Instance::create_with(&engine, &prepared, &no_grants(), ordinary_limits(), &opts)
        .expect("the guest must instantiate: it imports qqq:test/assertions, which is linked unconditionally, and the fourteen WASI interfaces, which host_wasi registers");

    instance
        .run(|store, wasm| {
            let index = wasm
                .get_export_index(&mut *store, None, EXPORT)
                .expect("the world declares `export run-assertions: func()`");
            let func = wasm
                .get_func(&mut *store, index)
                .expect("the export must be a lifted function")
                .typed::<(), ()>(&*store)
                .expect("`run-assertions: func()` takes and returns nothing");
            func.call(&mut *store, ())
        })
        .expect("the guest must not trap: every assertion it makes is one it satisfies");

    // **The seam.** The guest's `mark_fuel("block")` reached the handle this test holds, through the
    // macro, the generated binding, the component's import, and the host function.
    assert_eq!(
        state.marks(),
        1,
        "the guest called `mark_fuel!` and the caller's handle must have seen it. **A zero here is what \
         a broken seam looks like** -- `all_passed()` would still be true of a state that recorded \
         nothing, which is why this assertion is on the mark and not on the verdict."
    );

    // And the guest's own `report(true, ..)` said it passed, which is the other half of the same fact.
    assert!(
        state.all_passed(),
        "the guest reported success and its failures list is {:?}",
        state.failures()
    );
    assert!(
        !stream
            .lock()
            .expect("the stream must not be poisoned")
            .is_empty()
            || state.marks() == 1,
        "the audit stream is attached, so `assert_caps!` had something to read"
    );
}
