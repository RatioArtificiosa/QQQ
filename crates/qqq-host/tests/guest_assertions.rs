// SPDX-License-Identifier: Apache-2.0

//! **The seam, witnessed** — a real guest reaches the assertion host through the macros, and both ways an
//! assertion can go wrong are witnessed too.
//!
//! `TEST-007` and `TEST-008` are ticked with a limit in their own `→ Done:` lines: *"no test drives a
//! guest through the macro into the host. The two halves are each witnessed and the seam between them is
//! not."* This file is that seam — and, since a passing path alone proves only that the plumbing connects,
//! it also drives the two refusals the interface exists for.
//!
//! # The three cases, and why each is a separate measurement
//!
//! | export | what the host does | what this file asserts |
//! |---|---|---|
//! | `run-assertions` | records a mark; all assertions hold | `marks() == 1` and `all_passed()` |
//! | `assert-fuel-exceeded` | **records a failure**; the call returns `Ok` | the call succeeded **and** `failures()` names the bound |
//! | `assert-caps-unknown` | returns `unknown-capability`; the macro panics | **the call fails** |
//!
//! **The middle row is the one that needs care**, because the host treats a false bound and an
//! unevaluable assertion differently — and that difference is the whole reason `assertion-error` exists:
//!
//!   * a **false bound** is a failed assertion: `assert-fuel-below` pushes to the failure list and returns
//!     `Ok(())`, so one run reports every failure rather than stopping at the first;
//!   * an **unevaluable** assertion is `not-assertable` or `no-fuel-baseline`: a WIT error, which the macro
//!     panics on, because a comparison with nothing behind it must not look like a verdict.
//!
//! **A test that only asserted "it failed" would pass on either path**, which is why the recording case
//! asserts on the *message* and the refusal case asserts on the *trap*.
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

use std::process::Command;
use std::sync::OnceLock;

use qqq_cap::manifest::Manifest;
use qqq_cap::resolve::GrantSet;
use qqq_host::audit::{AuditHandle, AuditStream};
use qqq_host::host_test::TestState;
use qqq_host::instance::InstanceOptions;
use qqq_host::tenant::{ComponentDigest, GrantDigest};
use qqq_host::{Instance, LimitSet, PreparedComponent};

/// The exit gate, so all three cases share one build rather than running three nested `cargo build`s.
///
/// `None` means the target is not installed, and that is a distinct answer from "the build failed" — the
/// distinction `dwarf_e2e.rs` records as the reason its skip is honest.
static GUEST: OnceLock<Option<Vec<u8>>> = OnceLock::new();

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

/// Build the tracked guest crate for `wasm32-wasip2`, or `None` when the toolchain cannot build it.
///
/// # Why the target root comes from the environment
///
/// **`CARGO_TARGET_DIR` is `/linux-target` in the bridge image** (`docker/Dockerfile:310`), and
/// `Command::new("cargo")` inherits it — so the artifact lands under that root, not under the crate. An
/// earlier version read `crate_dir/target` unconditionally, which meant **the read always failed in the
/// bridge, `None` was returned, and the test reported a missing toolchain for a build that had
/// succeeded.** It would skip in the bridge and run in CI, and **no gate-parity check can see the
/// difference** — which is the shape `§O-400` records for an artifact that is stale while the instrument
/// that would notice is broken at the same time.
///
/// # Why a spawn failure panics and only three signatures skip
///
/// A skip is a claim that the test did not run *for a stated reason*. An earlier version ended with
/// `.ok()?`, so **every** spawn failure became that claim, and "cargo is not on PATH" became
/// indistinguishable from "the fork failed". `"no such file"` was worse: it matches any missing file at
/// all — a wrong `--target`, a deleted source, a bad path.
///
/// **So the three signatures below are the toolchain's, and nothing else is treated as one.** After a
/// build *succeeds*, an unreadable artifact is a panic with its path, because that is a defect in this
/// test rather than a missing toolchain.
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
        .unwrap_or_else(|e| {
            panic!("`cargo` could not be run, so this test cannot report a result: {e}")
        });

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("can't find crate for `std`")
            || stderr.contains("target may not be installed")
            || stderr.contains("is not installed for the toolchain")
        {
            return None;
        }
        panic!("`examples/qqq-test` failed to build, which is a defect in the example:\n{stderr}");
    }

    // **The root Cargo actually wrote to.** `CARGO_TARGET_DIR` wins when it is set, which is every run
    // inside the bridge.
    //
    // **A relative value is resolved against `crate_dir`, because that is what Cargo does.** The
    // variable is relative to the *invocation's* working directory, and the `current_dir` above makes
    // that `crate_dir`; resolving it against this test process instead names a directory Cargo never
    // wrote to. That is what this did until the review caught it -- it traded a silent skip for a loud
    // panic rather than for the right path, which is better and still wrong.
    let root = match std::env::var_os("CARGO_TARGET_DIR") {
        None => crate_dir.join("target"),
        Some(dir) => {
            let candidate = std::path::PathBuf::from(&dir);
            if candidate.is_absolute() {
                candidate
            } else {
                crate_dir.join(candidate)
            }
        }
    };
    let artifact = root
        .join("wasm32-wasip2")
        .join("debug")
        .join("qqq_test.wasm");
    Some(std::fs::read(&artifact).unwrap_or_else(|e| {
        panic!(
            "the guest built, so the toolchain is present, but {} could not be read: {e}",
            artifact.display()
        )
    }))
}

/// Run one export with a **fresh** assertion state, and hand back both the outcome and the state.
///
/// A fresh state per case is not tidiness: `run-assertions` asserts `all_passed()`, so a failure left
/// behind by another case would make it fail for a reason that has nothing to do with what it tests.
fn run_export(wasm: &[u8], export: &str) -> (bool, TestState) {
    let engine = engine();
    let prepared =
        PreparedComponent::compile(&engine, wasm).expect("the guest must compile as a component");
    let state = TestState::default();

    // The audit stream, because `assert_caps!` reads what the code *attempted* and refuses with
    // `not-assertable` when there is no stream to read -- deliberately, so an assertion that cannot be
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
    // dropping the handle this file exists to read.
    let opts = InstanceOptions {
        audit: Some(audit),
        test: Some(state.clone()),
        ..InstanceOptions::default()
    };

    let instance =
        Instance::create_with(&engine, &prepared, &no_grants(), ordinary_limits(), &opts).expect(
            "the guest must instantiate: it imports qqq:test/assertions, which is linked unconditionally, \
             and the fourteen WASI interfaces, which host_wasi registers",
        );

    let ok = instance
        .run(|store, wasm| {
            let index = wasm
                .get_export_index(&mut *store, None, export)
                .unwrap_or_else(|| panic!("the world declares `export {export}: func()`"));
            let func = wasm
                .get_func(&mut *store, index)
                .expect("the export must be a lifted function")
                .typed::<(), ()>(&*store)
                .expect("the export takes and returns nothing");
            func.call(&mut *store, ())
        })
        .is_ok();

    (ok, state)
}

/// The skip message, kept in one place so all three cases say the same thing.
///
/// # Why this is a helper rather than three copies
///
/// Because `OnceLock::get_or_init` is what makes the three cases share one build — and a skip that was
/// spelled three ways could drift into one of them returning early for a reason of its own.
fn skipped() -> bool {
    if GUEST.get_or_init(build_the_guest).is_some() {
        return false;
    }
    eprintln!(
        "SKIPPED: the wasm32-wasip2 target is not installed - this test did not run.\n\
         Install it with: rustup target add wasm32-wasip2"
    );
    true
}

#[test]
fn a_guest_reaches_the_assertion_host_through_the_macros() {
    if skipped() {
        return;
    }
    let wasm = GUEST.get().and_then(Option::as_ref).expect("checked above");

    let (ok, state) = run_export(wasm, "run-assertions");
    assert!(ok, "the reference guest satisfies every assertion it makes");

    // **The seam.** The guest's `mark_fuel("block")` reached the handle this test holds, through the
    // macro, the generated binding, the component's import, and the host function.
    assert_eq!(
        state.marks(),
        1,
        "the guest called `mark_fuel!` and the caller's handle must have seen it. **A zero here is what \
         a broken seam looks like** -- `all_passed()` would still be true of a state that recorded \
         nothing, which is why this assertion is on the mark and not on the verdict."
    );
    assert!(
        state.all_passed(),
        "the guest reported success and its failures list is {:?}",
        state.failures()
    );
}

/// **A typo in a capability name is a refusal, not a silent pass.**
///
/// The WIT calls this *"the one error here that is almost always a test bug"*, and explains why it exists:
/// an unresolvable name would otherwise assert nothing and succeed. **The host returns
/// `unknown-capability` rather than a verdict, and the macro panics** — so the assertion cannot be
/// mistaken for one that held.
#[test]
fn a_misspelled_capability_refuses_rather_than_passing() {
    if skipped() {
        return;
    }
    let wasm = GUEST.get().and_then(Option::as_ref).expect("checked above");

    let (ok, state) = run_export(wasm, "assert-caps-unknown");
    assert!(
        !ok,
        "the guest asserted `clock.wal`, which is not a capability this runtime knows, so the macro must \
         panic -- and an assertion that checked nothing must never look like one that held. Its failures \
         list is {:?}",
        state.failures()
    );
}

/// **A bound the guest exceeds is *recorded*, not returned** — and the message says which bound.
///
/// The two are not the same refusal, and the difference is the reason `assertion-error` exists: a false
/// bound is a failed assertion that one run collects with every other, where an unevaluable one is an
/// error the macro panics on. **Asserting only "it failed" would pass on either path**, so this asserts on
/// the call's success *and* on the message.
#[test]
fn a_bound_the_guest_exceeds_is_recorded_rather_than_passing() {
    if skipped() {
        return;
    }
    let wasm = GUEST.get().and_then(Option::as_ref).expect("checked above");

    let (ok, state) = run_export(wasm, "assert-fuel-exceeded");
    assert!(
        ok,
        "a false bound is a *failed assertion*, not an error: the host records it and returns `Ok`, so one \
         run reports every failure instead of stopping at the first"
    );

    let failures = state.failures();
    assert_eq!(
        failures.len(),
        1,
        "the guest exceeded exactly one bound and the caller's handle must hold exactly that: {failures:?}"
    );
    assert!(
        failures[0].contains("which is not below 0"),
        "the recorded failure must name the bound it broke, because `assert_fuel_below!(\"exceeded\", 0)` \
         and a missing mark both end in a failure-shaped string: {failures:?}"
    );
    assert!(
        failures[0].contains("exceeded"),
        "the failure must name the mark, so a reader can find the assertion that broke: {failures:?}"
    );
}
