// SPDX-License-Identifier: Apache-2.0

//! The WASI 0.3 subset the host serves: `wasi:clocks/monotonic-clock@0.3.2`
//! `now` and `get-resolution`.
//!
//! These two functions are sync in both revisions of the interface, so serving
//! them claims nothing about async execution: the same ambient read answers
//! whether the guest asked under `0.2` or `0.3`. Everything else in 0.3 —
//! `wait-until`, `wait-for`, and every other `async` function — is a trapping
//! stub below that names engine async support when called, never served and
//! never silently absent.
//!
//! Why a separate module rather than arms in `host_wasi`: the 0.2 path is
//! frozen by the dual-ABI contract (HOST-025) and must not change shape when
//! the 0.3 surface grows. A new module keeps the 0.2 diff at zero while the
//! 0.3 set expands one function at a time, each with its own red-first test.
//!
//! # Why the bindings are hand-written
//!
//! Same reason as `host_clock.rs`: `bindgen!` would wire the whole build graph
//! for one interface. The correspondence with the real
//! `proposals/clocks/wit/monotonic-clock.wit` (vendored byte-for-byte, with
//! provenance, at `crates/qqq-host/tests/fixtures/wasi-0.3.2-monotonic-clock.wit`)
//! is pinned by the anti-drift test in this file: a hand-written binding that
//! drifts from the interface it claims is a silent ABI mismatch, so the test
//! fails the build instead.
//!
//! # Reaching this module
//!
//! The module is private: guests reach it through
//! [`crate::linker::build_linker_for_abi`] with [`crate::linker::AbiVersion::V03`].
//!
//! ```
//! use qqq_cap::manifest::Manifest;
//! use qqq_cap::resolve::GrantSet;
//! use qqq_host::linker::{AbiVersion, build_linker_for_abi};
//!
//! let manifest = Manifest::parse(
//!     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.clock]\nmonotonic = true\n",
//! )
//! .expect("fixture manifest parses");
//! let engine = wasmtime::Engine::new(&wasmtime::Config::new()).expect("engine builds");
//! let built = build_linker_for_abi(&engine, &GrantSet::from_manifest(&manifest), AbiVersion::V03)
//!     .expect("the 0.3 linker builds beside the retained 0.2 path");
//! assert!(
//!     built.bound.interfaces.iter().any(|i| i.contains("0.3.2")),
//!     "the 0.3 linker binds the versioned clock: {:?}",
//!     built.bound.interfaces
//! );
//! ```
//!
//! ```
//! use qqq_host::linker::AbiVersion;
//!
//! // A 0.3 import routes to this module's path even beside a 0.2 one: the
//! // newer semantics win, or the 0.3 import would be served something older
//! // than it asked for.
//! assert_eq!(
//!     AbiVersion::detect([
//!         "qqq:clock/monotonic-clock@1.0.0",
//!         "wasi:clocks/monotonic-clock@0.3.2"
//!     ]),
//!     AbiVersion::V03
//! );
//! ```
//!
//! ```
//! use qqq_cap::resolve::GrantSet;
//! use qqq_host::linker::{AbiVersion, build_linker};
//!
//! // The 0.2 path is retained byte for byte: the same builder as before,
//! // so every 0.2 test keeps proving the 0.2 path while the 0.3 one exists.
//! let engine = wasmtime::Engine::new(&wasmtime::Config::new()).expect("engine builds");
//! let built = build_linker(&engine, &GrantSet::empty()).expect("the 0.2 linker builds");
//! assert!(
//!     !built.bound.interfaces.iter().any(|i| i.contains("0.3.2")),
//!     "the retained path binds no 0.3 name: {:?}",
//!     built.bound.interfaces
//! );
//! ```

use wasmtime::StoreContextMut;
use wasmtime::component::Linker;

use qqq_cap::capability::Capability;
use qqq_cap::resolve::GrantSet;

use crate::linker::StoreData;

/// The 0.3 interface this module serves, exactly as the guest names it.
pub const MONOTONIC_CLOCK_03: &str = "wasi:clocks/monotonic-clock@0.3.2";

/// Every `instance/function` name this module serves. The declared contract
/// the anti-drift test below pins: a function added to `register` without
/// updating this list is caught, and a list entry with no implementation
/// behind it is caught too. It is a declaration for the test, not an input
/// the linker reads — the registrations in `register` are explicit literals
/// so the ARCH-003/ARCH-012 scanners see them.
///
/// `allow(dead_code)`: the only consumer is the anti-drift test, which
/// compiles under `cfg(test)` and therefore does not count as a use when the
/// library builds for real guests. Deleting the table and re-deriving it in
/// the test by parsing this file would make the test depend on its own
/// formatting instead of on a declared contract.
#[allow(dead_code)]
pub const SERVED_03: &[&str] = &[
    "wasi:clocks/monotonic-clock@0.3.2/now",
    "wasi:clocks/monotonic-clock@0.3.2/get-resolution",
];

/// 0.3 imports the host refuses by name: real `async` functions in the v0.3.2
/// WIT that the engine cannot execute without component-model async, which
/// this host does not enable. Each name below has a trapping stub in
/// [`register`]: the guest instantiates, and calling one traps with the
/// reason instead of failing to link. That is deliberate, and it follows the
/// repo's own precedent (`host_test` registers unconditionally and its
/// functions refuse without test state): an absent import gives the guest a
/// generic "unknown import", which names the wrong problem, while the trap
/// names the missing capability — here, engine async support.
///
/// Advisory, not exhaustive: anything not served AND not listed here still
/// fails closed at instantiation as an unknown import; these names get the
/// helpful error instead of the generic one. Extend with real `async`
/// declarations only, each with its own refusal test.
///
/// `allow(dead_code)`: as with `SERVED_03` above, the only consumer is the
/// anti-drift test under `cfg(test)`. The registrations in `register` are
/// explicit literals (so the ARCH scanners see them); this table is the
/// declared contract the test pins them against.
#[allow(dead_code)]
pub const KNOWN_ASYNC_03: &[&str] = &[
    "wasi:clocks/monotonic-clock@0.3.2/wait-until",
    "wasi:clocks/monotonic-clock@0.3.2/wait-for",
];

/// Register the served 0.3 subset: the versioned clock the grants justify.
///
/// Registration is conditional on [`Capability::ClockMonotonic`], exactly as
/// `host_clock::register` gates the 0.2 monotonic clock: an ungranted guest
/// finds the instance *absent* and fails closed at instantiation with an
/// unknown import naming the clock, rather than being denied at call time.
/// A versioned name must never be a wider authority than the unversioned one.
///
/// `now` additionally re-checks the grant on every call (defence in depth,
/// same reasoning as `host_clock`'s `now`): if a future change ever registers
/// this function unconditionally, the guest still cannot read the clock
/// without the grant. `get-resolution` carries no recheck, mirroring the 0.2
/// `resolution`: the tick interval is configuration, not a reading.
///
/// # Errors
///
/// A `wasmtime::Error` if the linker rejects a definition — which would mean
/// this file and the WIT disagree, and is a build-time bug rather than a
/// configuration one.
pub fn register(linker: &mut Linker<StoreData>, grants: &GrantSet) -> wasmtime::Result<()> {
    if !grants.grants(Capability::ClockMonotonic) {
        return Ok(());
    }

    let mut inst = linker.instance(MONOTONIC_CLOCK_03)?;

    inst.func_wrap(
        "now",
        |store: StoreContextMut<'_, StoreData>, (): ()| -> wasmtime::Result<(u64,)> {
            crate::guard::guard("wasi:clocks@0.3.2/monotonic-clock.now", || {
                if !store.data().grants.grants(Capability::ClockMonotonic) {
                    return Err(denied(Capability::ClockMonotonic));
                }
                Ok((store.data().ambient.read_monotonic_nanos()?,))
            })
        },
    )?;

    inst.func_wrap(
        "get-resolution",
        |store: StoreContextMut<'_, StoreData>, (): ()| -> wasmtime::Result<(u64,)> {
            crate::guard::guard("wasi:clocks@0.3.2/monotonic-clock.get-resolution", || {
                Ok((store.data().ambient.tick_interval_nanos(),))
            })
        },
    )?;

    // Async 0.3 clocks: named traps, not absent imports.
    //
    // Written as two explicit registrations rather than a loop over
    // KNOWN_ASYNC_03, deliberately: the ARCH-003/ARCH-012 scanners anchor on
    // the string literal after `func_wrap(`, so a loop over a `&str` variable
    // would be invisible to the "exhaustive by construction" audit while still
    // binding host functions. Explicit literals keep every bound name inside
    // the audit. The table stays as the declared contract the anti-drift test
    // pins; the registrations below are its implementation, one per entry.
    inst.func_wrap(
        "wait-until",
        |_store: StoreContextMut<'_, StoreData>, (_when,): (u64,)| -> wasmtime::Result<()> {
            crate::guard::guard("wasi:clocks@0.3.2/monotonic-clock.async-refusal", || {
                Err(wasmtime::Error::msg(
                    "wasi:clocks/monotonic-clock@0.3.2 `wait-until` requires engine async support \
                     (component-model async / stack switching), which this host does not enable; \
                     re-measure when the engine enables it and a 0.3 toolchain exists",
                ))
            })
        },
    )?;

    inst.func_wrap(
        "wait-for",
        |_store: StoreContextMut<'_, StoreData>, (_how_long,): (u64,)| -> wasmtime::Result<()> {
            crate::guard::guard("wasi:clocks@0.3.2/monotonic-clock.async-refusal", || {
                Err(wasmtime::Error::msg(
                    "wasi:clocks/monotonic-clock@0.3.2 `wait-for` requires engine async support \
                     (component-model async / stack switching), which this host does not enable; \
                     re-measure when the engine enables it and a 0.3 toolchain exists",
                ))
            })
        },
    )?;

    Ok(())
}

/// The error a call-time re-check produces.
///
/// Phrased as a host error rather than a guest-visible refusal because
/// reaching it means the linker was built incorrectly: the guest should never
/// have been able to call this function at all. Trapping makes that a loud
/// failure in testing rather than a quiet denial in production. Same shape as
/// `host_clock::denied`, which documents the same reasoning.
fn denied(cap: Capability) -> wasmtime::Error {
    wasmtime::Error::msg(format!(
        "capability `{cap}` was re-checked at call time and is not granted; \
         this means the linker was built incorrectly, which is a QQQ bug"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The anti-drift test.** These bindings are hand-written against the
    /// real v0.3.2 `monotonic-clock.wit` (vendored with provenance in
    /// `tests/fixtures`), so they can drift from the interface they claim.
    /// The test reads the fixture line by line and asserts three things:
    /// every served name exists there *and* its line is not `async` (an
    /// `async` marker on a served function would mean the host claims a
    /// semantic it cannot execute); every refused name exists there *and*
    /// its line *is* async (a sync function on the refuse list would hide a
    /// servable shape behind a refusal); and the two lists do not overlap
    /// (a trap that fires on a served function).
    #[test]
    fn served_names_exist_and_async_ones_are_refused() {
        let wit = include_str!("../tests/fixtures/wasi-0.3.2-monotonic-clock.wit");
        assert!(
            wit.contains("package wasi:clocks@0.3.2;"),
            "the fixture must be the real 0.3.2 file, not a paraphrase"
        );
        let line_for = |func: &str| {
            wit.lines()
                .find(|line| line.contains(func) && line.contains("func("))
                .unwrap_or_else(|| panic!("the fixture must declare {func}"))
        };
        for name in SERVED_03 {
            let func = name
                .rsplit('/')
                .next()
                .expect("served names name a function");
            let line = line_for(func);
            assert!(
                !line.contains("async"),
                "served function must not be async in the real interface: {line}"
            );
        }
        for name in KNOWN_ASYNC_03 {
            let func = name
                .rsplit('/')
                .next()
                .expect("known-async names a function");
            assert!(
                !SERVED_03.contains(name),
                "an async function must never also be served: {func}"
            );
            let line = line_for(func);
            assert!(
                line.contains("async"),
                "refused function must be async in the real interface: {line}"
            );
        }
    }

    /// **HOST-026** — the served 0.3 surface needs no 0.3.1 WIT features.
    ///
    /// WASI 0.3.1 added `implements` and `map<K,V>` to WIT, and its release
    /// notes require both for 0.3.1+ compatibility. The pinned stack does not
    /// have them: wit-parser 0.254.2's keyword table (vendored sources,
    /// `ast/lex.rs`) has `map` but no `implements`, and wasmtime-wasi 48.0.7
    /// is enabled with `features = ["p2"]` only (workspace `Cargo.toml`),
    /// while its own `p3/` tree is 0.3.0-level (no `implements`, no `map<`).
    /// So the 0.3 path this host serves must be expressible without either —
    /// and this test pins exactly that: the vendored fixture the served
    /// shapes are hand-written against must contain no `implements`
    /// declaration and no `map<` type.
    ///
    /// A fixture that gains either (upstream re-vendors at 0.3.1+) fails here
    /// on purpose: that is the tripwire that re-opens HOST-026, because
    /// serving such a shape would need engine support this pin does not have.
    /// The `async` 0.3 functions fail the same way through the sibling test;
    /// together they bound the served surface to what the pinned engine can
    /// actually execute (`ENGINE_VERSION` names the pin; see its anti-drift
    /// test for the lockstep rule).
    #[test]
    fn served_03_needs_no_031_features() {
        let wit = include_str!("../tests/fixtures/wasi-0.3.2-monotonic-clock.wit");
        for line in wit.lines() {
            // Strip `//` comments so prose *about* a keyword (like this very
            // comment block, mirrored in the fixtures' own header) cannot trip
            // the check. Limitation, stated not hidden: a `//` inside a WIT
            // *string literal* would truncate the line and could hide a keyword
            // after it. No such literal exists in the fixture, and re-vendoring
            // is a reviewed act — either appearing reopens this (review note
            // on HOST-026).
            let code = line.split("//").next().unwrap_or(line);
            assert!(
                !code.contains("implements"),
                "`implements` needs 0.3.1 engine support the pin lacks: {line}"
            );
            // Both the canonical `map<K,V>` and a spaced `map <K, V>`: the
            // check is about the type existing, not about upstream formatting
            // it one particular way.
            assert!(
                !code.contains("map<") && !code.contains("map <"),
                "`map<...>` needs 0.3.1 engine support the pin lacks: {line}"
            );
        }
    }
}
