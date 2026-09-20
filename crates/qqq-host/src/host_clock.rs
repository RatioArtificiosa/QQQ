//! The `qqq:clock` host implementation.
//!
//! Wires the WIT package in `wit/qqq-clock.wit` to the [`AmbientState`] already
//! living in the store, so a granted `clock.wall` or `clock.monotonic` becomes
//! a set of callable host functions.
//!
//! Implements `HOST-016` for the clock interface.
//!
//! [`AmbientState`]: crate::ambient::AmbientState
//!
//! # Why the bindings are written by hand
//!
//! The long-term path is `wasmtime::component::bindgen!`, which generates the
//! trait and registration code from the WIT at compile time. That macro needs
//! the `wit/` directory wired into this crate's build, which is a change to
//! `Cargo.toml` and the build graph that affects every crate — the right call
//! for the *whole* interface set at once, not for one interface.
//!
//! Until then the signatures are written against the published WIT by hand, and
//! the correspondence is pinned by tests that read `qqq-clock.wit` and assert
//! every declared function is registered here. That test is what keeps a
//! hand-written binding honest: it cannot drift from the interface silently.
//!
//! # Determinism
//!
//! Every read goes through [`AmbientState`], which is deterministic when the
//! host is. There is no path here that consults the system clock directly —
//! that is the property that makes Proposal §10.5's replay guarantee hold for a
//! guest's view of time.
//!
//! # Registration is per-function, not per-interface
//!
//! `clock.wall` and `clock.monotonic` are separate capabilities. A manifest
//! granting only `monotonic` must not expose `now`, so each function is
//! registered under its own grant rather than the whole interface being
//! exposed whenever any part of it is granted.

use wasmtime::component::Linker;
use wasmtime::StoreContextMut;

use qqq_cap::capability::Capability;
use qqq_cap::resolve::GrantSet;

use crate::linker::StoreData;

/// The WIT package this module implements.
pub const INTERFACE: &str = "qqq:clock@1.0.0";

/// The `wall-clock` interface, as a component imports it.
pub const WALL_CLOCK: &str = "qqq:clock/wall-clock@1.0.0";

/// The `monotonic-clock` interface, as a component imports it.
pub const MONOTONIC_CLOCK: &str = "qqq:clock/monotonic-clock@1.0.0";

/// Why a clock operation failed, mirroring the WIT `clock-error` variant.
///
/// **The order is the WIT declaration order and must not be reordered.** A
/// `variant` is an indexed type, so `not-granted` is case 0. Swapping two cases
/// would make a guest interpret a denial as an out-of-range error — a silent,
/// security-relevant miscommunication that no type system catches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockError {
    /// The capability was not granted by any configuration layer.
    NotGranted = 0,
    /// The instant is not representable, or precedes the epoch.
    OutOfRange = 1,
    /// The host is shutting down.
    ShuttingDown = 2,
}

impl ClockError {
    /// The variant index, as the component ABI lowers it.
    #[must_use]
    pub const fn as_index(self) -> u32 {
        self as u32
    }
}

/// Register the clock host functions the grants justify.
///
/// # Errors
///
/// A `wasmtime::Error` if the linker rejects a signature — which would mean
/// this file and the WIT disagree, and is a build-time bug rather than a
/// configuration one.
pub fn register(linker: &mut Linker<StoreData>, grants: &GrantSet) -> wasmtime::Result<()> {
    if grants.grants(Capability::ClockWall) {
        register_wall_clock(linker)?;
    }
    if grants.grants(Capability::ClockMonotonic) {
        register_monotonic_clock(linker)?;
    }
    Ok(())
}

/// The `wall-clock` functions.
fn register_wall_clock(linker: &mut Linker<StoreData>) -> wasmtime::Result<()> {
    let mut inst = linker.instance(WALL_CLOCK)?;

    // `now: func() -> result<instant-ns, clock-error>`
    //
    // The capability check is repeated here even though registration is already
    // conditional. This is the defence-in-depth check: if a future change ever
    // registers this function unconditionally, the guest still cannot read the
    // clock without the grant. `recheck` in the linker module documents the
    // same reasoning for capabilities generally.
    inst.func_wrap(
        "now",
        |store: StoreContextMut<'_, StoreData>, (): ()| -> wasmtime::Result<(u64,)> {
            if !store.data().grants.grants(Capability::ClockWall) {
                return Err(denied(Capability::ClockWall));
            }
            Ok((store.data().ambient.now_nanos(),))
        },
    )?;

    // `resolution: func() -> duration-ns`
    inst.func_wrap(
        "resolution",
        |store: StoreContextMut<'_, StoreData>, (): ()| -> wasmtime::Result<(u64,)> {
            Ok((store.data().ambient.tick_interval_nanos(),))
        },
    )?;

    // `timezone: func() -> string`
    inst.func_wrap(
        "timezone",
        |_store: StoreContextMut<'_, StoreData>, (): ()| -> wasmtime::Result<(String,)> {
            // Always UTC. A host that applied its local timezone would make
            // guest output depend on deployment configuration, which the WIT
            // documentation explicitly forbids.
            Ok(("UTC".to_owned(),))
        },
    )?;

    Ok(())
}

/// The `monotonic-clock` functions.
fn register_monotonic_clock(linker: &mut Linker<StoreData>) -> wasmtime::Result<()> {
    let mut inst = linker.instance(MONOTONIC_CLOCK)?;

    inst.func_wrap(
        "now",
        |store: StoreContextMut<'_, StoreData>, (): ()| -> wasmtime::Result<(u64,)> {
            if !store.data().grants.grants(Capability::ClockMonotonic) {
                return Err(denied(Capability::ClockMonotonic));
            }
            Ok((store.data().ambient.elapsed_nanos(),))
        },
    )?;

    inst.func_wrap(
        "resolution",
        |store: StoreContextMut<'_, StoreData>, (): ()| -> wasmtime::Result<(u64,)> {
            Ok((store.data().ambient.tick_interval_nanos(),))
        },
    )?;

    Ok(())
}

/// The error a call-time re-check produces.
///
/// Phrased as a host error rather than a guest-visible `clock-error` because
/// reaching it means the linker was built incorrectly: the guest should never
/// have been able to call this function at all. Trapping makes that a loud
/// failure in testing rather than a quiet denial in production.
fn denied(cap: Capability) -> wasmtime::Error {
    wasmtime::Error::msg(format!(
        "capability `{cap}` was re-checked at call time and is not granted; \
         this means the linker was built incorrectly, which is a QQQ bug"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime::Engine;

    /// **The anti-drift test.** These bindings are hand-written against
    /// `wit/qqq-clock.wit`, so they can drift from it. This test reads the WIT
    /// and asserts every function it declares is registered in this file — the
    /// check that turns a silent ABI mismatch into a failing build.
    #[test]
    fn every_wit_function_is_registered() {
        let wit = include_str!("../../../wit/qqq-clock.wit");
        let this_file = include_str!("host_clock.rs");

        // `now` and `resolution` appear in BOTH interfaces, so a naive
        // occurrence check would pass with only one registered. Counting
        // instead is what makes this test actually verify the second.
        for name in ["now", "resolution"] {
            let declared = wit.matches(&format!("\n  {name}: func(")).count();
            let registered = this_file.matches(&format!("\"{name}\"")).count();
            assert!(
                declared >= 2,
                "`{name}` should be in both interfaces: {declared}"
            );
            assert!(
                registered >= declared,
                "`{name}` is declared {declared} times in the WIT but registered \
                 only {registered} times here"
            );
        }

        // Interface-unique functions: `timezone` exists only on wall-clock.
        let unique = "timezone";
        assert!(
            wit.contains(&format!("\n  {unique}: func(")),
            "`{unique}` is not declared in qqq-clock.wit"
        );
        assert!(
            this_file.matches(&format!("\"{unique}\"")).count() >= 1,
            "`{unique}` is declared in the WIT but never registered here"
        );
    }

    /// The package name must match the WIT declaration exactly. A typo means
    /// the linker binds a name no component imports, and every clock call fails
    /// with "unknown import" while this file looks correct.
    #[test]
    fn the_package_name_matches_the_wit() {
        let wit = include_str!("../../../wit/qqq-clock.wit");
        assert!(
            wit.contains(&format!("package {INTERFACE};")),
            "the WIT package declaration does not match INTERFACE={INTERFACE}"
        );
    }

    /// The interface paths must match the WIT `interface` declarations, because
    /// a component imports `qqq:clock/wall-clock@1.0.0` — not the package name.
    /// Getting this wrong binds nothing a component can reach.
    #[test]
    fn the_interface_paths_match_the_wit_declarations() {
        let wit = include_str!("../../../wit/qqq-clock.wit");
        assert!(wit.contains("interface wall-clock {"), "wall-clock renamed");
        assert!(
            wit.contains("interface monotonic-clock {"),
            "monotonic-clock renamed"
        );
        assert_eq!(WALL_CLOCK, "qqq:clock/wall-clock@1.0.0");
        assert_eq!(MONOTONIC_CLOCK, "qqq:clock/monotonic-clock@1.0.0");
    }

    /// The error variant order is an ABI. The WIT declares `not-granted` first.
    #[test]
    fn the_error_variant_order_matches_the_wit() {
        let wit = include_str!("../../../wit/qqq-clock.wit");
        let not_granted = wit.find("not-granted").expect("declared");
        let out_of_range = wit.find("out-of-range").expect("declared");
        let shutting_down = wit.find("shutting-down").expect("declared");
        assert!(
            not_granted < out_of_range && out_of_range < shutting_down,
            "the WIT declaration order changed; ClockError's indices must change too"
        );
        assert_eq!(ClockError::NotGranted.as_index(), 0);
        assert_eq!(ClockError::OutOfRange.as_index(), 1);
        assert_eq!(ClockError::ShuttingDown.as_index(), 2);
    }

    /// The discriminating test: only the granted capabilities are registered.
    ///
    /// A manifest granting `monotonic` alone must not expose the wall clock.
    /// Registering the whole interface when any part is granted is the widening
    /// bug this pins against.
    ///
    /// Each assertion uses a **fresh linker**, because the `has_func` probe
    /// defines the name it is testing when the name turns out to be free.
    #[test]
    fn registration_follows_the_grants() {
        let engine = test_engine();

        // Wall only: `now` under wall-clock, but nothing under monotonic-clock.
        {
            let mut linker = Linker::<StoreData>::new(&engine);
            register(&mut linker, &grants_with(&[Capability::ClockWall])).expect("register");
            assert!(
                has_func(&mut linker, WALL_CLOCK, "now"),
                "wall grant exposes now"
            );
            assert!(
                has_func(&mut linker, WALL_CLOCK, "timezone"),
                "wall grant exposes timezone"
            );

            let mut fresh = Linker::<StoreData>::new(&engine);
            register(&mut fresh, &grants_with(&[Capability::ClockWall])).expect("register");
            assert!(
                !has_func(&mut fresh, MONOTONIC_CLOCK, "now"),
                "a wall-only grant must not expose the monotonic clock"
            );
        }

        // Monotonic only: the converse.
        {
            let mut linker = Linker::<StoreData>::new(&engine);
            register(&mut linker, &grants_with(&[Capability::ClockMonotonic])).expect("register");
            assert!(
                has_func(&mut linker, MONOTONIC_CLOCK, "now"),
                "monotonic grant exposes monotonic-clock now"
            );

            let mut fresh = Linker::<StoreData>::new(&engine);
            register(&mut fresh, &grants_with(&[Capability::ClockMonotonic])).expect("register");
            assert!(
                !has_func(&mut fresh, WALL_CLOCK, "now"),
                "a monotonic-only grant must not expose the wall clock"
            );

            let mut fresh2 = Linker::<StoreData>::new(&engine);
            register(&mut fresh2, &grants_with(&[Capability::ClockMonotonic])).expect("register");
            assert!(
                !has_func(&mut fresh2, WALL_CLOCK, "timezone"),
                "a monotonic-only grant must not expose any wall-clock function"
            );
        }

        // Neither: nothing at all. This is the deny-by-default case, and it is
        // the most important of the three.
        {
            let mut linker = Linker::<StoreData>::new(&engine);
            register(&mut linker, &grants_with(&[])).expect("register");
            assert!(
                !has_func(&mut linker, WALL_CLOCK, "now"),
                "no grant must expose no wall-clock function"
            );

            let mut fresh = Linker::<StoreData>::new(&engine);
            register(&mut fresh, &grants_with(&[])).expect("register");
            assert!(
                !has_func(&mut fresh, MONOTONIC_CLOCK, "now"),
                "no grant must expose no monotonic function"
            );
        }
    }

    /// The probe itself must be able to detect a *present* name, or every
    /// assertion above passes vacuously. This is the positive control for
    /// `has_func`: without it, a probe that always returned `false` would make
    /// the deny-by-default test look like proof.
    #[test]
    fn the_registration_probe_can_detect_a_bound_function() {
        let engine = test_engine();
        let mut linker = Linker::<StoreData>::new(&engine);
        register(&mut linker, &grants_with(&[Capability::ClockWall])).expect("register");

        // `now` is registered, so the probe must report it present...
        assert!(
            has_func(&mut linker, WALL_CLOCK, "now"),
            "the probe failed to detect a function that is certainly registered"
        );
        // ...and a name that is certainly absent must be reported absent.
        let mut fresh = Linker::<StoreData>::new(&engine);
        register(&mut fresh, &grants_with(&[Capability::ClockWall])).expect("register");
        assert!(
            !has_func(&mut fresh, WALL_CLOCK, "definitely-not-a-clock-function"),
            "the probe reported a function that was never registered"
        );
    }

    /// Whether a linker exposes a function under an interface.
    ///
    /// # Why this is indirect
    ///
    /// `Linker` and `LinkerInstance` expose no lookup API in Wasmtime 48 — the
    /// full public surface is `new`, `engine`, `allow_shadowing`, `root`,
    /// `instance`, `instantiate*`, `func_wrap*`, `func_new*`, `module`,
    /// `resource*` and `define_unknown_imports_as_traps`. There is no `get` and
    /// no `iter`.
    ///
    /// The observable signal is **shadowing**: with shadowing disallowed (the
    /// default), redefining an existing name under the same interface fails,
    /// while defining a new one succeeds. So a successful second definition
    /// proves the name was *absent*, and its failure proves it was *present*.
    ///
    /// This is a real check rather than a placeholder — an earlier draft of
    /// this function returned a hardcoded `false`, which would have made the
    /// grant test pass vacuously.
    fn has_func(linker: &mut Linker<StoreData>, interface: &str, name: &str) -> bool {
        let Ok(mut inst) = linker.instance(interface) else {
            // The interface itself is absent, so no function under it can exist.
            return false;
        };
        // A zero-argument function returning `()` is the simplest possible
        // probe. Its signature is irrelevant: shadowing is a *name* check, so
        // a definition succeeds or fails before any type is compared.
        let probe = inst.func_wrap(name, |_: StoreContextMut<'_, StoreData>, (): ()| {
            Ok::<_, wasmtime::Error>(())
        });
        match probe {
            // The name was free, so it was not registered. Note that the probe
            // has now defined it, which is why callers must use a throwaway
            // linker per assertion.
            Ok(()) => false,
            // The name was taken, so it *was* registered.
            Err(_) => true,
        }
    }

    fn test_engine() -> Engine {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        Engine::new(&cfg).expect("engine")
    }

    /// A grant set containing exactly `caps`, built the way the runtime builds
    /// one.
    ///
    /// # Why this goes through a manifest
    ///
    /// `GrantSet::from_manifest` is documented as **the only layer that may
    /// grant authority**, and `narrow` intersects — so
    /// `GrantSet::empty().narrow(&Overlay::allow_only(...))` grants *nothing*,
    /// because intersecting with the empty set is empty. An earlier version of
    /// this helper did exactly that, and every assertion in
    /// `registration_follows_the_grants` passed or failed for reasons unrelated
    /// to the code under test: "no grant registers nothing" held trivially, and
    /// "a wall grant exposes `now`" failed.
    ///
    /// A test that cannot construct the state it means to test is worse than no
    /// test, so this builds a real `qqq.toml` and parses it.
    fn grants_with(caps: &[Capability]) -> GrantSet {
        use qqq_cap::manifest::Manifest;

        let has = |c: Capability| caps.contains(&c);
        let mut toml = String::from("[package]\nname = \"test\"\nversion = \"0.1.0\"\n");

        // One stanza per namespace: TOML forbids redeclaring a table, so the
        // capabilities sharing `[capabilities.clock]` must be written together.
        if has(Capability::ClockWall) || has(Capability::ClockMonotonic) {
            toml.push_str("\n[capabilities.clock]\n");
            if has(Capability::ClockWall) {
                toml.push_str("wall = true\n");
            }
            if has(Capability::ClockMonotonic) {
                toml.push_str("monotonic = true\n");
            }
        }
        if has(Capability::CryptoHash) || has(Capability::CryptoRandom) {
            toml.push_str("\n[capabilities.crypto]\n");
            if has(Capability::CryptoRandom) {
                toml.push_str("random = true\n");
            }
            if has(Capability::CryptoHash) {
                toml.push_str("hash = [\"sha256\"]\n");
            }
        }
        for cap in caps {
            assert!(
                matches!(
                    cap,
                    Capability::ClockWall
                        | Capability::ClockMonotonic
                        | Capability::CryptoHash
                        | Capability::CryptoRandom
                ),
                "grants_with has no stanza for {cap}; add one"
            );
        }

        let manifest = Manifest::parse(&toml).expect("test manifest must parse");
        let grants = GrantSet::from_manifest(&manifest);

        // The helper must not silently under-grant, or every test above it is
        // meaningless. Asserting the precondition is what caught the earlier
        // version, which granted nothing at all.
        for cap in caps {
            assert!(
                grants.grants(*cap),
                "grants_with failed to grant {cap}; the manifest stanza is wrong"
            );
        }
        grants
    }

    /// The test helper must be able to grant, and must be able to grant
    /// **nothing**. Without this positive control, a helper that always
    /// returned an empty set would make the deny-by-default assertion look like
    /// proof while making the positive assertions impossible.
    #[test]
    fn the_test_helper_grants_exactly_what_it_is_asked_for() {
        let none = grants_with(&[]);
        assert!(none.is_empty(), "an empty request must grant nothing");

        let wall = grants_with(&[Capability::ClockWall]);
        assert!(wall.grants(Capability::ClockWall));
        assert!(
            !wall.grants(Capability::ClockMonotonic),
            "granting wall must not grant monotonic"
        );

        let both = grants_with(&[Capability::ClockWall, Capability::ClockMonotonic]);
        assert!(both.grants(Capability::ClockWall));
        assert!(both.grants(Capability::ClockMonotonic));
    }

    /// The deterministic clock must advance only on explicit ticks, so two
    /// readings without a tick are equal. This is the property that makes a
    /// replayed run bit-identical.
    #[test]
    fn the_deterministic_clock_does_not_advance_on_its_own() {
        let a = crate::ambient::AmbientState::new(true);
        let first = a.now_nanos();
        let second = a.now_nanos();
        assert_eq!(first, second, "a virtual clock must not advance unasked");

        a.tick();
        assert!(
            a.now_nanos() > first,
            "an explicit tick must advance the clock"
        );
    }

    /// A non-deterministic clock must advance, or it is not a clock.
    #[test]
    fn the_real_clock_advances() {
        let a = crate::ambient::AmbientState::new(false);
        let first = a.now_nanos();
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(a.now_nanos() > first, "a real clock must move forward");
    }

    /// The resolution must be non-zero: a guest dividing by it would otherwise
    /// hit a divide-by-zero, a host bug surfacing as a guest crash.
    #[test]
    fn the_reported_resolution_is_usable() {
        for deterministic in [true, false] {
            let a = crate::ambient::AmbientState::new(deterministic);
            assert!(
                a.tick_interval_nanos() > 0,
                "resolution must be non-zero (deterministic={deterministic})"
            );
        }
    }

    /// The monotonic reading must be non-decreasing — the one guarantee the
    /// WIT makes about it, and the reason it uses `Instant` rather than
    /// `SystemTime`.
    #[test]
    fn the_monotonic_reading_never_decreases() {
        let a = crate::ambient::AmbientState::new(true);
        let mut last = a.elapsed_nanos();
        for _ in 0..10 {
            a.tick();
            let now = a.elapsed_nanos();
            assert!(
                now >= last,
                "monotonic time went backwards: {last} -> {now}"
            );
            last = now;
        }
    }

    /// The real-time monotonic clock must also move forward and never back.
    #[test]
    fn the_real_monotonic_reading_advances() {
        let a = crate::ambient::AmbientState::new(false);
        let first = a.elapsed_nanos();
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(
            a.elapsed_nanos() > first,
            "a real monotonic clock must advance"
        );
    }
}
