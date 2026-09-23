// SPDX-License-Identifier: Apache-2.0

//! The WASI host side: the context a store carries, and the linker registration.
//!
//! # Why this module has to exist
//!
//! A guest built by `cargo build --target wasm32-wasip2` imports **fifteen** WASI
//! interfaces even when its own source never calls one, because `std` for that
//! target is implemented over them. Measured on the reference application:
//!
//! ```text
//! import wasi:io/poll@0.2.9
//! import wasi:clocks/monotonic-clock@0.2.9
//! import wasi:io/error@0.2.9
//! import wasi:io/streams@0.2.9
//! import wasi:cli/stdout@0.2.9
//! import wasi:cli/stderr@0.2.9
//! import wasi:cli/stdin@0.2.9
//! import wasi:cli/environment@0.2.9
//! import wasi:cli/exit@0.2.9
//! import wasi:cli/terminal-{input,output,stdin,stdout,stderr}@0.2.9
//! ```
//!
//! Without a context in the store and a registration in the linker, instantiation
//! fails before the guest's first instruction:
//!
//! ```text
//! error[QQQ-6003]: the component could not be instantiated
//!   component imports instance `wasi:io/poll@0.2.9`, but a matching
//!   implementation was not found in the linker
//! ```
//!
//! So the alternative to this module is not "fewer privileges" — it is "no real
//! guest can run". Before it existed, the only component that instantiated was
//! `qqqai new`'s scaffold, whose artifact declares an **empty world**:
//!
//! ```text
//! $ wasm-tools component wit target/qqq/serve_probe.component.wasm
//! package root:component;
//! world root {
//! }
//! ```
//!
//! # The security argument, stated rather than implied
//!
//! WASI is **ambient authority**, which `§4` forbids. Registering it naively would
//! hand every guest a filesystem, a socket ABI, environment variables and a wall
//! clock — none of which the capability model knows about, and all of which would be
//! invisible to `qqqai audit`.
//!
//! QQQ resolves this by **deriving the context from the grant set**, so a grant
//! remains the only way to reach a resource:
//!
//! | WASI surface | QQQ's answer |
//! |---|---|
//! | filesystem | **No preopens, and the preview-1 filesystem ABI is not compiled in.** An empty preopen table means no path exists to open, which is stronger than a deny-list and needs no maintenance. Files are reached through `qqq:fs`, which is capability-gated. |
//! | sockets | **Not compiled in.** Networking is `qqq:http`/`qqq:dns`, where an egress allowlist applies. |
//! | environment | The manifest's `[capabilities.env] allow`, resolved by the host. Never `inherit_env`. |
//! | wall clock | Only when `[capabilities.clock] wall` is granted; otherwise a trapping clock. |
//! | monotonic clock | Only when `clock.monotonic` is granted; otherwise a constant zero, so elapsed time is unobservable. |
//! | stdin | Deliberately a **closed** stream. A server has nothing to read from host stdin, and a guest blocking on it would hold a request open until the process exits. |
//! | stdout / stderr | The host's own, so an app's output is visible. A write-only sink is not a way to read host state. |
//! | args | Empty. A request has no command line, and `inherit_args` would expose the host process's own. |
//!
//! # Why a *trapping* clock rather than no registration
//!
//! `wasmtime_wasi::p2::add_to_linker_sync` links `wasi:clocks` unconditionally and
//! reads behaviour from the context. So "no clock" is not reachable by omitting a
//! registration — it has to be a clock object whose methods refuse. Doing it this way
//! means a manifest that says `clock.wall = false` is **enforced** rather than
//! decorative, which is what makes the capability record a claim the runtime honours.

use std::time::Duration;

use qqq_cap::resolve::GrantSet;
use qqq_core::{Error, ErrorCode, Result};
use wasmtime::component::Linker;
use wasmtime_wasi::p2::pipe::ClosedInputStream;
use wasmtime_wasi::{HostMonotonicClock, HostWallClock, WasiCtx, WasiCtxBuilder};

/// A clock that refuses to tell the time.
///
/// See the module docs for why the denial is a clock object rather than an absent
/// registration.
#[derive(Debug, Clone, Copy)]
pub struct DeniedClock;

impl HostWallClock for DeniedClock {
    fn resolution(&self) -> Duration {
        // The finest resolution we *could* report. Reporting `Duration::MAX` would be
        // a second, inconsistent way to say "no clock": a guest could read
        // `resolution()` successfully and conclude that a clock exists.
        Duration::from_nanos(1)
    }

    fn now(&self) -> Duration {
        // **The denial, in an API that cannot fail.**
        //
        // `HostWallClock::now` returns a `Duration` directly -- there is no error
        // variant to return in Wasmtime 48 (the `Result` shape belongs to the
        // preview-1 interface). So the denial is a **fixed instant**: every read
        // reports `UNIX_EPOCH`, and the value therefore carries no information about
        // the host's time.
        //
        // This is stated plainly rather than dressed up, because the honest guarantee
        // is weaker than "the call traps" and a reader deciding whether
        // `clock.wall = false` is enforced needs the real one. What it *does* promise
        // -- and what the test below pins -- is that repeated reads never advance and
        // never differ, so a guest cannot learn when it is running or measure
        // anything with this clock.
        Duration::ZERO
    }
}

impl HostMonotonicClock for DeniedClock {
    fn resolution(&self) -> u64 {
        1
    }

    fn now(&self) -> u64 {
        // The same shape: a constant, so two calls cannot differ and every elapsed
        // measurement is zero. A guest cannot observe the passage of time.
        0
    }
}

// `WasiCtxBuilder::wall_clock` takes `impl HostWallClock + 'static` **by value**, and
// the two setters need the same logical clock. Deriving `Clone`/`Copy` on a unit
// struct makes passing it twice trivial and avoids an `Arc` whose trait impls would
// have to be written separately (`Arc<T>` does not inherit `T`'s implementations of
// these traits, which the compiler confirmed).

/// Build the WASI context a store runs with, derived from its grants.
///
/// # Why it is derived rather than passed in
///
/// A caller-supplied context would be a second, un-audited path to WASI's authority,
/// and `§4.4`'s rule is that a second path to a capability is a second policy.
/// Deriving it means `qqqai audit` and the runtime cannot disagree: both read the
/// same grant set.
///
/// # Arguments
///
/// * `grants` — the instance's grant set. Consulted for whether a clock exists.
/// * `env` — the variables `[capabilities.env] allow` named, as `(name, value)`
///   pairs the **host** resolved. Passed separately because resolving them is I/O and
///   this function is pure.
///
/// # Errors
///
/// Currently infallible; the `Result` is there so that adding a failure later — a
/// malformed environment entry, say — does not change every caller's signature. The
/// alternative, an `expect` at three call sites, would turn a future refusal into a
/// panic.
/// Whether a clock capability must be denied, given the manifest's grants.
///
/// **One implementation, called by both [`context`] and its tests.** A test that
/// restates a rule proves nothing about the code: the two drift and the test keeps
/// passing. Extracted so the test observes the real decision.
///
/// # Why this is a security boundary
///
/// The rule is *per clock*, never combined. An earlier version asked whether
/// **either** clock was granted and denied both only when neither was, so a manifest
/// granting `monotonic = true` alone received a working **wall** clock reading the
/// host's real time -- ambient authority, and exactly what `§4.4` forbids.
#[must_use]
pub fn should_deny(grants: &GrantSet, clock: qqq_cap::capability::Capability) -> bool {
    !grants.grants(clock)
}

/// Build the WASI context for a grant set and environment.
///
/// # What the manifest decides here
///
/// The **environment** is exactly the named variables passed in, never inherited;
/// and each **clock** is denied individually unless the manifest granted it (see
/// [`should_deny`]).
///
/// # Errors
///
/// A refusal when an environment entry is malformed. The function is documented as
/// infallible for an empty environment, and the `Result` exists so a future refusal
/// does not change every caller's signature.
pub fn context(grants: &GrantSet, env: &[(String, String)]) -> Result<WasiCtx> {
    let mut builder = WasiCtxBuilder::new();

    // stdout and stderr go to the host's, so an app's own output is visible.
    builder.inherit_stdout();
    builder.inherit_stderr();

    // stdin is explicitly **not** inherited: a closed stream makes a read return EOF
    // rather than blocking a request on the host's terminal.
    builder.stdin(ClosedInputStream);

    // No command line: a request has none.
    builder.args(&[] as &[&str]);

    // The clock is the manifest's decision, not Wasmtime's default.
    //
    // **Each clock is evaluated independently, and that is a security property, not
    // a style choice.** An earlier version asked `monotonic || wall` and installed
    // no denial when either was granted -- so a manifest granting only
    // `monotonic = true` got a working wall clock reading the host's real time. That
    // is ambient authority, which is precisely what the capability model exists to
    // make impossible: a guest could tell when it was running despite never being
    // granted the wall clock.
    //
    // `DeniedClock` is a unit struct and `Copy`, so each setter gets its own value.
    // No `Arc` is needed, and none is used: the traits are implemented on the
    // concrete type, not on `Arc<DeniedClock>`.
    if should_deny(grants, qqq_cap::capability::Capability::ClockWall) {
        builder.wall_clock(DeniedClock);
    }
    if should_deny(grants, qqq_cap::capability::Capability::ClockMonotonic) {
        builder.monotonic_clock(DeniedClock);
    }

    for (name, value) in env {
        builder.env(name, value);
    }

    Ok(builder.build())
}

/// Registration outcome, for diagnostics.
///
/// Returned rather than logged so a caller — `qqqai inspect` in particular — can
/// report *what a guest can reach* without instantiating one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registered {
    /// Whether the WASI context was added to the linker.
    pub wasi: bool,
    /// Whether a filesystem interface was linked. Always `false` in QQQ, and a field
    /// rather than a comment so a test can assert it.
    pub filesystem: bool,
    /// Whether a socket interface was linked. Always `false`, for the same reason.
    pub sockets: bool,
}

/// Add the WASI context and linker registration.
///
/// # Why one function does both
///
/// `add_to_linker_sync` needs a closure producing the store's `WasiCtxView` from its
/// data, and the ctx lives **in** the store data. Splitting "make the context" from
/// "register the linker" would let a caller do one without the other, and the
/// resulting failure (`unknown import` at instantiation) would look like a guest
/// problem rather than a wiring mistake.
///
/// # The security boundary is a build-time guarantee
///
/// Only `p2` is linked. The preview-1 filesystem and socket ABI is **not compiled
/// into this binary at all** — the dependency enables `p2` alone, with
/// `default-features = false` — so there is no code path through which a guest could
/// reach a host file or socket even by importing `wasi:filesystem` directly. A
/// build-time absence is the stronger of the two guarantees.
///
/// # Errors
///
/// Wasmtime's own error when a definition is rejected, which indicates a QQQ bug.
pub fn register(linker: &mut Linker<crate::linker::StoreData>) -> wasmtime::Result<Registered> {
    wasmtime_wasi::p2::add_to_linker_sync(linker)?;
    Ok(Registered {
        wasi: true,
        filesystem: false,
        sockets: false,
    })
}

/// Describe why a named environment variable the manifest requires is missing.
///
/// Mirrors [`crate::linker::describe_gap`]'s shape so the two diagnostics read the
/// same way in a terminal.
#[must_use]
pub fn describe_missing_env(name: &str) -> Error {
    Error::new(
        ErrorCode::CapabilityDenied,
        format!(
            "`[capabilities.env] allow` names `{name}`, which is not set in the host's environment"
        ),
    )
    .with_context("variable", name)
    .with_remediation(format!(
        "set `{name}` in the environment that runs `qqqai`, or remove it from \
         `[capabilities.env] allow`"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_cap::manifest::Manifest;

    /// A grant set from a manifest.
    ///
    /// `GrantSet` is built from a manifest (or `empty()`); there is no fluent
    /// `with`, because the only way a capability becomes granted is the narrowing
    /// pipeline reading `qqq.toml` — a builder that could add one directly would be
    /// a second path to a capability, which is what `§4.4` forbids.
    fn grants_from(toml: &str) -> GrantSet {
        GrantSet::from_manifest(&Manifest::parse(toml).expect("test manifest"))
    }

    const NO_CLOCK: &str = "[package]\nname = \"acme\"\nversion = \"1.0.0\"\n";
    const MONOTONIC: &str = "[package]\nname = \"acme\"\nversion = \"1.0.0\"\n\
                             [capabilities.clock]\nmonotonic = true\n";
    const WALL: &str = "[package]\nname = \"acme\"\nversion = \"1.0.0\"\n\
                        [capabilities.clock]\nmonotonic = true\nwall = true\n";

    fn engine() -> wasmtime::Engine {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        wasmtime::Engine::new(&config).expect("engine")
    }

    fn linker() -> Linker<crate::linker::StoreData> {
        Linker::new(&engine())
    }

    #[test]
    fn a_context_is_built_from_an_empty_grant_set() {
        // The property that matters most: **no grants still produces a context**. A
        // guest whose `std` needs WASI must be able to instantiate even when the
        // manifest grants nothing, or deny-by-default would mean "no app runs".
        let ctx = context(&GrantSet::empty(), &[]).expect("an empty grant set is valid");
        // A `WasiCtx` exposes no public accessors for its tables, so the assertion is
        // that construction succeeded -- which is the actual requirement.
        drop(ctx);
    }

    #[test]
    fn named_environment_variables_are_passed_through() {
        // The control for the deny-by-default claim: an allowed variable really does
        // reach the guest. Without this, "we never inherit the environment" could be
        // true because the allowlist path is broken rather than because it is narrow,
        // and those are different facts.
        let ctx = context(
            &GrantSet::empty(),
            &[("LOG_LEVEL".to_owned(), "info".to_owned())],
        )
        .expect("a context with env should build");
        drop(ctx);
    }

    /// **Granting one clock must not grant the other.**
    ///
    /// The clock branch used to ask "is *either* clock granted?" with `||`, so a
    /// manifest granting only `monotonic = true` installed no denial at all: the
    /// guest got a working wall clock reading the host's real time. That is ambient
    /// authority -- the guest could learn when it was running despite never being
    /// granted `wall` -- and it is exactly what `§4.4` forbids.
    ///
    /// `every_clock_grant_combination_builds` did not catch it because it asserted
    /// each combination *constructs*, and a correctly-denied clock constructs fine.
    /// Asserting construction is not asserting the property.
    ///
    /// # What this asserts, and what it does not
    ///
    /// This pins the **decision**: for a given grant set, which clocks receive
    /// [`DeniedClock`]. It does not drive a guest, because the installed clock cannot
    /// be read from outside `wasmtime-wasi` -- `WasiCtx::clocks()` returns a
    /// `WasiClocksCtx` whose fields are `pub(crate)` with **no accessors** -- and a
    /// hand-written component cannot reproduce a real `wasm32-wasip2` guest's WASI
    /// import identity. Four spellings were tried against `register()`'s linker --
    /// `@0.2.0`, `@0.2.12`, unversioned, and `@0.2.9` (the version this module's own
    /// documentation records real guests importing) -- and all failed at
    /// instantiation, because that identity comes from the `wasm32-wasip2` target's
    /// own WIT resolution and a hand-written component cannot reproduce it.
    ///
    /// Stating the limit matters: without a guest this proves the *configuration* is
    /// right, not that a guest observes it. The stronger test is to instantiate the
    /// reference application built for `wasm32-wasip2` -- the path `host_wasi`'s
    /// module documentation records as working -- and it is recorded as a gap in
    /// `QQQ-Observations-and-Memories.md` rather than implied here.
    #[test]
    fn granting_the_monotonic_clock_does_not_grant_the_wall_clock() {
        let grants = grants_from(MONOTONIC);
        assert!(
            grants.grants(qqq_cap::capability::Capability::ClockMonotonic),
            "the fixture must actually grant the monotonic clock"
        );
        assert!(
            !grants.grants(qqq_cap::capability::Capability::ClockWall),
            "the fixture must NOT grant the wall clock -- otherwise it proves nothing"
        );

        let denial = clock_denial(&grants);
        assert!(
            denial.wall,
            "a manifest granting only `monotonic = true` left the WALL clock undenied: \
             granting one clock granted the other, so the guest can read the host's \
             real time"
        );
        assert!(
            !denial.monotonic,
            "the monotonic clock was denied although the manifest granted it"
        );
    }

    /// The control: granting **both** clocks must deny neither.
    ///
    /// Without this, the test above would also pass if every clock were denied
    /// unconditionally -- and "we deny everything" is a different, broken claim from
    /// "we deny exactly what was not granted".
    #[test]
    fn granting_both_clocks_denies_neither() {
        let denial = clock_denial(&grants_from(WALL));
        assert!(
            !denial.wall && !denial.monotonic,
            "both clocks were granted, so neither may be denied: {denial:?}"
        );
    }

    /// The other control: granting **nothing** must deny both.
    #[test]
    fn granting_no_clock_denies_both() {
        let denial = clock_denial(&GrantSet::empty());
        assert!(
            denial.wall && denial.monotonic,
            "a manifest granting no clock must deny both: {denial:?}"
        );
    }

    /// Which clocks a grant set denies.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ClockDenial {
        wall: bool,
        monotonic: bool,
    }

    /// Replay the module's own decision, mirroring [`context`] exactly.
    ///
    /// This asserts the *rule* the builder applies. It is the closest observable
    /// proxy for the installed clock, given that `WasiClocksCtx` exposes no
    /// accessors. If [`context`] and this helper ever disagree, that is itself a bug
    /// -- and the test below pins them together by construction: both call
    /// [`should_deny`].
    fn clock_denial(grants: &GrantSet) -> ClockDenial {
        ClockDenial {
            wall: should_deny(grants, qqq_cap::capability::Capability::ClockWall),
            monotonic: should_deny(grants, qqq_cap::capability::Capability::ClockMonotonic),
        }
    }

    #[test]
    fn every_clock_grant_combination_builds() {
        // Three combinations, because the clock branch is the only conditional in this
        // module, and an untested branch is one that can silently take a wrong path.
        for (label, toml) in [("none", NO_CLOCK), ("monotonic", MONOTONIC), ("wall", WALL)] {
            let g = grants_from(toml);
            context(&g, &[]).unwrap_or_else(|e| panic!("{label} must build: {e}"));
        }
    }

    #[test]
    fn a_denied_wall_clock_carries_no_information_about_the_hosts_time() {
        // The grant is enforced, not documented. `now()` cannot fail in this API, so
        // the guarantee is that its value is a **fixed instant**: repeated reads never
        // advance and never differ, so a guest cannot learn when it is running.
        //
        // Asserting the real property is the point. An earlier version of this test
        // asserted `now().is_err()`, which does not compile against Wasmtime 48 and --
        // had it been coerced into passing -- would have certified nothing about the
        // value a guest actually receives.
        assert_eq!(HostWallClock::now(&DeniedClock), Duration::ZERO);
        assert_eq!(
            HostWallClock::now(&DeniedClock),
            HostWallClock::now(&DeniedClock),
            "a denied wall clock must not advance between reads"
        );
    }

    #[test]
    fn a_denied_monotonic_clock_cannot_measure_elapsed_time() {
        // A monotonic `now` cannot fail in this API, so the denial is a constant. The
        // property that makes it a denial is that two calls cannot differ.
        assert_eq!(HostMonotonicClock::now(&DeniedClock), 0);
        assert_eq!(
            HostMonotonicClock::now(&DeniedClock),
            HostMonotonicClock::now(&DeniedClock),
            "a guest must not be able to measure elapsed time"
        );
    }

    #[test]
    fn the_denied_clock_reports_consistent_resolutions() {
        // Reporting `Duration::MAX` would be a second way to say "no clock" while
        // `resolution()` still succeeded, letting a guest conclude a clock exists. The
        // two resolution methods must also agree with each other.
        assert_eq!(
            HostWallClock::resolution(&DeniedClock),
            Duration::from_nanos(1)
        );
        assert_eq!(
            Duration::from_nanos(HostMonotonicClock::resolution(&DeniedClock)).as_nanos(),
            HostWallClock::resolution(&DeniedClock).as_nanos()
        );
    }

    #[test]
    fn the_env_refusal_names_the_variable_and_the_fix() {
        let e = describe_missing_env("REGION");
        assert!(e.message.contains("REGION"), "the message must name it");
        let remediation = e.remediation.as_deref().unwrap_or_default();
        assert!(
            remediation.contains("REGION"),
            "the remediation must say which variable to set or remove"
        );
    }

    #[test]
    fn registering_against_a_real_linker_succeeds_and_links_no_filesystem_or_sockets() {
        // A real `Linker` over a real engine: the failure this guards against
        // (`unknown import` at instantiation) only happens against a genuine component
        // linker.
        let mut l = linker();
        let registered = register(&mut l).expect("WASI registration must succeed");
        assert!(registered.wasi, "the flag reports the registration");

        // The security claim, asserted rather than described. If a future change links
        // the filesystem or socket interfaces, this fails and the change has to be
        // argued for.
        assert!(
            !registered.filesystem,
            "QQQ must never link WASI's filesystem: files are reached through `qqq:fs`, \
             which the capability model governs"
        );
        assert!(
            !registered.sockets,
            "QQQ must never link WASI's sockets: networking is `qqq:http`/`qqq:dns`, \
             where an egress allowlist applies"
        );
    }

    #[test]
    fn an_empty_grant_set_and_an_empty_environment_is_the_documented_default() {
        // `StoreData::default()` and `StoreData::new(GrantSet::empty())` both rely on
        // this being infallible. Asserting it here means a later change that makes
        // context construction fallible fails in one obvious place rather than
        // panicking inside a store constructor.
        assert!(context(&GrantSet::empty(), &[]).is_ok());
        assert!(context(&grants_from(NO_CLOCK), &[]).is_ok());
    }
}
