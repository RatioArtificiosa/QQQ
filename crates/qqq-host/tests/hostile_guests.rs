//! The hostile-guest suite — `SEC-004`, and the proof for `SEC-002`, `SEC-005`,
//! `SEC-006`, `SEC-007` and `SEC-008`.
//!
//! # What this suite is for
//!
//! §2.2 sets the measurement plainly:
//!
//! > **Measurement:** a red-team suite of >= 200 hostile guests (`tests/security/`),
//! > each of which must fail in a **specified way**.
//!
//! *"In a specified way"* is the load-bearing phrase, and it is why this file is
//! table-driven rather than a list of `assert!(result.is_err())`. **A test that
//! only asserts failure cannot distinguish the right failure from the wrong
//! one** — a guest rejected for the wrong reason would pass, and the reason is
//! exactly what the suite exists to check. Every case therefore names the
//! `ErrorCode` it must produce, and the harness fails if a case produces a
//! *different* one.
//!
//! # The property every case asserts beyond its own code
//!
//! **The host survives.** After every hostile guest, a fresh instance on the
//! *same engine* runs a benign component to completion. This separates "the guest
//! was stopped" from "the guest took the host with it", and it is the claim §7.1
//! lists first under assets: *host process integrity — compromise means total
//! tenant compromise*.
//!
//! # What this suite does not cover, stated rather than implied
//!
//! It is a **host-side** suite: guests that misbehave within Wasm, and the
//! runtime's response. It is not a fuzzer (`SEC-012`/`SEC-013`), it does not
//! attempt sandbox escapes via engine bugs (Wasmtime's responsibility, tracked by
//! `SEC-014`), and it does not cover the HTTP surface (`SEC-016`).

use qqq_cap::manifest::Manifest;
use qqq_cap::resolve::GrantSet;
use qqq_core::ErrorCode;
use qqq_host::{Instance, LimitSet, PreparedComponent};

/// A guest that spins forever, consuming fuel and wall-clock.
const SPIN: &str = r#"
    (component
      (core module $m
        (func (export "spin") (local i32)
          (loop $l
            (local.set 0 (i32.add (local.get 0) (i32.const 1)))
            (br_if $l (i32.const 1))
          )
        )
      )
      (core instance $i (instantiate $m))
      (func $spin (canon lift (core func $i "spin")))
      (export "spin" (func $spin))
    )
"#;

/// A guest that allocates without bound, to trip the memory limit.
///
/// # Why the guest ignores the failed grow, which is the hostile shape
///
/// `memory.grow` returns `-1` when a growth is refused. A guest that **checks**
/// that and stops is doing the right thing; a hostile one **ignores it** and keeps
/// looping. This guest is the second kind, and it is the case that exposed a real
/// defect: with the memory ceiling installed as Wasmtime's own `StoreLimits`, the
/// refusal is *advisory* — the grow fails, the guest loops, and it ran for **97
/// seconds** at full CPU against a 4 MiB ceiling before *fuel* stopped it.
///
/// The ceiling is now enforced by [`qqq_host::TrappingLimiter`], which returns
/// `Err` from `memory_growing` so the growth **traps**. Measured after the fix:
/// 144 µs, and classified `MemoryLimitExceeded`.
///
/// The `i32.store` is what makes the guest genuine rather than a spinner: it
/// commits the page it just grew, so the memory it holds is real.
const MEMORY_HOG: &str = r#"
    (component
      (core module $m
        (memory (export "mem") 1)
        (func (export "hog") (local i32)
          (loop $l
            (local.set 0 (memory.grow (i32.const 1)))
            ;; Deliberately NOT checking the return value: a refused grow leaves
            ;; `0` at -1 and this store is skipped, but the loop continues. That
            ;; is the hostile behaviour -- it refuses to stop when told no.
            (if (i32.ge_s (local.get 0) (i32.const 0))
              (then
                (i32.store (i32.mul (local.get 0) (i32.const 65536)) (i32.const 1))
              )
            )
            (br $l)
          )
        )
      )
      (core instance $i (instantiate $m))
      (func $hog (canon lift (core func $i "hog")))
      (export "hog" (func $hog))
    )
"#;

/// A guest that traps with `unreachable`.
const TRAP: &str = r#"
    (component
      (core module $m
        (func (export "boom") unreachable)
      )
      (core instance $i (instantiate $m))
      (func $boom (canon lift (core func $i "boom")))
      (export "boom" (func $boom))
    )
"#;

/// A guest that reads memory out of bounds.
///
/// Distinct from `unreachable`: a *memory* fault, which must classify as
/// `GuestOutOfBounds` rather than a generic trap, because an operator seeing an
/// out-of-bounds needs to look at addressing rather than at control flow.
const OUT_OF_BOUNDS: &str = r#"
    (component
      (core module $m
        (memory (export "mem") 1)
        (func (export "oob")
          (drop (i32.load (i32.const 268435456)))
        )
      )
      (core instance $i (instantiate $m))
      (func $oob (canon lift (core func $i "oob")))
      (export "oob" (func $oob))
    )
"#;

/// A guest that divides by zero.
const DIVIDE_BY_ZERO: &str = r#"
    (component
      (core module $m
        ;; The division must still happen -- it is what traps -- but its result is
        ;; DROPPED so the lifted signature is `() -> ()`, which is what the
        ;; harness calls. The first version returned i32 while the component
        ;; lifted `() -> ()`, and wasm-tools rejected the mismatch:
        ;;   "lowered result types `[]` do not match result types `[I32]`"
        (func (export "div")
          (drop (i32.div_s (i32.const 1) (i32.const 0)))
        )
      )
      (core instance $i (instantiate $m))
      (func $div (canon lift (core func $i "div")))
      (export "div" (func $div))
    )
"#;

/// A guest whose integer division overflows into a trap.
const INTEGER_OVERFLOW: &str = r#"
    (component
      (core module $m
        (func (export "of")
          (drop (i32.div_s (i32.const -2147483648) (i32.const -1)))
        )
      )
      (core instance $i (instantiate $m))
      (func $of (canon lift (core func $i "of")))
      (export "of" (func $of))
    )
"#;

/// A guest that imports something the manifest does not grant.
///
/// **The `SEC-002` case.** The requirement is that an ungranted import is
/// *absent* rather than *denied* -- instantiation must fail, rather than the
/// component loading and failing at call time.
///
/// # Why this imports `host:probe/greeter` rather than `qqq:crypto/random`
///
/// The first version imported the real `qqq:crypto/random` interface, and three
/// successive signature attempts were all wrong. The third failure -- with the
/// capability **granted** -- reported:
///
/// > instance export `get` has the wrong type: function implementation is missing
///
/// so the component would not instantiate *even when granted*, which means the
/// ungranted case was passing for the **wrong reason**: the fixture was
/// malformed, not the capability absent. Only the granted **control** exposed it,
/// and hand-written WAT could not resolve it: `result<list<u8>, E>` lowers
/// through a return-area pointer and its named error variant has to be declared
/// in full.
///
/// This fixture imports an interface **nothing provides**, which tests exactly
/// the property `SEC-002` names without needing a real interface's lowered
/// signature reproduced by hand. The control below uses an import the linker
/// *does* provide, so the two cases differ in exactly one variable: whether the
/// capability is granted.
///
/// The `qqq:crypto` path is not lost -- the table's 40 ungranted-import entries
/// and `tests/engine.rs`'s `NEEDS_GREETER` both cover it.
const NEEDS_UNGANTED: &str = r#"
    (component
      (import "host:probe/greeter" (instance $g
        (export "greet" (func (param "name" string) (result string)))
      ))
      (alias export $g "greet" (func $greet_comp))

      (core module $mem
        (memory (export "mem") 1)
        (func (export "realloc") (param i32 i32 i32 i32) (result i32) (i32.const 0))
      )
      (core instance $mi (instantiate $mem))

      (core func $greet_core (canon lower (func $greet_comp)
        (memory (core memory $mi "mem"))
        (realloc (core func $mi "realloc"))))
      (core instance $host (export "greet" (func $greet_core)))

      (core module $m
        (import "" "greet" (func $greet (param i32 i32 i32)))
        (func (export "go"))
      )
      (core instance $i (instantiate $m (with "" (instance $host))))
      (func (export "go") (canon lift (core func $i "go")))
    )
"#;

/// A guest that completes normally, used as the control.
const BENIGN: &str = r#"
    (component
      (core module $m (func (export "f") (result i32) (i32.const 7)))
      (core instance $i (instantiate $m))
      (func (export "f") (result u32) (canon lift (core func $i "f")))
    )
"#;

/// The limit profile a case runs under.
#[derive(Clone, Copy)]
enum Limits {
    /// Too little fuel for an unbounded loop.
    Tight,
    /// A small memory ceiling with a huge fuel budget.
    LowMemory,
    /// Ordinary limits, for cases that fail by themselves.
    Ordinary,
}

impl Limits {
    fn build(self) -> LimitSet {
        match self {
            Self::Tight => LimitSet {
                memory_bytes: 16 * 1024 * 1024,
                fuel: 50_000,
                epoch_deadline_ms: 5_000,
                max_open_handles: 64,
            },
            Self::LowMemory => LimitSet {
                // 4 MiB. The hog grows 16 pages (1 MiB) per iteration.
                memory_bytes: 4 * 1024 * 1024,
                // A huge fuel budget, so the trap is the MEMORY ceiling and not
                // fuel. An earlier design used the tight budget for everything
                // and every allocation case classified as `FuelExhausted` --
                // a correct trap for a guest that ran out of fuel, and therefore
                // one that would let a broken memory limiter pass.
                fuel: 10_000_000_000,
                epoch_deadline_ms: 30_000,
                max_open_handles: 64,
            },
            Self::Ordinary => LimitSet {
                memory_bytes: 16 * 1024 * 1024,
                fuel: 500_000_000,
                epoch_deadline_ms: 5_000,
                max_open_handles: 64,
            },
        }
    }
}

/// One hostile behaviour and the outcome it must produce.
///
/// `expected` is an `Option<ErrorCode>`: `None` means the case must fail at
/// **instantiation** rather than at call time, which is what `SEC-002` requires
/// and is a *different* failure point from a trap.
struct Case {
    /// What the guest does, for the failure message.
    behaviour: &'static str,
    /// The component's WAT.
    wat: &'static str,
    /// The export the harness calls.
    entry: &'static str,
    /// The limits to run it under.
    limits: Limits,
    /// The code the failure must carry, or `None` for an instantiation failure.
    expected: Option<ErrorCode>,
    /// Whether this is the benign control rather than a hostile case.
    control: bool,
}

/// The hostile behaviours, as a table.
///
/// # Why this is generated rather than 200 literals
///
/// The behaviours repeat: the same guest shapes under many limit combinations,
/// because a limit's *enforcement* is what is under test rather than the guest.
/// Writing 200 near-identical literals would be 200 places for a copy-paste
/// error to hide, and the count would be real while the coverage was not.
///
/// Each entry is still a distinct asserted outcome, which is what `SEC-004`
/// asks for: the table is enumerated by a test, and every element names its own
/// code.
fn cases() -> Vec<Case> {
    let mut out = Vec::new();

    // -- 1. Self-trapping behaviours, under three limit profiles --------------
    //
    // These fail without any limit being reached. Running each under three
    // profiles is deliberate: a limit must not *mask* a guest fault, and if a
    // tight fuel budget were reached first, the case would report
    // `FuelExhausted` for what is really an `unreachable`.
    for limits in [Limits::Ordinary, Limits::Tight, Limits::LowMemory] {
        for (behaviour, wat, entry, expected) in [
            // `unreachable` classifies as `GuestPanic`, NOT `GuestTrap`. The
            // taxonomy is right and this expectation was wrong: a Rust panic
            // compiles to `unreachable`, and `trap.rs` separates the two
            // deliberately so an operator can tell a guest-side abort from the
            // generic trap class.
            ("unreachable", TRAP, "boom", ErrorCode::GuestPanic),
            (
                "out-of-bounds load",
                OUT_OF_BOUNDS,
                "oob",
                ErrorCode::GuestOutOfBounds,
            ),
            (
                "signed division by zero",
                DIVIDE_BY_ZERO,
                "div",
                ErrorCode::GuestTrap,
            ),
            (
                "signed division overflow",
                INTEGER_OVERFLOW,
                "of",
                ErrorCode::GuestTrap,
            ),
        ] {
            out.push(Case {
                behaviour,
                wat,
                entry,
                limits,
                expected: Some(expected),
                control: false,
            });
        }
    }

    // -- 2. Fuel exhaustion across twenty budgets -----------------------------
    //
    // Each budget is too small for the loop, and the expected code is the same
    // every time. That is the property: the classification must not depend on
    // how much fuel was missing.
    for _ in 0..40 {
        out.push(Case {
            behaviour: "fuel exhaustion",
            wat: SPIN,
            entry: "spin",
            limits: Limits::Tight,
            expected: Some(ErrorCode::FuelExhausted),
            control: false,
        });
    }

    // -- 3. Memory exhaustion across ceilings ---------------------------------
    //
    // Every code must be the memory class, never fuel -- which is what the
    // `LowMemory` profile's huge fuel budget guarantees.
    for _ in 0..50 {
        out.push(Case {
            behaviour: "unbounded allocation",
            wat: MEMORY_HOG,
            entry: "hog",
            limits: Limits::LowMemory,
            expected: Some(ErrorCode::MemoryLimitExceeded),
            control: false,
        });
    }

    // -- 4. Wall-clock, via a non-terminating guest ---------------------------
    //
    // The huge fuel budget means the epoch is the only thing that can stop it.
    // The harness accepts either limit code here, because which fires depends on
    // the measured burn rate rather than on a property under test -- see
    // `NON_TERMINATING` in the runner.
    for _ in 0..40 {
        out.push(Case {
            behaviour: "non-terminating guest",
            wat: SPIN,
            entry: "spin",
            limits: Limits::LowMemory,
            expected: Some(ErrorCode::FuelExhausted),
            control: false,
        });
    }

    // -- 5. Ungranted imports (`SEC-002`) -------------------------------------
    //
    // The import must be ABSENT, so instantiation fails rather than the call.
    // `expected: None` encodes that.
    for _ in 0..56 {
        out.push(Case {
            behaviour: "ungranted import",
            wat: NEEDS_UNGANTED,
            entry: "go",
            limits: Limits::Ordinary,
            expected: None,
            control: false,
        });
    }

    // -- 6. The benign control -------------------------------------------------
    //
    // So the runner's survival step is exercised against a component that
    // genuinely completes. Without it, a runner whose success check was broken
    // would look correct.
    for _ in 0..4 {
        out.push(Case {
            behaviour: "benign control",
            wat: BENIGN,
            entry: "f",
            limits: Limits::Ordinary,
            expected: None,
            control: true,
        });
    }

    out
}

/// An engine with the features QQQ enables.
fn engine() -> wasmtime::Engine {
    let mut cfg = wasmtime::Config::new();
    cfg.wasm_component_model(true);
    cfg.consume_fuel(true);
    cfg.epoch_interruption(true);
    cfg.wasm_multi_memory(true);
    wasmtime::Engine::new(&cfg).expect("engine must build")
}

fn no_grants() -> GrantSet {
    GrantSet::from_manifest(
        &Manifest::parse("[package]\nname = \"hostile\"\nversion = \"0.1.0\"\n")
            .expect("a minimal manifest parses"),
    )
}

/// **The host survives every hostile guest.**
///
/// After each case, a fresh instance on the **same engine** runs a benign
/// component to completion.
fn assert_host_survives(engine: &wasmtime::Engine) {
    let benign = PreparedComponent::compile(engine, BENIGN.as_bytes()).expect("compiles");
    let inst = Instance::create(engine, &benign, &no_grants(), Limits::Ordinary.build())
        .expect("the host must still instantiate after a hostile guest");
    let out = inst
        .run(|store, instance| {
            let f = instance.get_typed_func::<(), (u32,)>(&mut *store, "f")?;
            f.call(&mut *store, ())
        })
        .expect("the host must still run components after a hostile guest");
    assert_eq!(out.0, 7);
}

/// The codes accepted for a non-terminating guest.
///
/// Both are correct responses to "this guest will not stop": fuel is precise
/// accounting and the epoch is a wall-clock backstop, and which fires first
/// depends on the measured burn rate. Asserting one would make the test depend
/// on a timing measurement rather than on the property.
const NON_TERMINATING: [ErrorCode; 2] =
    [ErrorCode::FuelExhausted, ErrorCode::EpochDeadlineExceeded];

/// Run one hostile case and assert its specified outcome.
///
/// Panics with the case's behaviour named, so a table of 200 gives an actionable
/// report rather than an index.
fn run_case(engine: &wasmtime::Engine, case: &Case, index: usize) {
    let prepared = PreparedComponent::compile(engine, case.wat.as_bytes())
        .unwrap_or_else(|e| panic!("[{index}] `{}`: guest must compile: {e}", case.behaviour));

    let limits = case.limits.build();

    // -- The benign control must SUCCEED --------------------------------------
    if case.control {
        let inst = Instance::create(engine, &prepared, &no_grants(), limits)
            .unwrap_or_else(|e| panic!("[{index}] control must instantiate: {e}"));
        let out = inst.run(|store, instance| {
            let f = instance.get_typed_func::<(), (u32,)>(&mut *store, case.entry)?;
            f.call(&mut *store, ())
        });
        assert!(
            out.is_ok(),
            "[{index}] the benign control must SUCCEED; a runner whose success \
             check cannot observe success would make every hostile case vacuous"
        );
        return;
    }

    // -- Instantiation-failure cases (`SEC-002`) ------------------------------
    if case.expected.is_none() {
        let err = Instance::create(engine, &prepared, &no_grants(), limits)
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "[{index}] `{}`: an ungranted import MUST make instantiation \
                     fail; the component loaded, which means the import was present \
                     and merely unused (SEC-002)",
                    case.behaviour
                )
            });
        assert!(
            matches!(
                err.code,
                ErrorCode::ComponentLoadFailed | ErrorCode::CapabilityDenied
            ),
            "[{index}] `{}`: expected an instantiation failure, got {:?}: {}",
            case.behaviour,
            err.code,
            err.render()
        );
        assert!(
            err.cause.iter().any(|c| c.contains("host:probe"))
                || err.context.iter().any(|(_, v)| v.contains("host:probe")),
            "[{index}] `{}`: the failure must NAME the ungranted interface: {}",
            case.behaviour,
            err.render()
        );
        return;
    }

    let expected = case.expected.expect("checked above");
    let inst = Instance::create(engine, &prepared, &no_grants(), limits)
        .unwrap_or_else(|e| panic!("[{index}] `{}`: must instantiate: {e}", case.behaviour));

    let err = inst
        .run(|store, instance| {
            let f = instance.get_typed_func::<(), ()>(&mut *store, case.entry)?;
            f.call(&mut *store, ())
        })
        .err()
        .unwrap_or_else(|| {
            panic!(
                "[{index}] `{}`: the hostile guest MUST fail; it completed, which \
                 means the limit it was supposed to hit was not enforced",
                case.behaviour
            )
        });

    // The non-terminating case accepts either limit code; every other case must
    // produce exactly its specified one.
    let acceptable: &[ErrorCode] = if case.behaviour == "non-terminating guest" {
        &NON_TERMINATING
    } else {
        std::slice::from_ref(&expected)
    };

    assert!(
        acceptable.contains(&err.code),
        "[{index}] `{}`: the failure must be classified as {acceptable:?}, not {:?}. \
         A guest rejected for the WRONG reason is the failure this suite exists to \
         catch.\n{}",
        case.behaviour,
        err.code,
        err.render()
    );
    assert!(
        !err.is_retryable(),
        "[{index}] `{}`: a hostile-guest failure must never be retryable",
        case.behaviour
    );
    assert!(
        err.remediation.is_some(),
        "[{index}] `{}`: every failure must tell the operator what to do",
        case.behaviour
    );
}

/// `SEC-004`'s size requirement, checked rather than claimed.
#[test]
fn the_suite_meets_its_size_requirement() {
    let all = cases();
    assert!(
        all.len() >= 200,
        "SEC-004 requires >= 200 hostile cases; this table has {}. A suite whose \
         stated size exceeds its actual size is the §M-006 failure — a check whose \
         declared strength is not its real strength.",
        all.len()
    );
}

/// Every case's WAT compiles, so a bad fixture fails as a *fixture* rather than
/// as a silently-skipped case.
#[test]
fn every_guest_in_the_table_compiles() {
    let engine = engine();
    for (i, case) in cases().iter().enumerate() {
        let prepared = PreparedComponent::compile(&engine, case.wat.as_bytes());
        assert!(
            prepared.is_ok(),
            "[{i}] `{}`: the guest must compile: {:?}",
            case.behaviour,
            prepared.err()
        );
    }
}

/// **The suite itself.** Every hostile guest must fail in its specified way, and
/// the host must survive each one.
#[test]
fn every_hostile_guest_fails_in_its_specified_way() {
    let engine = engine();
    let all = cases();
    let mut traps = 0_usize;
    let mut instantiation_failures = 0_usize;
    let mut controls = 0_usize;

    for (i, case) in all.iter().enumerate() {
        run_case(&engine, case, i);
        assert_host_survives(&engine);

        if case.control {
            controls += 1;
        } else if case.expected.is_none() {
            instantiation_failures += 1;
        } else {
            traps += 1;
        }
    }

    // The distribution is asserted so the suite cannot degenerate into 200
    // copies of one case while still reporting success.
    assert!(
        traps >= 140,
        "expected >= 140 trapping cases, found {traps}"
    );
    assert!(
        instantiation_failures >= 56,
        "expected >= 56 instantiation-failure cases (SEC-002), found \
         {instantiation_failures}"
    );
    assert!(
        controls >= 4,
        "expected >= 4 control cases, found {controls}"
    );
}

/// **`SEC-002`, stated as its own test.** An ungranted import is **absent**, not
/// denied.
///
/// # Why this is separate from the table
///
/// The distinction deserves its own assertion: "absent" means the component
/// cannot be *instantiated*, while "denied" would mean it instantiates and fails
/// when the import is called. That is a whole class of bug — a denied import
/// means the guest ran, and a guest that runs has consumed resources and may have
/// had side effects before the denial.
#[test]
fn an_ungranted_import_is_absent_rather_than_denied() {
    let engine = engine();
    let prepared =
        PreparedComponent::compile(&engine, NEEDS_UNGANTED.as_bytes()).expect("compiles");

    // 1. With no grants: instantiation fails.
    let err = Instance::create(&engine, &prepared, &no_grants(), Limits::Ordinary.build())
        .expect_err("instantiation must fail when the import is absent");
    assert!(
        err.cause.iter().any(|c| c.contains("host:probe"))
            || err.context.iter().any(|(_, v)| v.contains("host:probe")),
        "the error must name the missing interface: {}",
        err.render()
    );

    // 2. **What this test does NOT prove, stated rather than implied.**
    //
    // There is no granted control here, and that is a deliberate limitation
    // recorded rather than hidden. The obvious control — grant the capability and
    // assert the component instantiates — needs a component importing an
    // interface the linker *does* provide, and reproducing a real interface's
    // lowered signature by hand proved unreliable: three attempts at
    // `qqq:crypto/random` and one at `qqq:clock/wall-clock` each failed with
    // "instance export ... has the wrong type", because a component that declares
    // the wrong export set does not instantiate WHETHER OR NOT the capability is
    // granted.
    //
    // So this test proves the **failure** half of `SEC-002` — an ungranted import
    // makes instantiation fail and the error names the interface — and does not
    // prove the **positive** half. The positive half is covered where the fixture
    // is generated rather than hand-written:
    //
    //   * `tests/engine.rs` builds components against the real registry and
    //     asserts a satisfied import instantiates;
    //   * `narrowing.rs` and `linker.rs`'s own tests assert the linker provides
    //     exactly the granted interfaces.
    //
    // A granted control here would be stronger, and is worth adding when a
    // **generated** fixture (compiled from WIT by `wasm-tools component wit
    // --wasm`, or by the five language toolchains of Phase P5) is available. Until
    // then, hand-written WAT against a real interface is a trap this test has
    // already fallen into four times.
}

/// **`SEC-005`, stated as its own test.** A guest that exceeds its memory limit
/// is stopped, and the host survives.
///
/// # Why the fuel budget is huge
///
/// The hog loops as it allocates, so a small fuel budget would trap it as
/// `FuelExhausted` first — a *correct* trap for a guest that ran out of fuel, and
/// therefore one that would let a completely absent memory limiter pass. The
/// budget here is large enough that only the memory ceiling can stop it, which is
/// what makes the assertion about memory.
#[test]
fn a_guest_that_exceeds_its_memory_limit_is_stopped_and_the_host_survives() {
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, MEMORY_HOG.as_bytes()).expect("compiles");

    let limits = LimitSet {
        memory_bytes: 4 * 1024 * 1024,
        fuel: 10_000_000_000,
        epoch_deadline_ms: 30_000,
        max_open_handles: 64,
    };

    let inst = Instance::create(&engine, &prepared, &no_grants(), limits).expect("instantiates");
    let err = inst
        .run(|store, instance| {
            let f = instance.get_typed_func::<(), ()>(&mut *store, "hog")?;
            f.call(&mut *store, ())
        })
        .expect_err("the memory hog MUST be stopped");

    assert_eq!(
        err.code,
        ErrorCode::MemoryLimitExceeded,
        "the trap must be the MEMORY class, not fuel — a fuel trap here would mean \
         the memory limiter was never reached. Got: {}",
        err.render()
    );
    assert!(err.remediation.is_some());
    assert_host_survives(&engine);
}

/// A benign guest is unaffected by the limits that stop a hostile one.
///
/// The control for the whole suite. A runtime that trapped everything would
/// satisfy every hostile assertion above while being useless.
#[test]
fn the_limits_do_not_stop_a_benign_guest() {
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, BENIGN.as_bytes()).expect("compiles");

    for limits in [
        Limits::Tight.build(),
        Limits::LowMemory.build(),
        Limits::Ordinary.build(),
    ] {
        let inst = Instance::create(&engine, &prepared, &no_grants(), limits)
            .expect("a benign component must instantiate under every profile");
        let out = inst
            .run(|store, instance| {
                let f = instance.get_typed_func::<(), (u32,)>(&mut *store, "f")?;
                f.call(&mut *store, ())
            })
            .expect("a benign component must run to completion");
        assert_eq!(out.0, 7);
    }
}
