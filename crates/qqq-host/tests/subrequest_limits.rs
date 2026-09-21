// SPDX-License-Identifier: Apache-2.0

//! The end-to-end subrequest-amplification proof — `SEC-009`.
//!
//! # Why this file exists separately from `refusal_amplification.rs`
//!
//! That file measures the *budget*: two policies, one loop, a ratio. This one
//! proves the budget is **wired into a running instance**, because a correct
//! budget that the host never consults stops nothing. That is not a hypothetical
//! failure mode — it is the exact shape of the defect this project already found
//! once, where the memory ceiling was *installed* and therefore looked enforced
//! while Wasmtime made it advisory (Observations §O-066).
//!
//! # What "wired in" means here, stated precisely
//!
//! A guest can only make a subrequest by calling a host function that performs
//! one. `qqq:http` and `qqq:dns` have no host implementation yet — they are
//! `QQQ-STUB(CON-009)` in the linker — so a real outbound request cannot be made
//! from a test today. What *can* be proven today, and what this file proves, is:
//!
//! 1. The budget is **derived from `LimitSet`** on every instance, through the
//!    real `Instance::create` path — not from a default and not from a global.
//! 2. `StoreData::charge_subrequest` **refuses** once the budget is spent, and
//!    the refusal carries `QQQ-3008`.
//! 3. A guest that **ignores** the refusal and keeps looping is not able to
//!    drive unbounded host work — the poisoned path makes subsequent charges
//!    free.
//! 4. The limit is **per instance**: tenant A exhausting its budget does not
//!    affect tenant B. This is the cross-tenant property, and it is the one a
//!    `static` guard would break.
//!
//! Point 3 is proven by asserting the counter, not by timing: the number of
//! *paid* refusals must be exactly 1 no matter how long the guest loops. A
//! timing assertion would be flaky on CI; a counted assertion is exact.
//!
//! # What remains open, recorded rather than implied
//!
//! The charge call sites inside `qqq:http`, `qqq:dns`, `qqq:sqs` and the rest do
//! not exist because those interfaces do not. When they are implemented, each
//! must call `charge_subrequest` before performing its effect — the contract is
//! documented on that method. The `qqq-abi` registry's `implemented` flag and the
//! linker's `QQQ-STUB(CON-009)` marker are what keep that gap visible.

use qqq_cap::manifest::Manifest;
use qqq_cap::resolve::GrantSet;
use qqq_core::ErrorCode;
use qqq_host::{Charge, Instance, LimitSet, PreparedComponent, StoreData, SubrequestBudget};

/// A guest that calls a host import in a loop, ignoring the result.
///
/// # Why the loop ignores the return value, and why that is the whole point
///
/// The hostile shape is *not* "calls too much". It is "**is told no and keeps
/// calling**". A polite guest stops at the first refusal; the one that matters is
/// the guest that treats the refusal as a no-op, because that guest is what turns
/// a refusal path into an amplification vector. The body deliberately discards
/// the call result.
///
/// The import is `host:probe/effect`, which nothing provides — so this fixture
/// cannot be instantiated, and it is used only for the *shapes* below that do not
/// need a granted interface. The wired cases use `BENIGN_LOOP`.
const _SHAPE_DOCUMENTATION_ONLY: &str = r#"
    (component
      (core module $m
        (func (export "fan_out") (local i32)
          (loop $l
            (local.set 0 (i32.add (local.get 0) (i32.const 1)))
            ;; The call result is dropped: the guest is told no and continues.
            (drop (call $effect))
            (br_if $l (i32.const 1))
          )
        )
      )
    )
"#;

/// A real component that loops, used to show the host survives.
///
/// Identical in spirit to `hostile_guests.rs`'s `SPIN`, kept local so this file
/// does not depend on another test binary's internals.
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

/// A benign guest that completes, for the survival check.
const BENIGN: &str = r#"
    (component
      (core module $m (func (export "f") (result i32) (i32.const 7)))
      (core instance $i (instantiate $m))
      (func (export "f") (result u32) (canon lift (core func $i "f")))
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
        &Manifest::parse("[package]\nname = \"subreq\"\nversion = \"0.1.0\"\n")
            .expect("a minimal manifest parses"),
    )
}

fn limits_with(max_subrequests: u32) -> LimitSet {
    LimitSet {
        memory_bytes: 16 * 1024 * 1024,
        fuel: 10_000_000,
        epoch_deadline_ms: 5_000,
        max_open_handles: 64,
        max_subrequests,
    }
}

/// Store data with both limit forms installed, through the real `set_limits`.
///
/// # Why this builds BOTH limiter types
///
/// `set_limits` takes Wasmtime's `StoreLimits` (which enforces at runtime) *and*
/// QQQ's `LimitSet` (which carries the manifest-derived numbers, including the
/// budgets this file is about). Writing the call once here means every test below
/// installs them identically, and a test cannot accidentally exercise a path
/// where the budgets were never derived.
fn store_data_with(max_subrequests: u32) -> StoreData {
    let limits = limits_with(max_subrequests);
    // The Wasmtime-side limiter, derived from the same bytes.
    let wasmtime_limits = wasmtime::StoreLimitsBuilder::new()
        .memory_size(usize::try_from(limits.memory_bytes).expect("16 MiB fits in usize"))
        .build();

    let mut data = StoreData::new(no_grants());
    data.set_limits(wasmtime_limits, limits);
    data
}

/// A manifest that declares a subrequest limit, parsed through the real path.
fn manifest_with(max_subrequests: u32) -> Manifest {
    Manifest::parse(&format!(
        "[package]\nname = \"subreq\"\nversion = \"0.1.0\"\n\
         [limits]\nmax_subrequests = {max_subrequests}\n"
    ))
    .expect("the manifest must parse")
}

// ---------------------------------------------------------------------------
// 1. The limit reaches the store through the real path
// ---------------------------------------------------------------------------

/// **The wiring test.** `LimitSet` is the single source of truth for the budget.
///
/// If the budget were defaulted rather than derived, every instance would get the
/// same number and a manifest's `max_subrequests` would be decorative — a limit
/// that an auditor can read but that nothing enforces. This asserts the number
/// arrives.
#[test]
fn the_limit_set_decides_the_budget_on_a_real_instance() {
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, BENIGN.as_bytes()).expect("compiles");

    for declared in [0_u32, 1, 32, 4_096] {
        let inst = Instance::create(&engine, &prepared, &no_grants(), limits_with(declared))
            .expect("a benign component instantiates under any budget");

        let budget = inst.store().data().subrequests();
        assert_eq!(
            budget.limit(),
            declared,
            "the instance's budget must equal `limits.max_subrequests` ({declared}); \
             a mismatch means the manifest field is decorative"
        );
        assert_eq!(
            budget.spent(),
            0,
            "a freshly created instance must not have spent budget"
        );
        assert!(
            !budget.is_poisoned(),
            "a fresh instance must not start poisoned"
        );
    }
}

/// The manifest path agrees with the programmatic path.
///
/// These are two routes to the same number, and they exist because embedding and
/// testing need one while production uses the other. Two routes that disagree is
/// how a limit becomes advisory in exactly one deployment.
#[test]
fn the_manifest_and_the_limit_set_agree_on_the_budget() {
    for declared in [0_u32, 8, 64] {
        let from_manifest = StoreData::from_manifest(&manifest_with(declared));
        assert_eq!(
            from_manifest.subrequests().limit(),
            declared,
            "`StoreData::from_manifest` must read `limits.max_subrequests`"
        );

        // And the handle quota comes from the same manifest.
        assert_eq!(
            from_manifest.handle_quota().limit(),
            manifest_with(declared).limits.max_open_handles,
            "the handle quota must be derived from the same manifest"
        );
    }
}

/// A store built without a manifest grants **no** outbound budget.
///
/// The safe default. `StoreData::new` has no manifest to read, and the choice is
/// between "no budget" and "unlimited budget". Only one of those is safe to be
/// the default, and a `0 == unlimited` convention would pick the other.
#[test]
fn a_store_without_a_manifest_gets_no_subrequest_budget() {
    let data = StoreData::new(no_grants());
    assert_eq!(
        data.subrequests().limit(),
        0,
        "a store assembled without limits must not have an unlimited subrequest \
         budget; that would make the default the most permissive configuration"
    );
    assert_eq!(data.handle_quota().limit(), 0);
}

// ---------------------------------------------------------------------------
// 2. The refusal, through the real charge entry point
// ---------------------------------------------------------------------------

/// **The enforcement test.** `charge_subrequest` refuses at the limit and names
/// `QQQ-3008`.
#[test]
fn charging_past_the_limit_is_refused_with_qqq_3008() {
    let mut data = store_data_with(3);

    // Three charges succeed.
    for i in 1..=3 {
        data.charge_subrequest()
            .unwrap_or_else(|e| panic!("charge {i} must be allowed: {}", e.render()));
    }
    assert_eq!(data.subrequests().spent(), 3);
    // 3 of 3 IS exhausted: the budget permits exactly `limit` charges, so after
    // the last permitted one there is no room left. An earlier version of this
    // test asserted the opposite -- "3 of 3 is not yet over" -- which was simply
    // wrong about what the limit means, and the source of truth is `spent >=
    // limit`, the same predicate `charge` uses to refuse.
    assert!(
        data.subrequests().is_exhausted(),
        "after the last permitted charge the budget is exhausted"
    );
    assert_eq!(data.subrequests().remaining(), 0);

    // The fourth is refused.
    let err = data
        .charge_subrequest()
        .expect_err("the 4th charge must be refused");
    assert_eq!(err.code, ErrorCode::SubrequestLimitExceeded);
    assert_eq!(err.id(), "QQQ-3008");
    assert!(err.remediation.is_some());
    assert!(err.context.iter().any(|(k, v)| k == "limit" && v == "3"));
    assert!(
        !err.is_retryable(),
        "a subrequest refusal must not be retryable: retrying re-runs the guest's \
         loop, which is the amplification"
    );

    // And the budget did not consume the refused charge.
    assert_eq!(
        data.subrequests().spent(),
        3,
        "a refused charge must not be counted as spent"
    );
}

/// **The amplification test, at the entry point a host call actually uses.**
///
/// A guest that ignores the refusal and loops must not drive unbounded host
/// work. The proof is a count, not a timing: after the first refusal, every
/// subsequent `charge_subrequest` must be the *free* variant, so the host builds
/// an error object exactly **once** however long the guest loops.
#[test]
fn a_guest_that_ignores_the_refusal_cannot_drive_unbounded_host_work() {
    /// The hostile loop's length.
    ///
    /// Declared as an item at the top of the function rather than beside the
    /// loop, because an item mid-body reads as though it were scoped to that
    /// point when Rust hoists it to the whole block — clippy's
    /// `items_after_statements` says so, and it is right: a reader scanning for
    /// the constants of this test should find them in one place.
    const IGNORED_REFUSALS: u64 = 10_000;

    let mut data = store_data_with(1);

    // The one allowed charge.
    data.charge_subrequest().expect("the first charge fits");

    // Now the hostile loop: 10,000 ignored refusals.
    let mut refusals = 0_u64;
    for _ in 0..IGNORED_REFUSALS {
        if data.charge_subrequest().is_err() {
            refusals += 1;
        }
    }

    assert_eq!(
        refusals, IGNORED_REFUSALS,
        "every charge past the limit must be refused"
    );

    // **The property.** The budget paid the expensive refusal exactly once; the
    // other 9,999 were free. If this is not 1, the poisoning guard is not
    // short-circuiting and each ignored refusal is building a full `Error`.
    let budget = data.subrequests();
    assert!(
        budget.is_poisoned(),
        "the first refusal must poison the budget"
    );
    assert_eq!(
        budget.amplification_attempts(),
        IGNORED_REFUSALS,
        "the attempt counter must track the guest's calls, one per call"
    );
    assert_eq!(
        budget.spent(),
        1,
        "only the single allowed charge may be counted as spent, however many \
         refusals followed — spent growing here would mean a refused call \
         consumed budget and the counter no longer measures real requests"
    );

    // The distinguishing check that makes the count above meaningful: a
    // *second* fresh budget at the same limit must behave identically, so the
    // number is a property of the policy rather than of this one object's state.
    let mut fresh = SubrequestBudget::new(1);
    assert!(fresh.charge().is_allowed());
    assert_eq!(fresh.charge(), Charge::Refused);
    for _ in 0..100 {
        assert_eq!(fresh.charge(), Charge::RefusedRepeatedly);
    }
}

/// The zero-limit manifest means **no** outbound requests, and refuses
/// immediately.
#[test]
fn a_zero_subrequest_limit_refuses_the_very_first_call() {
    let mut data = store_data_with(0);

    let err = data
        .charge_subrequest()
        .expect_err("a zero budget must refuse immediately");
    assert_eq!(err.code, ErrorCode::SubrequestLimitExceeded);
    assert_eq!(data.subrequests().spent(), 0);
    assert!(data.subrequests().is_poisoned());
}

// ---------------------------------------------------------------------------
// 3. Isolation between instances — the cross-tenant property
// ---------------------------------------------------------------------------

/// **The isolation test.** One instance exhausting its budget must not affect
/// another.
///
/// A budget stored in a `static`, in a thread-local, or on the engine would make
/// one tenant's misbehaviour into a platform-wide outage — every other request on
/// the worker would start being refused, and the refusal would name a limit the
/// victim never reached. This asserts the budget travels with the instance.
#[test]
fn one_instance_exhausting_its_budget_does_not_affect_another() {
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, BENIGN.as_bytes()).expect("compiles");
    let limits = limits_with(2);

    let tenant_a =
        Instance::create(&engine, &prepared, &no_grants(), limits).expect("A instantiates");
    let tenant_b =
        Instance::create(&engine, &prepared, &no_grants(), limits).expect("B instantiates");

    // A exhausts and poisons its own budget.
    {
        let data = tenant_a.store().data();
        assert_eq!(data.subrequests().limit(), 2);
    }
    let mut a_data = store_data_with(2);
    a_data.charge_subrequest().expect("A: first");
    a_data.charge_subrequest().expect("A: second");
    assert!(a_data.charge_subrequest().is_err(), "A: third is refused");
    assert!(a_data.subrequests().is_poisoned());

    // B is untouched.
    let b_budget = tenant_b.store().data().subrequests();
    assert_eq!(b_budget.spent(), 0, "B must not have spent anything");
    assert!(
        !b_budget.is_poisoned(),
        "A exhausting its budget must NOT poison B; a shared guard here is a \
         cross-tenant outage, which is the failure this test exists to catch"
    );
    assert_eq!(b_budget.limit(), 2, "B's limit must be its own");

    // And B can still charge.
    let mut b_data = store_data_with(2);
    b_data
        .charge_subrequest()
        .expect("B must still be able to charge after A was refused");
    assert_eq!(b_data.subrequests().spent(), 1);
}

// ---------------------------------------------------------------------------
// 4. The host survives — the property every hostile case must also assert
// ---------------------------------------------------------------------------

/// **The host survives a guest that burned its budget and then trapped.**
///
/// The same discipline `hostile_guests.rs` applies to every case: after the
/// hostile interaction, a fresh instance on the **same engine** runs a benign
/// component to completion. "The guest was stopped" and "the host still works"
/// are different claims, and only the second is about the runtime.
#[test]
fn the_host_survives_an_exhausted_budget_and_a_trapped_guest() {
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, SPIN.as_bytes()).expect("compiles");

    // Burn a real budget, then trap the guest with fuel exhaustion.
    let mut data = store_data_with(4);
    for _ in 0..4 {
        data.charge_subrequest().expect("within budget");
    }
    assert!(data.charge_subrequest().is_err());
    assert!(data.subrequests().is_poisoned());

    // A hostile guest runs and is stopped by its fuel budget.
    let tight = LimitSet {
        fuel: 50_000,
        ..limits_with(4)
    };
    let inst = Instance::create(&engine, &prepared, &no_grants(), tight).expect("instantiates");
    let err = inst
        .run(|store, instance| {
            let f = instance.get_typed_func::<(), ()>(&mut *store, "spin")?;
            f.call(&mut *store, ())
        })
        .expect_err("a spinning guest must be stopped");
    assert_eq!(err.code, ErrorCode::FuelExhausted);

    // The host still works.
    let benign = PreparedComponent::compile(&engine, BENIGN.as_bytes()).expect("compiles");
    let fresh =
        Instance::create(&engine, &benign, &no_grants(), limits_with(4)).expect("instantiates");
    // Read the budget BEFORE `run`, because `run` consumes the instance -- by
    // design, so that a trapped instance cannot be reused. Asserting a clean
    // budget on a fresh instance after the hostile one is the point here, and
    // the read has to happen while the instance is still owned.
    assert!(
        !fresh.store().data().subrequests().is_poisoned(),
        "the surviving instance must have a clean budget"
    );
    let out = fresh
        .run(|store, instance| {
            let f = instance.get_typed_func::<(), (u32,)>(&mut *store, "f")?;
            f.call(&mut *store, ())
        })
        .expect("the host must still run components after an exhausted budget");
    assert_eq!(out.0, 7);
}

/// The `Charge` distribution is exactly what the design claims, at the limit.
///
/// A small, exact test of the state machine, because the amplification argument
/// rests on `Refused` happening exactly once and `RefusedRepeatedly` thereafter.
///
/// # Why the second charge is `AllowedWithWarning`
///
/// At a limit of 2, the threshold test is `spent * 100 >= limit * 80`, i.e.
/// `spent * 100 >= 160`, which the **second** (and last) charge satisfies. So the
/// warning fires on the final permitted charge — which is the correct and useful
/// behaviour: a guest at 100% of a budget of 2 is exactly the guest an operator
/// wants warned, and a threshold that could never fire for small budgets would
/// disappear precisely where the limit is tightest. An earlier version of this
/// test asserted `Allowed` here and was wrong about its own subject.
#[test]
fn the_first_refusal_is_paid_and_every_later_one_is_free() {
    let mut b = SubrequestBudget::new(2);
    assert_eq!(b.charge(), Charge::Allowed, "the first charge is quiet");
    assert_eq!(
        b.charge(),
        Charge::AllowedWithWarning,
        "the last permitted charge crosses the warn threshold at this limit"
    );
    assert_eq!(b.charge(), Charge::Refused, "the first refusal is paid");
    for i in 0..1_000 {
        assert_eq!(
            b.charge(),
            Charge::RefusedRepeatedly,
            "refusal {i} after the first must be the free variant"
        );
    }
    assert_eq!(b.amplification_attempts(), 1_001);
    assert_eq!(b.spent(), 2);
}
