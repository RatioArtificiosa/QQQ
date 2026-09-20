//! # qqq-host
//!
//! The QQQ execution engine. Owns the Wasmtime engine and turns a component
//! plus a capability grant set into a running, limited, isolated instance.
//!
//! ## The two invariants this crate enforces
//!
//! 1. **A guest gets only the imports its grants name.** The linker is built
//!    *per instance* from the resolved grant set, so an ungranted capability is
//!    not merely denied at call time — it is **absent**, and instantiation
//!    fails with a clear code. Verified against the real toolchain.
//! 2. **A trap never takes down the host, and never reuses the instance.**
//!    Every trap discards; see [`trap`] for why that is a security property
//!    rather than a performance one.
//!
//! ## Protocol note
//!
//! Proposal §4.7 fixes the default guest concurrency model as
//! **async-single-threaded**: one logical task per request, using the Component
//! Model's `async`/`future`/`stream`. Shared linear memory is opt-in and
//! discouraged, because it undermines per-instance memory accounting — which is
//! a core security property.
//!
//! ## Checklist coverage
//!
//! `HOST-001` … `HOST-024`. See `QQQ-Proposal-V1.md` §6.1.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

/// How many epoch ticks a yielding guest is granted before it is asked to yield
/// again.
///
/// # Why one, and not a larger number
///
/// The epoch deadline is set to `1` tick beyond the current epoch at instance
/// creation ([`instance::Instance::create`]), and this constant is the `delta`
/// the async yield policy uses to extend it. A value of `1` means *"yield at
/// every tick"*, which is the finest-grained fairness the mechanism offers.
///
/// A larger delta trades scheduling fairness for fewer executor round-trips. It
/// is not configurable in V1 because there is no measurement yet that would
/// justify a particular larger number, and an unmeasured tuning knob is a
/// liability: it reads as meaningful, so somebody changes it, and nothing
/// detects whether that helped (`PERF-015` owns the measurement that would
/// close this).
///
/// # Why the non-zero rule is a compile-time check
///
/// A `delta` of `0` would extend the deadline by nothing, so the guest would
/// yield on every tick and never progress — a livelock that presents as a hung
/// guest with no trap to explain it. That is a property of the *constant*, so
/// it is enforced by the compiler below rather than by a test: a runtime
/// `assert!(EPOCH_YIELD_TICKS > 0)` is a constant expression, which clippy
/// rejects (`assertions_on_constants`) and which could never fail anyway. A
/// check that cannot fail carries no information (`§M-006`).
pub const EPOCH_YIELD_TICKS: u64 = 1;

// The livelock guard, checked when this crate is compiled.
const _: () = assert!(
    EPOCH_YIELD_TICKS > 0,
    "EPOCH_YIELD_TICKS must be at least 1: a delta of 0 extends the deadline by \
     nothing, so a yielding guest would yield forever without making progress"
);

pub mod ambient;
pub mod config;
pub mod guard;
pub mod host_clock;
pub mod host_crypto;
pub mod instance;
pub mod linker;
pub mod metrics;
pub mod pool;
pub mod trap;

pub use ambient::{hash_data, require, AmbientState, HashAlgorithm, HostCallError, RandomFailure};
pub use config::{
    aot_cache_key, build_pooling, target_triple, EngineConfig, StoreLimits as LimitSet,
};
pub use guard::{guard, guard_reporting, PanicReport};
pub use instance::{
    digest_of, epoch_tick_interval, uses_virtual_clock, DeterministicClock, ExecutionMode,
    ExecutionOutcome, Instance, PreparedComponent,
};
pub use linker::{
    build_linker, describe_gap, interface_for, recheck, required_interfaces, BoundInterfaces,
    BuiltLinker, StoreData,
};
pub use metrics::{Histogram, Metrics, TrapLabel};
pub use pool::{exhausted_error, Acquired, Exhausted, Pool, ReleaseOutcome};
pub use trap::{classify_trap, format_bytes, human_message, remediation_for, Trap, WasmFrame};
