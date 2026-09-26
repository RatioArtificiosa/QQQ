// SPDX-License-Identifier: Apache-2.0

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

/// The canonical ABI types for `qqq:http`.
///
/// Added alongside `invoke`: calling a guest needs the request and response to
/// exist as Rust types whose `Lower`/`Lift` layout matches the WIT exactly.
pub mod abi;
pub mod admission;
pub mod ambient;
pub mod arch003;
pub mod arch012;
pub mod audit;
pub mod audit_export;
pub mod boundary;
/// Calling a guest's handler: the request in, the response out.
///
/// `invoke` resolves *which* function to call; this performs the call, converting
/// between the typed ABI and the dynamic `Val` form Wasmtime wants.
pub mod call;
pub mod config;
pub mod guard;
/// Sanitising sinks for guest stdout and stderr.
///
/// Added with `§O-183`: `host_wasi::context` inherited the host's stdout for the
/// guest, and `qqq-serve`'s access log is written to that same stdout — so a guest
/// could emit a line byte-identical to a host access record.
pub mod guest_output;
pub mod handles;
pub mod host_clock;
pub mod host_crypto;
mod host_http;
pub mod host_secrets;
mod host_wasi;
pub mod instance;
/// Calling a guest: the edge between the host and an application component.
///
/// Added with `§O-146`: nothing in production resolved a guest's
/// `qqq:http/incoming-handler.handle`, so `qqqai serve` had no way to dispatch to a
/// guest and every benchmark depended on a call nobody had scheduled.
pub mod invoke;
pub mod linker;
pub mod metrics;
pub mod pool;
pub mod preload;
pub mod quota;
pub mod tenant;
pub mod trap;

pub use admission::{admit, Admitted, HostCapacity, Refusal};
pub use ambient::{hash_data, require, AmbientState, HashAlgorithm, HostCallError, RandomFailure};
pub use audit::{
    genesis_digest, Append, AppendCounters, AuditRecord, AuditStream, Ledger, LedgerError, Outcome,
    DEFAULT_CAPACITY,
};
pub use boundary::{
    all, boundaries_checking, consistent_length, discriminant, interfaces, list_size, one_of,
    path_component, path_shape, range_within, render_for_diagnostic, size, text, Boundary,
    CheckClass, Rejection, BOUNDARIES, MAX_ECHO_BYTES, MAX_IDENTIFIER_BYTES, MAX_LIST_BYTES,
    MAX_LIST_ELEMENTS, MAX_PATH_BYTES,
};
pub use config::{
    aot_cache_key, build_engine, build_pooling, target_triple, EngineConfig,
    StoreLimits as LimitSet,
};
pub use guard::{guard, guard_reporting, PanicReport};
pub use guest_output::{
    Escaper, GuestOutput, GuestSink, SanitisingWriter, MAX_ESCAPED_RUN, STDERR_PREFIX,
    STDOUT_PREFIX,
};
pub use handles::{Handle, HandleStats, HandleTable};
pub use host_http::{
    describe_ungranted as describe_http_ungranted, register as register_http,
    INTERFACE as HTTP_INTERFACE,
};
pub use host_secrets::{
    PermittedOp, RequestedOp, SecretCrypto, SecretMaterial, SecretStore, MAX_SECRET_INPUT,
};
pub use host_wasi::{
    context as wasi_context, describe_missing_env as describe_missing_wasi_env,
    register as register_wasi, DeniedClock, Registered as WasiRegistered,
};
pub use instance::{
    digest_of, epoch_tick_interval, uses_virtual_clock, DeterministicClock, ExecutionMode,
    ExecutionOutcome, Instance, PreparedComponent,
};
pub use linker::{
    build_linker, describe_gap, interface_for, recheck, required_interfaces, BoundInterfaces,
    BuiltLinker, StoreData, TrappingLimiter,
};
pub use metrics::{Histogram, Metrics, TrapLabel};
pub use pool::{exhausted_error, Acquired, Exhausted, Pool, ReleaseOutcome};
pub use preload::{cache_key_for, preload, PreloadItem, PreloadOutcome, PreloadReport};
pub use quota::{Charge, HandleQuota, SubrequestBudget, Verdict, WARN_THRESHOLD_PERCENT};
pub use tenant::{
    ComponentDigest, GrantDigest, InstanceKey, LedgerReport, ScopeRefusal, TenantLedger,
    TenantScope,
};
pub use trap::{classify_trap, format_bytes, human_message, remediation_for, Trap, WasmFrame};
