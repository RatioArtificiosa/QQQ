// SPDX-License-Identifier: Apache-2.0

//! The grant-built linker — where the capability model becomes enforcement.
//!
//! This is **the single most security-critical function in QQQ**. It is the
//! point at which a resolved [`GrantSet`] is turned into the set of imports a
//! guest can actually reach.
//!
//! # The property being enforced
//!
//! > A capability the manifest did not grant is **absent**, not denied.
//!
//! The distinction matters more than it first appears:
//!
//! * A **denied** call is one the guest can attempt and be refused. That means
//!   the guest can *enumerate* what exists, the host must handle the attempt,
//!   and any bug in the denial path is a vulnerability.
//! * An **absent** import cannot be referenced at all. The guest's module
//!   validation fails at instantiation, before a single instruction runs. There
//!   is no denial path to get wrong.
//!
//! This was verified against the real toolchain: instantiating a component
//! through an empty linker fails with *"component imports instance
//! `host:probe/greeter`, but a matching implementation was not found in the
//! linker"* — naming the exact missing import. See Observations §O-006.
//!
//! # Why the linker is built per instance, not per process
//!
//! A per-process linker would give every tenant the union of every tenant's
//! grants — a catastrophic cross-tenant authority leak, and exactly the failure
//! the whole architecture exists to prevent. Building per instance costs
//! microseconds (measured p50 800 ns for instantiation) and is the difference
//! between "the server has permissions" and "**this request** has permissions".
//!
//! # Defence in depth
//!
//! [`GrantSet`] is consulted twice: here at bind time, and again at call time by
//! [`recheck`]. The second check is cheap (a set lookup on a small enum) and
//! exists specifically to catch a host bug that mis-built a linker. Belt and
//! braces, deliberately.
//!
//! See Proposal §4.4, §7.3 and Checklist `CAP-008`, `SEC-002`.

use std::fmt;

use qqq_cap::capability::Capability;
use qqq_cap::resolve::GrantSet;
use qqq_core::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use wasmtime::component::Linker;
use wasmtime::StoreLimits;

/// The host-state type every store carries.
///
/// Deliberately minimal. `qqq-host`'s fuller store data (resource tables, quota
/// counters, tenant identity) is layered on this in later work; keeping the
/// security-critical path free of unnecessary state makes it auditable.
pub struct StoreData {
    /// The grants this instance was created with.
    ///
    /// Retained so the call-time re-check has something authoritative to
    /// consult, rather than re-deriving it from the linker — which would make
    /// the second check vacuous, since a mis-built linker would produce the
    /// same wrong answer twice.
    pub grants: GrantSet,

    /// The resource limiter, applied to every store.
    ///
    /// # Why the limiter lives inside the store data
    ///
    /// `Store::limiter` takes a closure returning `&mut impl ResourceLimiter`,
    /// and the returned reference must outlive the store. Storing it in the
    /// store's own data is the only arrangement that satisfies that without
    /// self-reference — and it keeps the limits travelling with the instance they
    /// constrain, so they cannot be swapped by mistake.
    ///
    /// # Why it is a [`TrappingLimiter`] and not a bare `StoreLimits`
    ///
    /// Because a bare `StoreLimits` makes the memory ceiling **advisory** —
    /// see that type for the measurement. The trapping wrapper delegates every
    /// non-memory limit, so nothing is lost by using it.
    resource_limits: TrappingLimiter,

    /// The QQQ-level limits, for diagnostics and fuel accounting.
    limits: Option<crate::config::StoreLimits>,

    /// Hash algorithms the manifest's `[capabilities.crypto] hash` list named.
    ///
    /// Retained so the host can refuse an algorithm it is perfectly capable of
    /// computing but was not granted. Without this the manifest's allowlist
    /// would be advisory, and a guest could use any primitive the host happened
    /// to link — which is ambient authority by another route.
    pub allowed_hashes: Vec<crate::ambient::HashAlgorithm>,

    /// The ambient state: clock and RNG, deterministic or not.
    pub ambient: crate::ambient::AmbientState,

    /// The subrequest budget for this instance — `SEC-009`.
    ///
    /// # Why the budget lives in the store rather than in each capability
    ///
    /// Because amplification is a property of the **guest's control flow**, not
    /// of one capability: a loop alternating `http.get` and `dns.resolve` doubles
    /// its fan-out while touching only a third of either interface's own quota.
    /// One budget per instance is what makes "this request caused N outbound
    /// effects" a number the host can state and enforce. Per-capability limits
    /// still exist (`CapabilityQuotaExhausted`, `4005`) and they answer a
    /// different question — how much of *this capability* was used.
    pub subrequests: crate::quota::SubrequestBudget,

    /// The handle quota for this instance — `SEC-008`.
    pub handles: crate::quota::HandleQuota,

    /// Which tenant this instance serves, and under which grants — `CAP-014`.
    ///
    /// # Why the scope lives in the store rather than beside it
    ///
    /// The alternative — a field on the pooled-instance wrapper — puts the
    /// tenant identity in the one struct that is *copied out* of the pool and
    /// handed to a request handler. Anything that can be reassigned on the way
    /// is a cross-tenant path. Inside the store it is created with the store
    /// and reachable only by immutable reference, so "this instance belongs to
    /// tenant X" is a property of the thing doing the work.
    ///
    /// `None` means the store was not scoped to a tenant at all, which is the
    /// correct state for the single-tenant `qqqai run` path and for the many
    /// unit tests that exercise capabilities without a server. It is **not** a
    /// wildcard: [`StoreData::tenant_scope`] returns `None` and the server
    /// refuses to hand an unscoped store to a tenant-serving request path. A
    /// `None` that meant "any tenant" would be the failure this field exists to
    /// prevent.
    pub tenant: Option<crate::tenant::TenantScope>,

    /// The WASI context, derived from the grants.
    ///
    /// # Why a store cannot exist without one
    ///
    /// A guest built by `cargo build --target wasm32-wasip2` imports fifteen WASI
    /// interfaces even when its own source never calls one, because `std` for that
    /// target is implemented over them. `wasmtime_wasi::p2::add_to_linker_sync`
    /// takes the context from the **store**, so a store without one cannot
    /// instantiate such a guest at all:
    ///
    /// ```text
    /// error[QQQ-6003]: the component could not be instantiated
    ///   component imports instance `wasi:io/poll@0.2.9`, but a matching
    ///   implementation was not found in the linker
    /// ```
    ///
    /// It is a plain field rather than an `Option` because an `Option` would let a
    /// store be built without one, and that failure reads like a guest defect
    /// rather than a wiring omission -- the same reasoning the `tenant` field
    /// documents for refusing a `None` that means "any tenant".
    ///
    /// The authority (host and port) this instance's requests arrive on, if it is
    /// serving.
    ///
    /// # Why the store carries it rather than the request
    ///
    /// `qqq:http/http`'s `incoming-authority` reports it to the guest, and the guest
    /// must not derive it from the `Host` header: that header is **client-controlled**,
    /// so trusting it lets a client decide what the guest believes it is serving.
    /// `GuestApp`'s module docs make the same argument for the URL it builds. The
    /// authority the server bound is configuration, and configuration lives here.
    ///
    /// Empty for a store that is not serving — the `qqqai run` path and every unit
    /// test — which is the honest value. A guest that asks without the `http.server`
    /// grant gets a visible sentinel rather than this empty string, so "not serving"
    /// and "not permitted oh" stay distinguishable (`crate::host_http`).
    pub incoming_authority: String,

    /// Every store has a context; the **grants** decide what it permits. See
    /// [`crate::host_wasi`] for the mapping, which registers no filesystem and no
    /// sockets at all.
    pub wasi: wasmtime_wasi::WasiCtx,

    /// The WASI resource table: where guest-side handles live.
    ///
    /// # Why it belongs to the store
    ///
    /// A `pollable` or an output stream is created *by* the guest and owned *by* the
    /// instance. Keeping the table in the store means those handles are dropped with
    /// the instance, so §4.2's per-request isolation extends to WASI resources --
    /// there is no table that outlives its store and could be reached by the next
    /// request.
    pub wasi_table: wasmtime_wasi::ResourceTable,
}

/// The `WasiView` implementation the WASI linker requires.
///
/// # Why this must exist for the store to be usable at all
///
/// `wasmtime_wasi::p2::add_to_linker_sync` is generic over `T: WasiView`, and it
/// calls `ctx()` on every WASI host function to find the context and the resource
/// table. Without this impl `StoreData` cannot be used as a store for a
/// WASI-importing component, so **no real guest instantiates** -- the exact failure
/// `host_wasi`'s module documentation records.
///
/// Returning `&mut` references straight out of the store is the intended shape: the
/// table and the context are per-store state, and the borrow checker enforces that
/// no host call can hold one while the guest is running.
impl wasmtime_wasi::WasiView for StoreData {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        wasmtime_wasi::WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.wasi_table,
        }
    }
}

/// A `Debug` that names the WASI fields without printing them.
///
/// `WasiCtx` and `ResourceTable` are not `Debug`, and a derive would not compile.
/// That is a fortunate constraint rather than an obstacle: a guest's resource table
/// lists the handles it holds, and printing one into a shared log is how a
/// per-instance fact becomes a cross-instance leak. The field is named so a reader
/// knows it exists; its contents are not a log's business.
impl fmt::Debug for StoreData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreData")
            .field("grants", &self.grants)
            .field("limits", &self.limits)
            .field("allowed_hashes", &self.allowed_hashes)
            .field("ambient", &self.ambient)
            .field("has_wasi_ctx", &true)
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl Default for StoreData {
    /// An instance with **no** capability and no explicit limits. The safe
    /// default twice over: a store that was not explicitly given grants cannot
    /// do anything, and one without limits has Wasmtime's own defaults.
    fn default() -> Self {
        Self {
            grants: GrantSet::empty(),
            resource_limits: TrappingLimiter::new(StoreLimits::default(), usize::MAX),
            limits: None,
            allowed_hashes: Vec::new(),
            ambient: crate::ambient::AmbientState::default(),
            // Zero, not "unlimited". A store assembled without going through
            // `from_manifest` or `set_limits` has no declared budget, and the
            // safe reading of "no budget declared" is that the guest may drive
            // no outbound effects. An implicit `0 == unlimited` here would make
            // the default the most permissive possible configuration, which is
            // the failure mode §2.5 exists to forbid.
            subrequests: crate::quota::SubrequestBudget::new(0),
            handles: crate::quota::HandleQuota::new(0),
            tenant: None,
            // An empty environment and no wall clock: the deny-by-default answer
            // for a store that was not built from a manifest. The `expect` is
            // unreachable -- an empty grant set and an empty environment always
            // produce a context.
            wasi: crate::host_wasi::context(&GrantSet::empty(), &[])
                .expect("an empty grant set and empty environment always build"),
            wasi_table: wasmtime_wasi::ResourceTable::new(),
            incoming_authority: String::new(),
        }
    }
}

impl StoreData {
    /// Build store data from a grant set, with no explicit resource limits.
    ///
    /// # Panics
    ///
    /// The WASI context construction is documented as infallible for an empty
    /// environment, and this call passes an empty environment. The `expect` is
    /// therefore unreachable **as long as that guarantee holds** — it is there to
    /// turn a future change that makes context construction fallible into a loud
    /// failure at one obvious site rather than a silently wrong grant set.
    #[must_use]
    pub fn new(grants: GrantSet) -> Self {
        // The context borrows `grants` before the struct literal moves it. Ordering
        // matters: calling `context(&grants, ..)` inside a `Self { grants, .. }`
        // literal would borrow after the move, and the compiler rejects it. Computing
        // the value first is the fix — not cloning the grant set, which would leave
        // two copies to keep in step.
        let wasi = crate::host_wasi::context(&grants, &[])
            .expect("an empty environment cannot fail to build");
        Self {
            grants,
            resource_limits: TrappingLimiter::new(StoreLimits::default(), usize::MAX),
            limits: None,
            allowed_hashes: Vec::new(),
            ambient: crate::ambient::AmbientState::default(),
            subrequests: crate::quota::SubrequestBudget::new(0),
            handles: crate::quota::HandleQuota::new(0),
            tenant: None,
            // Derived from the grants so a store built this way permits exactly
            // what the grant set says -- no more, and no less.
            wasi,
            wasi_table: wasmtime_wasi::ResourceTable::new(),
            incoming_authority: String::new(),
        }
    }

    /// Build store data from a manifest, deriving the ambient state and the
    /// algorithm allowlists from its capability declaration.
    ///
    /// # Why this takes the manifest rather than the grant set
    ///
    /// The grant set says *that* `crypto.hash` is permitted; only the manifest
    /// says *which algorithms*. A host that enforced only the grant would let a
    /// guest use any algorithm the host links, which is not what the developer
    /// declared.
    ///
    /// # Panics
    ///
    /// As [`StoreData::new`]: the WASI context construction is infallible, and the
    /// `expect` exists so a future change to that guarantee fails here — at the one
    /// place a store is built from a manifest — rather than producing a store whose
    /// environment allowlist silently did not apply.
    #[must_use]
    pub fn from_manifest(manifest: &qqq_cap::manifest::Manifest) -> Self {
        Self::from_manifest_with_env(manifest, &[])
    }

    /// Build store data from a manifest, with the environment **injected**.
    ///
    /// # Why the environment is a parameter and not read here
    ///
    /// Because reading it would be ambient configuration, which `§2.5` forbids and
    /// `tools/check_no_ambient.py` enforces. A `std::env::var` call inside this
    /// constructor made the runtime's behaviour depend on hidden global state: two
    /// identical manifests under two environments would produce two different
    /// guests, and nothing in the manifest or the ledger would record it. The
    /// checker caught exactly that, on the change that added WASI.
    ///
    /// So the *edge* reads the environment — `qqq-run`, which is a CLI and is
    /// entitled to inspect its own process — and the runtime receives the result.
    /// The benefit beyond compilance is testability: a test passes a fixed map
    /// rather than mutating the real environment, which would race every other test
    /// in the binary.
    ///
    /// # Why a missing variable is dropped rather than passed as empty
    ///
    /// `env` carries only the pairs the caller resolved. A name the manifest lists
    /// but the caller did not supply is **absent** from the guest's environment,
    /// which is the safe direction: a guest reading `REGION` gets nothing and takes
    /// its own default, rather than receiving an empty string that looks like a real
    /// value. `host_wasi::describe_missing_env` is the diagnostic for the caller that
    /// wants to refuse instead.
    ///
    /// # Panics
    ///
    /// As [`StoreData::new`]: the WASI context construction is infallible, and the
    /// `expect` exists so a future change to that guarantee fails here — at the one
    /// place a store is built from a manifest — rather than producing a store whose
    /// environment allowlist silently did not apply.
    #[must_use]
    pub fn from_manifest_with_env(
        manifest: &qqq_cap::manifest::Manifest,
        env: &[(String, String)],
    ) -> Self {
        let grants = GrantSet::from_manifest(manifest);

        let allowed_hashes = manifest
            .capabilities
            .crypto
            .as_ref()
            .map(|c| {
                c.hash
                    .iter()
                    .filter_map(|h| crate::ambient::HashAlgorithm::parse(h))
                    .collect()
            })
            .unwrap_or_default();

        // Built before the struct literal, for the reason `StoreData::new`
        // documents: the context borrows `grants`, and a borrow inside a literal that
        // also moves it is rejected.
        let wasi = crate::host_wasi::context(&grants, env)
            .expect("building a context from an injected environment cannot fail");

        Self {
            grants,
            resource_limits: TrappingLimiter::new(StoreLimits::default(), usize::MAX),
            limits: None,
            allowed_hashes,
            ambient: crate::ambient::AmbientState::default(),
            // Derived from the manifest so `[limits]` is the single source of
            // truth. Deriving the ambient state from the manifest and the quotas
            // from somewhere else is how one of them ends up not being applied.
            subrequests: crate::quota::SubrequestBudget::new(manifest.limits.max_subrequests),
            handles: crate::quota::HandleQuota::new(manifest.limits.max_open_handles),
            tenant: None,
            wasi,
            wasi_table: wasmtime_wasi::ResourceTable::new(),
            incoming_authority: String::new(),
        }
    }

    /// Scope this instance to a tenant and a grant set — `CAP-014`.
    ///
    /// # Why this consumes `self` rather than taking `&mut self`
    ///
    /// Because a store must not be *scoped twice*. `self` by value makes the
    /// second call impossible without an explicit rebuild, and the rebuild is
    /// the point: an instance that changes tenant must be a new instance, with
    /// a fresh handle table and fresh ambient state, not the old one wearing a
    /// new label. `with_deterministic_ambient` follows the same shape for the
    /// same reason.
    ///
    /// # Why the digest is passed separately from the grants
    ///
    /// The store already holds a `GrantSet`, and `GrantSet::digest()` exists —
    /// so the caller could be spared the argument. It is required anyway for
    /// one property: the digest that **keys the pool** and the digest **stored
    /// in the instance** are then provably the same value, because the same
    /// [`crate::tenant::GrantDigest`] is passed to both. Deriving it inside
    /// would leave open the possibility that the pool was keyed on a digest of
    /// the pre-normalization manifest while the store recorded the
    /// post-normalization one — two descriptions of one grant set, and a pool
    /// that misses on every lookup or, worse, on some.
    #[must_use]
    pub fn with_tenant(mut self, scope: crate::tenant::TenantScope) -> Self {
        self.tenant = Some(scope);
        self
    }

    /// The tenant this instance is scoped to, if any.
    #[must_use]
    pub fn tenant_scope(&self) -> Option<&crate::tenant::TenantScope> {
        self.tenant.as_ref()
    }

    /// Install the deterministic ambient state.
    #[must_use]
    pub fn with_deterministic_ambient(mut self, deterministic: bool) -> Self {
        self.ambient = crate::ambient::AmbientState::new(deterministic);
        self
    }

    /// Mutable access to the resource limiter, for `Store::limiter`.
    #[must_use]
    pub fn limiter_mut(&mut self) -> &mut TrappingLimiter {
        &mut self.resource_limits
    }

    /// Install the Wasmtime limiter and record the QQQ limits.
    ///
    /// The default ceiling is `usize::MAX` because the caller that knows the
    /// manifest's memory limit is [`StoreData::install_trapping_limiter`], which
    /// takes it; this form exists for stores with no explicit limit.
    pub fn set_limits(&mut self, limiter: StoreLimits, limits: crate::config::StoreLimits) {
        self.resource_limits = TrappingLimiter::new(limiter, usize::MAX);
        // Re-derive BOTH quotas from the same `limits` value the memory ceiling
        // came from. Refreshing one and not the other is the single most likely
        // way for this code to go wrong: a caller who sets limits programmatically
        // (the test and embedding paths) would silently get a zero subrequest
        // budget, and every outbound call would fail with a confusing refusal
        // that names a limit the caller never wrote.
        self.subrequests = crate::quota::SubrequestBudget::new(limits.max_subrequests);
        self.handles = crate::quota::HandleQuota::new(limits.max_open_handles);
        self.limits = Some(limits);
    }

    /// Install a limiter that **traps** at `ceiling` bytes per linear memory.
    ///
    /// This is the enforced form. See [`TrappingLimiter`] for why the advisory
    /// alternative is not good enough.
    pub fn install_trapping_limiter(&mut self, limiter: StoreLimits) {
        let ceiling = self.limits.map_or(usize::MAX, |l| {
            usize::try_from(l.memory_bytes).unwrap_or(usize::MAX)
        });
        self.resource_limits = TrappingLimiter::new(limiter, ceiling);
    }

    /// The QQQ-level limits, when set.
    #[must_use]
    pub const fn limits(&self) -> Option<crate::config::StoreLimits> {
        self.limits
    }

    /// Charge one subrequest, enforcing `limits.max_subrequests` — `SEC-009`.
    ///
    /// # The contract every outbound host call must honour
    ///
    /// Any host function that causes an effect **outside the host process** —
    /// an HTTP request, a DNS lookup, a queue publish, a SQL round-trip — must
    /// call this **before** performing the effect, and must return the error to
    /// the guest when it is refused. The order matters: charging afterwards would
    /// let the guest exhaust the limit by however many requests fit in flight,
    /// and charging after a *failed* effect would charge for work that did not
    /// happen.
    ///
    /// # Why the return is `Result` and the poison matters
    ///
    /// On the first refusal the caller gets `Err` and returns it to the guest.
    /// On every later call the charge is free — that is
    /// [`SubrequestBudget::charge`]'s poisoning, and it is what stops a guest
    /// that ignores the error from turning the refusal path into its own
    /// amplification vector. See `crate::quota` for the measurement.
    ///
    /// # Errors
    ///
    /// `QQQ-3008 SubrequestLimitExceeded` when the budget is exhausted.
    pub fn charge_subrequest(&mut self) -> Result<()> {
        use crate::quota::Charge;
        match self.subrequests.charge() {
            // A permitted charge, with or without the threshold crossing.
            //
            // The two are one arm because the host does the same thing in both
            // cases: nothing. The warning is recorded *on the budget*
            // (`warned`), and a caller holding a `Metrics` handle reads it after
            // the call. Emitting a counter here would mean threading metrics
            // through every host function for a once-per-instance event, on the
            // hot path, which is the wrong trade — and the code this replaced
            // made that decision invisible by giving the two identical arms
            // separate bodies.
            Charge::Allowed | Charge::AllowedWithWarning => Ok(()),
            Charge::Refused => Err(self.subrequests.refusal()),
            // Deliberately a CHEAP error rather than the full one: the guest
            // already received that refusal, and constructing the context map
            // and remediation again is exactly the amplification this module
            // exists to stop. See `crate::quota` for the 2835x measurement.
            Charge::RefusedRepeatedly => Err(Error::new(
                ErrorCode::SubrequestLimitExceeded,
                "the subrequest budget for this instance remains exhausted",
            )),
        }
    }

    /// The subrequest budget, for diagnostics and tests.
    #[must_use]
    pub const fn subrequests(&self) -> &crate::quota::SubrequestBudget {
        &self.subrequests
    }

    /// The handle quota, for diagnostics and tests.
    #[must_use]
    pub const fn handle_quota(&self) -> &crate::quota::HandleQuota {
        &self.handles
    }
}

/// **The memory limit, enforced as a trap rather than as a failed grow.**
///
/// # The defect this fixes, measured
///
/// The obvious way to install a memory ceiling is `Store::limiter` with
/// Wasmtime's own `StoreLimits` — and that is what this crate did. Wasmtime
/// documents what that does:
///
/// > If `Ok(false)` is returned then this will cause the `memory.grow`
/// > instruction in a module to **return -1 (failure)** … If `Err(e)` is
/// > returned then the `memory.grow` function will behave **as if a trap has
/// > been raised**.
///
/// So a `StoreLimits` ceiling is **advisory to the guest**: the grow fails and
/// the guest keeps running. Measured with `cargo run --example memory_probe -p
/// qqq-host` against a 4 MiB ceiling and a 10-billion-fuel budget:
///
/// | Guest behaviour on a failed grow | Outcome | Time to stop |
/// |---|---|---|
/// | Traps (`unreachable`) | `GuestPanic` — **not** `MemoryLimitExceeded` | 487 µs |
/// | Ignores it and loops | `FuelExhausted` — **not** `MemoryLimitExceeded` | **97 seconds** |
///
/// Two consequences, both bad and neither visible without measuring:
///
/// 1. **`QQQ-3001 MemoryLimitExceeded` was unreachable through this path.** The
///    taxonomy documents it as the memory-limit code, and nothing could produce
///    it — so a memory-limited guest reported a *panic* or *fuel exhaustion*
///    instead, sending an operator to the wrong fix.
/// 2. **A hostile guest was not stopped promptly.** 97 seconds at full CPU for
///    one guest, when the ceiling it exceeded was 4 MiB, is not an enforced limit.
///
/// `SEC-005` requires that a guest OOM be stopped *and* that the host survive. An
/// advisory ceiling satisfies the second and fails the first, which is why this
/// type exists.
///
/// # What it does
///
/// Implements [`wasmtime::ResourceLimiter`] and returns **`Err`** on a breach, so
/// the grow traps — Wasmtime's documented behaviour for that return — carrying a
/// message the trap taxonomy classifies as `MemoryLimitExceeded`. Everything
/// within the limit is admitted by delegating to the inner limits, so the
/// per-instance and per-table ceilings still apply.
///
/// # Why it is a separate type rather than a flag on `StoreData`
///
/// `Store::limiter` borrows from the store's data, and a limiter that must know
/// both the ceiling *and* the configured limit belongs beside the data it reads.
/// Keeping it a distinct type also means the two enforcement strategies can be
/// compared in a test rather than described in a comment — see
/// `tests/hostile_guests.rs`, which asserts the trapping behaviour.
#[derive(Debug)]
pub struct TrappingLimiter {
    inner: StoreLimits,
    /// The QQQ ceiling, in bytes, for the trap message.
    memory_ceiling: usize,
}

impl TrappingLimiter {
    /// Build a limiter that traps at `memory_ceiling` bytes per memory.
    #[must_use]
    pub const fn new(inner: StoreLimits, memory_ceiling: usize) -> Self {
        Self {
            inner,
            memory_ceiling,
        }
    }
}

impl wasmtime::ResourceLimiter for TrappingLimiter {
    /// Admit a growth within the ceiling; **trap** on one beyond it.
    ///
    /// Returns `Err` rather than `Ok(false)` deliberately: `Ok(false)` is the
    /// silent-failure path that makes this limit advisory, and `Err` is the one
    /// Wasmtime documents as behaving "as if a trap has been raised".
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.memory_ceiling {
            return Err(wasmtime::Error::msg(format!(
                "memory limit exceeded: growing to {desired} bytes would pass the \
                 {}-byte limit (currently {current} bytes)",
                self.memory_ceiling
            )));
        }
        self.inner.memory_growing(current, desired, maximum)
    }

    fn memory_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.inner.memory_grow_failed(error)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.inner.table_growing(current, desired, maximum)
    }

    fn table_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.inner.table_grow_failed(error)
    }

    fn instances(&self) -> usize {
        self.inner.instances()
    }

    fn tables(&self) -> usize {
        self.inner.tables()
    }

    fn memories(&self) -> usize {
        self.inner.memories()
    }
}

/// Which host interfaces the built linker actually provides.
///
/// Returned alongside the linker so callers (and tests) can assert the mapping
/// from capabilities to interfaces without introspecting Wasmtime internals.
///
/// # Why `String` and not `&'static str`
///
/// The values originate as `'static` constants (see [`interface_for`]), and
/// keeping them `'static` would be marginally cheaper. But this type must be
/// **serializable** — it is part of `qqqai inspect --json` and of the audit
/// record — and `Deserialize` cannot produce a `&'static str`. Owning the
/// strings costs one small allocation per interface at bind time, on a path
/// that happens once per component rather than once per request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundInterfaces {
    /// The `qqq:` interfaces that were bound.
    pub interfaces: Vec<String>,
    /// The capabilities that were granted but have no host implementation yet.
    ///
    /// **Surfaced rather than silently ignored.** A capability that is granted
    /// with no implementation behind it will fail at runtime with a confusing
    /// error; naming it at bind time turns that into a clear diagnostic. It is
    /// also how a partially-implemented milestone stays honest.
    pub unimplemented: Vec<Capability>,
}

impl BoundInterfaces {
    /// Whether a specific interface was bound.
    #[must_use]
    pub fn has(&self, interface: &str) -> bool {
        self.interfaces.iter().any(|i| i == interface)
    }
}

impl fmt::Display for BoundInterfaces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.interfaces.is_empty() {
            return f.write_str("(none)");
        }
        f.write_str(&self.interfaces.join(", "))
    }
}

/// The canonical mapping from a capability to the WIT interface it unlocks.
///
/// # One mapping, two consumers
///
/// This delegates to `qqq_abi`, which owns the **single** source of truth shared
/// with the static capability report (`qqqai inspect`). Keeping a second table
/// here — even one that started identical — is how a report ends up saying a
/// component cannot reach the network while the runtime quietly lets it.
///
/// # The fallback is deliberate
///
/// `Capability` is `#[non_exhaustive]`, so a variant added in a later version
/// reaches this function. Unlocking no interface is the **safe** direction, and
/// `describe_gap` makes the gap loud rather than silent.
#[must_use]
pub fn interface_for(c: Capability) -> Option<&'static str> {
    qqq_abi::interfaces()
        .into_iter()
        .find(|i| i.is_unlocked_by(c))
        .map(|i| interface_name_static(&i.name))
}

/// Map a registry interface name to its `&'static str` form.
///
/// # Why this projection exists
///
/// The registry owns `String`s because it must be serializable — it is part of
/// `qqqai inspect --json`. Callers on the hot path want a `'static` handle
/// without allocating, so this maps to string literals.
///
/// # Why the fallback is `"<unmapped>"`
///
/// Adding an interface to `qqq_abi` without adding it here would otherwise
/// silently produce an empty name. Returning a visibly wrong value means the
/// test `static_names_cover_the_registry` fails the build instead, and a
/// surprise at runtime is impossible.
#[must_use]
fn interface_name_static(name: &str) -> &'static str {
    match name {
        "qqq:ai@1.0.0" => "qqq:ai@1.0.0",
        "qqq:clock@1.0.0" => "qqq:clock@1.0.0",
        "qqq:crypto@1.0.0" => "qqq:crypto@1.0.0",
        "qqq:dns@1.0.0" => "qqq:dns@1.0.0",
        "qqq:env@1.0.0" => "qqq:env@1.0.0",
        "qqq:fs@1.0.0" => "qqq:fs@1.0.0",
        "qqq:http@1.0.0" => "qqq:http@1.0.0",
        "qqq:kv@1.0.0" => "qqq:kv@1.0.0",
        "qqq:log@1.0.0" => "qqq:log@1.0.0",
        "qqq:queue@1.0.0" => "qqq:queue@1.0.0",
        "qqq:secrets@1.0.0" => "qqq:secrets@1.0.0",
        "qqq:sql@1.0.0" => "qqq:sql@1.0.0",
        "qqq:trace@1.0.0" => "qqq:trace@1.0.0",
        _ => "<unmapped>",
    }
}

/// The interfaces a grant set unlocks, in stable sorted order.
///
/// This is the **static** half of the capability report: it needs only a grant
/// set, not a running instance, which is what makes `qqqai inspect` possible
/// before execution.
#[must_use]
pub fn required_interfaces(grants: &GrantSet) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = grants
        .capabilities()
        .into_iter()
        .filter_map(interface_for)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The result of building a linker for one instance.
///
/// Carries the linker together with the interfaces it actually bound, so a
/// caller never has to introspect Wasmtime internals to learn what a guest can
/// reach — and so tests can assert the capability-to-interface mapping without
/// reaching into the engine.
pub struct BuiltLinker<'a> {
    /// The linker to instantiate through.
    pub linker: Linker<StoreData>,
    /// What was bound — see [`BoundInterfaces`].
    pub bound: BoundInterfaces,
    /// Ties the linker to the engine's lifetime.
    _engine: std::marker::PhantomData<&'a wasmtime::Engine>,
}

impl fmt::Debug for BuiltLinker<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BuiltLinker")
            .field("bound", &self.bound)
            .finish_non_exhaustive()
    }
}

/// Build a linker containing **exactly** the interfaces the grants unlock.
///
/// # The security property
///
/// The returned linker provides an interface if and only if at least one
/// capability mapping to it is granted. There is no code path that adds an
/// interface the grant set does not justify.
///
/// # Errors
///
/// Returns an error only if Wasmtime rejects a definition, which would indicate
/// a QQQ bug rather than user error.
pub fn build_linker<'a>(
    engine: &'a wasmtime::Engine,
    grants: &GrantSet,
) -> wasmtime::Result<BuiltLinker<'a>> {
    let mut linker: Linker<StoreData> = Linker::new(engine);

    // Interfaces with a Rust host implementation land here as they are built.
    //
    // Each interface is registered **only when its capability is granted**. The
    // linker is never populated speculatively and then filtered: building it
    // from the grants alone is what makes an ungranted import absent rather than
    // denied, and that property is the whole security argument.
    // WASI is registered **unconditionally**, before the capability loop, and the
    // reason is worth stating where the loop is:
    //
    // The loop below adds a `qqq:*` interface only when a grant unlocks it. WASI is
    // different because it is not an interface a guest *chooses* to import -- it is
    // how the guest's own `std` is implemented on `wasm32-wasip2`. A real guest
    // imports fifteen `wasi:*` interfaces even when its source calls none of them.
    // Requiring a grant for them would not be a stricter policy; it would mean no
    // app built by the normal toolchain can run at all.
    //
    // The authority that matters is withheld by the **context**, which is derived
    // from the same grant set everything else reads (`StoreData::wasi`,
    // `crate::host_wasi`): no preopens, no filesystem interface, no sockets, an
    // environment allowlist rather than an inherit, and no wall clock unless
    // `clock.wall` is granted. So this is not a hole in deny-by-default; it is where
    // the deny is enforced.
    crate::host_wasi::register(&mut linker)?;

    let required = required_interfaces(grants);
    let mut interfaces: Vec<String> = Vec::with_capacity(required.len());
    let mut unimplemented = Vec::new();

    for iface in required {
        interfaces.push(iface.to_owned());
        match iface {
            "qqq:clock@1.0.0" => {
                crate::host_clock::register(&mut linker, grants)?;
            }
            "qqq:crypto@1.0.0" => {
                crate::host_crypto::register(&mut linker, grants)?;
            }
            // `qqq:http` is the interface a guest both **imports** and **exports**
            // (see `host_http`'s module docs for why the import exists even when the
            // guest never calls `send`). Registering it here is what turns a granted
            // `http.server`/`http.client` into an instantiable guest; without the arm,
            // the module would exist and be unreachable, and `qqqai serve` would answer
            // `QQQ-6004` for every real app.
            //
            // `register` returns whether it bound anything, and the arm ignores it
            // deliberately: the interface name is already in `interfaces` above, which
            // is what `BoundInterfaces` reports. A `false` here would mean the grant set
            // and `required_interfaces` disagreed, and `every_capability_maps_to_an_
            // interface` is the test that covers that.
            "qqq:http@1.0.0" => {
                let _bound = crate::host_http::register(&mut linker, grants)?;
            }
            // QQQ-STUB(CON-009): `qqq:fs`, `qqq:http`, `qqq:sql` and the rest
            // have no registered interface yet. `qqq:clock` and `qqq:crypto`
            // are the two wired up so far. Recording the gap keeps a
            // partially-implemented milestone honest: a component that imports
            // the others gets a clear diagnostic naming the capability, not
            // Wasmtime's "unknown import".
            //
            // Two notes on the reference, because getting it wrong twice is
            // itself worth recording (Observations §O-020d):
            //
            // * An earlier version cited `HOST-016`, which is
            //   `epoch_deadline_async_yield_and_update` — a scheduling concern,
            //   not interface implementation.
            // * There is no checklist item that says "implement the host
            //   functions of interface X". `CON-009` is the closest governing
            //   item: it fixes the contract each host call must honour
            //   (`result<T, E>` on every fallible call), which is what
            //   `host_clock.rs` and `host_crypto.rs` are written against.
            //   Per-interface work is tracked by the WIT files themselves and
            //   by the `implemented` flag in the `qqq-abi` registry.
            //
            // `CON-009`'s defence in depth is `recheck` below — the capability
            // predicate is `GrantSet::grants`, and no method named `allows`
            // exists on `GrantSet`. An earlier revision of this note referred to
            // an `allows` check; this comment is now the only place that name
            // appears in the crate, which is why it is quoted and explained
            // rather than used.
            //
            // `recheck` itself is called from its own three tests and from no
            // invocation path yet: the host interfaces that would call it —
            // `qqq:fs`, `qqq:sql`, `qqq:http` and the rest — are the ones this
            // stub records as unbound. That is the honest state, and it is
            // recorded here rather than left for a reader to discover by
            // searching for callers.
            //
            // Note that `qqq:crypto` is only *partially* implemented — `random`
            // and `hashing` are real, `hmac`/`aead`/`signing` are absent on
            // purpose. A component importing the latter therefore still gets
            // this diagnostic, which is the correct outcome: `host_crypto`
            // registers what exists and the rest stays visibly missing.
            _ => {
                for &c in &grants.capabilities() {
                    if interface_for(c) == Some(iface) {
                        unimplemented.push(c);
                    }
                }
            }
        }
    }
    unimplemented.sort_unstable();
    unimplemented.dedup();

    Ok(BuiltLinker {
        linker,
        bound: BoundInterfaces {
            interfaces,
            unimplemented,
        },
        _engine: std::marker::PhantomData,
    })
}

/// Describe what a granted-but-unbound capability means for this instance.
///
/// Returns a `QQQ-6004` error naming the capability and the missing interface,
/// so a developer sees *"`qqq:crypto@1.0.0` is granted but this build has no
/// implementation"* rather than Wasmtime's generic "unknown import".
#[must_use]
pub fn describe_gap(capability: Capability) -> qqq_core::Error {
    let iface = interface_for(capability).unwrap_or("<unmapped>");
    qqq_core::Error::new(
        qqq_core::ErrorCode::InternalInvariantViolated,
        format!("capability `{capability}` is granted but `{iface}` has no host implementation"),
    )
    .with_context("capability", capability.name())
    .with_context("interface", iface)
    .with_remediation(
        "this is a QQQ build gap, not a configuration error — please report it; \
         meanwhile remove the capability from qqq.toml to run",
    )
}

/// The call-time re-check.
///
/// Consults the instance's grant set **again**, at the point of use, rather than
/// trusting that the linker was built correctly.
///
/// # Why a second check when the linker already enforces this
///
/// Because the two checks fail differently. A mis-built linker is a bug in
/// *our* code that would silently grant authority; this check is a bug in our
/// code that produces a *denial*. Given that the two failure modes are
/// "security hole" and "annoying error", the asymmetry justifies the cost — a
/// lookup in a small `BTreeSet`, on a path that is already dominated by the
/// ABI crossing itself.
///
/// # Errors
///
/// Returns `QQQ-4003` with the full resolution context when the capability is
/// not granted, so the error names *what* was denied and *how* to fix it.
#[must_use]
pub fn recheck(data: &StoreData, capability: Capability) -> Option<qqq_core::Error> {
    if data.grants.grants(capability) {
        return None;
    }
    Some(
        qqq_core::Error::new(
            qqq_core::ErrorCode::CapabilityDenied,
            format!("capability `{capability}` is not granted for this instance"),
        )
        .with_context("capability", capability.name())
        .with_context("grant-digest", data.grants.digest())
        .with_context("instance-grants", data.grants.to_string())
        .with_remediation(format!(
            "add a [[capabilities.*]] stanza granting `{capability}` to qqq.toml, \
             then run `qqqai why {capability}` to confirm"
        )),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_cap::manifest::Manifest;

    /// A minimal well-formed manifest: `[package]` requires both `name` and
    /// `version`, and a bare `name = "..."` is rejected with `MissingField`.
    /// Recording the shape here means the next test does not rediscover it.
    const MINIMAL_MANIFEST: &str = "[package]\nname = \"acme\"\nversion = \"1.0.0\"\n";

    fn grants_from(src: &str) -> GrantSet {
        let m = Manifest::parse(src).expect("test manifest");
        GrantSet::from_manifest(&m)
    }

    /// Every capability must map to an interface. A gap here means a granted
    /// capability silently unlocks nothing — the guest fails at instantiation
    /// with no explanation of why.
    #[test]
    fn every_capability_maps_to_an_interface() {
        for &c in Capability::all() {
            assert!(
                interface_for(c).is_some(),
                "capability {c} has no interface mapping"
            );
        }
    }

    /// **The delegation must stay honest.** This crate projects the registry's
    /// owned names into `&'static str` literals for the hot path. If an
    /// interface is added to `qqq_abi` without being added to
    /// `interface_name_static`, the projection yields `"<unmapped>"` — a name
    /// that matches no linker definition, so the capability would silently bind
    /// nothing.
    ///
    /// This test is what makes that omission impossible to ship.
    #[test]
    fn static_names_cover_the_registry() {
        for i in qqq_abi::interfaces() {
            assert_ne!(
                interface_name_static(&i.name),
                "<unmapped>",
                "interface `{}` is in the qqq-abi registry but has no static \
                 projection in qqq-host::linker; add it to `interface_name_static`",
                i.name
            );
            assert_eq!(interface_name_static(&i.name), i.name);
        }
    }

    /// The two crates must agree about which capability unlocks which interface.
    /// A disagreement is exactly the drift that makes `qqqai inspect` lie.
    #[test]
    fn host_and_abi_agree_on_every_mapping() {
        for &c in Capability::all() {
            let via_abi = qqq_abi::interface_for(c).map(|i| i.name);
            let via_host = interface_for(c).map(str::to_owned);
            assert_eq!(
                via_abi, via_host,
                "qqq-abi and qqq-host disagree about capability `{c}`"
            );
        }
    }

    /// Interface names must be well-formed and versioned, because they are part
    /// of the machine contract an agent reads.
    ///
    /// # Version shape: `major.minor.patch`
    ///
    /// **Corrected.** This test previously asserted `major.minor` and asserted
    /// that full semver would be wrong — on the reasoning that "the patch level
    /// of an interface carries no meaning". That reasoning was plausible and
    /// **incorrect**: WIT requires full semver, verified by parsing with the
    /// real toolchain:
    ///
    /// ```text
    /// package qqq:x@1.0;    -> error: expected '.', found ';'
    /// package qqq:x@1.0.0;  -> parses
    /// ```
    ///
    /// The mistake is recorded in Observations `§O-017`. The lesson is that a
    /// plausible-sounding principle about a format is not evidence about that
    /// format — the parser is.
    #[test]
    fn interface_names_are_wellformed_and_versioned() {
        for &c in Capability::all() {
            let i = interface_for(c).unwrap();
            assert!(
                i.starts_with("qqq:"),
                "interface `{i}` must be in the qqq: namespace"
            );
            let (name, version) = i
                .split_once('@')
                .unwrap_or_else(|| panic!("interface `{i}` must carry a version"));
            assert!(name.len() > 4, "interface `{name}` is malformed");

            let parts: Vec<&str> = version.split('.').collect();
            assert_eq!(
                parts.len(),
                3,
                "interface version `{version}` must be major.minor.patch — \
                 WIT requires full semver"
            );
            for p in &parts {
                assert!(
                    !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()),
                    "interface version `{version}` has a non-numeric component `{p}`"
                );
            }
            let major: u32 = parts[0].parse().unwrap();
            assert!(major >= 1, "a published interface must be at major >= 1");
        }
    }

    #[test]
    fn granted_capabilities_unlock_their_interfaces() {
        let g = grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.http]\nserver = true\n\
             [capabilities.crypto]\nrandom = true\nhash = [\"sha256\"]\n\
             [capabilities.clock]\nwall = true\n",
        );
        let ifaces = required_interfaces(&g);
        assert!(ifaces.contains(&"qqq:http@1.0.0"));
        assert!(ifaces.contains(&"qqq:crypto@1.0.0"));
        assert!(ifaces.contains(&"qqq:clock@1.0.0"));
        // Never granted, never unlocked.
        assert!(!ifaces.contains(&"qqq:fs@1.0.0"));
        assert!(!ifaces.contains(&"qqq:sql@1.0.0"));
        assert!(!ifaces.contains(&"qqq:secrets@1.0.0"));
    }
    /// The headline security property, stated as a test: an empty grant set
    /// unlocks **nothing**.
    #[test]
    fn empty_grants_unlock_no_interfaces() {
        let g = GrantSet::empty();
        assert!(
            required_interfaces(&g).is_empty(),
            "an empty grant set must unlock no interfaces"
        );
    }

    #[test]
    fn interfaces_are_sorted_and_deduplicated() {
        // Two capabilities mapping to the same interface must yield it once.
        let g = grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nrandom = true\nhash = [\"sha256\"]\n\
             hmac = [\"sha256\"]\naead = [\"aes\"]\nsign = [\"ed25519\"]\n",
        );
        let ifaces = required_interfaces(&g);
        let crypto_count = ifaces.iter().filter(|i| **i == "qqq:crypto@1.0.0").count();
        assert_eq!(crypto_count, 1, "must be deduplicated: {ifaces:?}");
        let mut sorted = ifaces.clone();
        sorted.sort_unstable();
        assert_eq!(ifaces, sorted, "must be sorted");
    }

    /// A capability unlocked by *any* member of a family unlocks the interface
    /// once. A component granted only `fs.read` still gets `qqq:fs`.
    #[test]
    fn one_capability_per_family_is_enough_to_unlock_the_interface() {
        let g = grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [[capabilities.fs]]\npath = \".\"\nmode = \"read-only\"\n",
        );
        assert!(required_interfaces(&g).contains(&"qqq:fs@1.0.0"));
    }

    #[test]
    fn linker_builds_against_a_real_engine() {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&cfg).unwrap();
        let g = grants_from("[package]\nname = \"a\"\nversion = \"0.1.0\"\n");
        let built = build_linker(&engine, &g).expect("linker must build");
        // An empty grant set yields no bound interfaces.
        assert!(
            built.bound.interfaces.is_empty(),
            "no grants must mean no interfaces: {:?}",
            built.bound
        );
        assert!(built.bound.unimplemented.is_empty());
    }

    // -- HOST-011: every host function is panic-guarded ----------------------

    /// **`HOST-011`, enforced structurally.** Every `func_wrap` registration in
    /// this crate must route its body through [`crate::guard`].
    ///
    /// # Why this is a source-level test
    ///
    /// The guard is a *wrapper*, so a host function added without it compiles
    /// perfectly and behaves correctly on every input that does not panic —
    /// which is every input in every test anyone would write. The defect only
    /// appears when a guest finds the panicking path, and then it appears as a
    /// dead process rather than a failing test, because the release profile sets
    /// `panic = "abort"`.
    ///
    /// There is therefore no runtime test that can enforce this, and the rule
    /// exists precisely to prevent a failure that no test can reach. A source
    /// check is the only mechanism available, and it is honest about being one.
    ///
    /// # Why it counts rather than listing names
    ///
    /// Counting `func_wrap(` against `guard::guard(` means a *newly added* host
    /// function is caught, not just a known set. A list of names would go stale
    /// the moment somebody registered the next interface — which is exactly when
    /// this matters most, because new host code is where new panics live.
    ///
    /// # The one exclusion, and why it is safe
    ///
    /// The check reads only the **production** half of each file — everything
    /// before its `#[cfg(test)]` module. Registration in a test's own linker is
    /// not a host function the guest can reach; it exists to probe how Wasmtime
    /// reports a registration, and wrapping it would test the guard rather than
    /// the thing under test.
    ///
    /// Truncating at the test module rather than subtracting a hardcoded number
    /// is what keeps the check honest: a new unguarded registration in
    /// *production* code still fails it, and the first version of this test —
    /// which counted the whole file — reported a mismatch that was really the
    /// probe.
    #[test]
    fn every_host_function_is_panic_guarded() {
        // Each file that registers host functions. `include_str!` reads the
        // repository's own source, so the check runs against what is committed.
        let sources: [(&str, &str); 2] = [
            ("host_clock.rs", include_str!("host_clock.rs")),
            ("host_crypto.rs", include_str!("host_crypto.rs")),
        ];

        for (file, source) in sources {
            // Production code only: everything before the test module. The
            // marker is the same `#[cfg(test)]` every module in this crate uses.
            let production = source
                .split("#[cfg(test)]")
                .next()
                .expect("split always yields at least one element");

            // Whitespace is stripped for the same reason as in
            // `host_crypto::tests::registers`: a match that depends on how
            // `rustfmt` breaks a line is testing formatting, not behaviour.
            let squeezed: String = production.chars().filter(|c| !c.is_whitespace()).collect();

            let registrations = squeezed.matches("func_wrap(").count();
            let guards = squeezed.matches("guard::guard(").count();

            assert!(
                registrations > 0,
                "{file} registers no host functions in production code; if that is \
                 true this check should stop including it, and if it is not, the \
                 check is broken"
            );
            assert_eq!(
                registrations, guards,
                "{file} registers {registrations} host functions but only {guards} \
                 are wrapped in `guard`; an unguarded function unwinds through the \
                 engine on panic, and the release profile sets `panic = \"abort\"`, \
                 so one guest finding it kills the host process (HOST-011)"
            );
        }
    }

    /// A granted capability binds its interface, and one whose interface the
    /// host does not implement is reported as *unimplemented* — a loud,
    /// inspectable gap rather than a silent one.
    ///
    /// # Why this no longer uses `crypto.hash`
    ///
    /// It did, until `host_crypto.rs` landed and `qqq:crypto` became a real
    /// implementation for `random` and `hashing`. The test then failed, which is
    /// exactly right: it was asserting a gap that had been closed. Repointed at
    /// `fs.read`, which has no registered interface, so the property stays under
    /// test instead of being deleted along with its example.
    ///
    /// The general lesson, recorded because it keeps recurring: **a test that
    /// names a specific unfinished feature is a test with an expiry date.** When
    /// one fails after a feature lands, the fix is to repoint it at something
    /// still unfinished, not to remove the assertion.
    #[test]
    fn a_granted_capability_binds_its_interface_and_reports_the_gap() {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&cfg).unwrap();
        let g = grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [[capabilities.fs]]\npath = \"/tmp\"\nmode = \"read-only\"\n",
        );
        let built = build_linker(&engine, &g).unwrap();
        assert!(built.bound.has("qqq:fs@1.0.0"));
        assert!(
            built.bound.unimplemented.contains(&Capability::FsRead),
            "the unimplemented capability must be reported: {:?}",
            built.bound
        );
        // And crucially: nothing outside the grants is bound.
        assert!(!built.bound.has("qqq:sql@1.0.0"));
        assert!(!built.bound.has("qqq:http@1.0.0"));
    }

    /// The converse, now that `qqq:clock` and `qqq:crypto` are implemented: a
    /// capability whose interface *is* registered must **not** be reported as
    /// unimplemented. Without this, a change that marked everything
    /// unimplemented would leave the test above passing.
    #[test]
    fn an_implemented_capability_is_not_reported_as_a_gap() {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&cfg).unwrap();

        for (stanza, cap) in [
            (
                "[capabilities.crypto]\nhash = [\"sha256\"]\n",
                Capability::CryptoHash,
            ),
            (
                "[capabilities.crypto]\nrandom = true\n",
                Capability::CryptoRandom,
            ),
            ("[capabilities.clock]\nwall = true\n", Capability::ClockWall),
            (
                "[capabilities.clock]\nmonotonic = true\n",
                Capability::ClockMonotonic,
            ),
        ] {
            let src = format!("[package]\nname = \"a\"\nversion = \"0.1.0\"\n{stanza}");
            let built = build_linker(&engine, &grants_from(&src)).unwrap();
            assert!(
                !built.bound.unimplemented.contains(&cap),
                "{cap} has a host implementation and must not be reported as a gap: {:?}",
                built.bound
            );
        }
    }

    /// **The core security test.** A component importing a capability we did
    /// not grant must fail to instantiate, and the error must name the import.
    ///
    /// This is the claim verified against the real toolchain in Observations
    /// §O-006, now a permanent regression test.
    #[test]
    fn an_ungranted_import_fails_instantiation_and_names_itself() {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        cfg.consume_fuel(true);
        let engine = wasmtime::Engine::new(&cfg).unwrap();

        // A component that imports `host:probe/greeter`.
        let wat = r#"
            (component
              (import "host:probe/greeter" (instance $g
                (export "greet" (func (param "name" string) (result string)))
              ))
              (alias export $g "greet" (func $greet_comp))
              (core module $mem
                (memory (export "mem") 1)
                (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                  (i32.const 0))
              )
              (core instance $mi (instantiate $mem))
              (core func $greet_core (canon lower (func $greet_comp)
                (memory (core memory $mi "mem"))
                (realloc (core func $mi "realloc"))))
              (core instance $host (export "greet" (func $greet_core)))
              (core module $m
                (import "" "greet" (func $greet (param i32 i32 i32)))
                (func (export "run"))
              )
              (core instance $i (instantiate $m (with "" (instance $host))))
              (func (export "run") (canon lift (core func $i "run")))
            )
        "#;
        let component = wasmtime::component::Component::new(&engine, wat)
            .expect("the probe component must compile");

        let g = GrantSet::empty();
        let built = build_linker(&engine, &g).unwrap();
        let mut store = wasmtime::Store::new(&engine, StoreData::default());

        let result = built.linker.instantiate(&mut store, &component);
        let Err(err) = result else {
            panic!("instantiation MUST fail with an empty linker");
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("greet") || msg.contains("host:probe"),
            "the error must name the missing import: {msg}"
        );
    }

    /// The **control case** for the test above. Without it, the previous test
    /// could be passing because the harness is broken rather than because the
    /// capability model works. This is the pattern recorded in §O-006.
    #[test]
    fn a_satisfied_import_instantiates_and_runs() {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        cfg.consume_fuel(true);
        let engine = wasmtime::Engine::new(&cfg).unwrap();

        let wat = r#"
            (component
              (core module $m (func (export "f") (result i32) (i32.const 42)))
              (core instance $i (instantiate $m))
              (func (export "f") (result u32) (canon lift (core func $i "f")))
            )
        "#;
        let component = wasmtime::component::Component::new(&engine, wat).unwrap();
        let built = build_linker(&engine, &GrantSet::empty()).unwrap();
        let mut store = wasmtime::Store::new(&engine, StoreData::default());
        store.set_fuel(1_000_000).unwrap();

        let instance = built
            .linker
            .instantiate(&mut store, &component)
            .expect("a component with no imports must instantiate");
        let f = instance
            .get_typed_func::<(), (u32,)>(&mut store, "f")
            .unwrap();
        let (v,) = f.call(&mut store, ()).unwrap();
        assert_eq!(v, 42, "the control case must actually work");
    }

    // -- The call-time re-check -------------------------------------------

    #[test]
    fn recheck_passes_for_a_granted_capability() {
        let data = StoreData::new(grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhash = [\"sha256\"]\n",
        ));
        assert!(recheck(&data, Capability::CryptoHash).is_none());
    }

    #[test]
    fn recheck_denies_an_ungranted_capability_with_full_context() {
        let data = StoreData::new(grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
        ));
        let err =
            recheck(&data, Capability::SqlQuery).expect("an ungranted capability must be denied");
        assert_eq!(err.code, qqq_core::ErrorCode::CapabilityDenied);
        assert_eq!(err.id(), "QQQ-4003");
        assert!(err.remediation.is_some());
        assert!(
            err.context.iter().any(|(k, _)| k == "grant-digest"),
            "the audit digest must be in the denial context"
        );
        assert!(!err.is_retryable());
    }

    /// The re-check consults the *store's* grants, not a re-derivation. If it
    /// re-derived from the linker it would agree with a mis-built linker and
    /// the second check would be vacuous.
    #[test]
    fn recheck_is_independent_of_the_linker() {
        // A store whose grants are empty, even though some other linker might
        // have been built with more.
        let data = StoreData::new(GrantSet::empty());
        for &c in Capability::all() {
            assert!(
                recheck(&data, c).is_some(),
                "{c} must be denied for an empty grant set"
            );
        }
    }

    #[test]
    fn gap_diagnostic_names_the_capability_and_interface() {
        let e = describe_gap(Capability::CryptoHash);
        let msg = e.message.clone();
        assert!(
            msg.contains("crypto.hash"),
            "must name the capability: {msg}"
        );
        assert!(
            msg.contains("qqq:crypto@1.0.0"),
            "must name the interface: {msg}"
        );
        assert!(e.remediation.is_some());
        assert!(e.render().contains("QQQ-6004"));
    }

    #[test]
    fn bound_interfaces_has_lookup_works() {
        let b = BoundInterfaces {
            interfaces: vec!["qqq:http@1.0.0".to_owned(), "qqq:clock@1.0.0".to_owned()],
            unimplemented: vec![],
        };
        assert!(b.has("qqq:http@1.0.0"));
        assert!(!b.has("qqq:sql@1.0.0"));
        assert!(b.to_string().contains("qqq:http@1.0.0"));

        let empty = BoundInterfaces {
            interfaces: Vec::new(),
            unimplemented: Vec::new(),
        };
        assert_eq!(empty.to_string(), "(none)");
        assert!(!empty.has("qqq:http@1.0.0"));
    }

    // -- Tenant scoping — `CAP-014` ---------------------------------------

    /// A store built without a tenant has no scope, and that `None` is a
    /// refusal rather than a wildcard.
    ///
    /// The distinction matters because `None` is the value the single-tenant
    /// `qqqai run` path and every existing unit test produce. If `None` meant
    /// "any tenant", every one of those stores would silently be a
    /// cross-tenant hole the day it was handed to a server request.
    #[test]
    fn an_unscoped_store_reports_no_tenant_rather_than_any_tenant() {
        let data = StoreData::default();
        assert!(data.tenant_scope().is_none());
        assert!(StoreData::new(GrantSet::empty()).tenant_scope().is_none());
    }

    /// The scope travels with the store, and the digest stored in the store is
    /// the digest the caller can key a pool on.
    ///
    /// This is the "same value to both" property documented on
    /// [`StoreData::with_tenant`]: the host must not have to re-derive the
    /// grant digest to look the instance up, because a re-derivation is where
    /// a pre-/post-normalization mismatch would enter.
    #[test]
    fn a_scoped_store_carries_the_tenant_and_the_grant_digest_it_was_keyed_on() {
        use crate::tenant::{GrantDigest, TenantScope};
        use qqq_cap::egress::TenantId;

        let grants =
            GrantSet::from_manifest(&Manifest::parse(MINIMAL_MANIFEST).expect("test manifest"));
        let digest = GrantDigest::new(&grants.digest()).expect("GrantSet::digest is canonical hex");
        let tenant = TenantId::new("acme").expect("test tenant");

        let data =
            StoreData::new(grants).with_tenant(TenantScope::new(tenant.clone(), digest.clone()));

        let scope = data.tenant_scope().expect("the store is scoped");
        assert_eq!(scope.tenant(), &tenant);
        assert_eq!(scope.grants(), &digest);
        assert!(scope.probe(&tenant, &digest).is_ok());
    }

    /// **The end-to-end isolation test.**
    ///
    /// Two stores, two tenants, one shared component digest. Neither store's
    /// scope accepts the other's identity, and their pool keys differ. This is
    /// §7.1's "no cross-tenant handles" exercised through the real types rather
    /// than through the ledger alone.
    #[test]
    fn two_tenants_over_one_artifact_cannot_adopt_each_others_scope() {
        use crate::tenant::{ComponentDigest, GrantDigest, InstanceKey, TenantScope};
        use qqq_cap::egress::TenantId;

        let manifest = Manifest::parse(MINIMAL_MANIFEST).expect("test manifest");
        let grants = GrantSet::from_manifest(&manifest);
        let gd = GrantDigest::new(&grants.digest()).expect("canonical digest");
        let cd = ComponentDigest::new("0011223344556677").expect("canonical digest");

        let acme = TenantId::new("acme").expect("tenant");
        let globex = TenantId::new("globex").expect("tenant");

        let acme_store = StoreData::new(GrantSet::from_manifest(&manifest))
            .with_tenant(TenantScope::new(acme.clone(), gd.clone()));
        let globex_store = StoreData::new(GrantSet::from_manifest(&manifest))
            .with_tenant(TenantScope::new(globex.clone(), gd.clone()));

        let acme_scope = acme_store.tenant_scope().expect("scoped");
        let globex_scope = globex_store.tenant_scope().expect("scoped");

        // Each refuses the other, and the refusal names both sides.
        let err = acme_scope
            .probe(&globex, &gd)
            .expect_err("acme must refuse globex's identity");
        assert!(err.to_string().contains("globex"), "{err}");
        assert!(globex_scope.probe(&acme, &gd).is_err());

        // The pool keys diverge even though component and grants are shared.
        let acme_key = InstanceKey::new(acme, cd.clone(), gd.clone());
        let globex_key = InstanceKey::new(globex, cd, gd);
        assert_ne!(acme_key, globex_key);
    }

    /// A narrowed grant set invalidates the old store's scope, so a pooled
    /// instance built under wider grants cannot be reused after the operator
    /// revokes them.
    ///
    /// # Why the wide manifest must actually grant something
    ///
    /// The first version of this test used a capability-free manifest for the
    /// "wide" side and compared its digest to `GrantSet::empty()`. Both are the
    /// empty capability set, and `GrantSet::digest` is SHA-256 over the
    /// **capability names only** — so both digests are the SHA-256 of the empty
    /// input, `e3b0c442…`, and the test failed on its own premise rather than on
    /// the code. The lesson generalizes: a fixture whose digest is a function
    /// of an empty list distinguishes nothing, and a test built on one proves
    /// nothing while looking like it does (`§O-105`).
    #[test]
    fn narrowing_the_grants_invalidates_a_warm_instances_scope() {
        use crate::tenant::{GrantDigest, TenantScope};
        use qqq_cap::egress::TenantId;

        // The wide set really does grant something.
        let wide = grants_from(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nrandom = true\nhash = [\"sha256\"]\n",
        );
        let narrow = GrantSet::empty();

        let wide_digest = GrantDigest::new(&wide.digest()).expect("canonical");
        let narrow_digest = GrantDigest::new(&narrow.digest()).expect("canonical");
        assert_ne!(wide_digest, narrow_digest, "the digests must differ");
        assert!(!wide.capabilities().is_empty(), "the wide set is not empty");

        let tenant = TenantId::new("acme").expect("tenant");
        let scope = TenantScope::new(tenant.clone(), wide_digest);

        let refusal = scope
            .probe(&tenant, &narrow_digest)
            .expect_err("the narrowed digest must not match the warm instance");
        assert!(
            refusal.to_string().contains("revoked"),
            "the refusal must explain that authority was revoked: {refusal}"
        );
    }

    /// The empty grant set has a stable, non-empty digest — and it is the
    /// SHA-256 of the empty input, because the digest covers capability names
    /// and nothing else.
    ///
    /// Pinned because it is a value that two *different* descriptions collide
    /// on: a manifest declaring no capabilities and a manifest declaring
    /// `[capabilities]` with everything off resolve to the same authority and
    /// therefore the same digest. That is correct — the digest is specified to
    /// depend on effective authority, and two routes to "nothing" are one
    /// authority. What would be a bug is an *empty string*, since that is
    /// indistinguishable from an unset field.
    #[test]
    fn the_empty_grant_set_digests_to_the_sha256_of_nothing_not_to_an_empty_string() {
        use crate::tenant::GrantDigest;

        let empty = GrantSet::empty();
        let digest = empty.digest();
        assert_eq!(
            digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "the empty grant set must digest to SHA-256 of the empty input"
        );
        assert!(
            GrantDigest::new(&digest).is_ok(),
            "the digest must be canonical lowercase hex"
        );

        // Two spellings of "no capability" are one authority, so one digest.
        assert_eq!(
            grants_from(MINIMAL_MANIFEST).digest(),
            digest,
            "a capability-free manifest is the empty grant set"
        );
    }
}
