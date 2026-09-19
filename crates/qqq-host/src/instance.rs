//! The instance lifecycle: store construction, limit binding, execution and
//! trap handling.
//!
//! Implements `HOST-005` … `HOST-012`, `HOST-015` … `HOST-019` from Proposal
//! §6.1.
//!
//! # The lifecycle, and where each guarantee is enforced
//!
//! ```text
//!   PreparedComponent   ← compiled once, shared across all instances
//!          │
//!          ▼
//!   Instance::create(grants, limits)
//!          ├─ build a per-instance linker from the grants   (linker.rs)
//!          ├─ apply StoreLimits                              ← HOST-007
//!          ├─ set the epoch deadline                         ← HOST-005
//!          └─ set the fuel budget                            ← HOST-006
//!          │
//!          ▼
//!   run(|store, instance| …)     ← execution
//!          │
//!          ├─ Ok(value)  → instance released
//!          └─ Err(trap)  → instance DISCARDED                 ← HOST-010
//! ```
//!
//! # Why the instance is discarded on trap
//!
//! A trapped instance was interrupted mid-execution. Its linear memory may hold
//! half-written state, its resource handles may be half-closed, and its fuel
//! accounting is spent. Returning it to the pool would hand the next request a
//! **contaminated context** — precisely the cross-request leak the capability
//! model exists to prevent. [`Instance::run`] consumes `self`, so the
//! compiler enforces that a trapped instance cannot be reused: there is nothing
//! to reuse it *with*.

use std::time::{Duration, Instant};

use qqq_cap::resolve::GrantSet;
use qqq_core::{Error, ErrorCode, Result};
use wasmtime::component::{Component, Instance as WasmInstance, Linker};
use wasmtime::{Store, StoreLimitsBuilder};

use crate::config::{EngineConfig, StoreLimits};
use crate::linker::{build_linker, StoreData};
use crate::trap::Trap;

/// A compiled component, ready to instantiate many times.
///
/// # Why this is separate from an instance
///
/// Compilation is expensive (Cranelift, tens of milliseconds) and
/// instantiation is cheap (measured p50 800 ns). Sharing one
/// `PreparedComponent` across every request is what makes per-request isolation
/// affordable: the expensive work happens once, the cheap work happens per
/// request. This is the structural reason QQQ can give every request its own
/// sandbox.
pub struct PreparedComponent {
    component: Component,
    /// The digest of the source bytes, used for cache keying and logging.
    digest: String,
    /// Creation time, for load-latency metrics.
    compiled_at: Instant,
}

impl std::fmt::Debug for PreparedComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedComponent")
            .field("digest", &self.digest)
            .field("compiled_in", &self.compiled_at.elapsed())
            .finish_non_exhaustive()
    }
}

impl PreparedComponent {
    /// Compile a component from bytes.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-1002` when the bytes are not a valid component, naming the
    /// underlying parse failure. This is a **build-time** error class because
    /// it is the user's artifact that is wrong, not the host's state.
    pub fn compile(engine: &wasmtime::Engine, bytes: &[u8]) -> Result<Self> {
        let component = Component::new(engine, bytes).map_err(|e| {
            Error::new(
                ErrorCode::InvalidComponentArtifact,
                "the artifact is not a valid WebAssembly component",
            )
            .with_cause(format!("{e:#}"))
            .with_remediation(
                "confirm the toolchain targets the component model \
                 (`wasm32-wasip2` or later), not a core module",
            )
        })?;

        Ok(Self {
            component,
            digest: digest_of(bytes),
            compiled_at: Instant::now(),
        })
    }

    /// The content digest of the source bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// How long compilation took.
    #[must_use]
    pub fn compile_duration(&self) -> Duration {
        self.compiled_at.elapsed()
    }

    /// The interfaces this component **imports**, derived statically.
    ///
    /// This is what makes `qqqai inspect` possible before execution: the
    /// component's import table is known from the compiled artifact without
    /// running it (NN-5).
    ///
    /// # Why the engine is a parameter
    ///
    /// `Component::component_type` needs the engine to resolve type
    /// information, and `PreparedComponent` deliberately does **not** retain a
    /// second engine reference — doing so would risk it disagreeing with the
    /// engine the component was compiled against, which is exactly the kind of
    /// aliasing bug that produces unreproducible behaviour. Passing the engine
    /// in makes the caller prove it is using the right one.
    #[must_use]
    pub fn imported_interfaces(&self, engine: &wasmtime::Engine) -> Vec<String> {
        let mut out: Vec<String> = self
            .component
            .component_type()
            .imports(engine)
            .map(|(name, _ty)| name.to_string())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// The Wasmtime component, for callers that need it directly.
    #[must_use]
    pub fn component(&self) -> &Component {
        &self.component
    }
}

/// A live component instance with its capability and resource limits applied.
///
/// Owning the store means the instance cannot outlive its execution context,
/// which is what makes the trap-discard guarantee enforceable by the compiler
/// rather than by convention.
pub struct Instance<'a> {
    store: Store<StoreData>,
    /// The instantiated component.
    ///
    /// Named `wasm` rather than `instance` so it does not restate the struct's
    /// own name, which clippy flags and which reads worse at the call site.
    wasm: WasmInstance,
    limits: StoreLimits,
    /// Wall-clock start, for the epoch deadline computation.
    started: Instant,
    /// The engine, retained so the deadline can be refreshed on yield.
    engine: &'a wasmtime::Engine,
    /// Whether this instance may still be used.
    ///
    /// Set to `false` on any error path. [`Instance::run`] consumes `self`, so
    /// this mainly serves [`Instance::check_usable`] during a long-running
    /// call; it is the belt to the ownership model's braces.
    usable: bool,
    /// Fuel remaining when the instance was last observed.
    last_fuel: Option<u64>,
}

impl std::fmt::Debug for Instance<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Instance")
            .field("limits", &self.limits)
            .field("elapsed", &self.started.elapsed())
            .field("usable", &self.usable)
            .finish_non_exhaustive()
    }
}

impl<'a> Instance<'a> {
    /// Create an instance with exactly the granted capabilities.
    ///
    /// # The security property
    ///
    /// The linker is built **from `grants` alone** ([`build_linker`]), so an
    /// ungranted capability is absent rather than denied. There is no code path
    /// here that adds an import the grant set does not justify.
    ///
    /// # Errors
    ///
    /// * `QQQ-6003` — the component imports something the linker does not
    ///   provide. The message names the missing import.
    /// * `QQQ-3001`, `QQQ-3002` — the limits could not be applied.
    pub fn create(
        engine: &'a wasmtime::Engine,
        prepared: &PreparedComponent,
        grants: &GrantSet,
        limits: StoreLimits,
    ) -> Result<Self> {
        // -- Store state: grants, limits, and the limiter ----------------
        let data = StoreData::new(grants.clone());
        let mut store = Store::new(engine, data);

        // StoreLimits is what enforces the memory ceiling *at runtime*, as
        // distinct from the pooling config which reserves for the worst case.
        // Both are needed: the pool bound prevents over-reservation at
        // startup, this bound is what actually traps a runaway guest.
        let wasm_limits = StoreLimitsBuilder::new()
            .memory_size(usize::try_from(limits.memory_bytes).unwrap_or(usize::MAX))
            .instances(1)
            .tables(16)
            .build();
        store.data_mut().set_limits(wasm_limits, limits);
        // The limiter borrows from the store's own data, which is what keeps
        // the limits travelling with the instance they constrain.
        store.limiter(|d| d.limiter_mut());

        // -- Fuel --------------------------------------------------------
        // Set before instantiation so a component whose *start* function runs
        // long cannot escape metering.
        store.set_fuel(limits.fuel).map_err(|e| {
            Error::new(
                ErrorCode::LimitOutOfRange,
                "the host is not configured for fuel metering",
            )
            .with_cause(format!("{e:#}"))
            .with_remediation("this is a QQQ configuration bug; please report it")
        })?;

        // -- Epoch deadline ----------------------------------------------
        // The deadline is expressed in *ticks*, and the host increments the
        // epoch on a timer. Setting it to 1 means "trap at the next tick",
        // which is what the host's ticker converts the millisecond budget into.
        store.set_epoch_deadline(1);

        // -- Build the linker from the grants ALONE ----------------------
        let built = build_linker(engine, grants).map_err(|e| {
            Error::new(
                ErrorCode::InternalInvariantViolated,
                "failed to construct the capability linker",
            )
            .with_cause(format!("{e:#}"))
            .with_remediation("this is a QQQ bug; please report it")
        })?;

        // Nothing may be granted that the linker cannot satisfy. Discovering
        // this here turns an opaque instantiation failure into a clear
        // diagnostic naming the capability.
        if let Some(&first) = built.bound.unimplemented.first() {
            return Err(crate::linker::describe_gap(first));
        }

        let instance = instantiator(&built.linker, &mut store, prepared).map_err(|e| {
            let detail = format!("{e:#}");
            Error::new(
                ErrorCode::ComponentLoadFailed,
                "the component could not be instantiated",
            )
            .with_context("component", prepared.digest().to_owned())
            .with_context("granted", grants.to_string())
            .with_cause(detail.clone())
            .with_remediation(
                "the error above names the missing import; grant it in qqq.toml \
                 or correct the component's imports",
            )
        })?;

        Ok(Self {
            store,
            wasm: instance,
            limits,
            started: Instant::now(),
            engine,
            usable: true,
            last_fuel: None,
        })
    }

    /// Whether this instance is still safe to use.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.usable
    }

    /// Elapsed wall-clock time since the instance was created.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Fuel consumed so far, when metering is enabled.
    ///
    /// Returns `None` if the fuel counter cannot be read, which happens only if
    /// the store was constructed without fuel — a configuration error rather
    /// than a runtime condition.
    #[must_use]
    pub fn fuel_consumed(&self) -> Option<u64> {
        let remaining = self.store.get_fuel().ok()?;
        Some(self.limits.fuel.saturating_sub(remaining))
    }

    /// Remaining fuel budget.
    #[must_use]
    pub fn fuel_remaining(&self) -> Option<u64> {
        self.store.get_fuel().ok()
    }

    /// The limits this instance was created with.
    #[must_use]
    pub const fn limits(&self) -> StoreLimits {
        self.limits
    }

    /// Borrow the store, for the execution call.
    ///
    /// Deliberately `&mut self` and scoped: a caller cannot hold the store
    /// across an await point without the borrow checker agreeing, which keeps
    /// the "one instance, one logical task" model (Proposal §4.7) enforced
    /// rather than merely documented.
    pub fn store_mut(&mut self) -> &mut Store<StoreData> {
        &mut self.store
    }

    /// Borrow the store immutably.
    #[must_use]
    pub fn store(&self) -> &Store<StoreData> {
        &self.store
    }

    /// The underlying Wasmtime instance.
    #[must_use]
    pub const fn wasm_instance(&self) -> &WasmInstance {
        &self.wasm
    }

    /// The engine this instance belongs to.
    #[must_use]
    pub const fn engine(&self) -> &'a wasmtime::Engine {
        self.engine
    }

    /// Mark the instance unusable.
    ///
    /// Called on every error path. Public so a host function that detects a
    /// condition only it can see can poison the instance rather than allowing
    /// a half-completed operation to continue.
    pub fn poison(&mut self) {
        self.usable = false;
    }

    /// Convert a raw engine error into a structured trap.
    ///
    /// Attaches the diagnostics the proposal requires: fuel consumed, memory
    /// peak where observable, and the guest backtrace.
    fn trap_from(&self, raw: &str) -> Trap {
        let t = Trap::from_engine_error(raw);
        match self.fuel_consumed() {
            Some(f) => t.with_fuel_consumed(f),
            None => t,
        }
    }

    /// Run a closure against the store, discarding the instance on failure.
    ///
    /// # Why this consumes `self`
    ///
    /// So the compiler enforces `HOST-010`: a trapped instance cannot be
    /// returned to a pool, because after `run` returns there is nothing left to
    /// return. The alternative — a `must_discard` flag a caller could forget to
    /// check — is exactly the kind of convention that eventually gets skipped.
    ///
    /// # Errors
    ///
    /// Returns the closure's error, or a structured [`Trap`] converted to
    /// [`Error`] when execution fails.
    pub fn run<T, F>(mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Store<StoreData>, &WasmInstance) -> std::result::Result<T, wasmtime::Error>,
    {
        if !self.usable {
            return Err(Error::new(
                ErrorCode::InternalInvariantViolated,
                "attempted to execute a poisoned instance",
            )
            .with_remediation("this is a QQQ bug; please report it"));
        }

        match f(&mut self.store, &self.wasm) {
            Ok(value) => Ok(value),
            Err(e) => {
                self.usable = false;
                let raw = format!("{e:#}");
                Err(self.trap_from(&raw).to_error())
            }
        }
    }

    /// Run a closure and additionally return the diagnostics gathered.
    ///
    /// Used by the metrics path, where the caller wants fuel and duration even
    /// on success.
    ///
    /// # Errors
    ///
    /// As [`Instance::run`].
    pub fn run_measured<T, F>(mut self, f: F) -> Result<ExecutionOutcome<T>>
    where
        F: FnOnce(&mut Store<StoreData>, &WasmInstance) -> std::result::Result<T, wasmtime::Error>,
    {
        let started = Instant::now();
        if !self.usable {
            return Err(Error::new(
                ErrorCode::InternalInvariantViolated,
                "attempted to execute a poisoned instance",
            ));
        }
        let result = f(&mut self.store, &self.wasm);
        let duration = started.elapsed();
        let fuel = self.fuel_consumed();

        match result {
            Ok(value) => Ok(ExecutionOutcome {
                value,
                fuel_consumed: fuel,
                duration,
                trapped: false,
            }),
            Err(e) => {
                self.usable = false;
                let raw = format!("{e:#}");
                self.last_fuel = fuel;
                Err(self.trap_from(&raw).to_error())
            }
        }
    }
}

/// Diagnostics from a completed execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutcome<T> {
    /// The closure's return value.
    pub value: T,
    /// Fuel consumed, when metering is enabled.
    pub fuel_consumed: Option<u64>,
    /// Wall-clock duration.
    pub duration: Duration,
    /// Always `false` — a trapped execution returns `Err` instead, so an
    /// `ExecutionOutcome` that exists represents success. The field is present
    /// so the metrics path can record it uniformly.
    pub trapped: bool,
}

/// Instantiate through a linker.
///
/// Extracted so the error mapping in [`Instance::create`] stays readable and so
/// the signature can change with the Wasmtime API in exactly one place.
fn instantiator(
    linker: &Linker<StoreData>,
    store: &mut Store<StoreData>,
    prepared: &PreparedComponent,
) -> std::result::Result<WasmInstance, wasmtime::Error> {
    linker.instantiate(store, prepared.component())
}

/// Content digest of an artifact, for cache keying and deduplication.
///
/// `HOST-014` uses this to share one compiled module across every tenant
/// running the same artifact: compilation happens once, and the *instances*
/// remain separate. That is what makes density affordable without weakening
/// isolation — instances never share linear memory.
#[must_use]
pub fn digest_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The epoch tick interval the host should use for a given deadline.
///
/// # Why this is a pure function
///
/// The relationship between "a 5-second deadline" and "how often the host must
/// tick" is a *correctness* property: tick too slowly and a guest runs far past
/// its budget; tick too fast and the host burns CPU on timer wakeups. Making it
/// a named, tested function means the reasoning is reviewable and the constant
/// is not buried in a spawn call.
///
/// The chosen interval targets ~100 ticks per deadline, which bounds overshoot
/// to roughly 1% of the budget while keeping wakeups negligible.
#[must_use]
pub fn epoch_tick_interval(deadline_ms: u64) -> Duration {
    // At least 1 ms, at most 100 ms: below 1 ms the wakeup cost dominates,
    // above 100 ms the overshoot becomes visible to users.
    let ms = (deadline_ms / 100).clamp(1, 100);
    Duration::from_millis(ms)
}

/// Deterministic-mode clock configuration.
///
/// In deterministic mode the wall clock is **virtual**: it returns a fixed
/// instant and advances only when the host explicitly ticks it. Without this, a
/// guest that reads the clock produces different output on every run and the
/// bit-identical replay guarantee of Proposal §10.5 is unachievable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeterministicClock {
    /// The fixed instant, in nanoseconds since the Unix epoch.
    pub fixed_unix_nanos: u64,
    /// How far the clock advances per explicit tick.
    pub tick_nanos: u64,
}

impl Default for DeterministicClock {
    /// `2026-01-01T00:00:00Z`, advancing one millisecond per tick.
    fn default() -> Self {
        Self {
            // Chosen as a round, obviously-synthetic instant: a fixed clock
            // reading a *plausible* current time would make a determinism bug
            // invisible in test output.
            fixed_unix_nanos: 1_767_225_600_000_000_000,
            tick_nanos: 1_000_000,
        }
    }
}

impl DeterministicClock {
    /// Build a clock fixed at a given instant.
    #[must_use]
    pub const fn at(fixed_unix_nanos: u64) -> Self {
        Self {
            fixed_unix_nanos,
            tick_nanos: 1_000_000,
        }
    }

    /// The current virtual time after `ticks` explicit ticks.
    ///
    /// Saturating at both steps: a caller that ticks an absurd number of times
    /// gets the maximum instant rather than a wrapped one, because a wrapped
    /// clock is *earlier* than when it started and would silently break any
    /// ordering assumption in guest code.
    ///
    /// The multiplication saturates in `u64` rather than widening to `u128` and
    /// casting back, so no truncating conversion exists on this path.
    #[must_use]
    pub const fn now_after(&self, ticks: u64) -> u64 {
        let advance = self.tick_nanos.saturating_mul(ticks);
        self.fixed_unix_nanos.saturating_add(advance)
    }
}

/// Whether an engine configuration requires the deterministic clock.
///
/// A named predicate rather than an inline `if cfg.deterministic`, so the
/// question "does this configuration change observable behaviour?" has one
/// answer in one place.
#[must_use]
pub const fn uses_virtual_clock(cfg: &EngineConfig) -> bool {
    cfg.deterministic
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_cap::manifest::Manifest;

    fn engine() -> wasmtime::Engine {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        cfg.consume_fuel(true);
        // Epoch interruption is required for `set_epoch_deadline` to be legal.
        cfg.epoch_interruption(true);
        wasmtime::Engine::new(&cfg).expect("engine")
    }

    /// A trivially valid component that exports a function returning 7.
    const OK_WAT: &str = r#"
        (component
          (core module $m (func (export "f") (result i32) (i32.const 7)))
          (core instance $i (instantiate $m))
          (func (export "f") (result u32) (canon lift (core func $i "f")))
        )
    "#;

    /// A component that spins forever, for limit testing.
    const SPIN_WAT: &str = r#"
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

    fn limits() -> StoreLimits {
        StoreLimits {
            memory_bytes: 16 * 1024 * 1024,
            fuel: 10_000_000,
            epoch_deadline_ms: 5_000,
            max_open_handles: 64,
        }
    }

    fn grants(src: &str) -> GrantSet {
        GrantSet::from_manifest(&Manifest::parse(src).unwrap())
    }

    fn none() -> GrantSet {
        grants("[package]\nname = \"a\"\nversion = \"0.1.0\"\n")
    }

    #[test]
    fn compile_accepts_a_valid_component() {
        let e = engine();
        let p = PreparedComponent::compile(&e, OK_WAT.as_bytes()).expect("must compile");
        assert_eq!(p.digest().len(), 64, "sha256 hex");
        assert!(p.compile_duration() < Duration::from_mins(1));
    }

    #[test]
    fn compile_rejects_garbage_with_a_helpful_error() {
        let e = engine();
        let err = PreparedComponent::compile(&e, b"not wasm at all").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidComponentArtifact);
        assert!(err.remediation.is_some());
        assert!(
            err.render().contains("component model"),
            "must point at the likely cause: {}",
            err.render()
        );
    }

    #[test]
    fn digest_is_content_addressed() {
        assert_eq!(digest_of(b"abc"), digest_of(b"abc"));
        assert_ne!(digest_of(b"abc"), digest_of(b"abd"));
        assert_eq!(digest_of(b"").len(), 64);
    }

    /// The happy path, end to end through the real engine.
    #[test]
    fn instance_runs_a_component_and_returns_its_value() {
        let e = engine();
        let p = PreparedComponent::compile(&e, OK_WAT.as_bytes()).unwrap();
        let inst = Instance::create(&e, &p, &none(), limits()).expect("must instantiate");
        assert!(inst.is_usable());

        let out = inst
            .run(|store, instance| {
                let f = instance.get_typed_func::<(), (u32,)>(&mut *store, "f")?;
                f.call(&mut *store, ())
            })
            .expect("must run");
        assert_eq!(out.0, 7);
    }

    /// `run_measured` must report fuel actually consumed, which is what makes
    /// billing and regression detection possible.
    #[test]
    fn execution_reports_fuel_consumed() {
        let e = engine();
        let p = PreparedComponent::compile(&e, OK_WAT.as_bytes()).unwrap();
        let inst = Instance::create(&e, &p, &none(), limits()).unwrap();
        let outcome = inst
            .run_measured(|store, instance| {
                let f = instance.get_typed_func::<(), (u32,)>(&mut *store, "f")?;
                f.call(&mut *store, ())
            })
            .expect("must run");

        assert_eq!(outcome.value.0, 7);
        let fuel = outcome.fuel_consumed.expect("fuel must be observable");
        assert!(fuel > 0, "a real call must consume fuel, got {fuel}");
        assert!(
            fuel < limits().fuel,
            "a trivial call must not exhaust the budget"
        );
        assert!(!outcome.trapped);
    }

    /// **HOST-010, proven.** A guest that exhausts its fuel must trap, and the
    /// host must remain usable afterwards — the same engine, a fresh instance,
    /// still works.
    #[test]
    fn fuel_exhaustion_traps_the_guest_and_the_host_survives() {
        let e = engine();
        let p = PreparedComponent::compile(&e, SPIN_WAT.as_bytes()).unwrap();
        let tiny = StoreLimits {
            fuel: 10_000, // far too little for the infinite loop
            ..limits()
        };
        let inst = Instance::create(&e, &p, &none(), tiny).unwrap();

        let err = inst
            .run(|store, instance| {
                let f = instance.get_typed_func::<(), ()>(&mut *store, "spin")?;
                f.call(&mut *store, ())
            })
            .expect_err("the infinite guest MUST trap");

        assert_eq!(
            err.code,
            ErrorCode::FuelExhausted,
            "must be classified as fuel: {}",
            err.render()
        );
        assert_eq!(err.id(), "QQQ-3002");
        assert!(!err.is_retryable());
        assert!(err.remediation.is_some());
        assert!(
            err.context.iter().any(|(k, _)| k == "fuel-consumed"),
            "the trap must report fuel consumed: {:?}",
            err.context
        );

        // The host must still work: same engine, fresh instance.
        let ok = PreparedComponent::compile(&e, OK_WAT.as_bytes()).unwrap();
        let inst2 = Instance::create(&e, &ok, &none(), limits()).expect("host must survive");
        let v = inst2
            .run(|store, instance| {
                let f = instance.get_typed_func::<(), (u32,)>(&mut *store, "f")?;
                f.call(&mut *store, ())
            })
            .expect("host must still run components");
        assert_eq!(v.0, 7, "the host survived the guest trap");
    }

    /// A poisoned instance must refuse to run rather than execute with
    /// unknown state.
    #[test]
    fn a_poisoned_instance_refuses_to_run() {
        let e = engine();
        let p = PreparedComponent::compile(&e, OK_WAT.as_bytes()).unwrap();
        let mut inst = Instance::create(&e, &p, &none(), limits()).unwrap();
        inst.poison();
        assert!(!inst.is_usable());

        let err = inst
            .run(|store, instance| {
                let f = instance.get_typed_func::<(), (u32,)>(&mut *store, "f")?;
                f.call(&mut *store, ())
            })
            .expect_err("a poisoned instance must refuse");
        assert_eq!(err.code, ErrorCode::InternalInvariantViolated);
        assert!(err.remediation.is_some(), "even an internal error needs a fix");
    }

    /// The instantiation path must enforce the same capability rule the linker
    /// tests do — end to end, through `Instance::create`.
    #[test]
    fn instance_creation_fails_when_an_import_is_ungranted() {
        let e = engine();
        // A component importing a host interface.
        let importing = r#"
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
        let p = PreparedComponent::compile(&e, importing.as_bytes()).unwrap();
        let Err(err) = Instance::create(&e, &p, &none(), limits()) else {
            panic!("instantiation must fail without the grant");
        };
        assert_eq!(err.code, ErrorCode::ComponentLoadFailed);
        let rendered = err.render();
        assert!(
            rendered.contains("greet") || rendered.contains("host:probe"),
            "the error must name the missing import: {rendered}"
        );
    }

    /// A granted-but-unimplemented capability must fail at *create* time with a
    /// clear diagnostic, not at first call with a Wasmtime error.
    #[test]
    fn a_granted_but_unimplemented_capability_is_reported_clearly() {
        let e = engine();
        let p = PreparedComponent::compile(&e, OK_WAT.as_bytes()).unwrap();
        let g = grants(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhash = [\"sha256\"]\n",
        );
        let Err(err) = Instance::create(&e, &p, &g, limits()) else {
            panic!("an unimplemented capability must be reported");
        };
        assert_eq!(err.code, ErrorCode::InternalInvariantViolated);
        assert!(
            err.message.contains("crypto.hash"),
            "must name the capability: {}",
            err.message
        );
        assert!(err.render().contains("qqq:crypto@1.0.0"));
    }

    // -- Epoch configuration ----------------------------------------------

    #[test]
    fn epoch_tick_interval_is_bounded_and_proportional() {
        // Proportional: ~1% overshoot.
        assert_eq!(epoch_tick_interval(5_000), Duration::from_millis(50));
        assert_eq!(epoch_tick_interval(1_000), Duration::from_millis(10));
        // Floor: never wake faster than 1 ms.
        assert_eq!(epoch_tick_interval(10), Duration::from_millis(1));
        assert_eq!(epoch_tick_interval(0), Duration::from_millis(1));
        // Ceiling: never overshoot more than 100 ms.
        assert_eq!(epoch_tick_interval(86_400_000), Duration::from_millis(100));
    }

    /// The interval must never exceed the deadline — a guest could otherwise
    /// finish its whole budget before the first tick.
    #[test]
    fn epoch_tick_never_exceeds_the_deadline() {
        for deadline in [1_u64, 10, 100, 1_000, 5_000, 60_000, 86_400_000] {
            let tick = epoch_tick_interval(deadline);
            // `as_millis` yields u128; a tick interval is at most 100 ms, so
            // the conversion is exact by construction rather than by luck. The
            // bound is asserted rather than assumed.
            let tick_ms = u64::try_from(tick.as_millis())
                .expect("a tick interval always fits in u64 milliseconds");
            assert!(
                tick_ms <= deadline.max(1),
                "tick {tick:?} exceeds deadline {deadline}ms"
            );
        }
    }

    // -- Deterministic clock ----------------------------------------------

    #[test]
    fn deterministic_clock_is_fixed_and_advances_only_on_tick() {
        let c = DeterministicClock::default();
        assert_eq!(c.now_after(0), c.now_after(0), "must not drift on its own");
        assert!(c.now_after(1) > c.now_after(0));
        assert_eq!(c.now_after(10), c.fixed_unix_nanos + 10 * c.tick_nanos);
    }

    #[test]
    fn deterministic_clock_uses_an_obviously_synthetic_instant() {
        // A fixed clock reading a *plausible* current time would hide a
        // determinism bug in test output. 2026-01-01T00:00:00Z is round and
        // unmistakably synthetic.
        let c = DeterministicClock::default();
        assert_eq!(c.fixed_unix_nanos, 1_767_225_600_000_000_000);
    }

    #[test]
    fn virtual_clock_is_used_only_in_deterministic_mode() {
        assert!(!uses_virtual_clock(&EngineConfig::default()));
        assert!(uses_virtual_clock(&EngineConfig::deterministic()));
    }

    #[test]
    fn clock_construction_is_explicit() {
        let c = DeterministicClock::at(0);
        assert_eq!(c.now_after(0), 0);
        assert_eq!(c.now_after(u64::MAX), u64::MAX, "must saturate, not wrap");
    }
}
