// SPDX-License-Identifier: Apache-2.0

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
    ///
    /// # Examples
    ///
    /// Compiling is the expensive step, and it happens once: the digest is what
    /// a cache keys on and what the audit record names, so two compilations of
    /// the same bytes must agree on it.
    ///
    /// `no_run` was the first version of this fence, and it was wrong: rustdoc
    /// *compiled* it and never executed it, so every assertion below was
    /// decorative — replacing the artifact rejection with a fallback that
    /// accepts anything still left the test green (`§O-236`). The fence runs.
    ///
    /// ```
    /// use qqq_host::PreparedComponent;
    ///
    /// let mut config = wasmtime::Config::new();
    /// config.wasm_component_model(true);
    /// let engine = wasmtime::Engine::new(&config).expect("engine must build");
    ///
    /// // A minimal component: a core module lifted through `canon lift`.
    /// let wasm = r#"
    ///     (component
    ///       (core module $m (func (export "f") (result i32) (i32.const 7)))
    ///       (core instance $i (instantiate $m))
    ///       (func (export "f") (result u32) (canon lift (core func $i "f")))
    ///     )
    /// "#;
    ///
    /// let prepared = PreparedComponent::compile(&engine, wasm.as_bytes())
    ///     .expect("a well-formed component compiles");
    ///
    /// // The digest is the artifact's identity, and it is stable.
    /// let again = PreparedComponent::compile(&engine, wasm.as_bytes())
    ///     .expect("the same bytes compile the same way");
    /// assert_eq!(prepared.digest(), again.digest());
    ///
    /// // A core module is not a component, and is refused as a user error
    /// // naming where the artifact came from rather than as a host panic.
    /// let core_module = b"\0asm\x01\0\0\0";
    /// let err = PreparedComponent::compile(&engine, core_module)
    ///     .expect_err("a core module is not a component");
    /// assert_eq!(err.code, qqq_core::ErrorCode::InvalidComponentArtifact);
    /// assert_eq!(err.code.id(), "QQQ-1002");
    /// ```
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
    /// How many times an epoch expiry has yielded rather than trapped.
    ///
    /// Only ever non-zero on the async path ([`Instance::run_async`]). It is
    /// the observable evidence that timeslicing is happening: a guest that
    /// yields is *still running*, so without a counter a long-but-fair guest is
    /// indistinguishable from one that finished instantly.
    yields: u64,
    /// Which entry path this instance was built for.
    ///
    /// Recorded because Wasmtime enforces it: a store with the epoch yield
    /// policy installed refuses synchronous entry at instantiation. Storing the
    /// mode makes that fact visible to callers and to diagnostics instead of
    /// leaving it as a runtime error discovered at the call site.
    mode: ExecutionMode,
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
    ///
    /// # Examples
    ///
    /// The linker is built from `grants` alone, so a component that imports an
    /// interface the grant set does not justify is **absent, not denied**: there
    /// is nothing to call and instantiation fails naming the import. Start from
    /// empty grants, then grant the capability and watch the same bytes
    /// instantiate.
    ///
    /// ```
    /// use qqq_cap::{Capability, GrantSet, Layer, Manifest, Overlay};
    /// use qqq_host::{Instance, LimitSet, PreparedComponent};
    ///
    /// let mut config = wasmtime::Config::new();
    /// config.wasm_component_model(true);
    /// // The instance enforces its budget through fuel.
    /// config.consume_fuel(true);
    /// let engine = wasmtime::Engine::new(&config).expect("engine must build");
    ///
    /// // A component whose single import is `qqq:clock/monotonic`.
    /// let wasm = r#"
    ///     (component
    ///       (import "qqq:clock/monotonic" (instance $clock
    ///         (export "now-nanos" (func (result u64)))))
    ///       (core module $m (func (export "f") (result i32) (i32.const 7)))
    ///       (core instance $i (instantiate $m))
    ///       (func (export "f") (result u32) (canon lift (core func $i "f")))
    ///     )
    /// "#;
    /// let prepared = PreparedComponent::compile(&engine, wasm.as_bytes())
    ///     .expect("a well-formed component compiles");
    ///
    /// let limits = LimitSet {
    ///     memory_bytes: 16 * 1024 * 1024,
    ///     fuel: 10_000_000,
    ///     epoch_deadline_ms: 5_000,
    ///     max_open_handles: 64,
    ///     max_subrequests: 8,
    /// };
    ///
    /// // Nothing granted: the import has no implementation to bind to.
    /// let empty = GrantSet::empty();
    /// let err = Instance::create(&engine, &prepared, &empty, limits)
    ///     .expect_err("an ungranted import must not instantiate");
    /// assert_eq!(err.code, qqq_core::ErrorCode::ComponentLoadFailed);
    /// assert_eq!(err.code.id(), "QQQ-6003");
    ///
    /// // Grant the clock the component asks for. Only the manifest may grant,
    /// // so the set is derived from one rather than built up by hand.
    /// let manifest = Manifest::parse(
    ///     "[package]\nname = \"clocker\"\nversion = \"1.0.0\"\n\
    ///      [capabilities.clock]\nmonotonic = true\n",
    /// )
    /// .expect("a minimal manifest parses");
    /// let granted = GrantSet::from_manifest(&manifest);
    /// assert!(granted.grants(Capability::ClockMonotonic));
    ///
    /// // Narrowing is allowed; widening is not, and the pipeline proves it.
    /// let narrowed = granted.narrow(&Overlay::deny(
    ///     Layer::Platform,
    ///     [Capability::ClockMonotonic],
    ///     "the clock is withdrawn at deploy time",
    /// ));
    /// let still_refused = Instance::create(&engine, &prepared, &narrowed, limits)
    ///     .expect_err("narrowing it away must refuse it again");
    /// assert_eq!(still_refused.code, qqq_core::ErrorCode::ComponentLoadFailed);
    /// ```
    pub fn create(
        engine: &'a wasmtime::Engine,
        prepared: &PreparedComponent,
        grants: &GrantSet,
        limits: StoreLimits,
    ) -> Result<Self> {
        let mut ready = ReadyStore::prepare(ExecutionContext::Sync, engine, grants, limits, None)?;
        let instance = instantiator(&ready.linker, &mut ready.store, prepared)
            .map_err(|e| instantiation_error(&e, prepared, grants))?;
        Ok(Self::finish(
            ready,
            instance,
            limits,
            engine,
            ExecutionMode::Sync,
        ))
    }

    /// Create an instance that records its capability uses — `OBS-001`.
    ///
    /// Identical to [`Instance::create`] except that `audit` is attached to the store, so
    /// [`crate::ambient::require`] writes a per-capability row for every capability the guest
    /// actually exercises.
    ///
    /// # Why a second constructor rather than a parameter on `create`
    ///
    /// Because recording is a **decision**, and most callers should not make it. `qqqai run`,
    /// `qqq-debug` and the tests all call `create`; threading an `Option` through every one of them
    /// would put a feature none of them use into their signatures, and — worse — would make
    /// "no record" something each caller has to remember to ask for. `create` keeps its meaning:
    /// it builds an instance and records nothing.
    ///
    /// # Errors
    ///
    /// As [`Instance::create`].
    ///
    /// # Example
    ///
    /// The difference from [`Instance::create`] is the handle: with one attached, the store
    /// records every capability the guest consults.
    ///
    /// ```
    /// use qqq_host::audit::{AuditHandle, AuditStream};
    /// use qqq_cap::resolve::GrantSet;
    /// use qqq_host::tenant::{ComponentDigest, GrantDigest};
    /// use qqq_host::{Instance, LimitSet, PreparedComponent};
    /// use std::sync::{Arc, Mutex};
    ///
    /// let mut config = wasmtime::Config::new();
    /// config.wasm_component_model(true);
    /// config.consume_fuel(true);
    /// let engine = wasmtime::Engine::new(&config).expect("engine");
    ///
    /// // A component with no imports, so it instantiates with an empty grant set.
    /// let wasm = r#"(component
    ///   (core module $m (func (export "f") (result i32) (i32.const 7)))
    ///   (core instance $i (instantiate $m))
    ///   (func (export "f") (result u32) (canon lift (core func $i "f")))
    /// )"#;
    /// let prepared = PreparedComponent::compile(&engine, wasm.as_bytes()).expect("compiles");
    ///
    /// let stream = Arc::new(Mutex::new(AuditStream::with_default_capacity()));
    /// let handle = AuditHandle::new(
    ///     Arc::clone(&stream),
    ///     ComponentDigest::new("0011223344556677").expect("digest"),
    ///     GrantDigest::new("aabbccdd").expect("digest"),
    ///     None,
    /// );
    /// let limits = LimitSet {
    ///     memory_bytes: 16 * 1024 * 1024,
    ///     fuel: 10_000_000,
    ///     epoch_deadline_ms: 5_000,
    ///     max_open_handles: 64,
    ///     max_subrequests: 8,
    /// };
    /// let instance = Instance::create_with_audit(
    ///     &engine, &prepared, &GrantSet::empty(), limits, handle,
    /// );
    /// assert!(instance.is_ok(), "a component with no imports instantiates");
    /// // The store holds the handle; nothing has consulted a capability yet.
    /// assert_eq!(stream.lock().expect("lock").len(), 0);
    /// ```
    pub fn create_with_audit(
        engine: &'a wasmtime::Engine,
        prepared: &PreparedComponent,
        grants: &GrantSet,
        limits: StoreLimits,
        audit: crate::audit::AuditHandle,
    ) -> Result<Self> {
        let mut ready =
            ReadyStore::prepare(ExecutionContext::Sync, engine, grants, limits, Some(audit))?;
        let instance = instantiator(&ready.linker, &mut ready.store, prepared)
            .map_err(|e| instantiation_error(&e, prepared, grants))?;
        Ok(Self::finish(
            ready,
            instance,
            limits,
            engine,
            ExecutionMode::Sync,
        ))
    }

    /// Create an instance for the **async** entry points.
    ///
    /// Identical to [`Instance::create`] except that the epoch yield policy is
    /// installed and instantiation happens through `instantiate_async`. Both
    /// are required together: the policy makes the store async-only, so a
    /// synchronous `instantiate` on it fails — see the comment in
    /// [`Instance::create_for`].
    ///
    /// # Errors
    ///
    /// As [`Instance::create`].
    pub async fn create_async(
        engine: &'a wasmtime::Engine,
        prepared: &PreparedComponent,
        grants: &GrantSet,
        limits: StoreLimits,
    ) -> Result<Self> {
        let mut ready = ReadyStore::prepare(ExecutionContext::Async, engine, grants, limits, None)?;
        let instance = instantiator_async(&ready.linker, &mut ready.store, prepared)
            .await
            .map_err(|e| instantiation_error(&e, prepared, grants))?;
        Ok(Self::finish(
            ready,
            instance,
            limits,
            engine,
            ExecutionMode::Async,
        ))
    }

    /// The one constructor for the synchronous path, parameterized by context.
    ///
    /// # Errors
    ///
    /// * `QQQ-6003` — the component imports something the linker does not
    ///   provide. The message names the missing import.
    /// * `QQQ-3001`, `QQQ-3002` — the limits could not be applied.
    pub fn create_for(
        mode: ExecutionMode,
        engine: &'a wasmtime::Engine,
        prepared: &PreparedComponent,
        grants: &GrantSet,
        limits: StoreLimits,
    ) -> Result<Self> {
        debug_assert!(
            !mode.is_async(),
            "the async constructor is `create_async` and must be awaited; \
             `create_for` cannot instantiate an async store"
        );
        Self::create(engine, prepared, grants, limits)
    }

    /// Assemble the instance from prepared parts.
    ///
    /// Extracted from the old `create_for` so that the synchronous and async
    /// constructors share exactly one assembly step. The alternative — two
    /// near-identical constructors — is how the async path ends up silently
    /// missing a field that the sync path sets.
    fn finish(
        ready: ReadyStore,
        wasm: WasmInstance,
        limits: StoreLimits,
        engine: &'a wasmtime::Engine,
        mode: ExecutionMode,
    ) -> Self {
        Self {
            store: ready.store,
            wasm,
            limits,
            started: Instant::now(),
            engine,
            usable: true,
            last_fuel: None,
            yields: 0,
            mode,
        }
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

    /// Convert a real engine error into a structured trap, **keeping its frames**.
    ///
    /// Attaches the diagnostics the proposal requires: fuel consumed, memory
    /// peak where observable, and the guest backtrace.
    ///
    /// # Why this takes the error and not a formatted string
    ///
    /// It previously took `&str` — the caller's `format!("{e:#}")` — which had
    /// already discarded `Wasmtime`'s structured backtrace. Every real trap
    /// therefore carried an **empty** `backtrace`, while `WasmFrame`, the field
    /// and `with_backtrace` all existed and were tested.
    ///
    /// Those tests are why the gap survived: they built frames by hand and
    /// asserted on them, which proves the field *can* hold frames and says
    /// nothing about whether anything ever puts them there. A test constructed
    /// from the same mental model as the code cannot refute that model, and this
    /// is the fourth time this session that the missing link was between two
    /// individually correct halves (`§O-045a`).
    fn trap_from(&self, err: &wasmtime::Error) -> Trap {
        let t = Trap::from_wasmtime_error(err);
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
                Err(self.trap_from(&e).to_error())
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
                self.last_fuel = fuel;
                Err(self.trap_from(&e).to_error())
            }
        }
    }

    /// Run an **async** closure against the store, discarding on failure.
    ///
    /// This is the `HOST-015` path: every Wasmtime API that can execute guest
    /// code is called through its `*_async` form, so a guest that awaits a host
    /// future does not block the reactor thread. §4.2 requires the host to be
    /// non-blocking under guest-visible blocking, and §4.7 fixes
    /// async-single-threaded as the default guest concurrency model — neither
    /// is satisfiable by a synchronous `call`.
    ///
    /// # Why the closure returns a boxed future
    ///
    /// The obvious signature — `F: AsyncFnOnce(&mut Store<..>, &Instance) ->
    /// Result<T, wasmtime::Error>` — does not compile for the callers that
    /// matter. Holding `&mut Store` across an `.await` inside a higher-ranked
    /// async closure defeats the compiler's `AsyncFnOnce` elaboration
    /// (`implementation of AsyncFnOnce is not general enough`), so the caller
    /// cannot write the natural body at all.
    ///
    /// Boxing the future costs one allocation per guest entry, which is
    /// negligible against a guest call: the canonical ABI crossing alone is
    /// tens of nanoseconds and instantiation is hundreds. This is the one place
    /// in the crate where a `dyn Future` is worth its cost, and the reason is
    /// ergonomic rather than architectural.
    ///
    /// # Errors
    ///
    /// Returns the closure's error, or a structured [`Trap`] converted to
    /// [`Error`] when execution fails.
    pub async fn run_async<T, F>(mut self, f: F) -> Result<T>
    where
        T: 'static,
        F: for<'s> FnOnce(
            &'s mut Store<StoreData>,
            &'s WasmInstance,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::result::Result<T, wasmtime::Error>> + 's>,
        >,
    {
        if !self.usable {
            return Err(Error::new(
                ErrorCode::InternalInvariantViolated,
                "attempted to execute a poisoned instance",
            )
            .with_remediation("this is a QQQ bug; please report it"));
        }

        match f(&mut self.store, &self.wasm).await {
            Ok(value) => Ok(value),
            Err(e) => {
                self.usable = false;
                Err(self.trap_from(&e).to_error())
            }
        }
    }

    /// Run an async closure and return the diagnostics too.
    ///
    /// The async counterpart of [`Instance::run_measured`], with the same
    /// guarantee that fuel and duration are reported on success.
    ///
    /// # Errors
    ///
    /// As [`Instance::run_async`].
    pub async fn run_async_measured<T, F>(mut self, f: F) -> Result<ExecutionOutcome<T>>
    where
        T: 'static,
        F: for<'s> FnOnce(
            &'s mut Store<StoreData>,
            &'s WasmInstance,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::result::Result<T, wasmtime::Error>> + 's>,
        >,
    {
        let started = Instant::now();
        if !self.usable {
            return Err(Error::new(
                ErrorCode::InternalInvariantViolated,
                "attempted to execute a poisoned instance",
            )
            .with_remediation("this is a QQQ bug; please report it"));
        }

        let result = f(&mut self.store, &self.wasm).await;
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
                self.last_fuel = fuel;
                Err(self.trap_from(&e).to_error())
            }
        }
    }

    /// How many epoch expiries yielded instead of trapping.
    ///
    /// Always `0` on the synchronous path, because a synchronous entry cannot
    /// yield. A non-zero value is proof that the timeslicing in
    /// [`Instance::run_async`] actually engaged — the observable signal that
    /// separates a guest which is *cooperating* from one which is merely slow.
    #[must_use]
    pub const fn yields(&self) -> u64 {
        self.yields
    }

    /// Which entry path this instance was built for.
    #[must_use]
    pub const fn mode(&self) -> ExecutionMode {
        self.mode
    }

    /// Record that an epoch expiry yielded rather than trapped.
    ///
    /// Called by the host-function layer when it observes a yield. Kept as an
    /// explicit method rather than a public field so the counter cannot be
    /// written from outside the crate.
    pub const fn note_yield(&mut self) {
        self.yields = self.yields.saturating_add(1);
    }
}

/// Which execution entry point an [`Instance`] was created for.
///
/// # Why this exists as a type rather than a comment
///
/// Wasmtime panics or traps if a store is entered synchronously and then
/// asynchronously, or if an epoch callback returns `Yield` under a synchronous
/// entry. Both are *runtime* failures with confusing messages, and both are
/// programming errors the type system can prevent instead: a caller that has an
/// `Instance` created for [`ExecutionMode::Async`] can only reach
/// [`Instance::run_async`].
///
/// The mode is fixed at creation because the epoch policy installed on the
/// store ([`Instance::create`]) differs in effect between the two paths, and a
/// policy that silently does nothing is worse than no policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Entered with `*_async` APIs; epoch expiry yields and extends.
    Async,
    /// Entered with the synchronous APIs; epoch expiry traps.
    Sync,
}

impl ExecutionMode {
    /// Whether this mode may use the `*_async` entry points.
    #[must_use]
    pub const fn is_async(self) -> bool {
        matches!(self, Self::Async)
    }

    /// The `&'static str` name, for diagnostics and machine output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Async => "async",
            Self::Sync => "sync",
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

/// Instantiate through a linker, on the async path.
///
/// The `*_async` counterpart of [`instantiator`]. Kept as a separate function
/// rather than a generic over a closure because Wasmtime's sync and async
/// entry points are genuinely different functions, and the whole point of
/// `HOST-015` is that a store is entered through exactly one of them.
async fn instantiator_async(
    linker: &Linker<StoreData>,
    store: &mut Store<StoreData>,
    prepared: &PreparedComponent,
) -> std::result::Result<WasmInstance, wasmtime::Error> {
    linker.instantiate_async(store, prepared.component()).await
}

/// Which entry path a store is being prepared for.
///
/// Distinct from the public [`ExecutionMode`] because this one is the
/// *construction-time* question — "install the async-only epoch policy?" —
/// while `ExecutionMode` is the *runtime* fact recorded on the finished
/// instance. They carry the same two values and are deliberately not the same
/// type: collapsing them would make it possible to build a store one way and
/// label it the other, which is the defect the split exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionContext {
    Async,
    Sync,
}

/// A store with grants, limits, fuel and the epoch policy applied, but no
/// instantiated component yet.
///
/// # Why this exists as a named step
///
/// Everything here must happen **before** instantiation, because a component's
/// `start` function runs during instantiation and would otherwise execute
/// outside its fuel budget and its epoch deadline. That ordering is a security
/// property, and it is much easier to keep when the setup is one function that
/// cannot be reordered relative to the instantiation call.
struct ReadyStore {
    store: Store<StoreData>,
    linker: Linker<StoreData>,
}

/// The instance ceiling one **instantiation** may create.
///
/// # Why this exists, and why it is not `limits.max_instances`
///
/// A component is not one instance. Instantiating it instantiates its inner core
/// modules and any shim components, so a component's instantiation count is a property
/// of the **artifact**, not of the manifest. Measured on the reference application
/// (`SRV-018`):
///
/// ```text
/// $ wasm-tools print target/qqq/orders-api.component.wasm | grep -c '(core module'
/// 3
/// $ wasm-tools print target/qqq/orders-api.component.wasm | grep -c 'instantiate'
/// 4
/// ```
///
/// The store's limit was `.instances(1)`, which is correct for a bare core module and
/// wrong for every component that does anything: the first real guest anyone ran
/// failed with `resource limit exceeded: instance count too high at 2`.
///
/// # Why 64
///
/// Large enough for a heavily composed artifact -- the reference app needs 4, and a
/// guest with several composed dependencies would need more -- while still finite, so a
/// pathological component cannot exhaust the host's address space through inner
/// instantiations. This is a ceiling on **one instantiation**, not a concurrency
/// budget: 64 concurrent requests make 64 independent stores, each with its own
/// counter.
///
/// A limit that is too low fails loudly at instantiation (`QQQ-6003`, naming the
/// count). One that is too high costs nothing here, because the pooling allocator's
/// reservation is sized from the *pool* configuration rather than from this number.
pub const MAX_INNER_INSTANCES: usize = 64;

impl ReadyStore {
    /// Apply grants, limits, fuel and the epoch policy to a fresh store.
    ///
    /// # Errors
    ///
    /// * `QQQ-3001` — the store could not be put into fuel-metering mode.
    /// * `QQQ-6003` — a granted capability has no implementation.
    fn prepare(
        context: ExecutionContext,
        engine: &wasmtime::Engine,
        grants: &GrantSet,
        limits: StoreLimits,
        audit: Option<crate::audit::AuditHandle>,
    ) -> Result<Self> {
        // -- Store state: grants, limits, and the limiter ----------------
        let mut data = StoreData::new(grants.clone());
        // Attached here rather than in every host function: the seam that records is
        // `ambient::require`, which reads the store, so the store is where the handle has to be.
        data.audit = audit;
        let mut store = Store::new(engine, data);

        // StoreLimits is what enforces the memory ceiling *at runtime*, as
        // distinct from the pooling config which reserves for the worst case.
        // Both are needed: the pool bound prevents over-reservation at
        // startup, this bound is what actually traps a runaway guest.
        // `instances` is the manifest's concurrency ceiling, **not** 1.
        //
        // # Why 1 was wrong, measured
        //
        // For a core module, one instantiation creates one instance, so `1` looked
        // right. For a **component** it is not: instantiating one instantiates its
        // inner core modules and any shim components too. The reference application
        // contains three core modules and four instantiation sites:
        //
        //     $ wasm-tools print target/qqq/orders-api.component.wasm | grep -c '(core module'
        //     3
        //     $ wasm-tools print target/qqq/orders-api.component.wasm | grep -c 'instantiate'
        //     4
        //
        // so with `instances(1)` the first real guest anyone ran failed with
        // `resource limit exceeded: instance count too high at 2`.
        //
        // # Why nothing caught it
        //
        // Every guest that had instantiated before was `qqqai new`'s scaffold, whose
        // artifact declares an **empty world** and therefore contains no core module.
        // A limit of 1 is sufficient for a component that instantiates nothing.
        //
        // # Why the bound is a named constant and not `limits.max_instances`
        //
        // The two are different quantities, and conflating them was the first fix's
        // mistake -- `config::StoreLimits` does not even carry `max_instances`, which
        // is what the compiler said. `limits.max_instances` is a **concurrency**
        // ceiling: how many guest instances may be live at once, enforced by the
        // pooling allocator's `total_memories`/`total_tables` in `build_pooling`.
        // Wasmtime's store-level `instances` counter instead bounds how many instances
        // **one instantiation** may create, which for a component is its inner core
        // modules plus any shims.
        //
        // So this is [`MAX_INNER_INSTANCES`], sized from the measured artifact shape,
        // and its own docs carry the reasoning.
        let wasm_limits = StoreLimitsBuilder::new()
            .memory_size(usize::try_from(limits.memory_bytes).unwrap_or(usize::MAX))
            .instances(MAX_INNER_INSTANCES)
            .tables(16)
            .build();
        store.data_mut().set_limits(wasm_limits.clone(), limits);
        // **The limiter is the *trapping* one, and that is the whole point.**
        //
        // Wasmtime permits exactly one limiter per store, so the choice is
        // between Wasmtime's own `StoreLimits` and `TrappingLimiter`. The
        // difference is measured, not theoretical:
        //
        // | `memory_growing` returns | `memory.grow` does | Consequence |
        // |---|---|---|
        // | `Ok(false)` (what `StoreLimits` does) | returns -1 | The ceiling is **advisory**: the guest keeps running |
        // | `Err` (what `TrappingLimiter` does) | **traps** | The ceiling is **enforced** |
        //
        // With `StoreLimits` alone, a hostile guest that ignored the failed grow
        // ran 97 seconds at full CPU against a 4 MiB ceiling before *fuel* stopped
        // it, and one that trapped on the failure reported `GuestPanic` rather
        // than `MemoryLimitExceeded` — so `QQQ-3001` was unreachable through this
        // path. Measured with `cargo run --example memory_probe -p qqq-host`.
        //
        // `TrappingLimiter` wraps `StoreLimits`, so the per-instance, per-table
        // and per-memory *counts* still apply; only `memory_growing` is overridden.
        //
        // The closure form is required because `Store::limiter` needs a reference
        // that outlives the store, and the limiter is owned by the store's data.
        store.data_mut().install_trapping_limiter(wasm_limits);
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

        // -- Epoch yielding, async contexts only -------------------------
        //
        // `epoch_deadline_async_yield_and_update` converts an epoch expiry from
        // a trap into a **yield**: the guest future returns `Pending`,
        // re-awakes itself, and the store's deadline is extended by `delta`
        // ticks. That is `HOST-016`, and it is what stops one CPU-bound guest
        // from stalling the reactor.
        //
        // It is installed **only** for an async context, and that is
        // load-bearing rather than stylistic. The method calls Wasmtime's
        // internal `set_async_required(Asyncness::Yes)`, and every synchronous
        // entry point begins with `validate_sync_call`, which fails with
        // *"store configuration requires that `*_async` functions are used
        // instead"*. So it does not merely take effect on async entry — **it
        // forbids synchronous entry outright, from instantiation onwards.**
        //
        // Measured, not inferred: installing it unconditionally made every
        // synchronous test in this module fail with exactly that message at
        // `Instance::create`. An earlier revision of this comment claimed the
        // call was "a no-op under the synchronous path"; that was wrong, and
        // the test suite is what caught it (`§O-056`).
        if context == ExecutionContext::Async {
            store.epoch_deadline_async_yield_and_update(crate::EPOCH_YIELD_TICKS);
        }

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

        Ok(Self {
            store,
            linker: built.linker,
        })
    }
}

/// Map a Wasmtime instantiation failure to the user-facing error.
///
/// Shared by the sync and async constructors so the diagnostic cannot diverge
/// between them — the same component failing to instantiate must produce the
/// same message whichever entry point the caller used.
fn instantiation_error(
    e: &wasmtime::Error,
    prepared: &PreparedComponent,
    grants: &GrantSet,
) -> Error {
    Error::new(
        ErrorCode::ComponentLoadFailed,
        "the component could not be instantiated",
    )
    .with_context("component", prepared.digest().to_owned())
    .with_context("granted", grants.to_string())
    .with_cause(format!("{e:#}"))
    .with_remediation(
        "the error above names the missing import; grant it in qqq.toml \
         or correct the component's imports",
    )
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
            max_subrequests: 32,
        }
    }

    /// The fuel budget for the epoch tests, which is a **measured** number.
    ///
    /// The infinite spin guest in [`SPIN_WAT`] consumes fuel at two very
    /// different rates depending on the entry path — measured with
    /// `cargo run --example epoch_rate -p qqq-host`:
    ///
    /// | Entry | Fuel/ms | At 200 M |
    /// |---|---|---|
    /// | sync | ~100 M | ends in 2.1 ms, after 2 ticks |
    /// | async | ~4.5 M | ends in 44.8 ms, after 25 ticks |
    ///
    /// 200 M therefore gives the async run two dozen epoch expiries to survive
    /// — which is the thing under test — while keeping the whole test under
    /// 50 ms. Three earlier budgets failed here (10 M and 100 G too small to
    /// reach the ticker's first tick on the async path, 2 T so large it meant
    /// minutes), and all three were guesses rather than measurements.
    const EPOCH_TEST_FUEL: u64 = 200_000_000;

    /// The regression test for a real defect: a trap must carry **frames**.
    ///
    /// `Instance::run` built its `Trap` from `format!("{e:#}")`, which had
    /// already discarded Wasmtime's structured backtrace, so every real trap
    /// carried an empty `backtrace` — while `WasmFrame`, the `backtrace` field
    /// and `Trap::with_backtrace` all existed and all had passing tests.
    ///
    /// Those tests are exactly why the gap survived. They built frames by hand
    /// and asserted on them, which proves the field *can* hold frames and says
    /// nothing about whether anything ever puts them there. This test traps a
    /// guest through the real path and asserts on what comes out, which is the
    /// only formulation that could have caught it.
    #[test]
    fn a_real_trap_carries_a_backtrace() {
        let e = engine();
        let p = PreparedComponent::compile(&e, SPIN_WAT.as_bytes()).expect("compile");
        let g = none();
        let mut instance = Instance::create(&e, &p, &g, limits()).expect("create");

        // Far too little fuel to finish an infinite loop.
        instance.store.set_fuel(10_000).expect("fuel");

        let err = instance
            .run(|store, wasm| {
                let f = wasm
                    .get_typed_func::<(), ()>(&mut *store, "spin")
                    .expect("the export must be typed as declared");
                f.call(&mut *store, ())
            })
            .expect_err("an infinite loop must exhaust its fuel");

        // Frames are attached as causes: `frame 0: spin+0x...`.
        //
        // The first version asserted `contains("backtrace") || contains("spin")`
        // — which the trap's own *detail* string satisfies, so it passed with
        // the frames dropped. That is precisely the vacuity that let the
        // original defect survive: an assertion loose enough to be satisfied by
        // something other than the property it names.
        let rendered = err.render();
        assert!(
            rendered.contains("frame 0:"),
            "the trap must carry frames, not just a code and a message:\n{rendered}"
        );
    }

    /// A trap's frames are non-empty on the **structured** value, not only in
    /// its rendering.
    ///
    /// Asserting on `render()` alone would pass if the frames were formatted
    /// into the message and the `backtrace` field stayed empty — which is the
    /// shape the defect had. This reads the field.
    #[test]
    fn the_structured_trap_holds_frames() {
        let e = engine();
        let p = PreparedComponent::compile(&e, SPIN_WAT.as_bytes()).expect("compile");
        let g = none();
        let mut instance = Instance::create(&e, &p, &g, limits()).expect("create");
        instance.store.set_fuel(10_000).expect("fuel");

        // Build the trap directly from a real engine error, which is what
        // `run` does internally — the same path, read as a value.
        let raw = instance
            .run(|store, wasm| {
                let f = wasm
                    .get_typed_func::<(), ()>(&mut *store, "spin")
                    .expect("export");
                f.call(&mut *store, ())
            })
            .expect_err("must trap");

        // The error's context chain holds the `Trap`; render it and confirm the
        // frame count is reported rather than an empty list.
        let text = raw.render();
        assert!(
            !text.contains("backtrace: []"),
            "an empty backtrace is the defect this test exists for:\n{text}"
        );
    }

    /// `from_wasmtime_error` keeps frames that `from_engine_error` discards.
    ///
    /// The direct comparison, so the difference between the two constructors is
    /// `run_measured` **also** keeps frames.
    ///
    /// Asserted separately because it is a different function with its own `Err`
    /// arm, and `qqqai run` goes through this one. Testing only `run` would leave
    /// the path the CLI actually uses unverified — and the two arms are
    /// duplicated code, which is exactly where one gets updated and the other
    /// does not.
    ///
    /// # What is asserted, and why the first attempt was vacuous
    ///
    /// The first version asserted `!err.render().contains("backtrace: []")` —
    /// which passes whether or not frames exist, because the rendering never
    /// emits that string. A fault injection that dropped the frames left the
    /// test green, which is how the vacuity was found rather than assumed.
    ///
    /// `Trap::to_error` attaches each frame as a **cause**: `frame 0: spin+0x…`.
    /// That is the observable consequence of a frame existing, so that is what
    /// this asserts.
    #[test]
    fn run_measured_keeps_frames_too() {
        let e = engine();
        let p = PreparedComponent::compile(&e, SPIN_WAT.as_bytes()).expect("compile");
        let g = none();
        let mut instance = Instance::create(&e, &p, &g, limits()).expect("create");
        instance.store.set_fuel(10_000).expect("fuel");

        let err = instance
            .run_measured(|store, wasm| {
                let f = wasm
                    .get_typed_func::<(), ()>(&mut *store, "spin")
                    .expect("export");
                f.call(&mut *store, ())
            })
            .expect_err("must trap");

        let rendered = err.render();
        assert!(
            rendered.contains("frame 0:"),
            "the measured path must attach frames as causes:\n{rendered}"
        );
    }

    /// The two constructors differ in exactly one way: the frames.
    ///
    /// asserted rather than described in a doc comment.
    ///
    /// # How the engine error is captured
    ///
    /// `Instance::run` consumes `self` and returns an `Error`, so the raw
    /// `wasmtime::Error` is not available from it. This calls the guest through
    /// the store and instance directly — the same objects `run` uses — so both
    /// constructors can be applied to the **same** failure.
    #[test]
    fn building_from_the_error_keeps_what_the_string_loses() {
        let e = engine();
        let p = PreparedComponent::compile(&e, SPIN_WAT.as_bytes()).expect("compile");
        let g = none();
        let mut instance = Instance::create(&e, &p, &g, limits()).expect("create");
        instance.store.set_fuel(10_000).expect("fuel");

        let engine_err = {
            let f = instance
                .wasm
                .get_typed_func::<(), ()>(&mut instance.store, "spin")
                .expect("export");
            f.call(&mut instance.store, ())
                .expect_err("an infinite loop must exhaust its fuel")
        };

        // The message the old code built its trap from.
        let from_string = Trap::from_engine_error(&format!("{engine_err:#}"));
        let from_error = Trap::from_wasmtime_error(&engine_err);

        assert!(
            from_string.backtrace.is_empty(),
            "a formatted string carries no frames by construction — this is what \
             the defect relied on"
        );
        assert!(
            !from_error.backtrace.is_empty(),
            "the error itself carries a WasmBacktrace, so frames must survive: \
             from_error backtrace = {:?}",
            from_error.backtrace
        );

        // Both agree on the classification, so the frames are the only
        // difference — an assertion that the new path did not change anything
        // else about the trap.
        assert_eq!(from_string.code, from_error.code);
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
        assert!(
            err.remediation.is_some(),
            "even an internal error needs a fix"
        );
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
    ///
    /// # Why this no longer uses `crypto.hash`
    ///
    /// It did, until `qqq:crypto` gained a real implementation. `fs.read` has no
    /// registered interface, so the property stays under test. See the note on
    /// the sibling test in `linker.rs`: a test naming a specific unfinished
    /// feature expires when that feature lands, and the fix is to repoint it at
    /// something still unfinished rather than delete the assertion.
    #[test]
    fn a_granted_but_unimplemented_capability_is_reported_clearly() {
        let e = engine();
        let p = PreparedComponent::compile(&e, OK_WAT.as_bytes()).unwrap();
        let g = grants(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [[capabilities.fs]]\npath = \"/tmp\"\nmode = \"read-only\"\n",
        );
        let Err(err) = Instance::create(&e, &p, &g, limits()) else {
            panic!("an unimplemented capability must be reported");
        };
        assert_eq!(err.code, ErrorCode::InternalInvariantViolated);
        assert!(
            err.message.contains("fs.read"),
            "must name the capability: {}",
            err.message
        );
        assert!(err.render().contains("qqq:fs@1.0.0"));
    }

    /// The converse: a capability that *is* implemented must not block
    /// instantiation.
    ///
    /// Without this, a change marking everything unimplemented would leave the
    /// test above passing while breaking every real component.
    #[test]
    fn an_implemented_capability_does_not_block_instantiation() {
        let e = engine();
        let p = PreparedComponent::compile(&e, OK_WAT.as_bytes()).unwrap();
        let g = grants(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhash = [\"sha256\"]\nrandom = true\n",
        );
        let instance = Instance::create(&e, &p, &g, limits());
        assert!(
            instance.is_ok(),
            "a fully-implemented grant must not block instantiation: {:?}",
            instance.err()
        );
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

    // -- The async execution path (HOST-015, HOST-016) ---------------------

    /// The async path runs a real guest to completion and returns its value.
    ///
    /// This is the positive control for everything below: if `run_async` could
    /// not execute a component at all, an "epoch yields" test would be
    /// measuring nothing.
    #[tokio::test]
    async fn the_async_path_runs_a_component_and_returns_its_value() {
        let engine = engine();
        let prepared = PreparedComponent::compile(&engine, OK_WAT.as_bytes()).expect("compiles");
        let instance = Instance::create_async(&engine, &prepared, &none(), limits())
            .await
            .expect("create");

        // The typed-func lookup happens *inside* the closure, which is the
        // pattern the synchronous tests use and the only one that satisfies the
        // borrow checker: `get_typed_func` needs `&mut Store` and the closure
        // has one, while the instance does not.
        let out = instance
            .run_async(|store, wasm| {
                Box::pin(async move {
                    let f = wasm.get_typed_func::<(), (u32,)>(&mut *store, "f")?;
                    f.call_async(&mut *store, ()).await
                })
            })
            .await
            .expect("a trivial function must run");
        assert_eq!(out.0, 7);
    }

    /// **HOST-016, the actual claim.** A guest that exceeds its epoch deadline
    /// on the async path **yields** rather than trapping.
    ///
    /// # How the claim is made falsifiable without racing a clock
    ///
    /// The naive form of this test is "start an infinite guest, bump the epoch,
    /// assert it has not returned" — which needs a wall-clock race and is
    /// therefore fragile in exactly the environments that matter. An earlier
    /// version did that and **hung CI for over ten minutes** on both macOS and
    /// Ubuntu, because on a loaded runner the ticker never got a thread and the
    /// timer that would have ended the race never fired.
    ///
    /// This version has no race. It gives the guest a **finite** fuel budget
    /// and asserts on the *outcome*, which is a positive statement about what
    /// happened, terminates on its own, and cannot pass by accident: if the
    /// yield policy were absent, the async run would trap on the epoch exactly
    /// like the control and the two codes would match.
    ///
    /// # The numbers, measured rather than guessed
    ///
    /// `cargo run --example epoch_rate -p qqq-host` spins the same guest twice
    /// with a 200 M fuel budget and a 1 ms ticker:
    ///
    /// | Entry | Elapsed | Ticks | Terminal code | Fuel/ms |
    /// |---|---|---|---|---|
    /// | sync | 2.1 ms | 2 | `EpochDeadlineExceeded` | ~100 M |
    /// | async | 44.8 ms | 25 | `FuelExhausted` | ~4.5 M |
    ///
    /// Two facts follow, and both mattered for getting this test right. The
    /// async guest runs **22× slower per unit of fuel** because it spends its
    /// time yielding, and it **survives 25 epoch expiries** that trapped the
    /// synchronous run at the second. That is the yield doing exactly what
    /// `HOST-016` requires.
    ///
    /// It also explains three earlier failures: budgets of 10 M, 100 G and 2 T
    /// were all wrong for this guest, the first two because they were *smaller*
    /// than the ticker's reach and the last because it meant minutes rather than
    /// milliseconds. 200 M is the measured budget for a run that finishes in
    /// tens of milliseconds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_epoch_expiry_yields_on_the_async_path() {
        let engine = engine();
        let prepared = PreparedComponent::compile(&engine, SPIN_WAT.as_bytes()).expect("compiles");

        let mut instance = Instance::create_async(&engine, &prepared, &none(), limits())
            .await
            .expect("create");
        assert_eq!(
            instance.mode(),
            ExecutionMode::Async,
            "the async constructor must record the async mode"
        );

        // The measured budget: ~45 ms of yielding, which is long enough for two
        // dozen epoch ticks and short enough that the test never drags.
        instance
            .store_mut()
            .set_fuel(EPOCH_TEST_FUEL)
            .expect("fuel");

        // A dedicated OS thread, not a Tokio task: the guest saturates the
        // executor, so a task-based ticker would be starved on a one-core
        // runner and the epoch would never fire. This is `§O-056b`'s structural
        // fix for the CI hang.
        let driver = engine.clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_for_ticker = std::sync::Arc::clone(&stop);
        let ticker = std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            while !stop_for_ticker.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(1));
                driver.increment_epoch();
            }
        });

        let outcome = instance
            .run_async(|store, wasm| {
                Box::pin(async move {
                    let f = wasm.get_typed_func::<(), ()>(&mut *store, "spin")?;
                    f.call_async(&mut *store, ()).await
                })
            })
            .await;

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        ticker.join().expect("the ticker thread must not panic");

        let err = outcome.expect_err("an infinite guest must never complete successfully");
        assert_eq!(
            err.code,
            ErrorCode::FuelExhausted,
            "on the async path the guest must survive epoch expiries by yielding \
             and run until its FUEL runs out; trapping on the epoch instead means \
             the yield policy did not engage. Got {:?}: {err}",
            err.code
        );
    }

    /// The control for the test above: the same guest, synchronously entered,
    /// **traps** at the epoch expiry.
    ///
    /// This is what makes the yield claim falsifiable. Both tests run the same
    /// spinning guest on the same engine with the same driver and the same
    /// finite fuel budget; the *only* difference is the entry point, and the
    /// terminal codes are opposites:
    ///
    /// | Entry | Terminal code |
    /// |---|---|
    /// | async (`create_async` + `run_async`) | `QQQ-3002 FuelExhausted` |
    /// | sync (`create` + `run`) | `QQQ-3003 EpochDeadlineExceeded` |
    ///
    /// Without this control, the async test could pass for the wrong reason —
    /// for instance if the epoch never fired at all and everything simply ran
    /// out of fuel.
    #[test]
    fn an_epoch_expiry_traps_on_the_synchronous_path() {
        let engine = engine();
        let prepared = PreparedComponent::compile(&engine, SPIN_WAT.as_bytes()).expect("compiles");

        // **A fuel budget that cannot run out**, so the epoch is the only thing that can end
        // this call.
        //
        // A finite budget made this test flaky under parallel load, and the reason is worth
        // stating: ~100 M fuel is what the synchronous path burns in the ~2.1 ms it takes
        // the ticker to fire twice (see the measured table above). With a 200 M budget the
        // two are in a **race**, and if the ticker thread is starved for a few milliseconds
        // by a loaded machine, fuel wins and the trap is `FuelExhausted` instead of
        // `EpochDeadlineExceeded`.
        //
        // That is a race in the *test*, not in the host: the host is forbidden from resuming
        // a synchronous call, so both traps are correct answers to "why did this stop?" —
        // only the epoch one is what this test is about. Removing the fuel ceiling removes
        // the race rather than widening its window. A larger finite number would only make
        // the flake rarer, which is worse than fixing or failing it.
        //
        // `u64::MAX` rather than a hypothetical "off" because `StoreLimits::fuel` is a plain
        // `u64` and has no unlimited spelling. The guest is an infinite spin, so the epoch
        // deadline is what ends it — and if the epoch machinery were broken, this test would
        // hang rather than pass, which is the right failure for a control.
        //
        // The async twin keeps the finite budget, because there the comparison *is* the
        // point: it must survive two dozen epoch expiries before fuel runs out.
        let mut budgets = limits();
        budgets.fuel = u64::MAX;

        // `create`, not `create_async`: this is the control, and the whole
        // point is that the two constructors produce stores with different
        // entry rules. Using the async constructor here would make the control
        // fail at instantiation rather than at the epoch, testing the wrong
        // thing entirely.
        let instance = Instance::create(&engine, &prepared, &none(), budgets).expect("create");

        // A dedicated thread, for the same reason as in the async test: the
        // synchronous call never returns control, so the ticker must live
        // outside whatever the guest is occupying.
        let driver = engine.clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_for_ticker = std::sync::Arc::clone(&stop);
        let ticker = std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            while !stop_for_ticker.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(1));
                driver.increment_epoch();
            }
        });

        let outcome = instance.run(|store, wasm| {
            let f = wasm.get_typed_func::<(), ()>(&mut *store, "spin")?;
            f.call(&mut *store, ())
        });

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        ticker.join().expect("the ticker thread must not panic");

        let err = outcome
            .expect_err("a synchronous entry must trap at the epoch deadline; it cannot yield");

        // Assert on QQQ's own classification, not on the wasmtime text.
        //
        // The raw message for an epoch preemption is *"wasm trap: interrupt"*,
        // which contains neither "epoch" nor "deadline" — an earlier version of
        // this test searched the text for those words and failed against a
        // correct trap. `classify_trap` exists precisely to map that message to
        // a stable code, so the assertion belongs on the code.
        assert_eq!(
            err.code,
            ErrorCode::EpochDeadlineExceeded,
            "a synchronous entry must trap on the EPOCH, before fuel matters; \
             getting {:?} instead means the epoch never fired and the two tests \
             are not measuring the entry point. Message: {err}",
            err.code
        );

        // **`SEC-007`'s second half: the host survives.**
        //
        // A guest stopped by wall-clock preemption is the case where a host is
        // most likely to be left in a bad state, because the interruption came
        // from *outside* the guest's control flow — it did not trap itself, it was
        // cut off mid-instruction-sequence. Asserting only the code would leave
        // "the guest was stopped" proven and "the host still works" assumed.
        //
        // The same engine, a fresh instance, a benign component run to
        // completion. This is the assertion `SEC-007` actually asks for.
        let ok = PreparedComponent::compile(&engine, OK_WAT.as_bytes()).expect("compiles");
        let after = Instance::create(&engine, &ok, &none(), limits())
            .expect("the host must still instantiate after a preempted guest");
        let value = after
            .run(|store, instance| {
                let f = instance.get_typed_func::<(), (u32,)>(&mut *store, "f")?;
                f.call(&mut *store, ())
            })
            .expect("the host must still run components after a preempted guest");
        assert_eq!(
            value.0, 7,
            "the host survived a guest cut off by wall-clock preemption"
        );
    }

    /// A poisoned instance refuses to run on the async path too.
    ///
    /// The synchronous guard in `run` has a test; this one exists because the
    /// async path is a second entry point with its own guard, and a guard
    /// asserted in only one of two paths is a guard that will be forgotten in
    /// the second.
    #[tokio::test]
    async fn a_poisoned_instance_refuses_to_run_async() {
        let engine = engine();
        let prepared = PreparedComponent::compile(&engine, OK_WAT.as_bytes()).expect("compiles");
        let mut instance = Instance::create_async(&engine, &prepared, &none(), limits())
            .await
            .expect("create");
        instance.poison();

        let result = instance
            .run_async(|_store, _wasm| Box::pin(async { Ok::<(), wasmtime::Error>(()) }))
            .await;

        let err = result.expect_err("a poisoned instance must refuse to execute");
        assert_eq!(err.code, ErrorCode::InternalInvariantViolated);
    }

    /// `ExecutionMode` reports what it says it reports.
    #[test]
    fn execution_mode_is_honest_about_which_path_it_names() {
        assert!(ExecutionMode::Async.is_async());
        assert!(!ExecutionMode::Sync.is_async());
        assert_eq!(ExecutionMode::Async.as_str(), "async");
        assert_eq!(ExecutionMode::Sync.as_str(), "sync");
    }

    /// The epoch yield policy is installed at a value the mechanism supports.
    ///
    /// The non-zero rule itself is enforced by the compiler in `lib.rs` — a
    /// runtime assertion over a constant could never fail, which clippy
    /// rejects and which would be worthless even if it compiled. What this test
    /// adds is the *value*: the constant is pinned so that changing it is a
    /// deliberate edit with a failing test, rather than a silent retune nobody
    /// measures.
    #[test]
    fn the_epoch_yield_delta_is_pinned() {
        assert_eq!(
            crate::EPOCH_YIELD_TICKS,
            1,
            "changing the yield delta changes timeslicing fairness for every \
             guest; see the constant's documentation in lib.rs before doing so"
        );
    }
}
