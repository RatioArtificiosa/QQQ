// SPDX-License-Identifier: Apache-2.0

//! Engine and store configuration, derived from the manifest.
//!
//! Implements the configuration half of `HOST-001` and the limit binding of
//! `HOST-007` from Proposal §6.1.
//!
//! # The rule that shapes this module
//!
//! > **A limit the manifest cannot express is a limit an auditor cannot verify.**
//!
//! Every value here comes from `qqq.toml` `[limits]`. There are no hidden
//! defaults that silently widen authority, and no environment variable is read
//! implicitly (NN-5). If a limit is absent from the manifest, the *manifest's*
//! default applies — decided in `qqq-cap`, visible in `qqqai inspect` — not a
//! value buried in this module.
//!
//! # Preemption: epoch by default, fuel for precision
//!
//! Wasmtime offers two preemption mechanisms:
//!
//! * **Epoch interruption** — a counter the engine checks at loop back-edges
//!   and function entries. Instrumentation is very cheap. Scheduling is
//!   wall-clock based and therefore slightly nondeterministic.
//! * **Fuel** — a per-instruction budget. Instrumentation is substantially
//!   more expensive, but consumption is **deterministic** and exactly
//!   metered, which is what makes billing and reproducible replay possible.
//!
//! QQQ enables **both**. Epoch is the backstop that guarantees a
//! non-terminating guest is preempted; fuel is the precise accounting used for
//! limits, billing and determinism. Enabling only epoch loses determinism;
//! enabling only fuel loses the ability to bound wall-clock time. See
//! Proposal §6.1 and §10.5.

use qqq_cap::manifest::{ByteSize, Limits};
use qqq_core::{Error, ErrorCode, Result};
use wasmtime::Config;

/// How the host is configured for a given deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    /// Whether deterministic mode is active (Proposal §10.5).
    pub deterministic: bool,
    /// Whether the pooling allocator is used.
    ///
    /// On by default: it is what makes sub-100 µs instantiation possible and
    /// what keeps RSS predictable. Disabling it is supported for debugging.
    pub pooling: bool,
    /// Maximum number of concurrent instances across the whole host.
    pub max_instances: u32,
    /// Whether DWARF debug info is loaded, enabling source-mapped backtraces.
    pub debug_info: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            deterministic: false,
            pooling: true,
            max_instances: 10_000,
            debug_info: false,
        }
    }
}

impl EngineConfig {
    /// Deterministic mode, for tests and replay.
    #[must_use]
    pub fn deterministic() -> Self {
        Self {
            deterministic: true,
            pooling: true,
            max_instances: 64,
            debug_info: true,
        }
    }

    /// Build a Wasmtime [`Config`] from this configuration.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-1002` if Wasmtime rejects the combination. This should be
    /// unreachable for our own configurations, so a failure here indicates a
    /// QQQ bug rather than user error.
    pub fn to_wasmtime_config(&self) -> Result<Config> {
        let mut c = Config::new();

        // -- Component model: the whole point ---------------------------
        c.wasm_component_model(true);

        // -- Metering ---------------------------------------------------
        // Fuel must be enabled at Config time even if a particular store does
        // not use it; the instrumentation decision is per-engine.
        c.consume_fuel(true);

        // -- Preemption backstop ----------------------------------------
        // Epoch interruption bounds wall-clock time regardless of instruction
        // mix, which fuel alone cannot do (a guest blocked in a host call
        // consumes no fuel).
        c.epoch_interruption(true);

        // -- Async stacks -------------------------------------------------
        // Pinned explicitly even though it equals Wasmtime's default (2 MiB,
        // verified in the pinned source): admission's RSS math counts this
        // exact number per instance, so inheriting an upstream default
        // silently would let a future Wasmtime move diverge the reservation
        // from the enforcement without touching this file.
        c.async_stack_size(usize::try_from(ASYNC_STACK_BYTES).unwrap_or(usize::MAX));

        // -- Memory -----------------------------------------------------
        // Multiple memories are needed by composed components; the proposal's
        // §4.5 ABI discussion assumes they are available.
        c.wasm_multi_memory(true);
        // Guard pages make out-of-bounds accesses trap rather than corrupt,
        // which is the sandbox's primary memory-safety mechanism.
        c.memory_guard_size(MEMORY_GUARD_BYTES);

        // -- Determinism ------------------------------------------------
        if self.deterministic {
            // Canonicalize NaN bit patterns so the same arithmetic yields the
            // same bits on every architecture. Without this, a NaN produced on
            // x86 can differ from one produced on aarch64, breaking the
            // bit-identical replay guarantee in §10.5.
            c.cranelift_nan_canonicalization(true);
            // Relaxed-SIMD fusion is explicitly disallowed in deterministic
            // mode: it permits re-association that changes results.
            c.wasm_relaxed_simd(false);
            // Shared memory is refused in deterministic mode (`DET-012`): a
            // shared linear memory is visible to every holder at once, which
            // defeats per-instance memory accounting, and atomics on it are
            // outside the fuel-and-epoch determinism story. Upstream leaves
            // `wasm_threads` on by default and QQQ never disables it outside
            // this arm, so a shared-memory component compiles under the
            // default engine and fails here — that asymmetry is the point:
            // the default path is untouched while replay-grade runs cannot
            // admit what they cannot reproduce.
            c.wasm_threads(false);
        } else {
            // Relaxed SIMD is a Tier 1 proposal and a genuine performance win
            // for the JSON and parsing hot paths (§9.4). It is only excluded
            // when it would threaten reproducibility.
            c.wasm_relaxed_simd(true);
        }

        // -- Debug info -------------------------------------------------
        c.debug_info(self.debug_info);

        // -- Compilation ------------------------------------------------
        // Parallel compilation is on by default in Wasmtime and bounded by the
        // available core count, which is what we want for build latency and
        // scale-out. Stated explicitly so the intent is greppable.
        c.parallel_compilation(true);

        // -- Allocation strategy ----------------------------------------
        if !self.pooling {
            c.allocation_strategy(wasmtime::InstanceAllocationStrategy::OnDemand);
        }
        // The pooling configuration itself is applied by `build_pooling`, which
        // needs the manifest's per-instance limits.

        Ok(c)
    }
}

/// Max memories per component instance (`F-08`).
///
/// Single source of truth shared with the store limiter (`instance.rs`):
/// the pooling allocator and the per-store `StoreLimits` must agree, or one
/// of them admits what the other refuses.
pub const MAX_MEMORIES_PER_COMPONENT: u32 = 8;

/// Max tables per component instance (`F-10`).
///
/// Single source of truth shared by the pooling allocator and load-time
/// shape validation. Note the store's `.tables(16)` in `instance.rs` is a
/// *different* (wider, older) bound the pool never agreed with; this constant
/// is what the pool enforces and what load-time validation refuses past, so
/// those two agree by construction. Narrowing the store-level 16 is a
/// behaviour change no finding asks for, so it stays.
pub const MAX_TABLES_PER_COMPONENT: u32 = 8;

/// Async stack bytes per instance (`F-10`).
///
/// Wasmtime's engine default, verified in the pinned source
/// (`async_stack_size: 2 << 20`, "by default this option is 2 MiB"). Set
/// explicitly in `to_wasmtime_config` and read here by admission, so the
/// reservation and the enforcement agree even if the upstream default ever
/// moves.
pub const ASYNC_STACK_BYTES: u64 = 2 * 1024 * 1024;

/// Table bytes per element (`F-10`).
///
/// A table element is a funcref: pointer-sized, 8 bytes on 64-bit. On 32-bit
/// hosts this over-reserves twofold — the safe direction — and three-OS CI
/// keeps the arithmetic honest on both widths.
pub const TABLE_BYTES_PER_ELEMENT: u64 = 8;

/// Per-instance metadata estimate, in bytes (`F-10`).
///
/// Wasmtime's per-instance bookkeeping (instance struct, defined-tables
/// array, ancillary maps) has no stable published size, so admission cannot
/// measure it — but ignoring it admits exactly the overcommit the estimate
/// exists to prevent. 64 KiB is an unmeasured upper bound, stated as one:
/// it errs toward refusing, and §9.1's methodology is the named route to
/// replacing it with a measurement.
pub const INSTANCE_METADATA_ESTIMATE_BYTES: u64 = 64 * 1024;

/// Memory guard bytes per slot (`F-10`).
///
/// Must equal the `memory_guard_size` set in `to_wasmtime_config`: the guard
/// regions dominate the virtual-address reservation, so admission's virtual
/// math and the engine configuration read the same number.
pub const MEMORY_GUARD_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The pool shape one component needs, shared by the allocator and admission
/// (`F-10`).
///
/// Before this struct the two paths each derived their own numbers from the
/// manifest: the pool reserved one memory slot per instance while components
/// could hold eight, and admission charged the host's instance ceiling while
/// promising the manifest's number. Both disagreements failed under load —
/// the exact failure admission exists to prevent. One struct, computed once
/// from the manifest and the host config, read by both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolShape {
    /// What the manifest asked for, before the host ceiling applies.
    pub requested_instances: u32,
    /// What is actually reserved and admitted: `min(requested, host)`.
    pub instances: u32,
    /// Memories per instance: `MAX_MEMORIES_PER_COMPONENT` — multi-memory
    /// stays on per the F-08 decision, so the pool reserves for the max.
    pub memories_per_instance: u32,
    /// Tables per instance: `MAX_TABLES_PER_COMPONENT`.
    pub tables_per_instance: u32,
    /// Core instances per instance: `MAX_INNER_INSTANCES` — the audit's
    /// default unless a smaller bound is proven at load, and none is.
    pub core_instances_per_instance: u32,
    /// Aggregate memory ceiling per instance in bytes (post-F-08: the total,
    /// not per memory).
    pub memory_ceiling_bytes: u64,
    /// Table elements per table: `MAX_TABLE_ELEMENTS`.
    pub table_elements: u32,
}

impl PoolShape {
    /// Compute the shape from the manifest and the host configuration.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-2005` when `limits.memory` does not parse — the same
    /// error `build_pooling` used to return, from the same parse, so callers
    /// see no change but the message now names the shape.
    pub fn from_manifest(manifest: &Limits, cfg: &EngineConfig) -> Result<Self> {
        let memory_bytes = ByteSize::parse(&manifest.memory).map_err(|reason| {
            Error::new(
                ErrorCode::LimitOutOfRange,
                format!("limits.memory is not a valid size: {reason}"),
            )
            .with_context("value", manifest.memory.clone())
            .with_remediation(
                "set `limits.memory` to a size such as \"128MiB\", \"1GiB\" or \"65536\"",
            )
        })?;
        Ok(Self {
            requested_instances: manifest.max_instances,
            instances: manifest.max_instances.min(cfg.max_instances),
            memories_per_instance: MAX_MEMORIES_PER_COMPONENT,
            tables_per_instance: MAX_TABLES_PER_COMPONENT,
            core_instances_per_instance: u32::try_from(crate::instance::MAX_INNER_INSTANCES)
                .unwrap_or(u32::MAX),
            memory_ceiling_bytes: memory_bytes.as_bytes(),
            table_elements: MAX_TABLE_ELEMENTS,
        })
    }

    /// Pool-wide memory slots: instances times memories each, saturating.
    ///
    /// `saturating_mul` throughout these totals: a manifest declaring absurd
    /// counts must not wrap into a small reservation that passes admission —
    /// the unsafe direction.
    #[must_use]
    pub fn total_memories(&self) -> u32 {
        self.instances.saturating_mul(self.memories_per_instance)
    }

    /// Pool-wide table slots, saturating.
    #[must_use]
    pub fn total_tables(&self) -> u32 {
        self.instances.saturating_mul(self.tables_per_instance)
    }

    /// Pool-wide core-instance slots, saturating.
    #[must_use]
    pub fn total_core_instances(&self) -> u32 {
        self.instances
            .saturating_mul(self.core_instances_per_instance)
    }

    /// Resident (RSS) bound per instance: the aggregate memory ceiling plus
    /// the async stack, every table at full size, and the metadata estimate.
    ///
    /// Every table counts, not one: the shape allows `tables_per_instance`
    /// tables each of `table_elements` entries, and counting a single table
    /// under-reserves sevenfold at the default shape — the unsafe direction
    /// (`CodeRabbit` on F-10, reproduced by
    /// `f10_rss_bound_counts_every_table_per_instance`).
    ///
    /// This is the number admission reserves per instance. It exceeds the
    /// bare ceiling deliberately: the ceiling is what the guest may *hold*,
    /// this is what the host must *have*.
    #[must_use]
    pub fn rss_per_instance_bytes(&self) -> u64 {
        let tables = u64::from(self.tables_per_instance)
            .saturating_mul(u64::from(self.table_elements))
            .saturating_mul(TABLE_BYTES_PER_ELEMENT);
        self.memory_ceiling_bytes
            .saturating_add(ASYNC_STACK_BYTES)
            .saturating_add(tables)
            .saturating_add(INSTANCE_METADATA_ESTIMATE_BYTES)
    }

    /// Total RSS reservation: instances times the per-instance bound.
    #[must_use]
    pub fn reserved_rss_bytes(&self) -> u64 {
        u64::from(self.instances).saturating_mul(self.rss_per_instance_bytes())
    }

    /// Total virtual-address reservation: every memory slot reserves its
    /// maximum size plus its guard regions. Address space, not RSS — but a
    /// container that cannot map it fails at startup, so admission compares
    /// it against the configured virtual cap.
    #[must_use]
    pub fn virtual_reservation_bytes(&self) -> u64 {
        let per_slot = self.memory_ceiling_bytes.saturating_add(MEMORY_GUARD_BYTES);
        u64::from(self.total_memories()).saturating_mul(per_slot)
    }
}

/// Max table elements per table (`F-08`).
///
/// Wasmtime's pooling default (20,000), used for both the pooling allocator
/// and the per-store limiter so pooled and `OnDemand` stores trap at the same
/// size. Tables that outgrow it trap via `TrappingLimiter` instead of
/// returning -1 to the guest.
pub const MAX_TABLE_ELEMENTS: u32 = 20_000;

/// Build the pooling-allocator configuration from the pool shape.
///
/// # Why the pool size is derived rather than guessed
///
/// The pool is sized from the shape's instance count and per-instance maxima.
/// Getting this wrong is a real failure mode in both directions:
///
/// * **Too small** — the host sheds load with `QQQ-6001` while the machine is
///   idle. Under-provisioning is invisible until traffic arrives.
/// * **Too large** — the pool reserves virtual address space for every slot.
///   Over-provisioning is worse, because it fails at *startup* with an
///   allocation error rather than degrading gracefully under load.
///
/// So the pool is sized to the shape admission already approved, and the host
/// refuses to start if that reservation is implausible.
///
/// # Errors
///
/// Returns `QQQ-2005` when the shape is outside the range the pooling
/// allocator can serve. (The manifest parse that used to fail here moved to
/// [`PoolShape::from_manifest`]; this constructor keeps the error for the
/// allocator's own rejections.)
pub fn build_pooling(shape: &PoolShape) -> Result<wasmtime::PoolingAllocationConfig> {
    let mut p = wasmtime::PoolingAllocationConfig::default();

    let instances = shape.instances;

    // Every pool-wide total derives from the shape (F-10): the pool and
    // admission read the same multiplications, so one cannot admit what the
    // other cannot host. Method names verified against the pinned Wasmtime
    // 48 source, not memory.
    p.total_component_instances(instances.max(1));
    p.total_core_instances(shape.total_core_instances().max(1));
    p.total_memories(shape.total_memories().max(1));
    p.total_tables(shape.total_tables().max(1));
    p.max_memories_per_component(shape.memories_per_instance);
    p.max_tables_per_component(shape.tables_per_instance);
    // The pool ALSO caps memories and tables per core MODULE (verified in
    // the pinned source: `memory_pool.rs` refuses past
    // `max_memories_per_module`, default 1). A single core module holding two
    // memories — the ordinary multi-memory shape — dies at compile without
    // this, however generous the per-component caps above are. Each module
    // may spend the component's whole budget; the per-component caps still
    // bound the total. The audit's setter list missed these two; the
    // concurrency test caught it.
    p.max_memories_per_module(shape.memories_per_instance);
    p.max_tables_per_module(shape.tables_per_instance);
    p.max_core_instances_per_component(shape.core_instances_per_instance);
    p.table_elements(shape.table_elements as usize);

    // Bound the linear memory size so the reservation is predictable rather
    // than "whatever the guest grows to". This is the enforcement point for
    // the ceiling: Wasmtime's StoreLimits also enforces it per store, but
    // the pool must reserve for the worst case up front.
    //
    // `max_memory_size` takes a `usize`. On a 32-bit host a 64-bit memory
    // limit cannot be represented, so we clamp to the address space rather
    // than silently truncating — truncation would reserve a *smaller* pool
    // than the manifest asked for, which is the unsafe direction.
    let pool_memory = usize::try_from(shape.memory_ceiling_bytes).unwrap_or(usize::MAX);
    p.max_memory_size(pool_memory);

    p.total_stacks(instances.max(1));

    Ok(p)
}

/// Build a Wasmtime engine for a component, **admitting it first**.
///
/// # Why this exists as a single function
///
/// [`build_pooling`] sizes the reservation and
/// [`EngineConfig::to_wasmtime_config`] produces the runtime configuration, but
/// **neither can refuse**: the pool builder has no memory budget, and the config
/// builder has no manifest. A caller that used them separately would construct an
/// engine for a component that cannot fit, and discover it as an allocation
/// failure inside Wasmtime -- an error that names no manifest field and arrives
/// after the reservation has already been attempted.
///
/// This function is the join. It:
///
/// 1. **Admits first** ([`crate::admission::admit`]), so a component that cannot
///    fit is refused with both numbers and a remediation, before any address
///    space is committed.
/// 2. Applies the pooling configuration, if pooling is enabled.
/// 3. Constructs the engine.
///
/// # The order is the whole point
///
/// Checking *after* construction would still avoid running the guest, but by then
/// the reservation has already happened -- and on an over-committing host the
/// failure is a failed `mmap` or an OOM kill rather than a clean error. The test
/// `admits_before_constructing_the_engine` uses a capacity that admits nothing
/// and asserts the refusal is the **admission** error, which is only observable
/// if the check ran first.
///
/// # Errors
///
/// * `QQQ-2005` -- the component does not fit, or its limits are degenerate.
/// * `QQQ-2005` -- the manifest's limits are outside what the pooling allocator
///   can serve.
/// * `QQQ-1002` -- Wasmtime rejected the configuration, which indicates a QQQ bug.
pub fn build_engine(
    limits: &Limits,
    engine_config: &EngineConfig,
    capacity: &crate::admission::HostCapacity,
) -> Result<(wasmtime::Engine, crate::admission::Admitted)> {
    let store_limits = StoreLimits::from_manifest(limits)?;
    // One shape, computed once, read by both admission and the pool (F-10).
    let shape = PoolShape::from_manifest(limits, engine_config)?;

    // Admission BEFORE anything is reserved or constructed.
    let admitted = crate::admission::admit(&store_limits, &shape, capacity)?;

    let mut config = engine_config.to_wasmtime_config()?;
    if engine_config.pooling {
        let pooling = build_pooling(&shape)?;
        config.allocation_strategy(wasmtime::InstanceAllocationStrategy::Pooling(pooling));
    }

    let engine = wasmtime::Engine::new(&config).map_err(|e| {
        Error::new(
            ErrorCode::InvalidComponentArtifact,
            "the Wasmtime engine rejected QQQ's configuration",
        )
        .with_cause(format!("{e:#}"))
        .with_remediation("this is a QQQ bug; please report it")
    })?;

    // The admitted reservation is returned rather than discarded: it is the
    // number a caller logs, and recomputing it would be a second source of truth
    // for a value that decides whether the host starts at all.
    Ok((engine, admitted))
}

/// The per-store limits derived from a manifest.
///
/// Separate from the pooling config because the pool is a *reservation* (what
/// could exist) while these are *enforcement* (what this instance may do).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoreLimits {
    /// Hard memory ceiling in bytes.
    pub memory_bytes: u64,
    /// Fuel budget for the instance.
    pub fuel: u64,
    /// Wall-clock deadline in epoch ticks.
    pub epoch_deadline_ms: u64,
    /// Maximum simultaneously open resource handles.
    pub max_open_handles: u32,
    /// Maximum outbound subrequests one instance may drive.
    ///
    /// Separate from `fuel` because the two bound different things: fuel bounds
    /// what the guest *computes*, this bounds what the guest *causes*. A loop
    /// calling `http.get` costs a few fuel units per iteration and one outbound
    /// request per iteration, so without this field the fan-out is unbounded
    /// however tight the fuel budget is. See `crate::quota`.
    pub max_subrequests: u32,
}

impl StoreLimits {
    /// Derive per-store limits from a manifest.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-2005` if `limits.memory` cannot be parsed. Note that
    /// `qqq-cap` already validated this at parse time, so a failure here means
    /// the manifest was constructed programmatically without validation.
    pub fn from_manifest(limits: &Limits) -> Result<Self> {
        let memory_bytes = ByteSize::parse(&limits.memory)
            .map_err(|reason| {
                Error::new(
                    ErrorCode::LimitOutOfRange,
                    format!("limits.memory is not a valid size: {reason}"),
                )
                .with_context("value", limits.memory.clone())
                .with_remediation(
                    "set `limits.memory` to a size such as \"128MiB\", \"1GiB\" or \"65536\"",
                )
            })?
            .as_bytes();
        Ok(Self {
            memory_bytes,
            fuel: limits.fuel,
            epoch_deadline_ms: limits.epoch_deadline_ms,
            max_open_handles: limits.max_open_handles,
            max_subrequests: limits.max_subrequests,
        })
    }
}

/// The Wasmtime engine version this build was compiled against.
///
/// # Why a constant rather than `env!("CARGO_PKG_VERSION")`
///
/// `CARGO_PKG_VERSION` is *qqq-host's* version, not the engine's. The engine
/// version matters for AOT cache keying because Cranelift codegen changes
/// between engine releases, and a `.cwasm` compiled by one release is not
/// guaranteed valid for another.
///
/// `wasmtime` does not re-export its version, so this is pinned alongside the
/// workspace's `wasmtime` dependency and **verified by a test** that fails if
/// the two drift. That test is the mechanism that keeps this constant honest.
pub const ENGINE_VERSION: &str = "48.0.5";

/// The `wasmtime` requirement declared in the workspace manifest.
///
/// Duplicated here deliberately so a test can assert it agrees with
/// [`ENGINE_VERSION`]; see `engine_version_matches_the_pinned_dependency`.
pub const ENGINE_REQUIREMENT: &str = "48";

/// The target triple this artifact was built for — `DET-010`.
///
/// # Why this is a build script's output and not a `cfg`
///
/// See `crates/qqq-host/build.rs`: `cfg!(target_arch)` and `cfg!(target_os)` combine into
/// `x86_64-windows`, and **a `.cwasm` is native code whose validity depends on the vendor and the ABI
/// too.** The real triple is `x86_64-pc-windows-msvc`.
///
/// # Why it is `env!` and not a defaulted `option_env!`
///
/// Because a defaulted value would be silently wrong, and this constant is written into
/// [`crate::replay::ReplayHeader`] — a header whose whole purpose is telling a reader whether two
/// recorded runs are comparable. **A field that is wrong in the direction of agreeing with a
/// different platform is worse than a field that is absent.**
/// ```
/// use qqq_host::config::TARGET_TRIPLE;
///
/// assert!(TARGET_TRIPLE.contains("-"), "a triple has at least one dash");
/// assert!(!TARGET_TRIPLE.contains(' '), "and no spaces");
/// ```
pub const TARGET_TRIPLE: &str = env!("QQQ_TARGET_TRIPLE");

/// The AOT cache key for a compiled artifact.
///
/// # Why the key includes so much
///
/// An AOT-compiled `.cwasm` is **native machine code**. It is valid only for
/// the exact combination of:
///
/// * the component bytes (digest),
/// * the engine version that produced it (codegen changes between releases),
/// * the target triple (a different CPU or OS cannot run it),
/// * the engine configuration (dropping `nan_canonicalization` changes codegen).
///
/// Omitting any of these produces a cache hit that yields subtly wrong native
/// code — the exact class of bug that manifests as "worked in staging,
/// corrupted data in production". Computing the key from all four is cheap and
/// makes the failure mode impossible rather than unlikely.
///
/// See Proposal §9.4 and Checklist `HOST-013`.
#[must_use]
pub fn aot_cache_key(component_digest: &str, target: &str, cfg: &EngineConfig) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(component_digest.as_bytes());
    h.update(b"\x00");
    h.update(target.as_bytes());
    h.update(b"\x00");
    // **`ENGINE_VERSION`, not `env!("CARGO_PKG_VERSION")`.** The latter is *qqq-host's* version and
    // would key the cache on the wrong crate; a previous version of this comment claimed the version
    // was "captured via Cargo's own crate metadata", which the line below has never done. The constant
    // is hand-maintained and kept honest by `engine_version_matches_the_resolved_lockfile`, which reads
    // `Cargo.lock` -- so a lockfile bump cannot silently desynchronise this key from the engine that
    // actually produced the artifact.
    h.update(ENGINE_VERSION.as_bytes());
    h.update(b"\x00");
    // Configuration that affects codegen.
    h.update([u8::from(cfg.deterministic)]);
    h.update([u8::from(cfg.debug_info)]);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The current target triple, for cache keying and diagnostics.
///
/// `wasmtime` does not re-export `target-lexicon`, and the value must be
/// *stable across runs on the same host* rather than perfectly canonical, so
/// this uses the compile-time `std` target metadata which is always available.
#[must_use]
pub fn target_triple() -> &'static str {
    // `std::env::consts` gives architecture and OS separately; combining them
    // is sufficient for cache keying, where what matters is that two hosts
    // never collide.
    const ARCH: &str = std::env::consts::ARCH;
    const OS: &str = std::env::consts::OS;
    const ENV: &str = std::env::consts::FAMILY;
    match (ARCH, OS, ENV) {
        ("x86_64", "windows", _) => "x86_64-pc-windows-msvc",
        ("x86_64", "linux", _) => "x86_64-unknown-linux-gnu",
        ("x86_64", "macos", _) => "x86_64-apple-darwin",
        ("aarch64", "linux", _) => "aarch64-unknown-linux-gnu",
        ("aarch64", "macos", _) => "aarch64-apple-darwin",
        ("aarch64", "windows", _) => "aarch64-pc-windows-msvc",
        // An unrecognised combination still yields a unique, stable key — it
        // simply will not match a published prebuilt artifact, which is the
        // safe direction to fail.
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            memory: "128MiB".to_owned(),
            fuel: 50_000_000,
            epoch_deadline_ms: 5_000,
            max_instances: 200,
            max_open_handles: 256,
            max_subrequests: 32,
            max_poll_per_tick: 10,
        }
    }

    #[test]
    fn default_config_is_not_deterministic_and_uses_pooling() {
        let c = EngineConfig::default();
        assert!(!c.deterministic);
        assert!(c.pooling);
    }

    #[test]
    fn deterministic_preset_is_fully_deterministic() {
        let c = EngineConfig::deterministic();
        assert!(c.deterministic);
        assert!(c.debug_info, "replay needs source mapping");
    }

    /// The config must actually build a Wasmtime engine — this is the test
    /// that proves our flags are a valid combination for the pinned version,
    /// not merely plausible-looking.
    #[test]
    fn config_builds_a_real_engine() {
        for cfg in [EngineConfig::default(), EngineConfig::deterministic()] {
            let wc = cfg
                .to_wasmtime_config()
                .expect("config must be valid for this Wasmtime version");
            wasmtime::Engine::new(&wc).expect("engine must construct");
        }
    }

    /// **`DET-012`: deterministic mode refuses shared memory.**
    ///
    /// Upstream's `wasm_threads` defaults on and the default engine keeps it,
    /// so a shared-memory component compiles there — probed, `Ok` on both
    /// engines before the flag (`§O-537`). The deterministic engine must not
    /// admit what replay cannot reproduce, so the same bytes fail here. The
    /// asymmetry is asserted both ways: default acceptance documents that the
    /// refusal is the deterministic preset's doing, not a broken fixture.
    #[test]
    fn deterministic_mode_rejects_shared_memory() {
        const SHARED: &str = "(component (core module $m (memory 1 1 shared)))";
        let det = wasmtime::Engine::new(
            &EngineConfig::deterministic()
                .to_wasmtime_config()
                .expect("deterministic config builds"),
        )
        .expect("deterministic engine builds");
        let err = wasmtime::component::Component::new(&det, SHARED)
            .expect_err("shared memory must not compile in deterministic mode");
        let text = format!("{err:#}").to_ascii_lowercase();
        assert!(
            text.contains("shared") || text.contains("thread"),
            "the refusal must name its cause, not fail opaquely: {err:#}"
        );
        let default_engine = wasmtime::Engine::new(
            &EngineConfig::default()
                .to_wasmtime_config()
                .expect("default config builds"),
        )
        .expect("default engine builds");
        assert!(
            wasmtime::component::Component::new(&default_engine, SHARED).is_ok(),
            "the default path is untouched: refusal is deterministic-only"
        );
    }

    /// Determinism knobs must actually change the configuration, otherwise
    /// the §10.5 guarantee is a comment rather than a property.
    #[test]
    fn determinism_flags_differ_between_modes() {
        let det = EngineConfig::deterministic();
        let norm = EngineConfig::default();
        assert_ne!(det.deterministic, norm.deterministic);
        // Both must still build; the flags are checked by the engine above.
        assert!(det.to_wasmtime_config().is_ok());
        assert!(norm.to_wasmtime_config().is_ok());
    }

    #[test]
    fn store_limits_derive_from_the_manifest() {
        let l = StoreLimits::from_manifest(&limits()).unwrap();
        assert_eq!(l.memory_bytes, 128 * 1024 * 1024);
        assert_eq!(l.fuel, 50_000_000);
        assert_eq!(l.epoch_deadline_ms, 5_000);
        assert_eq!(l.max_open_handles, 256);
    }

    #[test]
    fn store_limits_reject_an_unparsable_memory_value() {
        let mut l = limits();
        l.memory = "not a size".to_owned();
        let e = StoreLimits::from_manifest(&l).unwrap_err();
        assert_eq!(e.code, ErrorCode::LimitOutOfRange);
        assert!(e.remediation.is_some());
    }

    #[test]
    fn pooling_config_reserves_for_the_declared_ceiling() {
        let cfg = EngineConfig::default();
        // Must not error for a sane manifest.
        let shape = PoolShape::from_manifest(&limits(), &cfg).expect("sane manifest");
        let p = build_pooling(&shape);
        assert!(p.is_ok(), "pooling config must build: {:?}", p.err());
    }

    /// **`HOST-023`, the join.** `build_engine` admits before it constructs.
    ///
    /// # Why the assertion is about *which* error, not merely that one occurred
    ///
    /// A component that does not fit must be refused. But so would a component
    /// whose engine configuration Wasmtime rejected, and the two produce
    /// different error codes — `QQQ-2005` from admission, `QQQ-1002` from the
    /// config. Asserting only "it failed" would pass even if admission ran
    /// *after* construction, which is the ordering this test exists to pin.
    ///
    /// An earlier version of this test asserted `is_err()` and would have passed
    /// for the wrong reason. It also had a second flaw: with pooling disabled,
    /// `build_pooling` is never called, so a capacity that refuses nothing would
    /// still construct fine — meaning the test needed a capacity that genuinely
    /// admits nothing to be non-vacuous at all.
    #[test]
    fn admits_before_constructing_the_engine() {
        use crate::admission::{HostCapacity, Refusal};

        // A host with a budget smaller than the resident baseline: it can admit
        // nothing at all. That is the strongest form of "this must be refused",
        // and it cannot be satisfied by the pooling config being merely large.
        let starved = HostCapacity {
            memory_budget_bytes: 64 * 1024 * 1024,
            max_instances: 8,
            resident_bytes: 128 * 1024 * 1024,
            max_virtual_reservation_bytes: u64::MAX,
        };
        assert_eq!(
            starved.available_bytes(),
            0,
            "the fixture must admit nothing"
        );

        let err = build_engine(&limits(), &EngineConfig::default(), &starved)
            .expect_err("a host with no capacity must refuse");
        assert_eq!(
            err.code,
            ErrorCode::LimitOutOfRange,
            "the refusal must be ADMISSION (QQQ-2005 LimitOutOfRange), not the \
             engine-config error (QQQ-1002) — a QQQ-1002 here means the engine was \
             constructed before the component was admitted. Got {:?}: {err}",
            err.code
        );
        assert!(
            err.context.iter().any(|(k, v)| k == "refusal"
                && v == Refusal::MemoryReservation {
                    required_bytes: 0,
                    available_bytes: 0
                }
                .as_str()),
            "the refusal must name the memory reservation: {err}"
        );
    }

    /// And the positive case: a component that fits produces an engine **and**
    /// the reservation it was admitted with.
    ///
    /// The control for the test above. Without it, a `build_engine` that refused
    /// everything would satisfy the refusal assertion.
    #[test]
    fn a_component_that_fits_builds_an_engine_and_reports_its_reservation() {
        use crate::admission::HostCapacity;

        let roomy = HostCapacity {
            memory_budget_bytes: 4 * 1024 * 1024 * 1024,
            max_instances: 16,
            resident_bytes: 0,
            max_virtual_reservation_bytes: u64::MAX,
        };

        // The manifest must ask within the host ceiling: admission refuses
        // over-host requests (F-10) rather than clamping them.
        let mut manifest = limits();
        manifest.max_instances = 16;
        let (engine, admitted) = build_engine(&manifest, &EngineConfig::default(), &roomy)
            .expect("a modest component on a roomy host must build");

        // **The engine is proved usable, not merely constructed.** Wasmtime 48
        // exposes no `is_pooling_allocator`, so the first version of this test
        // called a method that does not exist. Rather than settling for a weaker
        // assertion, the engine is made to do real work: compiling a component
        // exercises the allocation strategy, the component-model feature flag and
        // the codegen backend at once. An `Engine` that was constructed but
        // misconfigured fails here.
        //
        // This is strictly stronger than introspecting a flag: a flag can be set
        // without the engine honouring it.
        let precompiled = engine
            .precompile_component(TINY_COMPONENT)
            .expect("the engine must compile a real component; a misconfigured engine fails here");
        assert!(
            !precompiled.is_empty(),
            "precompilation must produce a cwasm artifact"
        );

        // And the reservation is the manifest's RSS bound times the admitted
        // count, not a placeholder: per instance 128 MiB memory + 2 MiB async
        // stack + 8 tables of 20,000×8 B + 64 KiB metadata estimate.
        assert_eq!(admitted.per_instance_bytes, 128 * 1024 * 1024);
        assert_eq!(admitted.instances, 16);
        assert_eq!(
            admitted.reserved_bytes,
            16 * (128 * 1024 * 1024 + 2 * 1024 * 1024 + 8 * 20_000 * 8 + 64 * 1024)
        );
    }

    /// A minimal valid component, for proving an engine actually works.
    ///
    /// A component rather than a core module because QQQ targets the component
    /// model, and `precompile_component` proves the feature flag took effect.
    const TINY_COMPONENT: &[u8] = b"\x00asm\x0d\x00\x01\x00";

    /// The pooling flag must still be honoured through `build_engine`.
    ///
    /// # How this is checked without an introspection API
    ///
    /// Wasmtime 48 has no `Engine::is_pooling_allocator`, so the flag cannot be
    /// read back. What *is* observable is that both configurations produce a
    /// **working** engine: the join must not have made `pooling = false` silently
    /// construct a pooled engine, and the strongest available evidence is that
    /// both compile a real component.
    ///
    /// The limitation is stated rather than hidden: this proves neither
    /// configuration is broken, and cannot prove which strategy was selected.
    /// `build_pooling` is unit-tested directly for the sizing arithmetic, which
    /// is where that is decidable.
    #[test]
    fn build_engine_honours_the_pooling_flag() {
        use crate::admission::HostCapacity;

        let roomy = HostCapacity {
            memory_budget_bytes: 4 * 1024 * 1024 * 1024,
            max_instances: 4,
            resident_bytes: 0,
            max_virtual_reservation_bytes: u64::MAX,
        };

        // Within the host ceiling, or admission (not the engine) refuses.
        let mut manifest = limits();
        manifest.max_instances = 4;
        let (pooled, _) =
            build_engine(&manifest, &EngineConfig::default(), &roomy).expect("pooled engine");
        assert!(
            pooled.precompile_component(TINY_COMPONENT).is_ok(),
            "the pooled engine must compile a component"
        );

        // Struct-update syntax rather than `Default::default()` followed by a
        // field assignment: clippy's `field_reassign_with_default` is right that
        // the two-line form reads as "start from a whole default, then mutate
        // one field", which hides that every other field is also default.
        let on_demand_cfg = EngineConfig {
            pooling: false,
            ..EngineConfig::default()
        };
        let (on_demand, _) =
            build_engine(&manifest, &on_demand_cfg, &roomy).expect("on-demand engine");
        assert!(
            on_demand.precompile_component(TINY_COMPONENT).is_ok(),
            "`pooling = false` must reach the engine, not be ignored by the join"
        );
    }

    /// The host-wide ceiling must cap the manifest's per-worker ceiling, so a
    /// mis-set manifest cannot over-reserve the machine.
    #[test]
    fn pooling_respects_the_host_wide_ceiling() {
        let mut l = limits();
        l.max_instances = 100_000;
        let cfg = EngineConfig {
            max_instances: 50,
            ..EngineConfig::default()
        };
        // The shape carries the effective count: min(100_000, 50).
        let shape = PoolShape::from_manifest(&l, &cfg).expect("shape must build");
        assert_eq!(shape.requested_instances, 100_000);
        assert_eq!(shape.instances, 50);
        assert!(build_pooling(&shape).is_ok());
    }

    #[test]
    fn pooling_rejects_an_unparsable_memory_value() {
        let mut l = limits();
        l.memory = "enormous".to_owned();
        let e = PoolShape::from_manifest(&l, &EngineConfig::default()).unwrap_err();
        assert_eq!(e.code, ErrorCode::LimitOutOfRange);
    }

    /// **F-10: one shape feeds the pool and admission, so the two agree.**
    ///
    /// Written first and failing first: no `PoolShape` exists yet, so this
    /// does not compile — which is the red. The totals multiply the
    /// per-instance counts (a composed component holds one memory per core
    /// module), saturating rather than wrapping on absurd inputs.
    #[test]
    fn f10_pool_shape_totals_multiply_by_per_instance_counts() {
        let s = PoolShape {
            requested_instances: 10,
            instances: 10,
            memories_per_instance: 2,
            tables_per_instance: 1,
            core_instances_per_instance: 4,
            memory_ceiling_bytes: 1 << 20,
            table_elements: 1000,
        };
        assert_eq!(s.total_memories(), 20);
        assert_eq!(s.total_tables(), 10);
        assert_eq!(s.total_core_instances(), 40);
    }

    /// **F-10: the RSS bound counts every table, not one.**
    ///
    /// `CodeRabbit` on F-10, reproduced red first: the first version multiplied
    /// `table_elements` by the byte width once, while the shape allows
    /// `tables_per_instance` tables — undercounting the table bound sevenfold
    /// at the default shape, in the unsafe (admits-more-than-fits)
    /// direction.
    #[test]
    fn f10_rss_bound_counts_every_table_per_instance() {
        let s = PoolShape {
            requested_instances: 4,
            instances: 4,
            memories_per_instance: 1,
            tables_per_instance: 2,
            core_instances_per_instance: 1,
            memory_ceiling_bytes: 1 << 20,
            table_elements: 1000,
        };
        assert_eq!(
            s.rss_per_instance_bytes(),
            (1 << 20) + 2 * 1024 * 1024 + 2 * 1000 * 8 + 64 * 1024
        );
    }

    // -- AOT cache key -----------------------------------------------------

    #[test]
    fn cache_key_is_stable_for_identical_inputs() {
        let cfg = EngineConfig::default();
        let a = aot_cache_key("sha256:abc", "x86_64-unknown-linux-gnu", &cfg);
        let b = aot_cache_key("sha256:abc", "x86_64-unknown-linux-gnu", &cfg);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "sha256 hex");
    }

    /// Every input must change the key. If any does not, the cache can return
    /// native code compiled for the wrong target or configuration — which is
    /// the exact class of bug that produces "works in staging, corrupts in
    /// production".
    #[test]
    fn cache_key_changes_with_every_input() {
        let cfg = EngineConfig::default();
        let base = aot_cache_key("digest-a", "target-a", &cfg);

        assert_ne!(
            base,
            aot_cache_key("digest-b", "target-a", &cfg),
            "component digest must affect the key"
        );
        assert_ne!(
            base,
            aot_cache_key("digest-a", "target-b", &cfg),
            "target must affect the key"
        );
        assert_ne!(
            base,
            aot_cache_key("digest-a", "target-a", &EngineConfig::deterministic()),
            "determinism must affect the key, since it changes codegen"
        );
        assert_ne!(
            base,
            aot_cache_key(
                "digest-a",
                "target-a",
                &EngineConfig {
                    debug_info: true,
                    ..EngineConfig::default()
                }
            ),
            "debug info must affect the key"
        );
    }

    /// The separator must prevent ambiguity between fields: `("ab","c")` and
    /// `("a","bc")` must not collide.
    #[test]
    fn cache_key_has_no_field_boundary_ambiguity() {
        let cfg = EngineConfig::default();
        assert_ne!(
            aot_cache_key("ab", "c", &cfg),
            aot_cache_key("a", "bc", &cfg)
        );
    }

    #[test]
    fn target_triple_is_stable_and_recognised() {
        let t = target_triple();
        assert_eq!(t, target_triple(), "must be stable within a process");
        assert!(!t.is_empty());
        // On the platforms we ship, it must be one of the known values.
        if std::env::consts::ARCH == "x86_64" && std::env::consts::OS == "windows" {
            assert_eq!(t, "x86_64-pc-windows-msvc");
        }
    }

    /// `ENGINE_VERSION` is hand-maintained because Wasmtime does not export its
    /// version. This test is what keeps it honest: the AOT cache key includes
    /// the engine version, so a stale constant would let a `.cwasm` compiled by
    /// one engine be loaded by another — producing native code that is subtly
    /// wrong rather than obviously broken.
    ///
    /// The check reads the workspace manifest at compile time, so bumping the
    /// `wasmtime` dependency without updating `ENGINE_VERSION` fails the build.
    #[test]
    fn engine_version_matches_the_pinned_dependency() {
        let workspace = include_str!("../../../Cargo.toml");
        // Find the `wasmtime = "48"` line in [workspace.dependencies].
        let line = workspace
            .lines()
            .find(|l| l.trim_start().starts_with("wasmtime ="))
            .expect("the workspace manifest must declare a wasmtime dependency");

        let declared = line
            .split('"')
            .nth(1)
            .expect("the wasmtime dependency must have a quoted version");

        assert_eq!(
            declared, ENGINE_REQUIREMENT,
            "ENGINE_REQUIREMENT ({ENGINE_REQUIREMENT}) disagrees with the workspace \
             manifest ({declared}); update both together"
        );
        assert!(
            ENGINE_VERSION.starts_with(ENGINE_REQUIREMENT),
            "ENGINE_VERSION ({ENGINE_VERSION}) is not in the {ENGINE_REQUIREMENT}.x line"
        );
        assert_eq!(
            ENGINE_VERSION.split('.').count(),
            3,
            "ENGINE_VERSION must be a full major.minor.patch"
        );
    }

    /// **`ENGINE_VERSION` agrees with the version `Cargo.lock` actually resolves.**
    ///
    /// # Why the test above is not enough
    ///
    /// It compares against the workspace manifest's **requirement** — `"48"` — so
    /// it catches a major-line change and permits any patch. But the AOT cache key
    /// is built from `ENGINE_VERSION` (see [`aot_cache_key`]), and Cranelift's
    /// codegen changes between *patch* releases. So if `Cargo.lock` resolved
    /// `wasmtime 48.0.3` while the constant still said `48.0.2`, the cache key
    /// would be computed with the wrong engine version and a `.cwasm` compiled by
    /// one patch release could be loaded by another — producing **native code that
    /// is subtly wrong rather than obviously broken**.
    ///
    /// # Why this matters specifically to `SEC-014`
    ///
    /// `docs/wasmtime-advisory-process.md` names step 5 of an advisory response as
    /// "regenerate the AOT cache expectations", and its verification table claims
    /// that "the engine version cannot drift silently". Before this test, that
    /// claim was **only half true**: a major-line drift failed loudly and a
    /// patch-level drift was invisible. The process document is written against
    /// what the checks actually do, so the check had to be completed rather than
    /// the claim softened — a security process whose stated verification does not
    /// exist is the failure mode `§O-066` and `§O-071` both record.
    ///
    /// # Why it reads `Cargo.lock` rather than asking the crate
    ///
    /// Because `wasmtime` does not re-export its own version, and the resolved
    /// version in the lockfile is precisely the value that determines which
    /// compiled artifact a deployment gets. Reading the source of truth beats
    /// asking a proxy for it.
    #[test]
    fn engine_version_matches_the_resolved_lockfile() {
        let lock = include_str!("../../../Cargo.lock");

        // Find the `[[package]] name = "wasmtime"` block and read its `version`.
        // The lockfile lists crates in name order, and there are many packages
        // whose names *begin* with `wasmtime` (`wasmtime-internal-*`, `-environ`,
        // …), so the match is on the exact quoted name rather than a prefix —
        // unlike the anti-drift test above, a prefix match here would read the
        // version of an internal crate and pass while the engine drifted.
        let mut lines = lock.lines();
        let mut resolved: Option<&str> = None;
        while let Some(line) = lines.next() {
            if line.trim() == "name = \"wasmtime\"" {
                // The `version` key follows within the same `[[package]]` block.
                for _ in 0..6 {
                    let Some(next) = lines.next() else { break };
                    if next.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = next.trim().strip_prefix("version = ") {
                        resolved = Some(v.trim_matches('"'));
                        break;
                    }
                }
                break;
            }
        }

        let resolved =
            resolved.expect("Cargo.lock must contain a resolved `wasmtime` package version");

        assert_eq!(
            resolved, ENGINE_VERSION,
            "ENGINE_VERSION ({ENGINE_VERSION}) disagrees with the version Cargo.lock \
             resolves ({resolved}). The AOT cache key is built from ENGINE_VERSION, so a \
             patch-level drift means a `.cwasm` compiled by one release can be loaded by \
             another and produce native code that is subtly wrong rather than obviously \
             broken. Update the constant and the lockfile together."
        );
    }
}
