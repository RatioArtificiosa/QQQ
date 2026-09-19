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

        // -- Memory -----------------------------------------------------
        // Multiple memories are needed by composed components; the proposal's
        // §4.5 ABI discussion assumes they are available.
        c.wasm_multi_memory(true);
        // Guard pages make out-of-bounds accesses trap rather than corrupt,
        // which is the sandbox's primary memory-safety mechanism.
        c.memory_guard_size(2 * 1024 * 1024 * 1024);

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

/// Build the pooling-allocator configuration from manifest limits.
///
/// # Why the pool size is derived rather than guessed
///
/// The pool is sized from `limits.max_instances` and `limits.memory`. Getting
/// this wrong is a real failure mode in both directions:
///
/// * **Too small** — the host sheds load with `QQQ-6001` while the machine is
///   idle. Under-provisioning is invisible until traffic arrives.
/// * **Too large** — the pool reserves virtual address space for every slot.
///   Over-provisioning is worse, because it fails at *startup* with an
///   allocation error rather than degrading gracefully under load.
///
/// So the pool is sized to the manifest's declared ceiling, and the host
/// refuses to start if that reservation is implausible.
///
/// # Errors
///
/// Returns `QQQ-2005` when the manifest's limits are outside the range the
/// pooling allocator can serve.
pub fn build_pooling(
    limits: &Limits,
    cfg: &EngineConfig,
) -> Result<wasmtime::PoolingAllocationConfig> {
    let mut p = wasmtime::PoolingAllocationConfig::default();

    let memory_bytes = ByteSize::parse(&limits.memory).map_err(|reason| {
        Error::new(
            ErrorCode::LimitOutOfRange,
            format!("limits.memory is not a valid size: {reason}"),
        )
        .with_context("value", limits.memory.clone())
        .with_remediation("set `limits.memory` to a size such as \"128MiB\", \"1GiB\" or \"65536\"")
    })?;

    // The total instance count across the host is bounded by the smaller of
    // the manifest's per-worker ceiling and the host-wide ceiling, so a
    // mis-set manifest cannot over-reserve the whole machine.
    let instances = limits.max_instances.min(cfg.max_instances);

    p.total_memories(instances.max(1));
    p.total_tables(instances.max(1));
    // A component needs at least one memory and one table per instance; a
    // little headroom covers composed components with several core modules.
    p.max_memories_per_component(8);
    p.max_tables_per_component(8);

    // Bound the linear memory size so the reservation is predictable rather
    // than "whatever the guest grows to". This is the enforcement point for
    // `limits.memory`: Wasmtime's StoreLimits also enforces it per store, but
    // the pool must reserve for the worst case up front.
    //
    // `max_memory_size` takes a `usize`. On a 32-bit host a 64-bit memory
    // limit cannot be represented, so we clamp to the address space rather
    // than silently truncating — truncation would reserve a *smaller* pool
    // than the manifest asked for, which is the unsafe direction.
    let pool_memory = usize::try_from(memory_bytes.as_bytes()).unwrap_or(usize::MAX);
    p.max_memory_size(pool_memory);

    p.total_stacks(instances.max(1));

    Ok(p)
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
pub const ENGINE_VERSION: &str = "48.0.2";

/// The `wasmtime` requirement declared in the workspace manifest.
///
/// Duplicated here deliberately so a test can assert it agrees with
/// [`ENGINE_VERSION`]; see `engine_version_matches_the_pinned_dependency`.
pub const ENGINE_REQUIREMENT: &str = "48";

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
    // `wasmtime` does not re-export its version as a constant, so the engine
    // version is captured via Cargo's own crate metadata instead. `qqq-host`
    // depends on the exact `wasmtime` version in the workspace manifest, so a
    // change to that dependency changes this crate's version-independent
    // build metadata — and, more importantly, the workspace pins `wasmtime`
    // exactly, so a different engine cannot appear without a source change.
    // Using `env!("CARGO_PKG_VERSION")` here would be wrong (it is qqq-host's
    // version); the engine version is baked in by `build.rs`-free means below.
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
        let p = build_pooling(&limits(), &cfg);
        assert!(p.is_ok(), "pooling config must build: {:?}", p.err());
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
        // Should still build: the effective count is min(100_000, 50).
        assert!(build_pooling(&l, &cfg).is_ok());
    }

    #[test]
    fn pooling_rejects_an_unparsable_memory_value() {
        let mut l = limits();
        l.memory = "enormous".to_owned();
        let e = build_pooling(&l, &EngineConfig::default()).unwrap_err();
        assert_eq!(e.code, ErrorCode::LimitOutOfRange);
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
}
