// SPDX-License-Identifier: Apache-2.0

//! Native compilation without a second component-loading or capability path.
//! Cache directories are operator-owned executable-code storage: never grant
//! guests write access. Portable `.wasm` remains the source of truth.
//!
//! ```
//! let mut config = wasmtime::Config::new();
//! let cache = qqq_run::aot::configure(&mut config, None).unwrap();
//! assert!(cache.is_none());
//! ```

use qqq_core::{Error, ErrorCode, Result};
use std::hash::{Hash as _, Hasher as _};
use std::path::Path;

/// Enable Wasmtime's compatible native cache at an explicit host-owned path.
/// No ambient Wasmtime configuration is loaded. Returns counters for diagnostics.
///
/// # Examples
///
/// ```
/// # fn main() -> qqq_core::Result<()> {
/// let mut config = wasmtime::Config::new();
/// assert!(qqq_run::aot::configure(&mut config, None)?.is_none());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Refuses invalid, insecure or unusable explicit cache directories and invalid engine cache configuration.
pub fn configure(
    config: &mut wasmtime::Config,
    directory: Option<&Path>,
) -> Result<Option<wasmtime::Cache>> {
    let Some(directory) = directory else {
        return Ok(None);
    };
    if !directory.is_absolute() {
        return Err(failure(
            "AOT cache directory must be an absolute, host-owned path",
        ));
    }
    std::fs::create_dir_all(directory).map_err(|e| failure(e.to_string()))?;
    let metadata = std::fs::symlink_metadata(directory).map_err(|e| failure(e.to_string()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(failure("AOT cache must be a real directory, not a symlink"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(failure(
                "AOT cache must not be writable by group or other users",
            ));
        }
    }
    // Resolve the path once; use the verified physical path for cache I/O.
    let directory = std::fs::canonicalize(directory).map_err(|e| failure(e.to_string()))?;
    #[cfg(unix)]
    verify_ownership(&directory)?;
    let mut cache_config = wasmtime::CacheConfig::new();
    cache_config.with_directory(directory);
    let cache = wasmtime::Cache::new(cache_config).map_err(|e| failure(e.to_string()))?;
    config.cache(Some(cache.clone()));
    Ok(Some(cache))
}

/// Refuse writable guests while the grant model lacks path-aware cache exclusion.
/// A source signature cannot protect native cache bytes writable by a guest.
///
/// # Examples
///
/// ```
/// # fn main() -> qqq_core::Result<()> {
/// qqq_run::aot::check_grants(None, &qqq_cap::resolve::GrantSet::empty())?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Refuses persistent caching with a guest filesystem-write grant.
pub fn check_grants(cache: Option<&Path>, grants: &qqq_cap::resolve::GrantSet) -> Result<()> {
    if cache.is_some() && grants.grants(qqq_cap::Capability::FsWrite) {
        return Err(failure(
            "AOT cache cannot be combined with fs.write until path exclusion is enforced",
        ));
    }
    Ok(())
}

/// Compile portable bytes and emit content-addressed native code plus provenance.
/// Emission is safe; accepting arbitrary native code for execution is intentionally
/// not exposed. `Component::new` uses the managed cache when configured.
///
/// # Examples
///
/// ```
/// # fn main() -> qqq_core::Result<()> {
/// # fn compile(bytes: &[u8], output: &std::path::Path) -> qqq_core::Result<()> {
/// let native = qqq_run::aot::emit(bytes, output, None)?;
/// assert_eq!(native.extension().unwrap(), "cwasm");
/// # Ok(())
/// # }
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns compilation, serialization, cache-policy and artifact I/O failures.
pub fn emit(bytes: &[u8], directory: &Path, cache: Option<&Path>) -> Result<std::path::PathBuf> {
    let mut config = qqq_host::config::EngineConfig::default().to_wasmtime_config()?;
    configure(&mut config, cache)?;
    let engine = wasmtime::Engine::new(&config).map_err(|e| failure(e.to_string()))?;
    let component =
        wasmtime::component::Component::new(&engine, bytes).map_err(|e| failure(e.to_string()))?;
    let native = component.serialize().map_err(|e| failure(e.to_string()))?;
    let source_digest = qqq_host::digest_of(bytes);
    let native_digest = qqq_host::digest_of(&native);
    let destination = directory.join(format!("{source_digest}-{native_digest}.cwasm"));
    atomic_write(&destination, &native)?;
    let mut compatibility = std::collections::hash_map::DefaultHasher::new();
    engine
        .precompile_compatibility_hash()
        .hash(&mut compatibility);
    let metadata = serde_json::json!({
        "schema": 1,
        "source_sha256": source_digest,
        "native_sha256": native_digest,
        "engine": "wasmtime",
        "compatibility": format!("{:016x}", compatibility.finish()),
        "architecture": std::env::consts::ARCH,
        "os": std::env::consts::OS,
        "load_policy": "portable-source-with-managed-cache",
    });
    let encoded = serde_json::to_vec_pretty(&metadata).map_err(|e| failure(e.to_string()))?;
    atomic_write(&destination.with_extension("json"), &encoded)?;
    Ok(destination)
}

/// Stage complete bytes, then rename in the same directory. Never expose a
/// partially written component to a concurrent reader.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .ok_or_else(|| failure("artifact has no parent"))?;
    std::fs::create_dir_all(parent).map_err(|e| failure(e.to_string()))?;
    let temporary = parent.join(format!(
        ".qqq-stage-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| failure(e.to_string()))?;
        file.write_all(bytes).map_err(|e| failure(e.to_string()))?;
        file.sync_all().map_err(|e| failure(e.to_string()))?;
        drop(file);
        std::fs::rename(&temporary, path).map_err(|e| failure(e.to_string()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn failure(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::CompilationFailed, message).with_remediation(
        "inspect the artifact and host-owned AOT directory; portable WASM remains usable",
    )
}

#[cfg(unix)]
fn verify_ownership(directory: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    // A file created by this process gives its effective owner without FFI.
    let probe = directory.join(format!(
        ".qqq-owner-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|e| failure(e.to_string()))?;
    let metadata = file.metadata();
    drop(file);
    std::fs::remove_file(probe).map_err(|e| failure(e.to_string()))?;
    let owner = metadata.map_err(|e| failure(e.to_string()))?.uid();
    for (depth, ancestor) in directory.ancestors().enumerate() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|e| failure(e.to_string()))?;
        if metadata.file_type().is_symlink()
            || (metadata.uid() != owner && metadata.uid() != 0)
            || (depth == 0 && metadata.uid() != owner)
            || (metadata.mode() & 0o022 != 0 && (depth == 0 || metadata.mode() & 0o1000 == 0))
        {
            return Err(failure(
                "AOT cache and its ancestors must be protected from other users",
            ));
        }
    }
    Ok(())
}
