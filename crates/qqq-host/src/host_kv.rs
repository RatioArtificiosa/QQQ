// SPDX-License-Identifier: Apache-2.0

//! `qqq:kv/store` — namespaced in-memory stores with TTL expiry.
//!
//! The manifest names stores; the deploy layer resolves that list once and
//! hands this module a [`KvConfig`]. Nothing here reads the manifest or the
//! environment per call (`CON-010`): membership in the config is the
//! allowlist, exactly as `host_env`'s map is.
//!
//! The data lives in a [`KvBackend`] shared across the requests one
//! deployment serves (per-instance maps would be dropped with the instance,
//! which serve rebuilds per request). The backend travels as
//! `Arc<Mutex<..>>` clones — a short-held lock, never held across a guest
//! call — so concurrent requests serialize on storage rather than on each
//! other. Ordering under concurrency is therefore nondeterministic by
//! construction; single-flight replay stays reproducible, and the
//! single-threaded deterministic rule is `DET-012`'s to enforce, not this
//! slice's to invent.
//!
//! Expiry reads the ambient monotonic clock, so deterministic runs observe
//! the virtual ticks like every other clock read. TTLs are computed at
//! `set` time (`expires_at = now + ttl`); reads lazily evict.
//!
//! ```
//! let config = qqq_host::host_kv::KvConfig::new(vec!["sessions".to_owned()], true);
//! assert!(config.allows("sessions"));
//! assert!(!config.allows("cart"));
//! ```
//!
//! Full flow through one backend: configure, share, store, load.
//!
//! ```
//! use std::sync::{Arc, Mutex};
//! let view = qqq_host::host_kv::KvView::new(
//!     Arc::new(qqq_host::host_kv::KvConfig::new(vec!["s".to_owned()], true)),
//!     Arc::new(Mutex::new(qqq_host::host_kv::KvBackend::new())),
//! );
//! view.backend.lock().expect("lock").set("s", "k", b"v".to_vec(), None, 0).expect("fits");
//! assert_eq!(view.backend.lock().expect("lock").get("s", "k", 0), Some(b"v".to_vec()));
//! ```

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use qqq_cap::capability::Capability::{KvRead, KvWrite};

/// The WIT package this module implements.
///
/// ```
/// assert_eq!(qqq_host::host_kv::INTERFACE, "qqq:kv@1.0.0");
/// ```
pub const INTERFACE: &str = "qqq:kv@1.0.0";

/// The generated bindings carry no doc comments of their own, and re-exporting
/// them would fail `missing_docs` on the WIT's definition rather than on any
/// prose this crate wrote. The allow is scoped to the generated module so
/// hand-written items keep the lint.
#[allow(missing_docs)]
mod bindings {
    wasmtime::component::bindgen!({
        path: "../../wit/qqq-kv.wit",
        interfaces: "import qqq:kv/store@1.0.0;",
    });
}

/// The WIT `kv-error`, re-exported rather than re-declared: the WIT variant
/// is the definition. (Same rule as `host_log` and `host_secrets`.)
pub use bindings::qqq::kv::store::KvError as WitKvError;

/// The largest single key the host accepts, in bytes.
///
/// Crate-visible: the check lives in this module and the bound is an
/// implementation limit rather than a cross-crate contract.
pub(crate) const MAX_KV_KEY_BYTES: usize = 1024;

/// The largest single value the host accepts, in bytes.
pub(crate) const MAX_KV_VALUE_BYTES: usize = 64 * 1024;

/// The most keys one `get-many` call may request.
///
/// A guest fetching more pays one ABI crossing per batch — the WIT's own
/// batch-first guidance — and an unbounded batch is an unbounded host
/// allocation for one call.
pub(crate) const MAX_KV_BATCH_KEYS: usize = 128;

/// The most keys one `keys` call returns, however large the guest's `limit`.
///
/// The guest's limit is honored below this; above it the host caps rather
/// than materializing an unbounded listing for one call.
pub(crate) const MAX_KV_KEYS_LIMIT: u32 = 1000;

/// The most stored bytes one store may hold.
///
/// V1 quota is a fixed host default, not a manifest field: the manifest
/// configures names and direction, and per-store quota configuration is
/// future work. The WIT's `quota-exceeded` is the backpressure signal
/// either way. One mebibyte is a sixteenth of the smallest instance memory
/// (16 MiB), so a guest that fills it has spent a visible share getting there.
///
/// Both halves of an entry count: a store of a million one-byte values is
/// a hundred megabytes of map nodes for one counted mebibyte, so the
/// numerator is key bytes plus value bytes.
pub(crate) const MAX_KV_STORE_BYTES: u64 = 1024 * 1024;

/// The largest single store name the host accepts, in bytes.
///
/// Store names become map keys on every call, so an unbounded name is an
/// unbounded host allocation for one lookup. 256 bytes names any reasonable
/// store; manifest-declared sets are short identifiers by convention.
pub(crate) const MAX_KV_STORE_NAME_BYTES: usize = 256;

/// Which stores the guest may open, and whether it may write.
///
/// Resolved once at deploy from the manifest; cloned per request, never
/// re-resolved per call.
///
/// ```
/// let config = qqq_host::host_kv::KvConfig::new(Vec::new(), false);
/// assert!(!config.allows("anything"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct KvConfig {
    /// Store names the manifest configures, in declaration order.
    pub stores: Vec<String>,
    /// Whether `set`/`delete` are permitted (`write = true` in the manifest).
    pub write: bool,
}

impl KvConfig {
    /// The deploy-time resolution: exactly what the manifest configures.
    ///
    /// ```
    /// let config = qqq_host::host_kv::KvConfig::new(vec!["s".to_owned()], true);
    /// assert!(config.write);
    /// assert_eq!(config.stores, vec!["s".to_owned()]);
    /// ```
    #[must_use]
    pub fn new(stores: Vec<String>, write: bool) -> Self {
        Self { stores, write }
    }

    /// Whether `store` is configured. Membership is the allowlist: an
    /// unlisted name is `store-not-configured`, never an empty store the
    /// guest conjured into existence.
    ///
    /// ```
    /// let config = qqq_host::host_kv::KvConfig::new(vec!["s".to_owned()], false);
    /// assert!(config.allows("s"));
    /// assert!(!config.allows("other"));
    /// ```
    #[must_use]
    pub fn allows(&self, store: &str) -> bool {
        self.stores.iter().any(|name| name == store)
    }
}

/// One stored value with its optional expiry.
///
/// `expires_at` is monotonic nanoseconds from the ambient clock, or `None`
/// for no expiry. Computed at `set`, never refreshed by reads: a TTL is a
/// deadline, not a lease.
#[derive(Debug, Clone)]
struct KvEntry {
    value: Vec<u8>,
    expires_at: Option<u64>,
}

/// The shared in-memory backend: every entry of every store one deployment
/// serves.
///
/// A plain map, not wasmtime's `ResourceTable`: kv entries are addressed by
/// `(store, key)` strings the guest supplies, never by host-minted handles,
/// so there is nothing to mint and nothing a stale handle could resolve to.
/// Ordering is `BTreeMap` order — the same determinism rule `DET-006`
/// enforces everywhere (`keys` promises sorted output, and an ordered map
/// is how that promise is kept rather than sorted on every call).
///
/// ```
/// let mut backend = qqq_host::host_kv::KvBackend::new();
/// backend.set("s", "k", b"v".to_vec(), None, 0).expect("fits");
/// assert_eq!(backend.get("s", "k", 0), Some(b"v".to_vec()));
/// ```
#[derive(Debug, Default)]
pub struct KvBackend {
    entries: BTreeMap<(String, String), KvEntry>,
    /// Stored bytes per store, for the quota check.
    sizes: BTreeMap<String, u64>,
}

impl KvBackend {
    /// Empty: no entries, no bytes counted.
    ///
    /// ```
    /// let backend = qqq_host::host_kv::KvBackend::new();
    /// assert_eq!(backend.stored_bytes("s"), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `key` in `store` is expired at `now` — and, as a side effect
    /// of observing it, gone. Expiry is lazy: the entry is evicted on the
    /// access that notices it, so no sweeper exists to forget to run.
    fn is_expired(&mut self, store: &str, key: &str, now: u64) -> bool {
        let expired = self
            .entries
            .get(&(store.to_owned(), key.to_owned()))
            .is_some_and(|entry| entry.expires_at.is_some_and(|at| now >= at));
        if expired {
            self.remove(store, key);
        }
        expired
    }

    /// Remove unconditionally, keeping the byte accounting exact.
    fn remove(&mut self, store: &str, key: &str) {
        if let Some(entry) = self.entries.remove(&(store.to_owned(), key.to_owned())) {
            // Key plus value: the quota numerator is the entry footprint,
            // and freeing only the value would leak the key bytes forever.
            let freed = key.len() as u64 + entry.value.len() as u64;
            if let Some(total) = self.sizes.get_mut(store) {
                *total = total.saturating_sub(freed);
            }
        }
    }

    /// Read a value. `None` is absence *or* expiry: the WIT promises absence
    /// is not an error, and an expired key is absent by the time anyone asks.
    ///
    /// ```
    /// let mut backend = qqq_host::host_kv::KvBackend::new();
    /// backend.set("s", "k", b"v".to_vec(), None, 0).expect("fits");
    /// assert_eq!(backend.get("s", "k", 0), Some(b"v".to_vec()));
    /// assert_eq!(backend.get("s", "missing", 0), None);
    /// ```
    #[must_use]
    pub fn get(&mut self, store: &str, key: &str, now: u64) -> Option<Vec<u8>> {
        if self.is_expired(store, key, now) {
            return None;
        }
        self.entries
            .get(&(store.to_owned(), key.to_owned()))
            .map(|entry| entry.value.clone())
    }

    /// Whether a live (unexpired) value exists, without transferring it.
    ///
    /// ```
    /// let mut backend = qqq_host::host_kv::KvBackend::new();
    /// assert!(!backend.exists("s", "k", 0));
    /// backend.set("s", "k", b"v".to_vec(), None, 0).expect("fits");
    /// assert!(backend.exists("s", "k", 0));
    /// ```
    #[must_use]
    pub fn exists(&mut self, store: &str, key: &str, now: u64) -> bool {
        self.get(store, key, now).is_some()
    }

    /// Write a value with an absolute expiry (`None` never expires).
    ///
    /// The caller computes `expires_at` from the ambient clock; this layer
    /// only stores it, so TTL math stays in one place and tests drive any
    /// instant without a clock.
    ///
    /// ```
    /// let mut backend = qqq_host::host_kv::KvBackend::new();
    /// backend.set("s", "k", b"v".to_vec(), Some(100), 0).expect("fits");
    /// assert_eq!(backend.get("s", "k", 50), Some(b"v".to_vec()));
    /// assert_eq!(backend.get("s", "k", 100), None);
    /// ```
    ///
    /// # Errors
    ///
    /// `entry-too-large` when the key or value exceeds the host bounds;
    /// `quota-exceeded` when the store would pass its byte quota.
    pub fn set(
        &mut self,
        store: &str,
        key: &str,
        value: Vec<u8>,
        expires_at: Option<u64>,
        now: u64,
    ) -> std::result::Result<(), WitKvError> {
        if key.len() > MAX_KV_KEY_BYTES || value.len() > MAX_KV_VALUE_BYTES {
            return Err(WitKvError::EntryTooLarge);
        }
        // Evict-then-charge: an expired entry's bytes are already dead, so
        // overwriting it must not charge the old size — and an expired entry
        // would otherwise pin quota until some read happened to notice it.
        self.is_expired(store, key, now);
        // The entry's footprint, not just its value: a store of tiny values
        // is mostly map nodes, and the quota exists to bound host memory.
        let entry_bytes = key.len() as u64 + value.len() as u64;
        let previous = self
            .entries
            .get(&(store.to_owned(), key.to_owned()))
            .map_or(0, |entry| key.len() as u64 + entry.value.len() as u64);
        let total = self.sizes.get(store).copied().unwrap_or(0);
        if total - previous.min(total) + entry_bytes > MAX_KV_STORE_BYTES {
            return Err(WitKvError::QuotaExceeded);
        }
        self.sizes
            .insert(store.to_owned(), total - previous.min(total) + entry_bytes);
        self.entries.insert(
            (store.to_owned(), key.to_owned()),
            KvEntry { value, expires_at },
        );
        Ok(())
    }

    /// Delete a key. Absent keys succeed: deleting twice is not an error,
    /// because the end state — the key is gone — is what the caller asked for.
    ///
    /// ```
    /// let mut backend = qqq_host::host_kv::KvBackend::new();
    /// backend.set("s", "k", b"v".to_vec(), None, 0).expect("fits");
    /// backend.delete("s", "k");
    /// backend.delete("s", "k");
    /// assert_eq!(backend.get("s", "k", 0), None);
    /// ```
    pub fn delete(&mut self, store: &str, key: &str) {
        self.remove(store, key);
    }

    /// Keys under `prefix`, sorted, honoring `limit`.
    ///
    /// Expired keys are evicted as the scan notices them, so a listing never
    /// names a key `get` would refuse to serve.
    ///
    /// ```
    /// let mut backend = qqq_host::host_kv::KvBackend::new();
    /// backend.set("s", "b", b"v".to_vec(), None, 0).expect("fits");
    /// backend.set("s", "a", b"v".to_vec(), None, 0).expect("fits");
    /// assert_eq!(backend.keys("s", "", 100, 0), vec!["a", "b"]);
    /// ```
    pub fn keys(&mut self, store: &str, prefix: &str, limit: u32, now: u64) -> Vec<String> {
        let take = limit.min(MAX_KV_KEYS_LIMIT) as usize;
        // Expired keys evicted per call, so one listing over a store choked
        // with dead keys cannot materialize an unbounded `expired` buffer.
        // The scan itself still runs to completion — correctness first: a
        // listing that stopped early could miss live keys past the window —
        // while eviction stays opportunistic (the next call reaps more).
        let mut reaped = 0usize;
        let mut out: Vec<String> = Vec::new();
        let mut expired: Vec<String> = Vec::new();
        for ((entry_store, key), entry) in &self.entries {
            if entry_store != store || !key.starts_with(prefix) {
                continue;
            }
            if entry.expires_at.is_some_and(|at| now >= at) {
                if reaped < MAX_KV_KEYS_LIMIT as usize {
                    expired.push(key.clone());
                    reaped += 1;
                }
                continue;
            }
            if out.len() >= take {
                break;
            }
            out.push(key.clone());
        }
        for key in expired {
            self.remove(store, &key);
        }
        out
    }

    /// Stored bytes in `store` — the quota numerator, for tests and operators.
    ///
    /// ```
    /// let mut backend = qqq_host::host_kv::KvBackend::new();
    /// assert_eq!(backend.stored_bytes("s"), 0);
    /// backend.set("s", "k", b"v".to_vec(), None, 0).expect("fits");
    /// assert_eq!(backend.stored_bytes("s"), 1);
    /// ```
    #[must_use]
    pub fn stored_bytes(&self, store: &str) -> u64 {
        self.sizes.get(store).copied().unwrap_or(0)
    }
}

/// The per-instance view: deploy-resolved config plus the shared backend.
///
/// Both halves are `Arc` clones: the config is read-only after deploy, and
/// the backend is the one map every request of the deployment shares. A
/// rotation (`replacement`) clones both, so stored data survives deploys
/// exactly as the audit stream and tenant budgets do.
#[derive(Debug, Clone, Default)]
pub struct KvView {
    /// The deploy-resolved allowlist and direction.
    pub config: Arc<KvConfig>,
    /// The shared map every request of the deployment reads and writes.
    pub backend: Arc<Mutex<KvBackend>>,
}

impl KvView {
    /// A view over `config` and `backend`.
    ///
    /// ```
    /// let view = qqq_host::host_kv::KvView::new(
    ///     std::sync::Arc::new(qqq_host::host_kv::KvConfig::new(
    ///         vec!["s".to_owned()],
    ///         true,
    ///     )),
    ///     std::sync::Arc::new(std::sync::Mutex::new(qqq_host::host_kv::KvBackend::new())),
    /// );
    /// assert!(view.config.allows("s"));
    /// ```
    #[must_use]
    pub fn new(config: Arc<KvConfig>, backend: Arc<Mutex<KvBackend>>) -> Self {
        Self { config, backend }
    }
}

/// Register the key-value interface for the granted capabilities.
///
/// Links `qqq:kv/store` only when `kv.read` or `kv.write` is granted; every
/// function re-checks at call time.
///
/// ```
/// let engine = wasmtime::Engine::default();
/// let mut linker = wasmtime::component::Linker::<qqq_host::linker::StoreData>::new(&engine);
/// qqq_host::host_kv::register(&mut linker, &qqq_cap::resolve::GrantSet::empty())
///     .expect("empty grants register nothing");
/// ```
///
/// # Errors
///
/// A `wasmtime::Error` if the linker rejects an interface.
pub fn register(
    linker: &mut wasmtime::component::Linker<crate::linker::StoreData>,
    grants: &qqq_cap::resolve::GrantSet,
) -> wasmtime::Result<()> {
    use wasmtime::component::HasSelf;
    if !(grants.grants(KvRead) || grants.grants(KvWrite)) {
        return Ok(());
    }
    bindings::qqq::kv::store::add_to_linker::<
        crate::linker::StoreData,
        HasSelf<crate::linker::StoreData>,
    >(linker, |state| state)?;
    Ok(())
}

/// Whether a store name is safe to use as a map key.
///
/// Store names arrive per call and become `BTreeMap` keys, so an unbounded
/// name is an unbounded host allocation for one lookup. Empty names are
/// refused for the same reason attribute names are: a nameless store would
/// render as structure without identity.
fn valid_store_name(store: &str) -> bool {
    !store.is_empty() && store.len() <= MAX_KV_STORE_NAME_BYTES
}

/// Check a read: the direction grant, then the store membership.
///
/// Grant first (an ungranted call fails before its store name is judged),
/// then membership. `kv.read` alone gates reads: `kv.write` widens it in
/// the manifest, so a write-only grant set is a mis-built instance and
/// `not-granted` is the honest answer for the missing direction.
fn check_read(data: &crate::linker::StoreData, store: &str) -> std::result::Result<(), WitKvError> {
    if !data.grants.grants(KvRead) {
        return Err(WitKvError::NotGranted);
    }
    if !valid_store_name(store) || !data.kv.config.allows(store) {
        return Err(WitKvError::StoreNotConfigured);
    }
    Ok(())
}

/// Check a write: either grant missing, the store membership, then the direction.
///
/// `not-granted` means *neither* direction was granted (the WIT's own
/// words): a read-only manifest grants `kv.read`, so a write there is
/// `read-only`, not ungranted. Membership comes before direction because
/// the store list is public anyway (`stores()`), and an unlisted store is
/// unconfigured however the call arrived.
fn check_write(
    data: &crate::linker::StoreData,
    store: &str,
) -> std::result::Result<(), WitKvError> {
    if !(data.grants.grants(KvRead) || data.grants.grants(KvWrite)) {
        return Err(WitKvError::NotGranted);
    }
    if !valid_store_name(store) || !data.kv.config.allows(store) {
        return Err(WitKvError::StoreNotConfigured);
    }
    if !data.grants.grants(KvWrite) || !data.kv.config.write {
        // The grant without the config (or the reverse) is a mis-built
        // instance: the manifest grants both or neither, so a split means
        // the deploy path and the link path disagree — and the safe
        // direction is refusal, named read-only.
        return Err(WitKvError::ReadOnly);
    }
    Ok(())
}
/// Lock the shared backend, recovering from a poisoned lock.
///
/// Poisoning means a previous holder panicked mid-access — and shipping code
/// forbids panicking paths (`unwrap`/`expect`/indexing are refused), so the
/// map itself is intact. Refusing every later request for a panic that
/// cannot name would turn one failed call into a dead store; recovering
/// keeps the failure where it happened.
fn lock_backend(data: &crate::linker::StoreData) -> std::sync::MutexGuard<'_, KvBackend> {
    data.kv.backend.lock().unwrap_or_else(|poisoned| {
        let _ = &poisoned;
        poisoned.into_inner()
    })
}

/// The monotonic instant for TTL math, or a backend failure.
///
/// A replay error (an exhausted log) is a host fault, and `kv-error` has no
/// host-fault case — so it surfaces as `backend-failed`, naming the clock.
/// Failing closed rather than falling back to wall time: silent time travel
/// would resurrect expired keys or kill live ones, and neither direction is
/// a safe default.
fn now_or_fail(data: &crate::linker::StoreData) -> std::result::Result<u64, WitKvError> {
    data.ambient
        .read_monotonic_nanos()
        .map_err(|error| WitKvError::BackendFailed(error.to_string()))
}

/// The host implementation of `qqq:kv/store`.
///
/// # Why every method re-checks both the grant and the config
///
/// Registration is conditional on the grant AND the body re-checks it, so a
/// mis-built linker still denies (`ARCH-012`). The config check is separate
/// because grants are capability-level while stores are named: `kv.read`
/// says the guest may read *some* store, and only the config says which.
impl bindings::qqq::kv::store::Host for crate::linker::StoreData {
    fn get(
        &mut self,
        store: String,
        key: String,
    ) -> std::result::Result<Option<Vec<u8>>, WitKvError> {
        check_read(self, &store)?;
        let now = now_or_fail(self)?;
        Ok(lock_backend(self).get(&store, &key, now))
    }

    fn set(
        &mut self,
        store: String,
        key: String,
        value: Vec<u8>,
        ttl_seconds: Option<u64>,
    ) -> std::result::Result<(), WitKvError> {
        check_write(self, &store)?;
        let now = now_or_fail(self)?;
        let expires_at = if ttl_seconds.is_some() {
            // Saturating: a TTL past the clock's range pins the key rather
            // than wrapping it expired. `None` (no TTL) stays `None` —
            // saturating the `None` away would turn "forever" into a
            // deadline.
            Some(now.saturating_add(ttl_seconds.unwrap_or(0).saturating_mul(1_000_000_000)))
        } else {
            None
        };
        lock_backend(self).set(&store, &key, value, expires_at, now)
    }

    fn delete(&mut self, store: String, key: String) -> std::result::Result<(), WitKvError> {
        check_write(self, &store)?;
        lock_backend(self).delete(&store, &key);
        Ok(())
    }

    fn exists(&mut self, store: String, key: String) -> std::result::Result<bool, WitKvError> {
        check_read(self, &store)?;
        let now = now_or_fail(self)?;
        Ok(lock_backend(self).exists(&store, &key, now))
    }

    fn keys(
        &mut self,
        store: String,
        prefix: String,
        limit: u32,
    ) -> std::result::Result<Vec<String>, WitKvError> {
        check_read(self, &store)?;
        // A prefix is a key fragment: bounding it by the key bound keeps a
        // megabyte prefix from turning every comparison into a long one.
        if prefix.len() > MAX_KV_KEY_BYTES {
            return Err(WitKvError::EntryTooLarge);
        }
        let now = now_or_fail(self)?;
        Ok(lock_backend(self).keys(&store, &prefix, limit, now))
    }

    fn get_many(
        &mut self,
        store: String,
        keys: Vec<String>,
    ) -> std::result::Result<Vec<Option<Vec<u8>>>, WitKvError> {
        check_read(self, &store)?;
        if keys.len() > MAX_KV_BATCH_KEYS {
            return Err(WitKvError::EntryTooLarge);
        }
        // Lengths validated before the lock: one oversize key must not
        // allocate its lookup, and the batch reads as one atomic snapshot —
        // up to 128 keys, each already known to fit the per-entry bound.
        if keys.iter().any(|key| key.len() > MAX_KV_KEY_BYTES) {
            return Err(WitKvError::EntryTooLarge);
        }
        let now = now_or_fail(self)?;
        let mut backend = lock_backend(self);
        Ok(keys
            .iter()
            .map(|key| backend.get(&store, key, now))
            .collect())
    }

    fn stores(&mut self) -> Vec<String> {
        // Infallible by WIT design (the manifest set is public), so the
        // grant re-check fails closed by answering empty rather than by
        // erroring: an ungranted caller learns nothing, including membership.
        if !(self.grants.grants(KvRead) || self.grants.grants(KvWrite)) {
            return Vec::new();
        }
        self.kv.config.stores.clone()
    }
}

// Test indexing (`F-18`): assertions index vectors built inline above.
// One module-level reason, not per-site noise; shipping code above
// carries no such allowance.
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions index inline vectors"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::linker::StoreData;
    use qqq_cap::manifest::Manifest;
    use qqq_cap::resolve::GrantSet;

    fn granted_store(write: bool) -> StoreData {
        let stanza = if write {
            "[capabilities.kv]\nstores = [\"s\"]\nwrite = true\n"
        } else {
            "[capabilities.kv]\nstores = [\"s\"]\n"
        };
        let manifest = Manifest::parse(&format!(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n{stanza}"
        ))
        .expect("manifest parses");
        let grants = GrantSet::from_manifest(&manifest);
        let config = Arc::new(KvConfig::new(vec!["s".to_owned()], write));
        StoreData::new(grants).with_kv(KvView::new(config, Arc::new(Mutex::new(KvBackend::new()))))
    }

    fn ungranted_store() -> StoreData {
        StoreData::new(GrantSet::empty())
    }

    /// A set round-trips through get, exists, and the byte accounting.
    #[test]
    fn set_get_exists_round_trip() {
        let data = granted_store(true);
        lock_backend(&data)
            .set("s", "k", b"v".to_vec(), None, 0)
            .expect("fits");
        assert_eq!(lock_backend(&data).get("s", "k", 0), Some(b"v".to_vec()));
        assert!(lock_backend(&data).exists("s", "k", 0));
        assert_eq!(
            lock_backend(&data).stored_bytes("s"),
            2,
            "quota counts key plus value"
        );
    }

    /// Expiry is lazy and absolute: past the deadline the key reads absent,
    /// and the access evicts it.
    #[test]
    fn expired_keys_read_absent_and_evict() {
        let mut backend = KvBackend::new();
        backend
            .set("s", "k", b"v".to_vec(), Some(100), 0)
            .expect("fits");
        assert_eq!(backend.get("s", "k", 50), Some(b"v".to_vec()));
        assert_eq!(
            backend.get("s", "k", 100),
            None,
            "the deadline is inclusive"
        );
        assert!(
            !backend
                .entries
                .contains_key(&("s".to_owned(), "k".to_owned())),
            "the observing access evicts"
        );
    }

    /// Deleting an absent key succeeds: the end state is what was asked for.
    #[test]
    fn delete_is_idempotent() {
        let mut backend = KvBackend::new();
        backend.delete("s", "missing");
        backend.set("s", "k", b"v".to_vec(), None, 0).expect("fits");
        backend.delete("s", "k");
        assert_eq!(backend.get("s", "k", 0), None);
        assert_eq!(backend.stored_bytes("s"), 0, "accounting follows the data");
    }

    /// Overwrites charge the difference, not the sum: quota math that
    /// double-counted would refuse rewrites long before the store is full.
    #[test]
    fn overwrite_charges_the_difference() {
        let mut backend = KvBackend::new();
        backend
            .set("s", "k", vec![0u8; 100], None, 0)
            .expect("fits");
        backend
            .set("s", "k", vec![0u8; 200], None, 0)
            .expect("the delta fits");
        assert_eq!(backend.stored_bytes("s"), 201, "one key plus 200 bytes");
    }

    /// Oversize keys and values fail before anything is stored.
    #[test]
    fn oversize_entries_fail_closed() {
        let mut backend = KvBackend::new();
        let big_key = "k".repeat(MAX_KV_KEY_BYTES + 1);
        assert!(matches!(
            backend.set("s", &big_key, b"v".to_vec(), None, 0),
            Err(WitKvError::EntryTooLarge)
        ));
        let big_value = vec![0u8; MAX_KV_VALUE_BYTES + 1];
        assert!(matches!(
            backend.set("s", "k", big_value, None, 0),
            Err(WitKvError::EntryTooLarge)
        ));
        assert_eq!(backend.get("s", "k", 0), None, "nothing is stored");
    }

    /// The quota binds the store, not the call: filling to the brim then
    /// adding one byte fails, while replacing within it succeeds.
    #[test]
    fn quota_bounds_the_store() {
        let mut backend = KvBackend::new();
        let chunk = vec![0u8; 64 * 1024];
        let mut count = 0u32;
        loop {
            match backend.set("s", &format!("k{count}"), chunk.clone(), None, 0) {
                Ok(()) => count += 1,
                Err(WitKvError::QuotaExceeded) => break,
                Err(other) => panic!("unexpected failure: {other:?}"),
            }
            assert!(count < 10_000, "the quota must backpressure");
        }
        assert!(backend.stored_bytes("s") <= MAX_KV_STORE_BYTES);
        assert_eq!(
            backend.get("s", "k0", 0),
            Some(chunk),
            "quota math never double-counts: k0 still fits what was stored"
        );
    }

    /// `keys` lists under a prefix in sort order, skipping the expired.
    #[test]
    fn keys_are_sorted_and_skip_expired() {
        let mut backend = KvBackend::new();
        for key in ["b", "a", "c"] {
            backend.set("s", key, b"v".to_vec(), None, 0).expect("fits");
        }
        backend
            .set("s", "a0", b"v".to_vec(), Some(10), 0)
            .expect("fits");
        backend
            .set("other", "a1", b"v".to_vec(), None, 0)
            .expect("fits");
        assert_eq!(
            backend.keys("s", "a", 100, 50),
            vec!["a".to_owned()],
            "expired a0 is evicted by the listing, other-store keys never appear"
        );
        assert_eq!(
            backend.keys("s", "", 2, 0),
            vec!["a".to_owned(), "b".to_owned()],
            "sort order with the guest limit honored"
        );
    }

    /// Ungranted reads fail before the store name is judged: spraying store
    /// names at an ungranted interface learns nothing, not even membership.
    #[test]
    fn ungranted_reads_fail_closed() {
        let mut data = ungranted_store();
        let err = bindings::qqq::kv::store::Host::get(&mut data, "s".to_owned(), "k".to_owned())
            .expect_err("no grant");
        assert!(matches!(err, WitKvError::NotGranted));
    }

    /// Ungranted writes fail the same way, and read-only configs refuse
    /// writes by name even when the call reaches the store.
    #[test]
    fn ungranted_and_read_only_writes_fail_closed() {
        let mut data = ungranted_store();
        let err = bindings::qqq::kv::store::Host::set(
            &mut data,
            "s".to_owned(),
            "k".to_owned(),
            b"v".to_vec(),
            None,
        )
        .expect_err("no grant");
        assert!(matches!(err, WitKvError::NotGranted));
        let mut read_only = granted_store(false);
        let err = bindings::qqq::kv::store::Host::set(
            &mut read_only,
            "s".to_owned(),
            "k".to_owned(),
            b"v".to_vec(),
            None,
        )
        .expect_err("read-only");
        assert!(matches!(err, WitKvError::ReadOnly));
    }

    /// Unlisted stores are unconfigured, even for reads: the allowlist is
    /// membership, and a missing key in a missing store is not a signal.
    #[test]
    fn unlisted_stores_are_not_configured() {
        let mut data = granted_store(true);
        let err = bindings::qqq::kv::store::Host::get(&mut data, "nope".to_owned(), "k".to_owned())
            .expect_err("unlisted");
        assert!(matches!(err, WitKvError::StoreNotConfigured));
    }

    /// Oversize and empty store names are unconfigured, not lookups: a name
    /// that could never be configured must not reach the map.
    #[test]
    fn hostile_store_names_are_not_configured() {
        let mut data = granted_store(true);
        for hostile in ["", &"s".repeat(MAX_KV_STORE_NAME_BYTES + 1)] {
            let err =
                bindings::qqq::kv::store::Host::get(&mut data, hostile.to_owned(), "k".to_owned())
                    .expect_err("hostile store name refused");
            assert!(
                matches!(err, WitKvError::StoreNotConfigured),
                "{hostile:?} must fail closed"
            );
        }
    }

    /// Overwriting an expired key charges nothing for the dead entry: expiry
    /// evicts first, so the quota cannot be pinned by keys nobody reads.
    #[test]
    fn set_over_expired_key_frees_quota_first() {
        let mut backend = KvBackend::new();
        backend
            .set("s", "k", vec![0u8; 1000], Some(10), 0)
            .expect("fits");
        assert_eq!(backend.stored_bytes("s"), 1001);
        backend
            .set("s", "k", vec![0u8; 1000], None, 50)
            .expect("the dead entry frees first");
        assert_eq!(
            backend.stored_bytes("s"),
            1001,
            "no double charge for the evicted entry"
        );
        assert_eq!(
            backend.get("s", "k", 60),
            Some(vec![0u8; 1000]),
            "the live write replaced the dead one"
        );
    }

    /// `Some(0)` expires immediately: `None` is the only forever. The WIT
    /// warns against reading `0` as forever; this pins the other reading.
    #[test]
    fn zero_ttl_expires_immediately() {
        let mut backend = KvBackend::new();
        backend
            .set("s", "k", b"v".to_vec(), Some(0), 42)
            .expect("fits");
        assert_eq!(
            backend.get("s", "k", 42),
            None,
            "the deadline is inclusive, so zero means already past"
        );
    }

    /// Listings honor small limits and cap huge ones: `limit = 0` answers
    /// empty, and no listing materializes more than the host cap.
    #[test]
    fn keys_honor_and_cap_limits() {
        let mut backend = KvBackend::new();
        for i in 0..1500u32 {
            backend
                .set("s", &format!("k{i:04}"), b"v".to_vec(), None, 0)
                .expect("fits");
        }
        assert_eq!(backend.keys("s", "", 0, 0), Vec::<String>::new());
        let capped = backend.keys("s", "", u32::MAX, 0);
        assert_eq!(capped.len(), MAX_KV_KEYS_LIMIT as usize);
        assert!(
            capped.windows(2).all(|pair| pair[0] <= pair[1]),
            "the capped listing stays sorted"
        );
    }

    /// An oversize key in a batch fails before the lock: one bad key must
    /// not cost a lookup, and the batch reads as one snapshot.
    #[test]
    fn oversize_batch_keys_fail_closed() {
        let mut data = granted_store(true);
        let big = "k".repeat(MAX_KV_KEY_BYTES + 1);
        let err = bindings::qqq::kv::store::Host::get_many(&mut data, "s".to_owned(), vec![big])
            .expect_err("oversize batch key refused");
        assert!(matches!(err, WitKvError::EntryTooLarge));
    }

    /// `stores()` without a grant answers empty: the manifest set is public
    /// to granted guests, but an ungranted caller learns nothing.
    #[test]
    fn stores_without_grant_is_empty() {
        let mut data = ungranted_store();
        assert_eq!(
            bindings::qqq::kv::store::Host::stores(&mut data),
            Vec::<String>::new()
        );
    }

    /// Oversize batches fail before any read: one call cannot ask for an
    /// unbounded allocation.
    #[test]
    fn oversize_batches_fail_closed() {
        let mut data = granted_store(true);
        let keys: Vec<String> = (0..=MAX_KV_BATCH_KEYS).map(|i| format!("k{i}")).collect();
        let err = bindings::qqq::kv::store::Host::get_many(&mut data, "s".to_owned(), keys)
            .expect_err("too many keys");
        assert!(matches!(err, WitKvError::EntryTooLarge));
    }

    /// The register links only when a kv grant is present.
    #[test]
    fn register_links_only_when_granted() {
        const EMPTY: &str = r#"(component
          (import "qqq:kv/store@1.0.0" (instance $k))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        const NAMED: &str = r#"(component
          (import "qqq:kv/store@1.0.0" (instance $k
            (export "get" (func (param "a" string) (param "b" string)))))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        fn link(grants: &GrantSet, wat: &str) -> wasmtime::Result<()> {
            let mut config = wasmtime::Config::new();
            config.wasm_component_model(true);
            let engine = wasmtime::Engine::new(&config).expect("engine builds");
            let mut linker = wasmtime::component::Linker::new(&engine);
            register(&mut linker, grants)?;
            let bytes = wat::parse_str(wat).expect("fixture assembles");
            let component =
                wasmtime::component::Component::new(&engine, &bytes).expect("fixture compiles");
            let mut store = wasmtime::Store::new(&engine, StoreData::new(grants.clone()));
            linker.instantiate(&mut store, &component).map(|_| ())
        }
        let manifest = Manifest::parse(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.kv]\nstores = [\"s\"]\n",
        )
        .expect("manifest parses");
        link(&GrantSet::from_manifest(&manifest), EMPTY).expect("a granted import links");
        let err = link(&GrantSet::empty(), NAMED).expect_err("no grant means no instance");
        assert!(
            format!("{err:#}").contains("qqq:kv/store"),
            "the refusal must name the import: {err:#}"
        );
    }
}
