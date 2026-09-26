// SPDX-License-Identifier: Apache-2.0

//! Host implementations of the ambient interfaces: `qqq:clock` and
//! `qqq:crypto`.
//!
//! Implements `HOST-016`. These are the first real host functions, and they
//! close the stub recorded in Observations `§S-006`.
//!
//! # Why these two first
//!
//! They are the **only** interfaces a useful component can be built against
//! without any external service: a program that hashes, signs, or measures time
//! needs nothing more. Proving the host-call path end to end on interfaces with
//! no I/O means the first integration test exercises the capability gate, the
//! ABI crossing, the determinism machinery and the trap path — without also
//! needing a database or a network.
//!
//! # Determinism is enforced here, not in the guest
//!
//! In deterministic mode the wall clock returns a **fixed** instant and the
//! random source is **seeded**. A guest cannot observe nondeterminism the host
//! did not grant it, which is what makes bit-identical replay (Proposal §10.5)
//! achievable without the guest cooperating.
//!
//! # Every call re-checks the grant
//!
//! Each host function consults the store's grant set at call time via
//! [`recheck`], in addition to the linker having been built from those grants.
//! The two checks fail differently — a mis-built linker grants authority, a
//! spurious re-check denies it — and that asymmetry justifies the cost.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use qqq_cap::capability::Capability;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::audit::Outcome;
use crate::linker::StoreData;

/// The largest single `random.get` request the host will serve, in bytes.
///
/// # Why this is a named constant rather than a literal in the constructor
///
/// Because it is the **boundary limit** `SEC-011` names in its registry, and the
/// boundary check in `host_crypto` and the enforcement inside `random_bytes` must
/// agree. A literal inside a constructor is a number two places could drift from;
/// a constant is one number with a name an auditor can grep for.
///
/// 1 MiB: a guest asking for more is either buggy or attacking the host's memory,
/// and a bound is cheaper than an investigation.
pub const DEFAULT_MAX_RANDOM_BYTES: u32 = 1024 * 1024;

/// The number of members of the WIT `algorithm` enum.
///
/// # Why this is a constant rather than `HashAlgorithm::all().len()`
///
/// The boundary check validates a **raw discriminant** the guest supplied, before
/// any of it has been mapped to a [`HashAlgorithm`]. The count is a property of
/// the WIT declaration order (`sha256=0, sha512=1, blake3=2`), which is an ABI —
/// and a test asserts this constant agrees with the WIT file, so the two cannot
/// drift silently.
pub const HASH_ALGORITHM_COUNT: u32 = 3;

/// The deterministic clock and RNG state carried by a store.
///
/// # Why the state lives in the store
///
/// Because determinism is **per instance**, not per host. Two instances running
/// concurrently must each see a reproducible sequence; a shared counter would
/// make one instance's output depend on how much the other had run, which is
/// exactly the nondeterminism the feature exists to remove.
#[derive(Debug)]
pub struct AmbientState {
    /// Whether the host is in deterministic mode.
    deterministic: bool,
    /// The instant the virtual clock reports, in nanoseconds since the epoch.
    fixed_nanos: u64,
    /// How far the virtual clock advances per explicit tick.
    tick_nanos: u64,
    /// Number of explicit ticks applied.
    ticks: AtomicU64,
    /// The seeded generator's state, used only in deterministic mode.
    ///
    /// A splitmix64 counter: small, fast, and — critically — **reproducible
    /// across architectures**, which a `HashMap`-based RNG or anything relying
    /// on address entropy would not be.
    rng_state: AtomicU64,
    /// The largest random request the host will serve in one call.
    max_random_bytes: u32,
    /// The origin of the monotonic clock, captured on first use.
    ///
    /// A `OnceLock` rather than an `Instant` field so `new` does not read the
    /// clock: doing so would make constructing ambient state an observable
    /// event, and a determinism test that constructs two states would see two
    /// different origins. Lazy initialisation also keeps `new` cheap on the
    /// instantiation hot path, which is measured in hundreds of nanoseconds.
    origin: OnceLock<Instant>,
}

/// The floor the host reports as its real-time clock resolution.
///
/// 100 ns, not the hardware's nominal figure. Reporting an optimistic
/// resolution encourages a guest to poll faster than the host can service,
/// turning a measurement into a spin. A conservative floor makes a
/// well-written guest pace itself.
const REAL_TICK_FLOOR_NANOS: u64 = 100;

impl Default for AmbientState {
    fn default() -> Self {
        Self::new(false)
    }
}

impl AmbientState {
    /// Build ambient state for a mode.
    #[must_use]
    pub fn new(deterministic: bool) -> Self {
        Self {
            deterministic,
            // 2026-01-01T00:00:00Z — a round, obviously-synthetic instant. A
            // fixed clock reading a *plausible* current time would make a
            // determinism bug invisible in test output.
            fixed_nanos: 1_767_225_600_000_000_000,
            tick_nanos: 1_000_000,
            ticks: AtomicU64::new(0),
            rng_state: AtomicU64::new(0x5151_5151_5151_5151),
            // 1 MiB. A guest asking for more is either buggy or attacking the
            // host's memory, and a bound is cheaper than an investigation.
            max_random_bytes: DEFAULT_MAX_RANDOM_BYTES,
            origin: OnceLock::new(),
        }
    }

    /// Whether this state is deterministic.
    #[must_use]
    pub const fn is_deterministic(&self) -> bool {
        self.deterministic
    }

    /// The largest `random.get` this state will serve, in bytes.
    ///
    /// Exposed so `SEC-011`'s boundary check can state the *same* ceiling the
    /// allocation path enforces, rather than a second copy of the number. A
    /// boundary that validated against its own constant would be checking a
    /// different limit from the one that applies.
    #[must_use]
    pub const fn max_random_bytes(&self) -> u32 {
        self.max_random_bytes
    }

    /// The current virtual time, in nanoseconds since the epoch.
    ///
    /// In deterministic mode: the fixed instant plus `ticks` advances.
    /// Otherwise: the real system clock.
    #[must_use]
    pub fn now_nanos(&self) -> u64 {
        if self.deterministic {
            let ticks = self.ticks.load(Ordering::Relaxed);
            self.fixed_nanos
                .saturating_add(self.tick_nanos.saturating_mul(ticks))
        } else {
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => u64::try_from(d.as_nanos()).unwrap_or(u64::MAX),
                // A clock before 1970 means the system clock is wrong. Report
                // the epoch rather than wrapping to a huge value, which a guest
                // might store.
                Err(_) => 0,
            }
        }
    }

    /// Advance the virtual clock by one tick. No effect in real-time mode.
    pub fn tick(&self) {
        if self.deterministic {
            self.ticks.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Read the monotonic clock, in nanoseconds.
    ///
    /// # Why this is a separate method from [`Self::now_nanos`]
    ///
    /// They answer different questions. `now_nanos` is a *wall-clock instant* —
    /// nanoseconds since the Unix epoch, useful for timestamps.
    /// `elapsed_nanos` is a *duration since some unspecified origin*, useful
    /// only for differences, which is exactly what the WIT's `monotonic-clock`
    /// promises. Conflating them would let a guest treat a monotonic reading as
    /// a date, which the interface documentation explicitly warns against.
    ///
    /// In deterministic mode both are derived from the same tick counter, so a
    /// replayed run sees identical values. In real-time mode this uses
    /// `Instant`, which is monotonic by construction — unlike `SystemTime`,
    /// which can jump backwards when the system clock is adjusted, and a
    /// guest measuring a latency must never see a negative elapsed time.
    #[must_use]
    pub fn elapsed_nanos(&self) -> u64 {
        if self.deterministic {
            let ticks = self.ticks.load(Ordering::Relaxed);
            self.tick_nanos.saturating_mul(ticks)
        } else {
            // `get_or_init` rather than reading a stored `Instant`: the origin
            // is the moment the monotonic clock was *first read*, so two
            // instances constructed at different times still both start at
            // zero, which is what makes a monotonic reading comparable only
            // within one instance — exactly what the WIT promises.
            let origin = self.origin.get_or_init(Instant::now);
            u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
        }
    }

    /// The smallest interval this clock can meaningfully report, in nanoseconds.
    ///
    /// Reported so a guest can pace itself instead of spinning. In
    /// deterministic mode it is the virtual tick interval; in real-time mode it
    /// is a conservative floor rather than the hardware's nominal resolution,
    /// because reporting an optimistic resolution would encourage polling
    /// faster than the host can service.
    #[must_use]
    pub const fn tick_interval_nanos(&self) -> u64 {
        if self.deterministic {
            self.tick_nanos
        } else {
            REAL_TICK_FLOOR_NANOS
        }
    }

    /// Fill `len` bytes with randomness.
    ///
    /// # Errors
    ///
    /// Returns `Err(too_long)` when `len` exceeds the per-call maximum.
    ///
    /// # Panics
    ///
    /// Does not panic. In non-deterministic mode the OS source is read; a
    /// failure there is surfaced by the caller rather than substituted, because
    /// falling back to a weaker source would be worse than failing.
    pub fn random_bytes(&self, len: u32) -> Result<Vec<u8>, RandomFailure> {
        if len > self.max_random_bytes {
            return Err(RandomFailure::TooLong);
        }
        let mut out = vec![0u8; len as usize];
        if self.deterministic {
            // splitmix64: deterministic, architecture-independent, and good
            // enough for test reproducibility (it is explicitly NOT a CSPRNG,
            // and is never used outside deterministic mode).
            let mut state = self.rng_state.load(Ordering::Relaxed);
            for chunk in out.chunks_mut(8) {
                state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^= z >> 31;
                let bytes = z.to_le_bytes();
                let n = chunk.len().min(8);
                chunk[..n].copy_from_slice(&bytes[..n]);
            }
            self.rng_state.store(state, Ordering::Relaxed);
            Ok(out)
        } else {
            getrandom::fill(&mut out).map_err(|_| RandomFailure::SourceFailed)?;
            Ok(out)
        }
    }

    /// Hash bytes with a named algorithm.
    #[must_use]
    pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
        match algorithm {
            HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
            HashAlgorithm::Blake3 => blake3::hash(data).as_bytes().to_vec(),
        }
    }

    /// The digest length of a named algorithm, in bytes.
    ///
    /// Grouped by width rather than listed per algorithm: `Sha256` and `Blake3`
    /// genuinely share a 32-byte output, so the grouping states a fact about
    /// them rather than hiding one. A future algorithm with a distinct width
    /// needs its own arm, and the compiler will say so.
    #[must_use]
    pub const fn digest_len(algorithm: HashAlgorithm) -> usize {
        match algorithm {
            // 256-bit digests.
            HashAlgorithm::Sha256 | HashAlgorithm::Blake3 => 32,
            // 512-bit digest.
            HashAlgorithm::Sha512 => 64,
        }
    }
}

/// The hash algorithms the host supports.
///
/// Mirrors the WIT `hashing.algorithm` enum. Kept as a Rust enum so the
/// implementation is total — a new WIT case without a Rust arm fails to compile
/// rather than being silently unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashAlgorithm {
    /// 32-byte digest.
    Sha256,
    /// 64-byte digest.
    Sha512,
    /// 32-byte digest.
    Blake3,
}

impl HashAlgorithm {
    /// Parse from the WIT identifier.
    ///
    /// Returns `None` for an unknown name, which the caller turns into
    /// `algorithm-not-allowed` — the same response a known-but-ungranted
    /// algorithm gets, so a guest cannot enumerate the host's supported set by
    /// probing.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            "blake3" => Some(Self::Blake3),
            _ => None,
        }
    }

    /// The WIT identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::Blake3 => "blake3",
        }
    }
}

/// Why a randomness request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomFailure {
    /// The request exceeded the per-call maximum.
    TooLong,
    /// The OS entropy source failed.
    SourceFailed,
}

/// The result of a grant-checked host call.
///
/// A single type for every ambient call, so the host-function wrappers share one
/// error-mapping path. Divergent error handling per function is how one of them
/// ends up forgetting the capability check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCallError {
    /// The capability was not granted for this instance.
    NotGranted(Capability),
    /// The requested algorithm is not in the manifest's allowlist.
    AlgorithmNotAllowed(String),
    /// The request exceeded a host limit.
    TooLong,
    /// The OS entropy source failed.
    SourceFailed,
}

impl HostCallError {
    /// Convert to the shared error type.
    #[must_use]
    pub fn to_error(&self) -> qqq_core::Error {
        match self {
            Self::NotGranted(c) => qqq_core::Error::new(
                qqq_core::ErrorCode::CapabilityDenied,
                format!("capability `{c}` is not granted for this instance"),
            )
            .with_context("capability", c.name())
            .with_remediation(format!(
                "add a [[capabilities.*]] stanza granting `{c}` to qqq.toml"
            )),
            Self::AlgorithmNotAllowed(a) => qqq_core::Error::new(
                qqq_core::ErrorCode::CapabilityOutOfScope,
                format!("algorithm `{a}` is not in the manifest's allowlist"),
            )
            .with_context("algorithm", a.clone())
            .with_remediation("add it to the relevant `[capabilities.crypto]` list"),
            Self::TooLong => qqq_core::Error::new(
                qqq_core::ErrorCode::CapabilityOutOfScope,
                "the request exceeds the host's per-call maximum",
            )
            .with_remediation("split the request into smaller calls"),
            Self::SourceFailed => qqq_core::Error::new(
                qqq_core::ErrorCode::HostResourceExhausted,
                "the host entropy source failed",
            )
            .with_remediation(
                "do NOT fall back to a weaker source; this is an infrastructure fault",
            ),
        }
    }
}

/// Check that a capability is granted, returning a structured error if not.
///
/// # The capability-use record — `OBS-001`
///
/// This is **the seam where a capability is consulted**, so it is where a per-capability row is
/// written: `Granted` when the grant set allows the call, `Denied` when it does not. Recording
/// anywhere else would mean recording a capability the caller *guessed at* rather than the one
/// this function actually read — which is what the served path did before this, with a stated
/// placeholder, so a report aggregating by capability was aggregating a constant.
///
/// The append happens **before** the return, so a denial is recorded even though the call fails:
/// a refusal is the most interesting row in the stream (`Outcome::Denied`'s own doc says so), and
/// a record written only on success would omit exactly the events an auditor wants.
///
/// # Errors
///
/// `NotGranted` when the store's grants do not include `c`.
///
/// # Why the function name is a parameter
///
/// Because this is a generic check and the row must name **the host function that made the call**.
/// Hardcoding the one caller's name would be accurate until a second caller appeared and then
/// silently wrong — a record that misattributes an authority use is worse than one that omits it,
/// because it is evidence a reader would act on.
pub fn require(
    data: &StoreData,
    c: Capability,
    function: &'static str,
) -> Result<(), HostCallError> {
    let granted = data.grants.grants(c);
    if let Some(audit) = &data.audit {
        // The outcome is the *grant decision*, not the call's eventual success. A later failure
        // inside the host function is `Outcome::Failed`, which is a different row written by the
        // caller -- the two answer different questions and collapsing them would lose the
        // distinction `Outcome`'s own docs spend a paragraph on.
        let outcome = if granted {
            Outcome::Granted
        } else {
            Outcome::Denied
        };
        let _ = audit.record(c, function, outcome);
    }
    if granted {
        Ok(())
    } else {
        Err(HostCallError::NotGranted(c))
    }
}

/// Hash data, checking both the grant and the algorithm allowlist.
///
/// # Errors
///
/// `NotGranted` when `crypto.hash` is absent, or `AlgorithmNotAllowed` when the
/// algorithm is not in the manifest's list.
pub fn hash_data(
    data: &StoreData,
    algorithm: &str,
    input: &[u8],
) -> Result<Vec<u8>, HostCallError> {
    require(data, Capability::CryptoHash, "hash_data")?;
    let alg = HashAlgorithm::parse(algorithm)
        .ok_or_else(|| HostCallError::AlgorithmNotAllowed(algorithm.to_owned()))?;
    // The allowlist is enforced by the host, so a guest cannot use an algorithm
    // the manifest did not name even though the host *could* compute it.
    if !data.allowed_hashes.contains(&alg) {
        return Err(HostCallError::AlgorithmNotAllowed(algorithm.to_owned()));
    }
    Ok(AmbientState::hash(alg, input))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_cap::manifest::Manifest;

    /// A store whose capability uses are recorded — `OBS-001`.
    ///
    /// Returns the store and the stream, because the assertion is about **what the seam wrote**,
    /// and a test that could not read the stream would only be able to assert that `require`
    /// returned what it always returned.
    fn store_with_audit(
        src: &str,
    ) -> (
        StoreData,
        std::sync::Arc<std::sync::Mutex<crate::audit::AuditStream>>,
    ) {
        let m = Manifest::parse(src).expect("test manifest");
        // The digest the pool key uses, derived from the same grant set the store gets.
        let grants = qqq_cap::resolve::GrantSet::from_manifest(&m);
        let mut data = StoreData::from_manifest(&m);
        let stream = std::sync::Arc::new(std::sync::Mutex::new(
            crate::audit::AuditStream::with_default_capacity(),
        ));
        data.audit = Some(crate::audit::AuditHandle::new(
            std::sync::Arc::clone(&stream),
            crate::tenant::ComponentDigest::new("0011223344556677").expect("digest"),
            crate::tenant::GrantDigest::new(&grants.digest()).expect("digest"),
            None,
        ));
        (data, stream)
    }

    /// **The seam records the capability it actually read, not a constant — `OBS-001`.**
    ///
    /// This is the whole point of moving the record here. The served path used to write one row
    /// per request with a stated placeholder capability, so a report aggregating by capability was
    /// aggregating a constant. The assertion is therefore not *"a row was written"* but *"the row
    /// names the capability that was asked about"* — and it is run for **two different**
    /// capabilities, because a single one cannot distinguish a real value from a fixed one.
    #[test]
    fn the_seam_records_the_capability_it_read() {
        let (data, stream) = store_with_audit(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhash = [\"sha256\"]\n",
        );

        // Granted: the manifest allows crypto.hash.
        assert!(require(&data, Capability::CryptoHash, "hash_data").is_ok());
        // Denied: it does not allow sql.query.
        assert!(require(&data, Capability::SqlQuery, "hash_data").is_err());

        let s = stream.lock().expect("lock");
        let records = s.records();
        assert_eq!(records.len(), 2, "one row per consultation, granted or not");
        assert_eq!(
            records[0].capability,
            Capability::CryptoHash,
            "the granted row must name the capability that was read"
        );
        assert_eq!(records[1].capability, Capability::SqlQuery);
        assert_ne!(
            records[0].capability, records[1].capability,
            "two different capabilities must produce two different rows -- a constant would not"
        );
        assert_eq!(records[0].outcome, Outcome::Granted);
        assert_eq!(
            records[1].outcome,
            Outcome::Denied,
            "a refusal is recorded even though the call fails, because a refusal is the row an \
             auditor most wants"
        );
        assert_eq!(records[0].function, "hash_data");
        assert!(
            s.verify_chain().is_ok(),
            "the rows written by the seam must form a chain"
        );
    }

    /// **With no handle attached, nothing is recorded.**
    ///
    /// `qqqai run`, `qqq-debug` and every test that calls `Instance::create` must not start writing
    /// an evidence file. `None` is the honest default and this is the assertion that keeps it one.
    #[test]
    fn without_a_handle_nothing_is_recorded() {
        let m = Manifest::parse(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhash = [\"sha256\"]\n",
        )
        .expect("manifest");
        let data = StoreData::from_manifest(&m);
        assert!(data.audit.is_none(), "the default carries no handle");
        assert!(require(&data, Capability::CryptoHash, "hash_data").is_ok());
        // Nothing to assert on a stream that does not exist -- the assertion is the field itself,
        // and the point is that `require` did not need one to work.
    }

    /// **Every name in `RECORDED_FUNCTIONS` survives a round trip through the file format.**
    ///
    /// The writer's allowlist and the reader's are the same list, and a name added to one and not
    /// the other would produce a record the server writes and the CLI refuses to read -- a
    /// persisted record that cannot be reported on, discovered at the worst moment.
    #[test]
    fn every_recorded_function_round_trips() {
        for function in crate::audit::RECORDED_FUNCTIONS {
            let component =
                crate::tenant::ComponentDigest::new("0011223344556677").expect("digest");
            let grants = crate::tenant::GrantDigest::new("aabbccdd").expect("digest");
            let mut stream = crate::audit::AuditStream::with_default_capacity();
            let _ = stream.record(
                None,
                &component,
                &grants,
                Capability::CryptoHash,
                function,
                Outcome::Granted,
            );
            let json = stream.records()[0].to_json();
            let back = crate::audit::AuditRecord::from_json(&json)
                .unwrap_or_else(|e| panic!("`{function}` must round-trip: {e}"));
            assert_eq!(back.function, function);
        }
    }

    fn store_with(src: &str) -> StoreData {
        let m = Manifest::parse(src).expect("test manifest");
        // `from_manifest` rather than `new(grants)`: only the manifest names
        // *which* algorithms are allowed. Using `new` here would leave
        // `allowed_hashes` empty and every hash call would be refused — which
        // is exactly the bug this helper's first version had.
        StoreData::from_manifest(&m)
    }

    fn crypto_store() -> StoreData {
        store_with(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nrandom = true\nhash = [\"sha256\", \"blake3\"]\n",
        )
    }

    // -- Grant enforcement -------------------------------------------------

    #[test]
    fn a_missing_grant_is_refused() {
        let data = store_with("[package]\nname = \"a\"\nversion = \"0.1.0\"\n");
        let e = require(&data, Capability::CryptoHash, "hash_data").unwrap_err();
        assert_eq!(e, HostCallError::NotGranted(Capability::CryptoHash));
        let err = e.to_error();
        assert_eq!(err.code, qqq_core::ErrorCode::CapabilityDenied);
        assert!(err.remediation.is_some());
    }

    #[test]
    fn a_present_grant_is_accepted() {
        let data = crypto_store();
        assert!(require(&data, Capability::CryptoHash, "hash_data").is_ok());
        // And a capability NOT granted on the same store is still refused —
        // so the check is per-capability, not per-store.
        assert!(require(&data, Capability::SqlQuery, "hash_data").is_err());
    }

    // -- Hashing -----------------------------------------------------------

    #[test]
    fn hashing_produces_known_digests() {
        // Known-answer tests. A hash implementation that is "self-consistent"
        // but wrong would pass a round-trip test and break every consumer.
        let data = crypto_store();
        let sha = hash_data(&data, "sha256", b"abc").unwrap();
        assert_eq!(
            hex(&sha),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256 of \"abc\" must match the published test vector"
        );
        let b3 = hash_data(&data, "blake3", b"abc").unwrap();
        assert_eq!(
            hex(&b3),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
            "BLAKE3 of \"abc\" must match the published test vector"
        );
    }

    #[test]
    fn digest_lengths_match_the_algorithms() {
        for alg in [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
            HashAlgorithm::Blake3,
        ] {
            assert_eq!(
                AmbientState::hash(alg, b"x").len(),
                AmbientState::digest_len(alg),
                "{alg:?} digest length mismatch"
            );
        }
    }

    #[test]
    fn hashing_is_deterministic() {
        let data = crypto_store();
        let a = hash_data(&data, "sha256", b"payload").unwrap();
        let b = hash_data(&data, "sha256", b"payload").unwrap();
        assert_eq!(a, b);
    }

    /// An algorithm the host *can* compute but the manifest did not name must be
    /// refused. Otherwise the manifest's allowlist would be advisory.
    #[test]
    fn an_ungranted_algorithm_is_refused_even_though_the_host_supports_it() {
        let data = crypto_store(); // allows sha256 and blake3, NOT sha512
        let e = hash_data(&data, "sha512", b"x").unwrap_err();
        assert_eq!(e, HostCallError::AlgorithmNotAllowed("sha512".to_owned()));
        assert_eq!(e.to_error().code, qqq_core::ErrorCode::CapabilityOutOfScope);
    }

    /// An unknown algorithm gets the *same* error as a known-but-ungranted one,
    /// so a guest cannot enumerate the host's supported set by probing.
    #[test]
    fn unknown_and_ungranted_algorithms_are_indistinguishable() {
        let data = crypto_store();
        let unknown = hash_data(&data, "totally-made-up", b"x").unwrap_err();
        let ungranted = hash_data(&data, "sha512", b"x").unwrap_err();
        // Both are AlgorithmNotAllowed, differing only in the echoed name.
        assert!(matches!(unknown, HostCallError::AlgorithmNotAllowed(_)));
        assert!(matches!(ungranted, HostCallError::AlgorithmNotAllowed(_)));
        assert_eq!(unknown.to_error().code, ungranted.to_error().code);
    }

    #[test]
    fn hashing_without_the_grant_fails_before_looking_at_the_algorithm() {
        let data = store_with("[package]\nname = \"a\"\nversion = \"0.1.0\"\n");
        let e = hash_data(&data, "sha256", b"x").unwrap_err();
        assert_eq!(e, HostCallError::NotGranted(Capability::CryptoHash));
    }

    #[test]
    fn algorithm_parsing_is_strict() {
        assert_eq!(HashAlgorithm::parse("sha256"), Some(HashAlgorithm::Sha256));
        assert_eq!(
            HashAlgorithm::parse("SHA256"),
            None,
            "must be case-sensitive"
        );
        assert_eq!(
            HashAlgorithm::parse("md5"),
            None,
            "md5 is deliberately absent"
        );
        assert_eq!(
            HashAlgorithm::parse("sha1"),
            None,
            "sha1 is deliberately absent"
        );
        assert_eq!(HashAlgorithm::parse(""), None);
        for alg in [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
            HashAlgorithm::Blake3,
        ] {
            assert_eq!(
                HashAlgorithm::parse(alg.as_str()),
                Some(alg),
                "must round-trip"
            );
        }
    }

    // -- Determinism -------------------------------------------------------

    #[test]
    fn real_time_mode_reads_the_system_clock() {
        let s = AmbientState::new(false);
        assert!(!s.is_deterministic());
        let a = s.now_nanos();
        assert!(
            a > 1_600_000_000_000_000_000,
            "should be a plausible modern instant"
        );
    }

    /// **The determinism guarantee.** Two independent states in deterministic
    /// mode must produce identical sequences — that is what makes bit-identical
    /// replay possible.
    #[test]
    fn deterministic_mode_is_reproducible_across_instances() {
        let a = AmbientState::new(true);
        let b = AmbientState::new(true);
        assert_eq!(a.now_nanos(), b.now_nanos(), "the fixed clock must agree");
        for _ in 0..8 {
            assert_eq!(
                a.random_bytes(32).unwrap(),
                b.random_bytes(32).unwrap(),
                "two fresh instances must produce identical randomness"
            );
        }
    }

    #[test]
    fn deterministic_clock_advances_only_on_explicit_tick() {
        let s = AmbientState::new(true);
        let t0 = s.now_nanos();
        assert_eq!(s.now_nanos(), t0, "reading must not advance the clock");
        s.tick();
        assert!(s.now_nanos() > t0, "a tick must advance it");
        assert_eq!(s.now_nanos() - t0, s.tick_nanos);
    }

    #[test]
    fn ticking_does_not_affect_real_time_mode() {
        let s = AmbientState::new(false);
        s.tick();
        // It still reads the wall clock; the tick is a no-op.
        assert!(s.now_nanos() > 1_600_000_000_000_000_000);
    }

    #[test]
    fn deterministic_randomness_is_not_constant() {
        let s = AmbientState::new(true);
        let a = s.random_bytes(32).unwrap();
        let b = s.random_bytes(32).unwrap();
        assert_ne!(a, b, "each call must advance the generator");
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn random_lengths_are_honoured_exactly() {
        let s = AmbientState::new(true);
        for len in [0_u32, 1, 7, 8, 9, 31, 32, 100] {
            assert_eq!(
                s.random_bytes(len).unwrap().len(),
                len as usize,
                "length {len} not honoured"
            );
        }
    }

    #[test]
    fn oversized_random_requests_are_refused() {
        let s = AmbientState::new(true);
        let max = s.max_random_bytes;
        assert!(
            s.random_bytes(max).is_ok(),
            "exactly the maximum must be allowed"
        );
        assert_eq!(s.random_bytes(max + 1).unwrap_err(), RandomFailure::TooLong);
    }

    /// The deterministic generator must be architecture-independent, so a
    /// recorded run replays identically on another machine.
    ///
    /// # Why the value is pinned rather than computed
    ///
    /// The first version of this test asserted a value I had guessed. It failed
    /// — the real first eight bytes are `9639138b2c6e4176`. That is precisely
    /// why the assertion is valuable: the generator's output is a
    /// **compatibility surface** for replay, so an accidental change to the
    /// mixing function would silently invalidate every recorded run. Pinning the
    /// observed value means such a change fails the build and must be a
    /// deliberate decision.
    #[test]
    fn deterministic_randomness_is_pinned_to_known_bytes() {
        let s = AmbientState::new(true);
        let first = s.random_bytes(8).unwrap();
        assert_eq!(
            hex(&first),
            "9639138b2c6e4176",
            "the deterministic generator's first 8 bytes are a compatibility \
             surface; changing them breaks replay of every recorded run"
        );
    }

    #[test]
    fn real_time_randomness_differs_between_calls() {
        let s = AmbientState::new(false);
        let a = s.random_bytes(32).unwrap();
        let b = s.random_bytes(32).unwrap();
        assert_ne!(a, b, "a real CSPRNG must not repeat");
    }

    #[test]
    fn error_mapping_covers_every_variant() {
        for e in [
            HostCallError::NotGranted(Capability::CryptoHash),
            HostCallError::AlgorithmNotAllowed("x".to_owned()),
            HostCallError::TooLong,
            HostCallError::SourceFailed,
        ] {
            let err = e.to_error();
            assert!(err.remediation.is_some(), "{e:?} must carry a remediation");
            assert!(err.render().contains("QQQ-"));
        }
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}
