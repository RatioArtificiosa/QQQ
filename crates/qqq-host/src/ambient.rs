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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use qqq_cap::capability::Capability;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::audit::Outcome;
use crate::linker::StoreData;
use crate::replay::{ReplayLog, ReplayValue};

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
    /// The replay log, when one is attached — `DET-007`.
    ///
    /// # Why the sink is here and not in the caller
    ///
    /// Because the reads that must be recorded are this struct's own methods —
    /// [`Self::now_nanos`], [`Self::elapsed_nanos`] and [`Self::random_bytes`] —
    /// and all three take `&self`. A sink the caller held could not be reached
    /// from them without threading a parameter through every host function,
    /// which is the arrangement that makes a recording site easy to forget.
    ///
    /// # Why `Arc<Mutex<..>>` rather than a field
    ///
    /// The same reason [`crate::audit::AuditHandle`] uses it: `record` needs
    /// `&mut`, the readers have `&self`, and the state is shared across the
    /// instance's host calls. `Arc` because the log outlives the state so a
    /// caller can read what was recorded.
    ///
    /// # Why `None` is the default
    ///
    /// Because `Instance::create` is used by `qqqai run`, by tests and by
    /// `qqq-debug`, and **none of those should silently start writing a replay
    /// file.** [`Self::with_replay`] is the opt-in, mirroring
    /// `Instance::create_with_audit`.
    replay: Option<Arc<Mutex<ReplayLog>>>,
    /// The log a run is **replaying**, when `--replay` was given — `DET-008`.
    ///
    /// # Why this is separate from [`Self::replay`]
    ///
    /// Because they are opposite directions and a run does one or the other. `replay` is a sink the
    /// live path writes to; this is a source the replayed path reads from. **A single field would make
    /// "record" and "replay" the same state, and a run that both read from and wrote to one log would
    /// produce a file that describes itself.**
    ///
    /// # Why attaching this changes every read
    ///
    /// Because that is what a replay *is*. [`Self::with_replay_source`] is the opt-in, and every read
    /// then consults the cursor instead of the clock — through one decision point per read, so the two
    /// modes cannot drift.
    replay_source: Option<Arc<Mutex<ReplayLog>>>,
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
            replay: None,
            replay_source: None,
        }
    }

    /// Attach a log to **replay from** — `DET-008`.
    ///
    /// # Why this refuses outside deterministic mode
    ///
    /// Because a replayed run must build the same engine configuration the recorded one did, or the
    /// values it feeds back describe a different engine. The header carries `deterministic` for this
    /// reason, and [`Self::replay_mismatches`] is how a caller can say *which* field differs.
    ///
    /// # Why it also refuses when a sink is attached
    ///
    /// Because recording while replaying would append the replayed values to the log being read,
    /// which grows it as it is consumed and makes `is_exhausted` depend on how far the reader got.
    /// **The two directions are mutually exclusive by construction rather than by convention.**
    #[must_use]
    pub fn with_replay_source(mut self, log: Arc<Mutex<ReplayLog>>) -> Self {
        if self.deterministic && self.replay.is_none() {
            self.replay_source = Some(log);
        }
        self
    }

    /// Whether this state is replaying a recorded run.
    #[must_use]
    pub fn has_replay_source(&self) -> bool {
        self.replay_source.is_some()
    }

    /// Read the next recorded value for `function`, or `None` when this is a live run.
    ///
    /// # Why this is the single decision point
    ///
    /// Because the recording and the replaying have to agree about *which read this is*, and two
    /// functions that each decided independently would be two places a future change could miss. Every
    /// read below calls this first.
    ///
    /// A poisoned lock becomes [`crate::replay::ReplayError::ChainBroken`] rather than being ignored:
    /// unlike [`Self::note`], this path is what the guest's value *comes from*, and returning a
    /// fabricated one would be the failure the whole mechanism exists to prevent.
    fn next_replayed(
        &self,
        function: &'static str,
    ) -> Option<Result<crate::replay::ReplayValue, crate::replay::ReplayError>> {
        let source = self.replay_source.as_ref()?;
        Some(match source.lock() {
            Ok(mut log) => log.next_record(function),
            Err(_) => Err(crate::replay::ReplayError::ChainBroken),
        })
    }

    /// The wall clock, replaying if a source is attached — `DET-002` and `DET-008`.
    ///
    /// # Errors
    ///
    /// [`crate::replay::ReplayError`] when replaying and the log is exhausted, or when its next record
    /// is for a different function. **Both are errors rather than fallbacks**, so a replayed run that
    /// diverged from its recording stops instead of continuing against a real clock.
    pub fn read_wall_nanos(&self) -> Result<u64, crate::replay::ReplayError> {
        if let Some(next) = self.next_replayed("clock.wall") {
            return match next? {
                crate::replay::ReplayValue::Clock(v) => Ok(v),
                other => Err(crate::replay::ReplayError::Unexpected {
                    expected: "clock.wall",
                    // A value whose kind does not match the function it was recorded under. The
                    // function names already agree, so the log is internally inconsistent.
                    found: other.kind(),
                }),
            };
        }
        let value = self.live_wall_nanos();
        self.note("clock.wall", crate::replay::ReplayValue::Clock(value));
        Ok(value)
    }

    /// The monotonic clock, replaying if a source is attached.
    ///
    /// # Errors
    ///
    /// As [`Self::read_wall_nanos`].
    pub fn read_monotonic_nanos(&self) -> Result<u64, crate::replay::ReplayError> {
        if let Some(next) = self.next_replayed("clock.monotonic") {
            return match next? {
                crate::replay::ReplayValue::Clock(v) => Ok(v),
                other => Err(crate::replay::ReplayError::Unexpected {
                    expected: "clock.monotonic",
                    found: other.kind(),
                }),
            };
        }
        let value = self.live_monotonic_nanos();
        self.note("clock.monotonic", crate::replay::ReplayValue::Clock(value));
        Ok(value)
    }

    /// Random bytes, replaying if a source is attached.
    ///
    /// # Errors
    ///
    /// [`RandomFailure::Replay`] when replaying and the log cannot supply the bytes, and the live
    /// failures otherwise.
    pub fn read_random(&self, len: u32) -> Result<Vec<u8>, RandomFailure> {
        if let Some(next) = self.next_replayed("crypto.random") {
            return match next.map_err(RandomFailure::Replay)? {
                crate::replay::ReplayValue::Random(bytes) => {
                    // **The recorded length is checked against the request**, because a log that
                    // supplies 8 bytes for a 32-byte request would hand the guest a short buffer --
                    // which is a correctness failure the guest cannot see.
                    if bytes.len() == len as usize {
                        Ok(bytes)
                    } else {
                        Err(RandomFailure::Replay(
                            crate::replay::ReplayError::Unexpected {
                                expected: "crypto.random",
                                found: "crypto.random (wrong length)",
                            },
                        ))
                    }
                }
                other => Err(RandomFailure::Replay(
                    crate::replay::ReplayError::Unexpected {
                        expected: "crypto.random",
                        found: other.kind(),
                    },
                )),
            };
        }
        self.random_bytes(len)
    }

    /// Attach a replay log, so every nondeterministic read is recorded — `DET-007`.
    ///
    /// # Why this is a builder rather than a `new` parameter
    ///
    /// Because a fourth positional argument to `new` would have to be passed at
    /// every call site, and the call sites that do not want a log are the
    /// majority — `qqqai run`, tests, `qqq-debug`. A builder keeps the default
    /// honest and makes the opt-in greppable, which is the same shape
    /// `Instance::create_with_audit` uses for the audit stream.
    ///
    /// # Why it refuses to attach outside deterministic mode
    ///
    /// Because a log recorded with a real clock records nothing reproducible.
    /// `ReplayHeader` carries `deterministic` for exactly this reason, and
    /// attaching one here would produce a file whose header and whose contents
    /// disagree. The caller gets `None` back and can see it.
    #[must_use]
    pub fn with_replay(mut self, log: Arc<Mutex<ReplayLog>>) -> Self {
        if self.deterministic {
            self.replay = Some(log);
        }
        self
    }

    /// Whether a replay log is attached.
    #[must_use]
    pub fn has_replay(&self) -> bool {
        self.replay.is_some()
    }

    /// Record one nondeterministic read, if a log is attached.
    ///
    /// # Why this is one function and not three copies
    ///
    /// Because the three recording sites differ only in the function name and
    /// the value, and a copy per site is three places a future change can miss.
    /// It is also where the `deterministic` guard lives, so a site cannot record
    /// without it — which is the property `ReplayHeader::deterministic` depends
    /// on.
    ///
    /// A poisoned lock is ignored rather than propagated: this is a recording
    /// side-channel, and **failing a guest's clock read because a log writer
    /// panicked would turn a diagnostic into an outage.**
    fn note(&self, function: &'static str, value: ReplayValue) {
        if !self.deterministic {
            return;
        }
        if let Some(log) = &self.replay {
            if let Ok(mut log) = log.lock() {
                let _ = log.record(function, value);
            }
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

    /// The wall clock **without consulting a replay source** — the computation itself.
    ///
    /// Split out so [`Self::read_wall_nanos`] and [`Self::now_nanos`] share one definition of what the
    /// virtual clock *is*. Two copies would be two places a change to `tick_nanos` could miss.
    fn live_wall_nanos(&self) -> u64 {
        if self.deterministic {
            let ticks = self.ticks.load(Ordering::Relaxed);
            self.fixed_nanos
                .saturating_add(self.tick_nanos.saturating_mul(ticks))
        } else {
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => u64::try_from(d.as_nanos()).unwrap_or(u64::MAX),
                // A clock before 1970 means the system clock is wrong. Report the epoch rather than
                // wrapping to a huge value, which a guest might store.
                Err(_) => 0,
            }
        }
    }

    /// The monotonic clock **without consulting a replay source**.
    fn live_monotonic_nanos(&self) -> u64 {
        if self.deterministic {
            let ticks = self.ticks.load(Ordering::Relaxed);
            self.tick_nanos.saturating_mul(ticks)
        } else {
            // `get_or_init` rather than reading a stored `Instant`: the origin is the moment the
            // monotonic clock was *first read*, so two instances constructed at different times still
            // both start at zero, which is what makes a monotonic reading comparable only within one
            // instance — exactly what the WIT promises.
            let origin = self.origin.get_or_init(Instant::now);
            u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
        }
    }

    /// Panic if this state is replaying, for the infallible wrappers below.
    ///
    /// # Why a panic rather than a live read
    ///
    /// Because the alternative is the failure the whole mechanism exists to prevent: a replayed run
    /// that silently read the real clock would produce an execution that looks plausible and shares
    /// nothing with the recorded one. **A panic here is a programming error in the host** — the
    /// production call sites use the fallible [`Self::read_wall_nanos`] family — and it is loud on
    /// purpose.
    ///
    /// # Why the wrappers exist at all
    ///
    /// Because 25 tests call them, and a test that had to unwrap a `Result` for a value it knows is
    /// present would be noise. **The wrappers are the live path with a guard, not a second
    /// implementation.**
    fn assert_not_replaying(&self) {
        assert!(
            self.replay_source.is_none(),
            "a replayed run must read through `read_*`, not the infallible wrappers: \
             reading the live clock here would reproduce a different execution"
        );
    }

    /// The current virtual time, in nanoseconds since the epoch.
    ///
    /// In deterministic mode: the fixed instant plus `ticks` advances.
    /// Otherwise: the real system clock.
    ///
    /// **The value is recorded before it is returned**, so a replay reproduces what the guest saw
    /// rather than recomputing it — `DET-007`.
    ///
    /// # Panics
    ///
    /// If a replay source is attached. Use [`Self::read_wall_nanos`] on a replayed run.
    #[must_use]
    pub fn now_nanos(&self) -> u64 {
        self.assert_not_replaying();
        let value = self.live_wall_nanos();
        self.note("clock.wall", ReplayValue::Clock(value));
        value
    }

    /// Advance the virtual clock by one tick. No effect in real-time mode.
    ///
    /// **Not a recording site.** A tick produces no value a guest can observe —
    /// the next [`Self::now_nanos`] records the advanced reading. What has to be
    /// deterministic is *when* the host ticks, and in deterministic mode that is
    /// a property of the caller rather than of this method.
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
        self.assert_not_replaying();
        let value = self.live_monotonic_nanos();
        // A separate function name from `clock.wall`, because the two answer different questions and a
        // replay reader comparing them would otherwise see one series where the guest saw two.
        self.note("clock.monotonic", ReplayValue::Clock(value));
        value
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
        self.assert_not_replaying();
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
            // Recorded here rather than at the single `Ok(out)` below, because
            // the real-time path's bytes are not reproducible and must not be
            // logged: a `Random` record from a real run would replay a value the
            // generator never produced. `note` guards on `deterministic` too, so
            // this is the second of two checks rather than the only one.
            self.note("crypto.random", ReplayValue::Random(out.clone()));
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
    /// A replay could not supply the recorded bytes — `DET-008`.
    ///
    /// **A separate variant rather than a reuse of [`Self::SourceFailed`]**, and the reason is the one
    /// `§O-280` states from the other side: a report that cannot state its cause is not a report.
    /// "The entropy source failed" and "the replay log ended early" send a reader to different files,
    /// and collapsing them would make a truncated log look like an OS problem.
    Replay(crate::replay::ReplayError),
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

    /// **The injection this step exists for.** A sink wired to the wrong read, or
    /// wired but never called, passes a *presence* check and fails this one.
    ///
    /// Two `now_nanos()` calls in deterministic mode must produce two records
    /// whose `Clock` values are **equal** — the virtual clock does not advance
    /// unasked — and a third after a `tick()` must be **larger**. Reading the log
    /// back rather than asserting the field is what makes the test a measurement:
    /// `has_replay()` would be true for a sink that records nothing.
    #[test]
    fn two_deterministic_reads_are_recorded_and_equal() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(crate::replay::ReplayLog::new(
            crate::replay::ReplayHeader {
                artifact_digest: "sha256:test".to_owned(),
                engine_version: "48.0.2".to_owned(),
                target_triple: "test".to_owned(),
                deterministic: true,
            },
            8,
        )));
        let s = AmbientState::new(true).with_replay(std::sync::Arc::clone(&log));
        assert!(s.has_replay());

        let first = s.now_nanos();
        let second = s.now_nanos();
        assert_eq!(first, second, "a virtual clock must not advance unasked");

        let guard = log.lock().expect("log");
        assert_eq!(guard.records().len(), 2, "both reads must be recorded");
        match (&guard.records()[0].value, &guard.records()[1].value) {
            (crate::replay::ReplayValue::Clock(a), crate::replay::ReplayValue::Clock(b)) => {
                assert_eq!(a, b, "the two recorded readings must agree");
                assert_eq!(*a, first, "and must be the value the caller got");
            }
            other => panic!("expected two Clock records, got {other:?}"),
        }
        assert_eq!(guard.records()[0].function, "clock.wall");
        drop(guard);

        s.tick();
        let third = s.now_nanos();
        assert!(third > first, "a tick must advance the clock");
        let guard = log.lock().expect("log");
        assert_eq!(guard.records().len(), 3);
        match &guard.records()[2].value {
            crate::replay::ReplayValue::Clock(c) => assert_eq!(*c, third),
            other => panic!("expected a Clock record, got {other:?}"),
        }
        assert!(
            guard.verify().is_ok(),
            "the chain must verify after three appends"
        );
    }

    /// **The negative half, and it is the one that matters for safety.** A state
    /// in real-time mode must record **nothing**, because the bytes and instants
    /// it reads are not reproducible and a log of them would replay values the
    /// generator never produced.
    ///
    /// `with_replay` refuses to attach outside deterministic mode, and `note`
    /// guards again — so this asserts the second check independently of the
    /// first, which is why it constructs the state and then tries to attach.
    #[test]
    fn a_real_time_state_records_nothing() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(crate::replay::ReplayLog::new(
            crate::replay::ReplayHeader {
                artifact_digest: "sha256:test".to_owned(),
                engine_version: "48.0.2".to_owned(),
                target_triple: "test".to_owned(),
                deterministic: false,
            },
            8,
        )));
        let s = AmbientState::new(false).with_replay(std::sync::Arc::clone(&log));
        assert!(!s.has_replay(), "a real-time state must refuse a log");
        let _ = s.now_nanos();
        let _ = s.elapsed_nanos();
        let _ = s.random_bytes(8).expect("the OS source");
        assert!(
            log.lock().expect("log").records().is_empty(),
            "nothing may be recorded outside deterministic mode"
        );
    }

    /// The two clock reads are recorded under **different function names**, so a
    /// replay reader does not see one series where the guest saw two.
    #[test]
    fn the_wall_and_monotonic_reads_are_named_apart() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(crate::replay::ReplayLog::new(
            crate::replay::ReplayHeader {
                artifact_digest: "sha256:test".to_owned(),
                engine_version: "48.0.2".to_owned(),
                target_triple: "test".to_owned(),
                deterministic: true,
            },
            8,
        )));
        let s = AmbientState::new(true).with_replay(std::sync::Arc::clone(&log));
        let _ = s.now_nanos();
        let _ = s.elapsed_nanos();
        let _ = s.random_bytes(4).expect("the generator");
        let guard = log.lock().expect("log");
        let names: Vec<&str> = guard.records().iter().map(|r| r.function).collect();
        assert_eq!(
            names,
            vec!["clock.wall", "clock.monotonic", "crypto.random"]
        );
        assert!(
            matches!(
                guard.records()[2].value,
                crate::replay::ReplayValue::Random(_)
            ),
            "the random read must carry bytes, not an instant"
        );
    }

    /// **The positive half of `DET-008`.** A state replaying a log must return the recorded values
    /// rather than computing its own — and the values must be the ones in the log, not merely
    /// *some* values, which is why the recorded instant is deliberately different from the fixed one.
    #[test]
    fn a_replaying_state_returns_the_recorded_values() {
        let mut written = crate::replay::ReplayLog::new(replay_header(), 8);
        // Deliberately NOT the fixed instant `AmbientState::new(true)` reports, so a state that
        // computed its own value would return something else and the assertion would catch it.
        written
            .record("clock.wall", crate::replay::ReplayValue::Clock(42))
            .unwrap();
        written
            .record("clock.monotonic", crate::replay::ReplayValue::Clock(7))
            .unwrap();
        written
            .record(
                "crypto.random",
                crate::replay::ReplayValue::Random(vec![0xAB; 4]),
            )
            .unwrap();

        let source = std::sync::Arc::new(std::sync::Mutex::new(written));
        let s = AmbientState::new(true).with_replay_source(std::sync::Arc::clone(&source));
        assert!(s.has_replay_source());
        assert_eq!(
            s.read_wall_nanos().unwrap(),
            42,
            "the recorded instant, not the fixed one"
        );
        assert_eq!(s.read_monotonic_nanos().unwrap(), 7);
        assert_eq!(s.read_random(4).unwrap(), vec![0xAB; 4]);
        assert!(
            source.lock().expect("log").is_exhausted(),
            "all three reads must have consumed the log"
        );
    }

    /// **A truncated log must fail, not fall back to the real clock.** This is the property the whole
    /// mechanism exists for: a replay that continued against a live clock would reproduce a different
    /// execution and report success.
    #[test]
    fn an_exhausted_replay_fails_rather_than_reading_the_clock() {
        let mut written = crate::replay::ReplayLog::new(replay_header(), 8);
        written
            .record("clock.wall", crate::replay::ReplayValue::Clock(1))
            .unwrap();
        let s = AmbientState::new(true)
            .with_replay_source(std::sync::Arc::new(std::sync::Mutex::new(written)));
        assert!(s.read_wall_nanos().is_ok());
        assert_eq!(
            s.read_wall_nanos(),
            Err(crate::replay::ReplayError::Exhausted),
            "the second read must fail, not fall back"
        );
    }

    /// **A recorded length that does not match the request is refused.** A log supplying four bytes
    /// for a thirty-two-byte request would hand the guest a short buffer it cannot see.
    ///
    /// # What the first version of this test got wrong
    ///
    /// It requested 4 against a 4-byte record and asserted a refusal — but those *match*, so it
    /// asserted the opposite of the behaviour. And its second assertion reused the same state, whose
    /// only record the first call had already consumed, so it would have failed with `Exhausted`
    /// rather than with a length mismatch. **Two errors in three lines, both from writing the test
    /// against an imagined shape rather than the real one.** Each case now gets its own state.
    #[test]
    fn a_replayed_length_mismatch_is_refused() {
        // Recorded 4, requested 32: the refusal this test exists for.
        let s = state_replaying_one_random(4);
        assert!(
            matches!(s.read_random(32), Err(RandomFailure::Replay(_))),
            "a short record must not satisfy a longer request"
        );

        // And the matching case, which the first version asserted backwards.
        let s = state_replaying_one_random(4);
        assert_eq!(
            s.read_random(4).expect("a matching length").len(),
            4,
            "4 recorded bytes satisfy a 4-byte request"
        );
    }

    /// A state replaying exactly one `crypto.random` record of `len` bytes.
    fn state_replaying_one_random(len: usize) -> AmbientState {
        let mut written = crate::replay::ReplayLog::new(replay_header(), 8);
        written
            .record(
                "crypto.random",
                crate::replay::ReplayValue::Random(vec![0x5A; len]),
            )
            .unwrap();
        AmbientState::new(true)
            .with_replay_source(std::sync::Arc::new(std::sync::Mutex::new(written)))
    }

    /// **The infallible wrappers must refuse to run while replaying.** They exist for tests and for
    /// the live path; a replayed run reaching one would read the real clock and diverge silently, so
    /// the guard converts that into a loud failure.
    #[test]
    #[should_panic(expected = "must read through `read_*`")]
    fn the_infallible_wrapper_refuses_while_replaying() {
        let written = crate::replay::ReplayLog::new(replay_header(), 8);
        let s = AmbientState::new(true)
            .with_replay_source(std::sync::Arc::new(std::sync::Mutex::new(written)));
        let _ = s.now_nanos();
    }

    /// A real-time state refuses a replay source, for the same reason it refuses a sink: a replay of
    /// a non-deterministic run is not a replay.
    #[test]
    fn a_real_time_state_refuses_a_replay_source() {
        let written = crate::replay::ReplayLog::new(replay_header(), 8);
        let s = AmbientState::new(false)
            .with_replay_source(std::sync::Arc::new(std::sync::Mutex::new(written)));
        assert!(
            !s.has_replay_source(),
            "a real-time state must refuse a source"
        );
    }

    /// **Recording while replaying is refused**, so a log cannot grow as it is consumed.
    #[test]
    fn a_state_cannot_record_and_replay_at_once() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(crate::replay::ReplayLog::new(
            replay_header(),
            8,
        )));
        let s = AmbientState::new(true).with_replay(log.clone());
        assert!(s.has_replay());
        let s = s.with_replay_source(log);
        assert!(
            !s.has_replay_source(),
            "attaching a source beside a sink must be refused"
        );
    }

    fn replay_header() -> crate::replay::ReplayHeader {
        crate::replay::ReplayHeader {
            artifact_digest: "sha256:test".to_owned(),
            engine_version: "48.0.2".to_owned(),
            target_triple: "test".to_owned(),
            deterministic: true,
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
