// SPDX-License-Identifier: Apache-2.0

//! The replay log — `DET-007`, and the format `DET-008` reads back and `DET-011` records into.
//!
//! # What this is for
//!
//! Proposal §10.5 states the claim this module serves:
//!
//! > With `[determinism] enabled = true`, executing the same component with the same inputs produces
//! > a bit-identical result, and the execution is **recorded in a replay log sufficient to reproduce
//! > it exactly — including any failure**.
//!
//! The engine configuration (`crate::config::EngineConfig::deterministic`) makes the wall clock fixed,
//! the monotonic clock ticked and the RNG seeded. **That is not the same as being able to reproduce a
//! run**, because three things remain outside the configuration: a wall-clock read still returns a
//! value the guest can branch on, a random read still returns bytes, and network timing still varies.
//! **The log is what makes those three reproducible, by recording the value the host produced.**
//!
//! # The relationship to the audit stream
//!
//! [`crate::audit`] is the module next door, and it answers a different question about the same calls.
//! It records **that** `hash_data` was called, by which tenant, under which grants, with what outcome —
//! and it does **not** record what the call returned. This module records the return value and nothing
//! else. **Two sinks of one event point**, and the split is deliberate: an audit record is evidence
//! about authority, and a replay record is evidence about a computation. Conflating them would mean a
//! replay log carrying tenant identifiers it has no use for, and an audit stream carrying random bytes
//! it must not retain.
//!
//! # The five properties, each copied from `audit.rs` because each is a way a log fails silently
//!
//! | property | what a log does instead | what this does |
//! |---|---|---|
//! | **Append-only** | rotates, truncates, drops | a full ring **refuses** rather than overwrites |
//! | **Hash-chained** | each line independent | every record carries its predecessor's digest |
//! | **Counted** | best-effort, lossy | `recorded` / `refused` are split, so a gap is a **value** |
//! | **A closed function set** | any string | bounded by the interfaces' own WIT, and refused otherwise |
//! | **Injective encoding** | bare concatenation | every field is length-prefixed before hashing |
//!
//! The fourth and fifth are the ones a replay log needs more than an audit stream does, and for the
//! same reason: **a replay file is attacker-supplied by construction.** It is the artefact a user
//! downloads, mails to a colleague, or attaches to a bug report, so every field in it is data from
//! outside. `audit.rs` states the rule for the function-name case —
//!
//! > A parser that interned an arbitrary name would need `Box::leak`, which is a memory leak whose size
//! > **the file controls** — an unbounded allocation an attacker can drive from a file the server
//! > reads at start-up.
//!
//! — and a replay log reads a file the *user* names, so the rule applies with less ceremony and more
//! force.
//!
//! # What this module deliberately does not do
//!
//! It does not read the clock, the RNG or the network, and it is not wired into
//! [`crate::ambient::AmbientState`]. **That is the next step, and keeping it separate is what makes
//! this one testable without an engine**: the format can be wrong on its own, and a format that is
//! wrong is a format that reproduces a *different* execution and reports success.

use sha2::{Digest, Sha256};
use std::borrow::Cow;

/// The four things §10.5 says determinism is relative to, plus the one a reader also needs.
///
/// §10.5's honest-limits paragraph names the first three and the fourth:
///
/// > determinism holds for a given (**artifact digest, engine version, target triple, config**). It
/// > does not survive a Wasmtime upgrade that changes codegen in an observable way, and it cannot
/// > serialize true external I/O without recording it.
///
/// **A replay log whose header omits any of them cannot tell a reader whether the replay is valid**,
/// which is the same failure as a budget with no owner: the number exists and nothing can compare it.
///
/// # Why `deterministic` is a fifth field and not implied
///
/// Because a log can be produced with determinism **off** — nothing prevents it, and it is useful for
/// capturing a failure that only reproduces under real timing. **Such a log is not a replay of a
/// deterministic run**, and a reader that assumed it was would compare a virtual clock against a real
/// one and conclude the engine was broken.
#[derive(Debug, Clone, PartialEq, Eq)]
/// ```
/// use qqq_host::replay::ReplayHeader;
///
/// let h = ReplayHeader {
///     artifact_digest: "sha256:9f2c".to_owned(),
///     engine_version: "48.0.3".to_owned(),
///     target_triple: "x86_64-pc-windows-msvc".to_owned(),
///     deterministic: true,
/// };
/// assert!(h.mismatches(&h).is_empty());
/// ```
pub struct ReplayHeader {
    /// The artifact the execution ran, as the lockfile records it.
    pub artifact_digest: String,
    /// The engine version that produced the code. A codegen change invalidates a replay.
    pub engine_version: String,
    /// The target triple. A different CPU or OS cannot run the same native code.
    pub target_triple: String,
    /// Whether the run had determinism enabled.
    pub deterministic: bool,
}

impl ReplayHeader {
    /// Whether this header describes the same conditions as `other`.
    ///
    /// # Why this is a method rather than `==`
    ///
    /// Because a caller asking the question wants to know **which** field differs, and a `bool` cannot
    /// say. A replay refused with "the header does not match" sends a reader to four fields; the
    /// mismatch list sends them to one. The same reasoning `audit.rs` gives for travelling as a struct
    /// rather than positionally.
    #[must_use]
    /// ```
    /// use qqq_host::replay::ReplayHeader;
    ///
    /// let a = ReplayHeader {
    ///     artifact_digest: "a".to_owned(),
    ///     engine_version: "48.0.3".to_owned(),
    ///     target_triple: "test".to_owned(),
    ///     deterministic: true,
    /// };
    /// let mut b = a.clone();
    /// b.engine_version = "49.0.0".to_owned();
    /// assert_eq!(a.mismatches(&b), vec!["engine_version"]);
    /// ```
    pub fn mismatches(&self, other: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.artifact_digest != other.artifact_digest {
            out.push("artifact_digest");
        }
        if self.engine_version != other.engine_version {
            out.push("engine_version");
        }
        if self.target_triple != other.target_triple {
            out.push("target_triple");
        }
        if self.deterministic != other.deterministic {
            out.push("deterministic");
        }
        out
    }
}

/// A recorded nondeterministic value.
///
/// # Why this is a closed enum
///
/// A replay log exists to reproduce three specific reads, and an open value type cannot be refused.
/// `audit.rs` makes the same argument for `RECORDED_FUNCTIONS`: a parser that accepted an arbitrary
/// variant would have to invent a meaning for it, and a variant nobody defined is a value nobody can
/// replay. **Closed means a new kind of nondeterminism is a compile error rather than a silent gap.**
#[derive(Debug, Clone, PartialEq, Eq)]
/// ```
/// use qqq_host::replay::ReplayValue;
///
/// assert_eq!(ReplayValue::Clock(1).kind(), "clock");
/// assert_eq!(ReplayValue::Random(vec![0x51]).kind(), "random");
/// assert_eq!(ReplayValue::Network(4_200).kind(), "network");
/// ```
pub enum ReplayValue {
    /// A wall-clock or monotonic reading, in nanoseconds since the Unix epoch.
    Clock(u64),
    /// Bytes returned by `qqq:crypto.random.get`.
    Random(Vec<u8>),
    /// A network timing observation, in nanoseconds.
    Network(u64),
}

impl ReplayValue {
    /// The variant's name, for a report and for the JSON encoding.
    #[must_use]
    /// ```
    /// use qqq_host::replay::ReplayValue;
    ///
    /// assert_eq!(ReplayValue::Clock(0).kind(), "clock");
    /// ```
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Clock(_) => "clock",
            Self::Random(_) => "random",
            Self::Network(_) => "network",
        }
    }

    /// This value as the string the digest is computed over.
    ///
    /// # Why bytes are hex-encoded rather than hashed directly
    ///
    /// Because the digest is over a **sequence of length-prefixed fields**, and a `Vec<u8>` is a field
    /// whose length is attacker-controlled. Hex makes it a string of known length and keeps every
    /// field's encoding the same shape. It costs one allocation per record and removes a class of
    /// ambiguity the length prefix exists to prevent — see [`field`].
    #[must_use]
    fn canonical(&self) -> String {
        match self {
            Self::Clock(nanos) | Self::Network(nanos) => nanos.to_string(),
            Self::Random(bytes) => hex(bytes),
        }
    }
}

/// One recorded read.
#[derive(Debug, Clone, PartialEq, Eq)]
/// ```
/// use qqq_host::replay::{ReplayHeader, ReplayLog, ReplayValue};
///
/// let mut log = ReplayLog::new(
///     ReplayHeader {
///         artifact_digest: "sha256:9f2c".to_owned(),
///         engine_version: "48.0.3".to_owned(),
///         target_triple: "test".to_owned(),
///         deterministic: true,
///     },
///     8,
/// );
/// log.record("clock.wall", ReplayValue::Clock(7)).expect("room");
/// assert_eq!(log.records()[0].sequence, 1, "the first record is 1, not 0");
/// ```
pub struct ReplayRecord {
    /// 1-based position in the log.
    ///
    /// **1-based for the reason `AuditRecord::sequence` is**: a missing record is visible as a gap
    /// rather than as an off-by-one that reads like a normal first element.
    pub sequence: u64,
    /// The host function that produced the value. Bounded by the interfaces' own WIT.
    pub function: &'static str,
    /// What it produced.
    pub value: ReplayValue,
    /// The digest of the preceding record, or [`genesis_digest`] for the first.
    pub previous: String,
    /// This record's digest: SHA-256 over every field above, in order, length-prefixed.
    pub chain: String,
}

/// The fields a record's digest covers, as one named value.
///
/// The same reasoning `AuditFields` gives: eight positional arguments to a hash function are eight
/// chances to pass the right values in the wrong order, and a named struct makes the mistake
/// impossible rather than unlikely.
///
/// `Clone` but **not `Copy`**, unlike `AuditFields`: `canonical` is a `Cow`, and a `Cow` that owns its
/// string cannot be copied. That is the whole point of the type — a caller that already has the string
/// passes a borrow, and one that had to build it passes the value.
#[derive(Debug, Clone)]
/// ```
/// use qqq_host::replay::ReplayFields;
///
/// let f = ReplayFields {
///     sequence: 1,
///     function: "clock.wall",
///     kind: "clock",
///     canonical: "7".into(),
///     previous: "genesis",
/// };
/// assert_eq!(f.sequence, 1);
/// ```
pub struct ReplayFields<'a> {
    /// 1-based position in the log.
    pub sequence: u64,
    /// The host function.
    pub function: &'a str,
    /// The variant name of the value — `clock`, `random` or `network`.
    pub kind: &'a str,
    /// The value, canonically encoded.
    ///
    /// `Cow` rather than `&'a str` because the encoding is **computed**, not borrowed: a `Clock`'s
    /// digits and a `Random`'s hex are produced by [`ReplayValue::canonical`], so a plain reference
    /// would point at a temporary that dies when `fields()` returns — which is `E0515`, and is what
    /// the first version of this file failed to compile with. Borrowed for a caller that already has
    /// the string, owned for the one that had to build it.
    pub canonical: Cow<'a, str>,
    /// The digest of the preceding record.
    pub previous: &'a str,
}

impl ReplayRecord {
    /// This record's own fields, for re-hashing during verification.
    #[must_use]
    /// ```
    /// use qqq_host::replay::{ReplayHeader, ReplayLog, ReplayValue};
    ///
    /// let mut log = ReplayLog::new(
    ///     ReplayHeader {
    ///         artifact_digest: "a".to_owned(),
    ///         engine_version: "48.0.3".to_owned(),
    ///         target_triple: "test".to_owned(),
    ///         deterministic: true,
    ///     },
    ///     4,
    /// );
    /// log.record("clock.wall", ReplayValue::Clock(7)).expect("room");
    /// assert_eq!(log.records()[0].fields().sequence, 1);
    /// ```
    pub fn fields(&self) -> ReplayFields<'_> {
        ReplayFields {
            sequence: self.sequence,
            function: self.function,
            kind: self.value.kind(),
            canonical: Cow::Owned(self.value.canonical()),
            previous: &self.previous,
        }
    }

    /// Compute the digest a record with these fields would carry.
    ///
    /// # Why the fields are hashed with a length prefix
    ///
    /// `audit.rs` states it and the argument transfers unchanged: a bare concatenation is ambiguous,
    /// because `("ab", "c")` and `("a", "bc")` produce the same input. **Here it is stronger**, since
    /// one of the fields is a byte string the *guest* chose the length of: without a prefix, a guest
    /// that can ask for `random.get(n)` can construct two different records with one digest, and a
    /// chain that can be made to collide is a chain that cannot detect an edit.
    #[must_use]
    /// ```
    /// use qqq_host::replay::{ReplayFields, ReplayRecord};
    ///
    /// let a = ReplayRecord::compute_chain(&ReplayFields {
    ///     sequence: 1,
    ///     function: "clock.wall",
    ///     kind: "clock",
    ///     canonical: "abcd".into(),
    ///     previous: "genesis",
    /// });
    /// let b = ReplayRecord::compute_chain(&ReplayFields {
    ///     sequence: 1,
    ///     function: "clock.wall",
    ///     kind: "clock",
    ///     canonical: "abc".into(),
    ///     previous: "genesis",
    /// });
    /// assert_ne!(a, b, "the encoding must be injective");
    /// ```
    pub fn compute_chain(fields: &ReplayFields<'_>) -> String {
        let mut h = Sha256::new();
        field(&mut h, &fields.sequence.to_string());
        field(&mut h, fields.function);
        field(&mut h, fields.kind);
        field(&mut h, &fields.canonical);
        field(&mut h, fields.previous);
        hex(&h.finalize())
    }

    /// The digest the first record in a log carries as its `previous`.
    ///
    /// # Why the chain starts at a named digest rather than the empty string
    ///
    /// Because the empty string is a value a record's `previous` could legitimately hold if a writer
    /// produced one by mistake, and then the mistake is indistinguishable from a valid genesis. A
    /// named constant makes "this is the first record" a value no other field can take.
    #[must_use]
    /// ```
    /// use qqq_host::replay::ReplayRecord;
    ///
    /// assert_eq!(ReplayRecord::genesis_digest().len(), 64, "a SHA-256 in hex");
    /// ```
    pub fn genesis_digest() -> String {
        let mut h = Sha256::new();
        field(&mut h, "qqq-replay-log-genesis-v1");
        hex(&h.finalize())
    }
}

/// How many records a log accepted, and how many it refused.
///
/// Split rather than summed because **a replay with a gap must say so**. `--replay` reading a log that
/// silently dropped a record would reproduce a *different* execution and report success, which is the
/// one outcome the whole mechanism exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// ```
/// use qqq_host::replay::AppendCounters;
///
/// let c = AppendCounters { recorded: 2, refused: 1 };
/// assert!(c.has_gaps(), "a refused record is a gap, and it is visible as a value");
/// ```
pub struct AppendCounters {
    /// Records accepted.
    pub recorded: u64,
    /// Records refused because the log was full.
    pub refused: u64,
}

impl AppendCounters {
    /// Whether any record was refused.
    #[must_use]
    /// ```
    /// use qqq_host::replay::AppendCounters;
    ///
    /// assert!(AppendCounters { recorded: 1, refused: 1 }.has_gaps());
    /// ```
    pub const fn has_gaps(self) -> bool {
        self.refused > 0
    }
}

/// Why a record could not be appended, or could not be read back.
///
/// `Copy` is retained, and the new variant is the reason it is worth stating: the two fields are
/// `&'static str` because **the function names in this log are `&'static str` by design** — bounded by
/// the interfaces' own WIT, the same reason [`crate::audit`]'s allowlist exists. A `String` here would
/// have cost the `Copy`, and nothing needed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// ```
/// use qqq_host::replay::ReplayError;
///
/// assert_eq!(ReplayError::Exhausted.to_string(), "the replay log ended before the execution did");
/// ```
pub enum ReplayError {
    /// The log is at capacity. **Refused rather than overwritten**, so the first records — the ones a
    /// reader needs to reproduce the *start* of an execution — are the ones that survive.
    Full,
    /// A record's `previous` does not match the digest of the record before it.
    ChainBroken,
    /// A record's `sequence` is not the next in order.
    OutOfOrder,
    /// The log is exhausted — the execution read more values than were recorded.
    ///
    /// **This is the failure a truncated log produces**, and it must be an error rather than a
    /// fallback: a replay that silently began reading the real clock at the point the log ended would
    /// reproduce a *different* execution and report success.
    Exhausted,
    /// The next record is for a different function than the one being replayed.
    ///
    /// **The property this protects is the one that makes a replay trustworthy.** Records are
    /// replayed in order, so if the log's next entry is a `clock.wall` and the execution is asking
    /// for `crypto.random`, the two runs diverged before this point — and feeding the clock value to
    /// the RNG would produce a plausible-looking execution that shares nothing with the recorded one.
    Unexpected {
        /// What the execution asked for.
        expected: &'static str,
        /// What the log holds next.
        found: &'static str,
    },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => f.write_str("the replay log is full"),
            Self::ChainBroken => {
                f.write_str("a record's `previous` does not match the one before it")
            }
            Self::OutOfOrder => f.write_str("a record's sequence is not the next in order"),
            Self::Exhausted => f.write_str("the replay log ended before the execution did"),
            Self::Unexpected { expected, found } => write!(
                f,
                "the execution asked to replay `{expected}` but the log's next record is `{found}`"
            ),
        }
    }
}

/// So a replay failure can propagate through a host function's `wasmtime::Result`.
///
/// # Why this is required rather than optional
///
/// The three host functions that read a nondeterministic value return `wasmtime::Result`, and
/// `read_wall_nanos()?` inside one of them needs `ReplayError` to convert. **Without this the
/// conversion is a compile error, which is the right outcome**: the alternative a caller would reach
/// for is `map_err(|_| ...)`, and that discards the cause — the failure mode `§O-280` names, where a
/// report cannot say what happened.
impl std::error::Error for ReplayError {}

/// A bounded, append-only, hash-chained log of the values an execution read.
#[derive(Debug, Clone)]
/// ```
/// use qqq_host::replay::{ReplayHeader, ReplayLog, ReplayValue};
///
/// let mut log = ReplayLog::new(
///     ReplayHeader {
///         artifact_digest: "sha256:9f2c".to_owned(),
///         engine_version: "48.0.3".to_owned(),
///         target_triple: "test".to_owned(),
///         deterministic: true,
///     },
///     2,
/// );
/// log.record("clock.wall", ReplayValue::Clock(1)).expect("room");
/// log.record("clock.wall", ReplayValue::Clock(2)).expect("room");
/// // A full log refuses rather than overwriting, so the first records survive.
/// assert!(log.record("clock.wall", ReplayValue::Clock(3)).is_err());
/// assert!(log.counters().has_gaps());
/// ```
pub struct ReplayLog {
    header: ReplayHeader,
    records: Vec<ReplayRecord>,
    capacity: usize,
    counters: AppendCounters,
    /// How far a *reader* has consumed the log — `DET-008`.
    ///
    /// # Why the cursor lives here rather than in the caller
    ///
    /// Because the read position and the records are one piece of state: a cursor in a caller could
    /// be advanced against a different log, or rewound while a replay is in flight. Keeping them
    /// together is what makes [`Self::next_record`] the only way to consume, and therefore the only
    /// place the exhaustion and wrong-function checks have to live.
    ///
    /// It is distinct from `records.len()`: a log may be written and then read, and the writer's
    /// count is not a read position.
    cursor: usize,
}

impl ReplayLog {
    /// A log with room for `capacity` records.
    ///
    /// A capacity of zero is a log that refuses everything, which is a legitimate configuration for a
    /// caller that wants the chain and the counters without retaining values — and it is *not* treated
    /// as "unbounded", which is the reading that turns a bound into a memory leak.
    #[must_use]
    /// ```
    /// use qqq_host::replay::{ReplayHeader, ReplayLog};
    ///
    /// let log = ReplayLog::new(
    ///     ReplayHeader {
    ///         artifact_digest: "a".to_owned(),
    ///         engine_version: "48.0.3".to_owned(),
    ///         target_triple: "test".to_owned(),
    ///         deterministic: true,
    ///     },
    ///     0,
    /// );
    /// assert!(log.records().is_empty(), "a zero-capacity log refuses everything");
    /// ```
    pub fn new(header: ReplayHeader, capacity: usize) -> Self {
        Self {
            header,
            records: Vec::new(),
            capacity,
            counters: AppendCounters::default(),
            cursor: 0,
        }
    }

    /// Consume the next record, which must be for `function` — `DET-008`.
    ///
    /// # Errors
    ///
    /// [`ReplayError::Exhausted`] when the execution read more values than were recorded, and
    /// [`ReplayError::Unexpected`] when the log's next record is for a different function. **Both are
    /// failures rather than fallbacks**, and the reason is the same for each: a replay that quietly
    /// substituted a real clock reading at the point the log ended, or that fed a recorded instant to
    /// an RNG, would produce an execution that looks plausible and shares nothing with the recorded
    /// one. **The whole mechanism exists to make that impossible rather than unlikely.**
    ///
    /// # Why the caller must name the function
    ///
    /// Because order alone is not enough to detect a divergence. Two runs of the same component can
    /// reach the same *number* of reads in a different *order* — a branch that reorders two calls
    /// changes nothing about the count — so the check has to be on identity, not position.
    /// ```
    /// use qqq_host::replay::{ReplayHeader, ReplayLog, ReplayValue};
    ///
    /// let mut log = ReplayLog::new(
    ///     ReplayHeader {
    ///         artifact_digest: "sha256:9f2c".to_owned(),
    ///         engine_version: "48.0.3".to_owned(),
    ///         target_triple: "test".to_owned(),
    ///         deterministic: true,
    ///     },
    ///     8,
    /// );
    /// log.record("clock.wall", ReplayValue::Clock(7)).expect("room");
    /// assert_eq!(log.next_record("clock.wall").expect("recorded"), ReplayValue::Clock(7));
    /// // A truncated log fails rather than falling back to the real clock.
    /// assert!(log.next_record("clock.wall").is_err());
    /// ```
    pub fn next_record(&mut self, function: &'static str) -> Result<ReplayValue, ReplayError> {
        let Some(record) = self.records.get(self.cursor) else {
            return Err(ReplayError::Exhausted);
        };
        if record.function != function {
            return Err(ReplayError::Unexpected {
                expected: function,
                found: record.function,
            });
        }
        self.cursor += 1;
        Ok(record.value.clone())
    }

    /// Whether a reader has consumed every record.
    #[must_use]
    /// ```
    /// use qqq_host::replay::{ReplayHeader, ReplayLog, ReplayValue};
    ///
    /// let mut log = ReplayLog::new(
    ///     ReplayHeader {
    ///         artifact_digest: "sha256:9f2c".to_owned(),
    ///         engine_version: "48.0.3".to_owned(),
    ///         target_triple: "test".to_owned(),
    ///         deterministic: true,
    ///     },
    ///     8,
    /// );
    /// assert!(log.is_exhausted(), "nothing recorded, nothing left to read");
    /// ```
    pub fn is_exhausted(&self) -> bool {
        self.cursor >= self.records.len()
    }

    /// How many records a reader has consumed.
    #[must_use]
    /// ```
    /// use qqq_host::replay::{ReplayHeader, ReplayLog, ReplayValue};
    ///
    /// let mut log = ReplayLog::new(
    ///     ReplayHeader {
    ///         artifact_digest: "sha256:9f2c".to_owned(),
    ///         engine_version: "48.0.3".to_owned(),
    ///         target_triple: "test".to_owned(),
    ///         deterministic: true,
    ///     },
    ///     8,
    /// );
    /// assert_eq!(log.cursor(), 0);
    /// ```
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Return the read position to the start, so a log can be replayed again.
    ///
    /// # Why this exists when a replay reads forward once
    ///
    /// Because `--trials N` with `--replay` runs the same log N times and compares the outputs — which
    /// is `DET-009`'s verification from the other side. A log that could only be consumed once would
    /// make that a re-read of the file rather than a rewind of the same value.
    /// ```
    /// use qqq_host::replay::{ReplayHeader, ReplayLog, ReplayValue};
    ///
    /// let mut log = ReplayLog::new(
    ///     ReplayHeader {
    ///         artifact_digest: "sha256:9f2c".to_owned(),
    ///         engine_version: "48.0.3".to_owned(),
    ///         target_triple: "test".to_owned(),
    ///         deterministic: true,
    ///     },
    ///     8,
    /// );
    /// log.record("clock.wall", ReplayValue::Clock(7)).expect("room");
    /// assert!(log.next_record("clock.wall").is_ok());
    /// log.rewind();
    /// assert!(!log.is_exhausted(), "a rewind lets the log be replayed again");
    /// ```
    pub fn rewind(&mut self) {
        self.cursor = 0;
    }

    /// The header this log was opened with.
    #[must_use]
    /// ```
    /// use qqq_host::replay::{ReplayHeader, ReplayLog, ReplayValue};
    ///
    /// let mut log = ReplayLog::new(
    ///     ReplayHeader {
    ///         artifact_digest: "sha256:9f2c".to_owned(),
    ///         engine_version: "48.0.3".to_owned(),
    ///         target_triple: "test".to_owned(),
    ///         deterministic: true,
    ///     },
    ///     8,
    /// );
    /// assert_eq!(log.header().engine_version, "48.0.3");
    /// ```
    pub const fn header(&self) -> &ReplayHeader {
        &self.header
    }

    /// The records, in order.
    #[must_use]
    /// ```
    /// use qqq_host::replay::{ReplayHeader, ReplayLog, ReplayValue};
    ///
    /// let mut log = ReplayLog::new(
    ///     ReplayHeader {
    ///         artifact_digest: "sha256:9f2c".to_owned(),
    ///         engine_version: "48.0.3".to_owned(),
    ///         target_triple: "test".to_owned(),
    ///         deterministic: true,
    ///     },
    ///     8,
    /// );
    /// assert!(log.records().is_empty());
    /// ```
    pub fn records(&self) -> &[ReplayRecord] {
        &self.records
    }

    /// How many were accepted and how many refused.
    #[must_use]
    /// ```
    /// use qqq_host::replay::{ReplayHeader, ReplayLog, ReplayValue};
    ///
    /// let mut log = ReplayLog::new(
    ///     ReplayHeader {
    ///         artifact_digest: "sha256:9f2c".to_owned(),
    ///         engine_version: "48.0.3".to_owned(),
    ///         target_triple: "test".to_owned(),
    ///         deterministic: true,
    ///     },
    ///     8,
    /// );
    /// assert_eq!(log.counters().recorded, 0);
    /// ```
    pub const fn counters(&self) -> AppendCounters {
        self.counters
    }

    /// Append a value, chaining it to the record before.
    ///
    /// # Errors
    ///
    /// [`ReplayError::Full`] when the log is at capacity. **The record is not stored and the counter
    /// moves**, so a caller that ignores the error still produces a log that reports the gap.
    /// ```
    /// use qqq_host::replay::{ReplayHeader, ReplayLog, ReplayValue};
    ///
    /// let mut log = ReplayLog::new(
    ///     ReplayHeader {
    ///         artifact_digest: "sha256:9f2c".to_owned(),
    ///         engine_version: "48.0.3".to_owned(),
    ///         target_triple: "test".to_owned(),
    ///         deterministic: true,
    ///     },
    ///     8,
    /// );
    /// log.record("clock.wall", ReplayValue::Clock(7)).expect("room");
    /// assert_eq!(log.counters().recorded, 1);
    /// ```
    pub fn record(
        &mut self,
        function: &'static str,
        value: ReplayValue,
    ) -> Result<(), ReplayError> {
        if self.records.len() >= self.capacity {
            self.counters.refused += 1;
            return Err(ReplayError::Full);
        }
        let sequence = u64::try_from(self.records.len()).unwrap_or(u64::MAX) + 1;
        let previous = self
            .records
            .last()
            .map_or_else(ReplayRecord::genesis_digest, |r| r.chain.clone());
        let mut record = ReplayRecord {
            sequence,
            function,
            value,
            previous,
            chain: String::new(),
        };
        record.chain = ReplayRecord::compute_chain(&record.fields());
        self.records.push(record);
        self.counters.recorded += 1;
        Ok(())
    }

    /// Verify the chain from the genesis digest to the last record.
    ///
    /// # Errors
    ///
    /// [`ReplayError::ChainBroken`] at the first record whose `previous` does not match, or whose own
    /// digest does not recompute. **Both directions matter**: an edited value breaks the second, and a
    /// removed record breaks the first.
    /// ```
    /// use qqq_host::replay::{ReplayHeader, ReplayLog, ReplayValue};
    ///
    /// let mut log = ReplayLog::new(
    ///     ReplayHeader {
    ///         artifact_digest: "sha256:9f2c".to_owned(),
    ///         engine_version: "48.0.3".to_owned(),
    ///         target_triple: "test".to_owned(),
    ///         deterministic: true,
    ///     },
    ///     8,
    /// );
    /// log.record("clock.wall", ReplayValue::Clock(7)).expect("room");
    /// assert!(log.verify().is_ok(), "a log written in order verifies");
    /// ```
    pub fn verify(&self) -> Result<(), ReplayError> {
        let mut expected_previous = ReplayRecord::genesis_digest();
        for (n, record) in self.records.iter().enumerate() {
            if record.previous != expected_previous {
                return Err(ReplayError::ChainBroken);
            }
            if record.sequence != u64::try_from(n).unwrap_or(u64::MAX) + 1 {
                return Err(ReplayError::OutOfOrder);
            }
            if record.chain != ReplayRecord::compute_chain(&record.fields()) {
                return Err(ReplayError::ChainBroken);
            }
            expected_previous.clone_from(&record.chain);
        }
        Ok(())
    }

    /// A test-only handle on the records, so a test can prove an edit is detected.
    ///
    /// `audit.rs` calls this **the narrower hole**, and the argument is its: the shipped library must
    /// not expose mutation, and a test that cannot edit a record cannot prove the chain notices.
    /// `cfg(test)` means this does not exist in the built library at all.
    #[cfg(test)]
    pub(crate) fn records_mut_for_test(&mut self) -> &mut Vec<ReplayRecord> {
        &mut self.records
    }
}

/// Hash one field with a length prefix, so the encoding is injective.
///
/// Copied in shape from `audit.rs::field`, and for the same measured reason. A bare concatenation of
/// `("ab", "c")` and `("a", "bc")` is one input, and here one of the fields is a byte string whose
/// length the guest chose.
fn field(h: &mut Sha256, value: &str) {
    h.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    h.update(value.as_bytes());
}

/// Lowercase hex of a digest or a byte string.
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// **The positive half of `DET-008`.** A log written by one run feeds the next, in order, and the
    /// values are the ones that were recorded.
    #[test]
    fn a_replay_feeds_the_recorded_values_in_order() {
        let mut written = log(8);
        written
            .record("clock.wall", ReplayValue::Clock(1_767_225_600_000_000_000))
            .unwrap();
        written
            .record("crypto.random", ReplayValue::Random(vec![0x51; 8]))
            .unwrap();
        written
            .record("clock.monotonic", ReplayValue::Clock(4_200))
            .unwrap();

        let mut replayed = written.clone();
        assert_eq!(
            replayed.next_record("clock.wall").unwrap(),
            ReplayValue::Clock(1_767_225_600_000_000_000)
        );
        assert_eq!(
            replayed.next_record("crypto.random").unwrap(),
            ReplayValue::Random(vec![0x51; 8])
        );
        assert_eq!(
            replayed.next_record("clock.monotonic").unwrap(),
            ReplayValue::Clock(4_200)
        );
        assert!(replayed.is_exhausted());
        assert_eq!(replayed.cursor(), 3);
    }

    /// **A truncated log must fail, not fall back.** A replay that began reading the real clock where
    /// the log ended would reproduce a *different* execution and report success.
    #[test]
    fn an_exhausted_log_fails_rather_than_falling_back() {
        let mut l = log(8);
        l.record("clock.wall", ReplayValue::Clock(1)).unwrap();
        let mut r = l.clone();
        assert!(r.next_record("clock.wall").is_ok());
        assert_eq!(r.next_record("clock.wall"), Err(ReplayError::Exhausted));
    }

    /// **The property that makes a replay trustworthy.** Order alone cannot detect a divergence —
    /// two runs can reach the same number of reads in a different order — so the check is on identity.
    /// Feeding a recorded instant to an RNG would produce an execution that looks plausible and shares
    /// nothing with the recorded one.
    #[test]
    fn a_wrong_function_fails_rather_than_diverging() {
        let mut l = log(8);
        l.record("clock.wall", ReplayValue::Clock(1)).unwrap();
        let mut r = l.clone();
        assert_eq!(
            r.next_record("crypto.random"),
            Err(ReplayError::Unexpected {
                expected: "crypto.random",
                found: "clock.wall",
            })
        );
        assert_eq!(r.cursor(), 0, "a refused read must not advance the cursor");
    }

    /// A rewind lets the same log be replayed again, which is what `--trials N --replay` needs.
    #[test]
    fn a_rewind_lets_a_log_be_replayed_again() {
        let mut l = log(8);
        l.record("clock.wall", ReplayValue::Clock(7)).unwrap();
        let mut r = l.clone();
        let first = r.next_record("clock.wall").unwrap();
        assert!(r.is_exhausted());
        r.rewind();
        assert!(!r.is_exhausted());
        assert_eq!(r.next_record("clock.wall").unwrap(), first);
    }

    fn header() -> ReplayHeader {
        ReplayHeader {
            artifact_digest: "sha256:9f2c".to_owned(),
            engine_version: "48.0.3".to_owned(),
            target_triple: "x86_64-pc-windows-msvc".to_owned(),
            deterministic: true,
        }
    }

    fn log(capacity: usize) -> ReplayLog {
        ReplayLog::new(header(), capacity)
    }

    /// **The property the whole module exists for.** Two logs fed the same values produce the same
    /// chain, so a replay can be compared rather than trusted.
    #[test]
    fn the_same_values_produce_the_same_chain() {
        let mut a = log(8);
        let mut b = log(8);
        for l in [&mut a, &mut b] {
            l.record("wall_clock", ReplayValue::Clock(1_767_225_600_000_000_000))
                .unwrap();
            l.record("random_get", ReplayValue::Random(vec![0x51; 32]))
                .unwrap();
            l.record("network_timing", ReplayValue::Network(4_200))
                .unwrap();
        }
        assert_eq!(
            a.records(),
            b.records(),
            "the same values must chain identically"
        );
        assert!(a.verify().is_ok(), "and the chain must verify");
    }

    /// A record's sequence is 1-based, so a missing first record is a gap rather than an off-by-one.
    #[test]
    fn sequence_is_one_based() {
        let mut l = log(2);
        l.record("wall_clock", ReplayValue::Clock(1)).unwrap();
        l.record("wall_clock", ReplayValue::Clock(2)).unwrap();
        assert_eq!(l.records()[0].sequence, 1);
        assert_eq!(l.records()[1].sequence, 2);
        assert_eq!(l.records()[0].previous, ReplayRecord::genesis_digest());
    }

    /// **The chain must notice an edit**, in both directions a reader can check.
    ///
    /// # What actually happens, which the first version of this test got wrong
    ///
    /// It was named `an_edited_record_changes_every_later_digest` and asserted that a later record's
    /// digest **differs** after an edit. It does not. A stored record's digest is computed from its own
    /// fields, so editing record 0 leaves record 1's `chain` byte-identical, and the assertion failed
    /// with `left == right`.
    ///
    /// **What breaks is the `previous` pointer, not the digest** — and that is the more useful
    /// property: `verify` fails at the successor because its `previous` names a digest record 0 no
    /// longer has. `audit.rs` says an edit *"changes every later digest"*, which is true of a **writer**
    /// that recomputes as it goes. A reader holds what was written, so the detection has to be at the
    /// comparison — which is where `verify` puts it.
    #[test]
    fn an_edited_record_breaks_the_chain() {
        let mut l = log(3);
        l.record("wall_clock", ReplayValue::Clock(1)).unwrap();
        l.record("random_get", ReplayValue::Random(vec![1, 2, 3]))
            .unwrap();
        l.record("wall_clock", ReplayValue::Clock(3)).unwrap();
        assert!(l.verify().is_ok());

        let second_before = l.records()[1].chain.clone();
        l.records_mut_for_test()[0].value = ReplayValue::Clock(9);
        assert_eq!(
            l.verify(),
            Err(ReplayError::ChainBroken),
            "an edited value must fail"
        );

        // Re-seal the edited record: the chain still fails, because the NEXT record points at the old
        // digest. This is the direction a value-only check would miss.
        let f = l.records()[0].fields();
        l.records_mut_for_test()[0].chain = ReplayRecord::compute_chain(&f);
        assert_eq!(
            l.verify(),
            Err(ReplayError::ChainBroken),
            "the successor must notice too"
        );
        // And the successor's own digest is untouched -- which is *why* the `previous` comparison has
        // to exist. Asserting `ne` here was the first version's error: it failed with `left == right`.
        assert_eq!(
            l.records()[1].chain,
            second_before,
            "a later digest is not recomputed"
        );
    }

    /// **A full log refuses rather than overwrites**, and says so as a value.
    #[test]
    fn a_full_log_refuses_rather_than_overwrites() {
        let mut l = log(2);
        l.record("wall_clock", ReplayValue::Clock(1)).unwrap();
        l.record("wall_clock", ReplayValue::Clock(2)).unwrap();
        assert_eq!(
            l.record("wall_clock", ReplayValue::Clock(3)),
            Err(ReplayError::Full)
        );
        assert_eq!(l.records().len(), 2, "the first two survive");
        assert_eq!(l.records()[0].sequence, 1, "and the first is the first");
        assert!(l.counters().has_gaps(), "and the gap is visible as a value");
        assert_eq!(
            l.counters(),
            AppendCounters {
                recorded: 2,
                refused: 1
            }
        );
    }

    /// A capacity of zero refuses everything and is not read as unbounded.
    #[test]
    fn a_zero_capacity_log_refuses_everything() {
        let mut l = log(0);
        assert_eq!(
            l.record("wall_clock", ReplayValue::Clock(1)),
            Err(ReplayError::Full)
        );
        assert!(l.records().is_empty());
        assert_eq!(l.counters().refused, 1);
    }

    /// **Two different byte splits must not collide.** This is the length prefix doing its job: the
    /// value is a byte string whose length the guest chose, so a bare concatenation would let one
    /// digest cover two records.
    #[test]
    fn the_encoding_is_injective_across_byte_splits() {
        let a = ReplayRecord::compute_chain(&ReplayFields {
            sequence: 1,
            function: "random_get",
            kind: "random",
            canonical: "abcd".into(),
            previous: "genesis",
        });
        let b = ReplayRecord::compute_chain(&ReplayFields {
            sequence: 1,
            function: "random_get",
            kind: "random",
            canonical: "abc".into(),
            previous: "genesis",
        });
        assert_ne!(a, b, "a shorter value must not produce the same digest");
    }

    /// The header's mismatch report names the field that differs, so a refusal sends a reader to one
    /// place rather than four.
    #[test]
    fn a_header_mismatch_names_the_field() {
        let a = header();
        let mut b = header();
        b.engine_version = "49.0.0".to_owned();
        assert_eq!(a.mismatches(&b), vec!["engine_version"]);
        assert!(a.mismatches(&a).is_empty());
    }

    /// **`deterministic: false` is a mismatch, not an irrelevance.** A log recorded without
    /// determinism is not a replay of a deterministic run.
    #[test]
    fn a_non_deterministic_log_is_a_mismatch() {
        let a = header();
        let mut b = header();
        b.deterministic = false;
        assert_eq!(a.mismatches(&b), vec!["deterministic"]);
    }

    /// Every variant reports a distinct kind, so a value cannot be mislabelled in a record's digest.
    #[test]
    fn every_value_kind_is_distinct() {
        let kinds = [
            ReplayValue::Clock(0).kind(),
            ReplayValue::Random(Vec::new()).kind(),
            ReplayValue::Network(0).kind(),
        ];
        let mut sorted = kinds.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), kinds.len(), "kinds must be distinct");
    }
}
