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

    /// Rebuild a value from its [`Self::canonical`] form and its kind — `DET-008`.
    ///
    /// # Why the kind is a separate argument and not inferred
    ///
    /// Because [`Self::canonical`] is **not injective across variants**: `Clock(7)` and `Network(7)`
    /// both encode as `"7"`. The kind is what distinguishes them, which is why the file format carries
    /// it as its own column and why a loader that guessed from the shape would silently turn a network
    /// timing into a wall-clock reading.
    ///
    /// # Why this returns `Option` rather than an error
    ///
    /// Because "this string is not a canonical value of this kind" is a *parse* failure, and the caller
    /// that knows which line it was on is the one that can say so. `ReplayLog::from_text` does exactly
    /// that, and reports [`ReplayError::Malformed`] with the line number.
    ///
    /// ```
    /// use qqq_host::replay::ReplayValue;
    ///
    /// assert_eq!(
    ///     ReplayValue::from_canonical("clock", "7"),
    ///     Some(ReplayValue::Clock(7))
    /// );
    /// assert_eq!(
    ///     ReplayValue::from_canonical("network", "7"),
    ///     Some(ReplayValue::Network(7)),
    ///     "the same canonical string is a different value under a different kind"
    /// );
    /// assert_eq!(
    ///     ReplayValue::from_canonical("random", "5a5b"),
    ///     Some(ReplayValue::Random(vec![0x5a, 0x5b]))
    /// );
    /// assert_eq!(ReplayValue::from_canonical("random", "5a5"), None, "odd hex");
    /// assert_eq!(ReplayValue::from_canonical("random", "zz"), None, "not hex");
    /// assert_eq!(ReplayValue::from_canonical("clock", "-1"), None, "unsigned");
    /// assert_eq!(ReplayValue::from_canonical("temperature", "7"), None, "unknown kind");
    /// ```
    #[must_use]
    pub fn from_canonical(kind: &str, canonical: &str) -> Option<Self> {
        match kind {
            "clock" => canonical.parse::<u64>().ok().map(Self::Clock),
            "network" => canonical.parse::<u64>().ok().map(Self::Network),
            "random" => {
                // An odd-length or non-hex string is refused rather than truncated: a shortened
                // `random` value would replay a byte string the generator never produced.
                if !canonical.len().is_multiple_of(2) {
                    return None;
                }
                let mut out = Vec::with_capacity(canonical.len() / 2);
                let bytes = canonical.as_bytes();
                for pair in bytes.chunks(2) {
                    let hi = hex_nibble(pair[0])?;
                    let lo = hex_nibble(pair[1])?;
                    out.push((hi << 4) | lo);
                }
                Some(Self::Random(out))
            }
            _ => None,
        }
    }
}

/// One hexadecimal digit's value, or `None`.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
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
    /// A line of a replay file could not be understood.
    /// ```
    /// use qqq_host::replay::ReplayError;
    ///
    /// let e = ReplayError::Malformed { line: 7, reason: "not a replay file" };
    /// assert!(e.to_string().contains("line 7"));
    /// ```
    Malformed {
        /// The 1-based line number, so a reader can look at it.
        line: usize,
        /// What was wrong, in a phrase.
        reason: &'static str,
    },
    /// A replay file parsed, but a record's chain does not match its own fields.
    ///
    /// **This is the variant that makes a replay file evidence rather than input.** A loader that
    /// recomputed the chain from whatever it read would accept an edited value and produce a new,
    /// internally consistent log -- so the file would say whatever its editor wanted. Comparing the
    /// stored chain against a re-derived one is what turns an edit into a refusal.
    /// ```
    /// use qqq_host::replay::ReplayError;
    ///
    /// let e = ReplayError::Tampered { line: 3 };
    /// assert!(e.to_string().contains("edited"));
    /// ```
    Tampered {
        /// The 1-based line number of the first record that did not match.
        line: usize,
    },
    /// A replay file's `previous` pointer does not lead to the record before it.
    /// ```
    /// use qqq_host::replay::ReplayError;
    ///
    /// let e = ReplayError::Discontinuous { line: 4 };
    /// assert!(e.to_string().contains("previous"));
    /// ```
    Discontinuous {
        /// The 1-based line number of the record whose link is broken.
        line: usize,
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
            Self::Malformed { line, reason } => {
                write!(f, "replay file line {line}: {reason}")
            }
            Self::Tampered { line } => write!(
                f,
                "replay file line {line}: the record's chain does not match its own fields, so the \
                 file has been edited since it was written"
            ),
            Self::Discontinuous { line } => write!(
                f,
                "replay file line {line}: the record's `previous` does not point at the record \
                 before it"
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

/// The first token of a replay file, so a file that is not one is refused by name.
/// ```
/// use qqq_host::replay::REPLAY_FILE_MAGIC;
///
/// assert!(REPLAY_FILE_MAGIC.starts_with("qqq"));
/// ```
pub const REPLAY_FILE_MAGIC: &str = "qqq-replay";

/// The format version. A file naming a different one is refused rather than guessed at.
/// ```
/// use qqq_host::replay::REPLAY_FILE_VERSION;
///
/// assert_eq!(REPLAY_FILE_VERSION, 1);
/// ```
pub const REPLAY_FILE_VERSION: u32 = 1;

/// The functions a replay file may name.
///
/// # Why an allowlist rather than accepting any string
///
/// `ReplayRecord::function` is `&'static str`, because the names are bounded by the interfaces'
/// own WIT -- the same reason `crate::audit`'s `RECORDED_FUNCTIONS` exists. A loader that accepted
/// an arbitrary string would have to leak it to satisfy the lifetime, so a file could grow the
/// process's memory by being long. **A file naming a function this runtime does not have is
/// refused**, which is also the honest answer: it was not written by this runtime.
/// ```
/// use qqq_host::replay::REPLAY_FUNCTIONS;
///
/// assert!(REPLAY_FUNCTIONS.contains(&"clock.wall"));
/// assert!(REPLAY_FUNCTIONS.contains(&"crypto.random"));
/// ```
pub const REPLAY_FUNCTIONS: [&str; 3] = ["clock.wall", "clock.monotonic", "crypto.random"];

/// Resolve a name from a file to the `&'static str` the record type requires.
fn static_function(name: &str) -> Option<&'static str> {
    REPLAY_FUNCTIONS.iter().copied().find(|f| *f == name)
}

/// A malformed-line error, named once so every parser reports the same shape.
fn malformed(line: usize, reason: &'static str) -> ReplayError {
    ReplayError::Malformed { line, reason }
}

/// Refuse a file that is not a replay log, **by name** — the magic and the version.
fn parse_magic(all: &[&str]) -> Result<(), ReplayError> {
    let Some(first) = all.first() else {
        return Err(malformed(1, "the file is empty"));
    };
    let mut magic = first.split(' ');
    if magic.next() != Some(REPLAY_FILE_MAGIC) {
        return Err(malformed(1, "not a replay file"));
    }
    match magic.next().and_then(|v| v.parse::<u32>().ok()) {
        Some(v) if v == REPLAY_FILE_VERSION => Ok(()),
        Some(_) => Err(malformed(1, "unsupported replay file version")),
        None => Err(malformed(1, "the version is not a number")),
    }
}

/// Parse the header, returning it with the refusal count and the index of the first record.
///
/// # Why the body's start is returned rather than searched for again
///
/// Because the header's keys and the records' first field are both "a token followed by more tokens",
/// and the only thing that separates them is that a record's first token is a number. **Finding that
/// boundary once and passing it on means the two parsers cannot disagree about where the header ended.**
fn parse_header(all: &[&str]) -> Result<(ReplayHeader, u64, usize), ReplayError> {
    let mut header = ReplayHeader {
        artifact_digest: String::new(),
        engine_version: String::new(),
        target_triple: String::new(),
        deterministic: false,
    };
    let mut refused = 0u64;
    let mut seen = 0u8;
    let mut body_start = all.len();
    for (idx, line) in all.iter().enumerate().skip(1) {
        let lineno = idx + 1;
        let Some((key, value)) = line.split_once(' ') else {
            return Err(malformed(lineno, "expected a header key and a value"));
        };
        // The first line whose key parses as a number is the first record.
        if key.parse::<u64>().is_ok() {
            body_start = idx;
            break;
        }
        match key {
            "artifact_digest" => {
                value.clone_into(&mut header.artifact_digest);
                seen |= 1;
            }
            "engine_version" => {
                value.clone_into(&mut header.engine_version);
                seen |= 2;
            }
            "target_triple" => {
                value.clone_into(&mut header.target_triple);
                seen |= 4;
            }
            "deterministic" => {
                header.deterministic = match value {
                    "true" => true,
                    "false" => false,
                    _ => return Err(malformed(lineno, "`deterministic` must be true or false")),
                };
                seen |= 8;
            }
            "refused" => {
                refused = value
                    .parse()
                    .map_err(|_| malformed(lineno, "`refused` is not a number"))?;
                seen |= 16;
            }
            _ => return Err(malformed(lineno, "unknown header key")),
        }
    }
    // All five, or the file is not one this format writes. A missing `deterministic` in particular
    // would default to `false` and silently refuse a replay that should have been accepted.
    if seen != 0b1_1111 {
        return Err(malformed(1, "a required header key is missing"));
    }
    Ok((header, refused, body_start))
}

/// Parse the records, **re-deriving each chain rather than trusting the one written**.
fn parse_records(all: &[&str], body_start: usize) -> Result<Vec<ReplayRecord>, ReplayError> {
    let mut records: Vec<ReplayRecord> = Vec::new();
    let mut previous = ReplayRecord::genesis_digest();
    let mut seq_expected = 1u64;
    for (idx, line) in all.iter().enumerate().skip(body_start) {
        let lineno = idx + 1;
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() != 6 {
            return Err(malformed(lineno, "a record needs six space-separated fields"));
        }
        let sequence: u64 = f[0]
            .parse()
            .map_err(|_| malformed(lineno, "the sequence is not a number"))?;
        if sequence != seq_expected {
            return Err(ReplayError::OutOfOrder);
        }
        let function = static_function(f[1])
            .ok_or_else(|| malformed(lineno, "the function is not one this log may record"))?;
        let value = ReplayValue::from_canonical(f[2], f[3])
            .ok_or_else(|| malformed(lineno, "the value is not canonical for its kind"))?;
        if f[4] != previous {
            return Err(ReplayError::Discontinuous { line: lineno });
        }
        let rederived = ReplayRecord::compute_chain(&ReplayFields {
            sequence,
            function,
            kind: value.kind(),
            canonical: Cow::Owned(value.canonical()),
            previous: &previous,
        });
        if rederived != f[5] {
            return Err(ReplayError::Tampered { line: lineno });
        }
        records.push(ReplayRecord {
            sequence,
            function,
            value,
            previous: previous.clone(),
            chain: rederived.clone(),
        });
        previous = rederived;
        seq_expected += 1;
    }
    Ok(records)
}

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
    /// The log as a text file — `DET-008`.
    ///
    /// # Why text and not a serialized struct
    ///
    /// Because this file is **evidence**, and evidence a reader cannot read is evidence a reader has to
    /// take on trust. A JSON array of records would carry the same bytes and be diffable only by tooling;
    /// a line per record is diffable by eye, which is what makes `--replay` reviewable in a pull request.
    ///
    /// # The format
    ///
    /// ```text
    /// qqq-replay 1
    /// artifact_digest sha256:9f2c...
    /// engine_version 48.0.3
    /// target_triple x86_64-pc-windows-msvc
    /// deterministic true
    /// refused 0
    /// 1 clock.wall clock 7 <genesis> <chain>
    /// 2 crypto.random random 5a5b <previous> <chain>
    /// ```
    ///
    /// **The chain is written, not omitted.** A loader could re-derive it, and then an edited value
    /// would produce a new internally consistent log -- so the file would say whatever its editor
    /// wanted. [`Self::from_text`] compares the stored chain against a re-derived one instead.
    ///
    /// **`refused` is written because a truncated log that does not say so is indistinguishable from a
    /// complete one** -- and the replay of a truncated log fails with [`ReplayError::Exhausted`] at a
    /// line the reader cannot see coming.
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
/// log.record("clock.wall", ReplayValue::Clock(7)).expect("room");
/// let text = log.to_text();
/// // Seven lines: the magic, five header keys, and one record. A count rather than a
/// // substring, because the record line is `1 clock.wall clock 7 <prev> <chain>` and an
/// // assertion on `"clock.wall 7"` fails on a file that is correct.
/// assert_eq!(text.lines().count(), 7);
/// assert!(text.starts_with("qqq-replay 1"));
/// ```
    pub fn to_text(&self) -> String {
        let mut out = String::with_capacity(128 + self.records.len() * 96);
        out.push_str(REPLAY_FILE_MAGIC);
        out.push(' ');
        out.push_str(&REPLAY_FILE_VERSION.to_string());
        out.push('\n');
        for (key, value) in [
            ("artifact_digest", self.header.artifact_digest.as_str()),
            ("engine_version", self.header.engine_version.as_str()),
            ("target_triple", self.header.target_triple.as_str()),
        ] {
            out.push_str(key);
            out.push(' ');
            out.push_str(value);
            out.push('\n');
        }
        out.push_str("deterministic ");
        out.push_str(if self.header.deterministic {
            "true"
        } else {
            "false"
        });
        out.push('\n');
        out.push_str("refused ");
        out.push_str(&self.counters.refused.to_string());
        out.push('\n');
        for r in &self.records {
            let f = r.fields();
            out.push_str(&f.sequence.to_string());
            out.push(' ');
            out.push_str(f.function);
            out.push(' ');
            out.push_str(f.kind);
            out.push(' ');
            out.push_str(&f.canonical);
            out.push(' ');
            out.push_str(&r.previous);
            out.push(' ');
            out.push_str(&r.chain);
            out.push('\n');
        }
        out
    }

/// Read a log back, **verifying its chain against its own contents** — `DET-008`.
///
/// # Errors
///
/// [`ReplayError::Malformed`] for a line that cannot be parsed, [`ReplayError::Tampered`] for a record
/// whose stored chain does not match a re-derived one, and [`ReplayError::Discontinuous`] for a
/// `previous` that does not point at the record before it.
///
/// # Why the three are separate
///
/// Because they send a reader to different places. `Malformed` means the file is not this format;
/// `Tampered` means it is, and its contents were changed after it was written; `Discontinuous` means a
/// record was **removed** -- which is the edit a per-record chain check cannot see, because every
/// remaining record still hashes to itself. **A deletion is the one edit that only the linkage
/// catches.**
///
/// # Why the work is in three functions
///
/// Because this one was 124 lines and `clippy::too_many_lines` is a warning this workspace denies. The
/// split is by *what is being parsed* rather than by line count: the magic, the header, and the records
/// each refuse for their own reasons and each names its own line number. **A single function that did
/// all three would still have had to report which of the three failed**, so the boundary was already
/// there.
///
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
/// let text = log.to_text();
/// let back = ReplayLog::from_text(&text).expect("a log it wrote");
/// assert_eq!(back.records().len(), 1);
/// assert_eq!(back.header().engine_version, "48.0.3");
/// ```
pub fn from_text(text: &str) -> Result<Self, ReplayError> {
    let all: Vec<&str> = text.lines().collect();
    parse_magic(&all)?;
    let (header, refused, body_start) = parse_header(&all)?;
    let records = parse_records(&all, body_start)?;
    let recorded = records.len() as u64;
    let capacity = records.len();
    Ok(Self {
        header,
        records,
        capacity,
        counters: AppendCounters { recorded, refused },
        cursor: 0,
    })
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

    /// A two-record log, for the file-format tests.
    fn two_record_log() -> ReplayLog {
        let mut log = log(8);
        log.record("clock.wall", ReplayValue::Clock(7))
            .expect("room");
        log.record("crypto.random", ReplayValue::Random(vec![0x5a, 0x5b]))
            .expect("room");
        log
    }

    /// **The round trip, and the reason the file exists at all.** A log written and read back must
    /// carry the same header, the same values and the same refusals.
    #[test]
    fn a_log_round_trips_through_its_text_form() {
        let written = two_record_log();
        let text = written.to_text();
        assert!(text.starts_with(REPLAY_FILE_MAGIC), "the magic leads");

        let back = ReplayLog::from_text(&text).expect("a log this crate wrote");
        assert_eq!(back.records().len(), 2);
        assert_eq!(
            back.header().engine_version,
            written.header().engine_version
        );
        assert_eq!(back.header().deterministic, written.header().deterministic);
        assert_eq!(back.records()[0].value, ReplayValue::Clock(7));
        assert_eq!(
            back.records()[1].value,
            ReplayValue::Random(vec![0x5a, 0x5b])
        );
        assert_eq!(back.records()[0].chain, written.records()[0].chain);
        assert_eq!(back.counters().recorded, 2);
        assert!(back.verify().is_ok(), "the rebuilt log verifies");
        // And it replays, which is what the file is for.
        let mut r = back;
        assert_eq!(
            r.next_record("clock.wall").expect("recorded"),
            ReplayValue::Clock(7)
        );
    }

    /// **An edited value is refused.** This is the property that makes the file evidence: a loader
    /// that re-derived the chain from whatever it read would accept this and produce a new, internally
    /// consistent log.
    #[test]
    fn an_edited_value_is_refused_as_tampered() {
        let text = two_record_log().to_text();
        // Change the recorded instant from 7 to 8, leaving the chain as written.
        let edited = text.replacen(" 7 ", " 8 ", 1);
        assert_ne!(edited, text, "the edit must have landed");
        assert!(
            matches!(
                ReplayLog::from_text(&edited),
                Err(ReplayError::Tampered { .. })
            ),
            "an edited value must be refused, not silently re-chained"
        );
    }

    /// **An edited linkage is refused.** A record whose `previous` was rewritten no longer points at
    /// the record before it, and the per-record chain check cannot see this -- only the linkage can.
    #[test]
    fn an_edited_previous_pointer_is_refused() {
        let text = two_record_log().to_text();
        let lines: Vec<&str> = text.lines().collect();
        let last = lines[lines.len() - 1];
        let mut f: Vec<&str> = last.split(' ').collect();
        assert_eq!(f.len(), 6, "six fields");
        f[4] = "0000000000000000000000000000000000000000000000000000000000000000";
        let edited = format!("{}\n{}\n", lines[..lines.len() - 1].join("\n"), f.join(" "));
        assert!(
            matches!(
                ReplayLog::from_text(&edited),
                Err(ReplayError::Discontinuous { .. })
            ),
            "a rewritten `previous` must be refused"
        );
    }

    /// **A removed record is refused.** Every remaining record still hashes to itself, so the chain
    /// check cannot see a deletion -- the sequence is what catches it.
    #[test]
    fn a_removed_record_is_refused() {
        let text = two_record_log().to_text();
        let lines: Vec<&str> = text.lines().collect();
        // Drop the first record's line (index 6, after the magic and five header keys).
        let mut kept: Vec<&str> = lines[..6].to_vec();
        kept.extend_from_slice(&lines[7..]);
        let edited = format!("{}\n", kept.join("\n"));
        assert!(
            matches!(ReplayLog::from_text(&edited), Err(ReplayError::OutOfOrder)),
            "a deleted record must be refused"
        );
    }

    /// **A file this crate did not write is refused by name**, rather than partially accepted.
    #[test]
    fn a_foreign_file_is_refused() {
        assert!(matches!(
            ReplayLog::from_text(""),
            Err(ReplayError::Malformed { line: 1, .. })
        ));
        assert!(matches!(
            ReplayLog::from_text("{\"records\": []}\n"),
            Err(ReplayError::Malformed { line: 1, .. })
        ));
        assert!(matches!(
            ReplayLog::from_text("qqq-replay 99\n"),
            Err(ReplayError::Malformed { line: 1, .. })
        ));
    }

    /// **A function this runtime does not have is refused.** Accepting an arbitrary name would have to
    /// leak it to satisfy `&'static str`, so a long file could grow the process's memory.
    #[test]
    fn an_unknown_function_is_refused() {
        let text = two_record_log()
            .to_text()
            .replace("clock.wall", "clock.fictional");
        assert!(matches!(
            ReplayLog::from_text(&text),
            Err(ReplayError::Malformed { .. })
        ));
    }

    /// **A truncated log says so in its own file.** A log that refused records is a partial recording,
    /// and a reader who cannot see that would read `Exhausted` as a bug in the replay.
    #[test]
    fn a_truncated_log_records_its_refusals() {
        let mut log = ReplayLog::new(header(), 1);
        log.record("clock.wall", ReplayValue::Clock(1))
            .expect("room");
        assert!(log.record("clock.wall", ReplayValue::Clock(2)).is_err());
        assert!(log.counters().has_gaps());

        let text = log.to_text();
        assert!(
            text.contains("refused 1"),
            "the file must say it is partial"
        );
        let back = ReplayLog::from_text(&text).expect("a log this crate wrote");
        assert_eq!(back.counters().refused, 1);
        assert!(
            back.counters().has_gaps(),
            "and a reader must be able to see it without parsing prose"
        );
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
