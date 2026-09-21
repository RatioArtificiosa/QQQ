// SPDX-License-Identifier: Apache-2.0

//! The `qqq.toml` manifest: the developer's declaration of capability.
//!
//! This module implements pipeline steps **1. PARSE** and part of
//! **2. NORMALIZE** from Proposal §6.2.
//!
//! # Design principles applied here
//!
//! * **Deny by default.** An absent stanza grants nothing. There is no
//!   wildcard, no `allow_all`, no ambient authority.
//! * **Explicit over implicit** (NN-5). No field is inferred, no default
//!   silently widens anything, and no environment variable is read implicitly.
//! * **Errors teach.** A bad manifest produces an error naming the field, the
//!   reason, and the fix — because the manifest is the first file a user
//!   writes and the first place they get stuck.
//!
//! # Why parsing is strict
//!
//! An unknown field is an **error**, not a warning. A user who writes
//! `[capabilities] httpp = ...` has made a mistake that, if silently ignored,
//! produces a service that fails at runtime with a capability denial far from
//! the typo. Rejecting it at parse time with a suggestion is the whole point.
//!
//! See Proposal §5.3, §6.2 and Checklist `CON-001`, `CON-002`, `CAP-002`.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::Capability;

// ---------------------------------------------------------------------------
// Manifest envelope
// ---------------------------------------------------------------------------

/// A parsed and validated `qqq.toml`.
///
/// Produced by [`Manifest::parse`]. Constructing one proves the manifest is
/// syntactically valid TOML and semantically coherent; it does **not** yet
/// prove the capabilities can be satisfied (paths exist, secrets resolve),
/// which is step 2, NORMALIZE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// `[package]` — identity.
    pub package: Package,
    /// `[build]` — how the project is compiled to a component.
    #[serde(default)]
    pub build: Build,
    /// `[capabilities]` — the authority declaration. Absent means deny-all.
    #[serde(default)]
    pub capabilities: Capabilities,
    /// `[limits]` — enforceable resource bounds.
    #[serde(default)]
    pub limits: Limits,
    /// `[dependencies]` — packages this project links against.
    ///
    /// Modelled explicitly rather than left to be ignored. Before this field
    /// existed, a manifest containing `[dependencies]` parsed **successfully**
    /// and the dependencies were silently dropped: `qqqai` reported no
    /// capabilities from a dependency it had not seen, and the user had no
    /// indication that the table was inert. A dependency that silently does not
    /// exist is worse than one that fails to resolve, because the first is
    /// discovered at runtime by the person least able to explain it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, Dependency>,
    /// `[dev-dependencies]` — packages needed only for tests and benchmarks.
    ///
    /// Kept separate because a dev-dependency's capabilities must **not** be
    /// granted to the shipped component. Merging the two tables would let a
    /// test-only package widen the production authority surface, which is
    /// precisely the supply-chain shape §5.4 exists to make visible.
    #[serde(
        default,
        rename = "dev-dependencies",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub dev_dependencies: BTreeMap<String, Dependency>,
    /// `[server]` — the network surface: routes, default auth, CORS.
    ///
    /// # Why this field had to exist before four other items could be finished
    ///
    /// Four other checklist items were each complete in `qqq-serve` and none was
    /// reachable,
    /// because this struct did not model `[server]` at all: a manifest declaring
    /// `routes` parsed successfully and the table was **inert**. The server then started,
    /// accepted connections, and 404'd everything.
    ///
    /// It is the defect the `[dependencies]` field's own doc comment records, one table
    /// over — *a [thing] that silently does not exist is worse than one that fails to
    /// resolve, because the first is discovered at runtime by the person least able to
    /// explain it.*
    ///
    /// Absent means no network surface, per the capability model's first rule.
    #[serde(default, skip_serializing_if = "Server::is_empty_unconfigured")]
    pub server: Server,
}

/// One entry in `[dependencies]`.
///
/// Written as a table (`{ version = "1.2", features = ["simd"] }`) per §5.3, but
/// a bare version string (`"qqqai/json" = "1.2"`) is accepted too: it is the
/// spelling every other ecosystem uses and there is no ambiguity to resolve.
/// Rejecting it would be a gratuitous difference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Dependency {
    /// `"qqqai/json" = "1.2"` — a version requirement and nothing else.
    Version(String),
    /// `"qqqai/json" = { version = "1.2", features = [...], ... }`.
    Full(Box<DependencyDetail>),
}

/// The full form of a dependency entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyDetail {
    /// The semver requirement, e.g. `1.2`, `^1.2.3`, `>=1.0, <2.0`.
    pub version: String,
    /// Optional features to enable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// An alternative source: `path+…`, `git+…`, `registry+…`.
    ///
    /// Recorded because two packages with the same name and version from
    /// different sources are different packages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Pin to exactly this version, ignoring the usual caret widening.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exact: bool,
    /// The capabilities this dependency **declares** it needs.
    ///
    /// # Why a dependency declares authority at all
    ///
    /// §5.4 states it as the feature that matters most about the lockfile:
    ///
    /// > **`caps` is recorded per dependency.** `qqqai install` prints a
    /// > **capability diff** — *"this update adds `http.client` to
    /// > `qqqai/telemetry`"*. Supply-chain attacks today hide in code; here the
    /// > *authority* delta is visible in the diff.
    ///
    /// The **lockfile's** `caps` field is the *record* — what was true when the
    /// lockfile was written. This field is the *declaration* — what the
    /// dependency needs now. A diff between the two is the only way an escalation
    /// can be observed at all, and until this field existed the comparison was
    /// between a value and itself, making the diff structurally empty
    /// (`§O-076`).
    ///
    /// # Why declaring is not granting
    ///
    /// A package can **ask** and never **take**: the effective grant for a
    /// runtime is still the root manifest's `[capabilities]` plus narrowing
    /// overlays. So this field is an *audit* input, not an authority source, and
    /// giving it any other meaning would be a capability-widening path — which
    /// `GrantSet::narrow` structurally cannot produce and which §D-008 forbids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
}

impl Dependency {
    /// The version requirement string, whichever form was written.
    #[must_use]
    pub fn requirement(&self) -> &str {
        match self {
            Self::Version(v) => v,
            Self::Full(d) => &d.version,
        }
    }

    /// The source, if one was given. A bare version string has none.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        match self {
            Self::Version(_) => None,
            Self::Full(d) => d.source.as_deref(),
        }
    }

    /// The capabilities this dependency declares, if it was written in the
    /// long form.
    ///
    /// Returns an empty slice for the bare `name = "1.2"` form, which declares
    /// nothing — the correct reading, since a shorthanded dependency has said
    /// nothing about what it needs rather than saying it needs nothing.
    ///
    /// # Why this returns `&[String]` rather than `Option<&[String]>`
    ///
    /// Because every caller wants "the declared set", and `None` and `&[]` would
    /// both mean an empty set at every call site while forcing each to handle
    /// two shapes. The `Option` would be a distinction without a difference —
    /// the manifest cannot express "declares no capabilities" differently from
    /// "does not use the long form", so pretending it can would invent a
    /// semantics the format does not have.
    #[must_use]
    pub fn caps(&self) -> &[String] {
        match self {
            Self::Version(_) => &[],
            Self::Full(d) => &d.caps,
        }
    }
}

/// `[package]` — the project's identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    /// Project name. Validated by `qqq-core`'s identifier rules.
    pub name: String,
    /// Semantic version of the project itself.
    pub version: String,
    /// One-line description, surfaced on the registry page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// SPDX licence identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

/// `[build]` — how the project is compiled into a component.
///
/// # Why this is in the manifest and not in a CLI flag
///
/// `qqqai build` must be reproducible from the manifest alone. If the language
/// or the target lived only in a command line, a CI job and a developer's
/// laptop could produce different artifacts from the same commit, and the
/// resulting digest mismatch would look like a supply-chain problem when it is
/// really a configuration one. Putting the build inputs in the manifest makes
/// the artifact a function of committed files.
///
/// Every field defaults, so a manifest written before `[build]` existed keeps
/// parsing unchanged — the alternative would break every existing project on
/// upgrade, which is exactly the kind of change a capability system must never
/// make silently.
///
/// See Proposal §5.3 (`[build]`) and Checklist `CLI-008`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Build {
    /// Source language: `rust`, `ts`, `go`, `python` or `cpp`.
    #[serde(default = "default_language")]
    pub language: String,
    /// Compilation target. `wasm32-wasip2` is the V1 default.
    #[serde(default = "default_target")]
    pub target: String,
    /// `debug` or `release`.
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Fail the build if a second compilation of the same inputs produces a
    /// different digest (Proposal §11, `QQQ-1005`).
    #[serde(default)]
    pub reproducible: bool,
}

fn default_language() -> String {
    "rust".to_owned()
}

fn default_target() -> String {
    "wasm32-wasip2".to_owned()
}

fn default_profile() -> String {
    "release".to_owned()
}

impl Default for Build {
    fn default() -> Self {
        Self {
            language: default_language(),
            target: default_target(),
            profile: default_profile(),
            reproducible: false,
        }
    }
}

impl Build {
    /// The languages `qqqai` can drive, in the order the docs list them.
    ///
    /// A closed set rather than an open string: an unknown language must be a
    /// parse error naming the valid options, not a build that fails later with
    /// "command not found" from a shell.
    pub const LANGUAGES: [&'static str; 5] = ["rust", "ts", "go", "python", "cpp"];

    /// The targets this build of `qqqai` can emit.
    ///
    /// `wasm32-wasip3` is listed because the Proposal (§5.3) anticipates it, but
    /// it is **not** accepted yet: no toolchain emits it, and accepting a target
    /// we cannot produce would be a silent stub. It is named in the error's
    /// permitted-values list so a user who tries it learns why.
    pub const TARGETS: [&'static str; 1] = ["wasm32-wasip2"];

    /// Targets that exist but are not yet producible by any toolchain.
    pub const ANTICIPATED_TARGETS: [&'static str; 1] = ["wasm32-wasip3"];

    /// Whether `language` is one this build supports.
    #[must_use]
    pub fn supports_language(language: &str) -> bool {
        Self::LANGUAGES.contains(&language)
    }

    /// Whether `target` is one this build can emit.
    #[must_use]
    pub fn supports_target(target: &str) -> bool {
        Self::TARGETS.contains(&target)
    }
}

/// The capability declaration.
///
/// Every field is optional and every absent field means **denied**. The struct
/// is deliberately *not* `deny_unknown_fields` at this level, because the
/// per-capability structs below are — which gives a better error (it names the
/// capability's own field).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// `[capabilities.http]` — server and/or client HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpCapability>,
    /// `[[capabilities.fs]]` — one entry per preopened path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fs: Vec<FsCapability>,
    /// `[capabilities.crypto]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto: Option<CryptoCapability>,
    /// `[capabilities.clock]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock: Option<ClockCapability>,
    /// `[capabilities.env]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvCapability>,
    /// `[capabilities.dns]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsCapability>,
}

/// `[capabilities.http]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCapability {
    /// Whether the component may receive inbound requests.
    #[serde(default)]
    pub server: bool,
    /// Outbound hosts the component may reach, as `host:port` patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client: Vec<String>,
}

/// One `[[capabilities.fs]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsCapability {
    /// The host path to preopen.
    pub path: String,
    /// `read-only`, `read-write` or `append-only`.
    pub mode: FsMode,
    /// Optional quota, e.g. `5GiB`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<String>,
}

/// Filesystem access mode. Ordered from least to most permissive so that
/// narrowing overlays can compare them directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FsMode {
    /// May read, may not modify.
    ReadOnly,
    /// May append, may not overwrite or delete.
    AppendOnly,
    /// May read, write and delete.
    ReadWrite,
}

impl FsMode {
    /// The manifest spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::AppendOnly => "append-only",
            Self::ReadWrite => "read-write",
        }
    }

    /// Whether this mode permits reading.
    #[must_use]
    pub const fn can_read(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite)
    }

    /// Whether this mode permits writing.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::AppendOnly | Self::ReadWrite)
    }

    /// Whether a grant with **this** mode satisfies a request for `requested`.
    ///
    /// Compared on the underlying *rights* (read, write), not on the enum's
    /// derived ordering. That matters because a mode added later must be taught
    /// to this function explicitly rather than silently inheriting permissive
    /// behaviour from its position in the ordering — which is exactly how a
    /// future "write-only, no-append" mode would accidentally become able to
    /// read.
    ///
    /// | Grant | request `read-only` | request `append-only` | request `read-write` |
    /// |---|---|---|---|
    /// | `read-only` | ✅ | ❌ | ❌ |
    /// | `append-only` | ❌ | ✅ | ❌ |
    /// | `read-write` | ✅ | ✅ | ✅ |
    ///
    /// Expressing this as a rights check rather than a match over pairs keeps
    /// the rule auditable: the question "does this grant cover this request?"
    /// reduces to "does the grant permit reading (if the request needs it) and
    /// writing (if the request needs it)?".
    #[must_use]
    pub const fn covers(self, requested: Self) -> bool {
        let grant_reads = self.can_read();
        let grant_writes = self.can_write();
        // A read-only request must be satisfiable by reading alone; an
        // append-only request by writing alone; a read-write request by both.
        let need_read = requested.can_read();
        let need_write = requested.can_write();
        (!need_read || grant_reads) && (!need_write || grant_writes)
    }
}

impl fmt::Display for FsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `[capabilities.crypto]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoCapability {
    /// Whether the guest may draw randomness. Defaults to **false**: an
    /// unrequested CSPRNG is a covert channel.
    #[serde(default)]
    pub random: bool,
    /// Allowlisted hash algorithms.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hash: Vec<String>,
    /// Allowlisted HMAC algorithms.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hmac: Vec<String>,
    /// Allowlisted AEAD constructions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aead: Vec<String>,
    /// Allowlisted signature algorithms.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sign: Vec<String>,
    /// Named secrets the guest may **use** without reading.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
}

/// `[capabilities.clock]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockCapability {
    /// Whether the guest may read the wall clock. Defaults to **false**.
    #[serde(default)]
    pub wall: bool,
    /// Whether the guest may read the monotonic clock. Defaults to **false**.
    #[serde(default)]
    pub monotonic: bool,
    /// Timezone name, for formatting only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

/// `[capabilities.env]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvCapability {
    /// Individually named variables. Never a blanket inherit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

/// `[capabilities.dns]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsCapability {
    /// Names the guest may resolve.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolve: Vec<String>,
}

/// `[limits]` — enforceable resource bounds.
///
/// Every limit is a hard cap enforced by the host. A limit that the manifest
/// cannot express is a limit an auditor cannot verify, so the set is
/// deliberately complete rather than open-ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Memory cap, e.g. `128MiB`.
    #[serde(default = "default_memory")]
    pub memory: String,
    /// Deterministic instruction budget per request.
    #[serde(default = "default_fuel")]
    pub fuel: u64,
    /// Wall-clock preemption backstop in milliseconds.
    #[serde(default = "default_epoch_ms")]
    pub epoch_deadline_ms: u64,
    /// Concurrency ceiling per worker.
    #[serde(default = "default_instances")]
    pub max_instances: u32,
    /// Maximum simultaneously open resource handles.
    #[serde(default = "default_handles")]
    pub max_open_handles: u32,
    /// Maximum outbound subrequests one instance may drive.
    ///
    /// # Why this is a limit about *caused* work rather than *performed* work
    ///
    /// Fuel bounds what the guest computes. It does not bound what the guest
    /// **causes**: a loop that calls `http.get` and ignores the result costs a
    /// handful of fuel units per iteration and one outbound request per
    /// iteration. §7.2 names resource exhaustion among the adversary's goals, and
    /// this is the field that makes the *amplification* variant of it
    /// enforceable rather than aspirational. See `qqq-host`'s `quota` module for
    /// the enforcement and the poisoning rule.
    #[serde(default = "default_subrequests")]
    pub max_subrequests: u32,
    /// Impose a single scheduler tick after this many instances are polled.
    #[serde(default = "default_poll")]
    pub max_poll_per_tick: u32,
}

fn default_memory() -> String {
    "128MiB".to_owned()
}
const fn default_fuel() -> u64 {
    50_000_000
}
const fn default_epoch_ms() -> u64 {
    5_000
}
const fn default_instances() -> u32 {
    200
}
const fn default_handles() -> u32 {
    256
}
const fn default_subrequests() -> u32 {
    32
}
const fn default_poll() -> u32 {
    10
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            memory: default_memory(),
            fuel: default_fuel(),
            epoch_deadline_ms: default_epoch_ms(),
            max_instances: default_instances(),
            max_open_handles: default_handles(),
            max_subrequests: default_subrequests(),
            max_poll_per_tick: default_poll(),
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing errors
// ---------------------------------------------------------------------------

/// Convert a **byte offset** into a **1-based line number**.
///
/// # Why this function exists, and the defect it repairs
///
/// `toml::de::Error::span()` returns a [`Span`] whose `start` is documented as
/// *"The start byte index"*. That value was assigned directly to a field named
/// `line` and rendered as `qqq.toml line {n}`, so **every syntax error reported a
/// byte offset while claiming to be a line**:
///
/// | Input | Reported | Actual | Python `tomllib` |
/// |---|---|---|---|
/// | `[package\nname = "a"\n` | line **8** | line **1** | line 1, col 9 |
/// | `not toml at all\n` | line **4** | line **1** | line 1, col 5 |
///
/// The error grows with the file: a 40-line manifest reports line numbers in the
/// thousands. A diagnostic whose entire purpose is to point a developer at a
/// location, and which is off by a factor of the average line length, is worse
/// than no location at all — because it is *believed*.
///
/// # Why the conversion counts `\n` rather than using `str::lines`
///
/// Because the offset must be interpreted against the **original bytes**. A
/// manifest read from disk may contain `\r\n`, and `lines()` normalises that
/// away — so counting lines over `lines()` while indexing into the raw string
/// would be correct on Linux and off by one on Windows for every line after the
/// first. Counting `\n` in the prefix is the definition of a line number and does
/// not depend on how the file was written.
///
/// # Why the offset is clamped rather than trusted
///
/// A span from a parser is not guaranteed to be inside the text it was parsed
/// from — a parser that reports "unexpected end of input" may point one past the
/// end. `take` clamps by construction, so a caller never sees a panic on a
/// malformed file, which is exactly when a diagnostic must not panic.
#[must_use]
fn line_number_at(text: &str, byte_offset: usize) -> usize {
    // The count of newlines strictly before the offset, plus one, is the 1-based
    // line number. `take` rather than slicing, so an out-of-range offset is
    // clamped instead of panicking.
    text.bytes()
        .take(byte_offset)
        .filter(|b| *b == b'\n')
        .count()
        + 1
}

/// A manifest could not be parsed or is semantically invalid.
///
/// Carries enough structure for `qqqai` to render the mandated error block
/// (Proposal §12.2) without guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// The file is not valid TOML.
    Syntax {
        /// The underlying parser message.
        detail: String,
        /// Line number, when the parser reported one.
        line: Option<usize>,
    },
    /// A required field is absent.
    MissingField {
        /// The TOML path, e.g. `package.name`.
        field: String,
    },
    /// A field has the wrong type or shape.
    InvalidField {
        /// The TOML path, e.g. `limits.fuel`.
        field: String,
        /// Why it is wrong.
        reason: String,
    },
    /// A limit is outside the range the host can enforce.
    LimitOutOfRange {
        /// The field name.
        field: String,
        /// The offending value.
        value: String,
        /// The permitted range.
        permitted: String,
    },
    /// A filesystem mode string is not one of the three known modes.
    UnknownFsMode {
        /// The offending value.
        got: String,
    },
    /// A capability path is empty or otherwise structurally impossible.
    InvalidPath {
        /// The offending path.
        path: String,
        /// Why it is invalid.
        reason: String,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { detail, line } => match line {
                Some(l) => write!(f, "qqq.toml line {l}: {detail}"),
                None => write!(f, "qqq.toml: {detail}"),
            },
            Self::MissingField { field } => {
                write!(f, "required field `{field}` is missing from qqq.toml")
            }
            Self::InvalidField { field, reason } => {
                write!(f, "field `{field}` is invalid: {reason}")
            }
            Self::LimitOutOfRange {
                field,
                value,
                permitted,
            } => write!(
                f,
                "limit `{field}` = {value} is out of range; permitted: {permitted}"
            ),
            Self::UnknownFsMode { got } => write!(
                f,
                "unknown filesystem mode `{got}`; expected one of read-only, append-only, read-write"
            ),
            Self::InvalidPath { path, reason } => {
                write!(f, "invalid capability path `{path}`: {reason}")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// Range bounds enforced on limits, in one place so the error message and the
/// check cannot disagree.
pub mod limit_bounds {
    /// Minimum memory cap: 64 KiB (one Wasm page).
    pub const MEMORY_MIN_BYTES: u64 = 64 * 1024;
    /// Maximum memory cap: 16 GiB. Beyond this the host cannot pool instances
    /// safely and the value is almost certainly a mistake.
    pub const MEMORY_MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
    /// Minimum fuel: a guest must be able to do *something*.
    pub const FUEL_MIN: u64 = 1_000;
    /// Maximum fuel: beyond this the budget constrains nothing.
    pub const FUEL_MAX: u64 = 1_000_000_000_000_000;
    /// Minimum epoch deadline: below this even trivial guests are preempted.
    pub const EPOCH_MIN_MS: u64 = 1;
    /// Maximum epoch deadline: 24 hours.
    pub const EPOCH_MAX_MS: u64 = 86_400_000;
    /// Maximum concurrent instances per worker.
    pub const INSTANCES_MAX: u32 = 100_000;
    /// Maximum open handles per instance.
    pub const HANDLES_MAX: u32 = 100_000;
    /// Maximum subrequests per instance.
    ///
    /// Lower than [`HANDLES_MAX`] deliberately. A handle is a locally pooled
    /// object and a hundred thousand of them is merely large; a subrequest is an
    /// outbound side effect on a **third party**, and a hundred thousand of them
    /// from one request is an outage aimed at somebody else. The ceiling is the
    /// range check's job — the operator picks the real number.
    pub const SUBREQUESTS_MAX: u32 = 10_000;
}

/// Test whether a limit error applies, generating the message from the same
/// constants the check uses.
///
/// All three parameters are taken by reference: none is consumed, and taking
/// any by value would force moves at every call site for no benefit.
fn check_range<T: PartialOrd + fmt::Display>(
    field: &str,
    value: &T,
    min: &T,
    max: &T,
) -> Result<(), ManifestError> {
    if value < min || value > max {
        return Err(ManifestError::LimitOutOfRange {
            field: field.to_owned(),
            value: value.to_string(),
            permitted: format!("{min}..={max}"),
        });
    }
    Ok(())
}

/// Render a slice of alternatives as `` `a`, `b` or `c` ``.
///
/// Used so every "expected one of" message in this module has the same shape.
/// A user who sees two differently-formatted lists of valid values reasonably
/// wonders whether they mean different things.
///
/// `pub(crate)` rather than private: `crate::server` validates the `[server]`
/// section and must produce messages of the same shape. Two renderings of "expected
/// one of" in one manifest's diagnostics is the kind of difference that makes a reader
/// look for a distinction that is not there.
pub(crate) fn quoted(values: &[&str]) -> String {
    match values {
        [] => "nothing".to_owned(),
        [one] => format!("`{one}`"),
        [rest @ .., last] => {
            let head: Vec<String> = rest.iter().map(|v| format!("`{v}`")).collect();
            format!("{} or `{last}`", head.join(", "))
        }
    }
}

// ---------------------------------------------------------------------------
// Size parsing
// ---------------------------------------------------------------------------

/// A parsed byte size such as `128MiB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteSize(pub u64);

impl ByteSize {
    /// The size in bytes.
    #[must_use]
    pub const fn as_bytes(self) -> u64 {
        self.0
    }

    /// Parse a human-readable size.
    ///
    /// Accepted suffixes (case-insensitive, `i` optional):
    /// `B`, `K`/`KiB`, `M`/`MiB`, `G`/`GiB`, `T`/`TiB`.
    ///
    /// Binary multipliers throughout, even for the bare `K`/`M`/`G` forms.
    /// Rationale: memory limits are always binary in practice, and offering
    /// decimal multipliers *only* for the unsuffixed spelling would make
    /// `128M` and `128MiB` differ, which is a trap. One meaning per suffix.
    ///
    /// # Errors
    ///
    /// Returns a description string when the input is not a valid size, so the
    /// caller can build a field-specific error.
    pub fn parse(s: &str) -> Result<Self, String> {
        let t = s.trim();
        if t.is_empty() {
            return Err("empty size".to_owned());
        }
        let split = t
            .find(|c: char| !c.is_ascii_digit() && c != '_')
            .unwrap_or(t.len());
        let (num, suffix) = t.split_at(split);
        let digits: String = num.chars().filter(|c| *c != '_').collect();
        if digits.is_empty() {
            return Err(format!("`{t}` has no numeric part"));
        }
        let value: u64 = digits
            .parse()
            .map_err(|_| format!("`{digits}` is not a valid number"))?;

        let mult: u64 = match suffix.trim().to_ascii_lowercase().as_str() {
            "" | "b" => 1,
            "k" | "kb" | "kib" => 1024,
            "m" | "mb" | "mib" => 1024 * 1024,
            "g" | "gb" | "gib" => 1024 * 1024 * 1024,
            "t" | "tb" | "tib" => 1024_u64.pow(4),
            other => return Err(format!("unknown size suffix `{other}`")),
        };
        value
            .checked_mul(mult)
            .map(Self)
            .ok_or_else(|| format!("`{t}` overflows"))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        if b >= 1024_u64.pow(4) && b.is_multiple_of(1024_u64.pow(4)) {
            write!(f, "{}TiB", b / 1024_u64.pow(4))
        } else if b >= 1024 * 1024 * 1024 && b.is_multiple_of(1024 * 1024 * 1024) {
            write!(f, "{}GiB", b / (1024 * 1024 * 1024))
        } else if b >= 1024 * 1024 && b.is_multiple_of(1024 * 1024) {
            write!(f, "{}MiB", b / (1024 * 1024))
        } else if b >= 1024 && b.is_multiple_of(1024) {
            write!(f, "{}KiB", b / 1024)
        } else {
            write!(f, "{b}B")
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

impl Manifest {
    /// Parse and validate a `qqq.toml`.
    ///
    /// Performs steps that need no environment: TOML syntax, required fields,
    /// limit ranges, filesystem mode spelling and path shape. Path *existence*
    /// and secret *resolution* are deferred to NORMALIZE, because they depend
    /// on the host the manifest is being deployed to.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] naming the offending field.
    pub fn parse(text: &str) -> Result<Self, ManifestError> {
        // Parse into a generic value first so we can produce better messages
        // than serde's for the common mistakes, then validate.
        let value: toml::Value = toml::from_str(text).map_err(|e| ManifestError::Syntax {
            detail: e.message().to_owned(),
            // **`e.span().start` is a BYTE OFFSET, not a line number.**
            //
            // This was assigned directly to `line` and rendered as
            // `qqq.toml line {n}`, so every syntax error reported a byte offset
            // while claiming to be a line. For a three-line manifest with an
            // unclosed table header the message read "line 8" — and the more
            // content preceded the error, the more wrong it got: a 40-line file
            // reported line numbers in the thousands.
            //
            // A diagnostic whose *whole purpose* is to point a developer at a
            // location must not be off by a factor of the file's average line
            // length. The conversion below is what makes the field's name true.
            line: e.span().map(|s| line_number_at(text, s.start)),
        })?;

        // Required-field checks with friendly messages before the strict
        // deserialisation, so a missing `package` reports that rather than a
        // serde type error.
        let table = value.as_table().ok_or_else(|| ManifestError::Syntax {
            detail: "the document root must be a table".to_owned(),
            line: None,
        })?;
        let pkg = table
            .get("package")
            .ok_or_else(|| ManifestError::MissingField {
                field: "package".to_owned(),
            })?;
        let pkg_table = pkg.as_table().ok_or_else(|| ManifestError::InvalidField {
            field: "package".to_owned(),
            reason: "must be a table (did you write `package.name = ...`?)".to_owned(),
        })?;
        for required in ["name", "version"] {
            if !pkg_table.contains_key(required) {
                return Err(ManifestError::MissingField {
                    field: format!("package.{required}"),
                });
            }
        }

        let manifest: Self =
            value
                .try_into()
                .map_err(|e: toml::de::Error| ManifestError::InvalidField {
                    field: e
                        .span()
                        .map_or_else(|| "<unknown>".to_owned(), |_| "<see message>".to_owned()),
                    reason: e.message().to_owned(),
                })?;

        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate `[build]` against the set of things this build can actually do.
    ///
    /// Kept separate from [`Self::validate`] because it is a different kind of
    /// check: [`Self::validate`] asks "is this a coherent manifest?", while this
    /// asks "can *this* `qqqai` carry it out?". The two have different lifetimes
    /// — the second answer changes when a language driver lands — so mixing them
    /// would make the general validator churn every time a toolchain is added.
    ///
    /// Validated at parse time rather than at build time so `qqqai inspect` and
    /// `qqqai caps` reject a bad `[build]` too. A manifest that can only be
    /// proven wrong by running the compiler is a manifest whose errors surface
    /// late, in CI, far from the edit that caused them.
    fn validate_build(&self) -> Result<(), ManifestError> {
        if !Build::supports_language(&self.build.language) {
            return Err(ManifestError::InvalidField {
                field: "build.language".to_owned(),
                reason: format!(
                    "`{}` is not a supported language; expected {}",
                    self.build.language,
                    quoted(&Build::LANGUAGES)
                ),
            });
        }
        if !Build::supports_target(&self.build.target) {
            // Distinguishing "anticipated" from "wrong" matters: a user who
            // read the docs and typed `wasm32-wasip3` needs to learn that the
            // target is planned but no toolchain emits it, not that they
            // invented a name.
            let extra = if Build::ANTICIPATED_TARGETS.contains(&self.build.target.as_str()) {
                format!(
                    " — `{}` is anticipated, but no toolchain emits it yet",
                    self.build.target
                )
            } else {
                String::new()
            };
            return Err(ManifestError::InvalidField {
                field: "build.target".to_owned(),
                reason: format!(
                    "`{}` is not a target this build can emit; expected {}{extra}",
                    self.build.target,
                    quoted(&Build::TARGETS)
                ),
            });
        }
        if !matches!(self.build.profile.as_str(), "debug" | "release") {
            return Err(ManifestError::InvalidField {
                field: "build.profile".to_owned(),
                reason: format!(
                    "`{}` is not a profile; expected `debug` or `release`",
                    self.build.profile
                ),
            });
        }
        Ok(())
    }

    /// Validate one dependency table.
    ///
    /// `table` is the TOML table name (`dependencies` or `dev-dependencies`) so
    /// the error can point at the right one — the two tables can hold the same
    /// package name, and "the error is in the other table" is a confusing thing
    /// to have to work out.
    ///
    /// An associated function rather than a method because it reads nothing from
    /// the manifest: everything it needs is passed in. Clippy's `unused_self`
    /// flagged exactly that, and it was right — a `&self` that is never read
    /// suggests the function is more coupled to the manifest than it is.
    fn validate_dependencies(
        deps: &BTreeMap<String, Dependency>,
        table: &str,
    ) -> Result<(), ManifestError> {
        for (name, dep) in deps {
            // The name must be a usable identifier. A dependency key is what
            // appears in a lockfile and in a capability diff, so a malformed
            // one is rejected at the source rather than surfacing later as a
            // resolution failure.
            if name.trim().is_empty() {
                return Err(ManifestError::InvalidField {
                    field: table.to_owned(),
                    reason: "a dependency name must not be empty".to_owned(),
                });
            }

            let req = dep.requirement();
            if req.trim().is_empty() {
                return Err(ManifestError::InvalidField {
                    field: format!("{table}.{name}"),
                    reason: "the version requirement must not be empty".to_owned(),
                });
            }

            // Shape-checked here; *semantics* deliberately not.
            //
            // `qqq-cap` owns the manifest, and requirement syntax is part of a
            // manifest's shape. Resolving it is `qqq-pkg`'s job, and the crate
            // graph runs qqq-pkg -> qqq-cap, so qqq-cap cannot call the real
            // parser without a dependency cycle. Duplicating the parser would
            // be worse than not checking: two implementations of "is this a
            // valid requirement" would eventually disagree, and the
            // disagreement would surface as a resolution failure on a manifest
            // that validated cleanly.
            //
            // So the check here is limited to what this crate can decide
            // honestly: the string is non-empty and contains no whitespace-only
            // nonsense. `qqqai add` (which links `qqq-pkg`) validates the real
            // grammar before writing, which is where the user can still be
            // told about a typo.
            if req.len() > 64 {
                return Err(ManifestError::InvalidField {
                    field: format!("{table}.{name}"),
                    reason: format!(
                        "`{req}` is {} characters; a version requirement is far shorter \
                         than that, which suggests the wrong value was pasted here",
                        req.len()
                    ),
                });
            }
            if req.contains(char::is_whitespace) && !req.contains(',') {
                return Err(ManifestError::InvalidField {
                    field: format!("{table}.{name}"),
                    reason: format!(
                        "`{req}` contains a space but no comma; a range is written \
                         `>=1.0, <2.0`"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Validate every `[limits]` field against the range the host can enforce.
    ///
    /// A limit outside the enforceable range is rejected rather than clamped:
    /// silently clamping a memory cap from 900 GiB to the maximum would mean the
    /// manifest says one thing and the runtime does another, which is exactly
    /// the divergence an auditor cannot detect.
    fn validate_limits(&self) -> Result<(), ManifestError> {
        let mem =
            ByteSize::parse(&self.limits.memory).map_err(|reason| ManifestError::InvalidField {
                field: "limits.memory".to_owned(),
                reason,
            })?;
        check_range(
            "limits.memory",
            &mem.as_bytes(),
            &limit_bounds::MEMORY_MIN_BYTES,
            &limit_bounds::MEMORY_MAX_BYTES,
        )?;
        check_range(
            "limits.fuel",
            &self.limits.fuel,
            &limit_bounds::FUEL_MIN,
            &limit_bounds::FUEL_MAX,
        )?;
        check_range(
            "limits.epoch_deadline_ms",
            &self.limits.epoch_deadline_ms,
            &limit_bounds::EPOCH_MIN_MS,
            &limit_bounds::EPOCH_MAX_MS,
        )?;
        check_range(
            "limits.max_instances",
            &self.limits.max_instances,
            &1,
            &limit_bounds::INSTANCES_MAX,
        )?;
        check_range(
            "limits.max_open_handles",
            &self.limits.max_open_handles,
            &0,
            &limit_bounds::HANDLES_MAX,
        )?;
        check_range(
            "limits.max_subrequests",
            &self.limits.max_subrequests,
            &0,
            &limit_bounds::SUBREQUESTS_MAX,
        )?;
        Ok(())
    }

    /// Semantic validation beyond what serde can express.
    fn validate(&self) -> Result<(), ManifestError> {
        // -- package.name must satisfy the shared identifier rules -------
        qqq_core::PackageName::new(self.package.name.clone()).map_err(|e| {
            ManifestError::InvalidField {
                field: "package.name".to_owned(),
                reason: e.to_string(),
            }
        })?;
        // -- package.version must be a parsable version ------------------
        self.package
            .version
            .parse::<qqq_core::Version>()
            .map_err(|e| ManifestError::InvalidField {
                field: "package.version".to_owned(),
                reason: e.to_string(),
            })?;

        // -- build -------------------------------------------------------
        self.validate_build()?;

        // -- server ------------------------------------------------------
        //
        // Wired here, not in `qqq-serve`, so `qqqai inspect`, `qqqai caps` and
        // `qqqai check` all reject a bad `[server]` without a server running — the
        // same argument `validate_build`'s doc makes for validating at parse time.
        // A route table that can only be proven wrong by starting a listener is one
        // whose errors surface late, in CI, far from the edit that caused them.
        self.server.validate()?;

        // -- limits ------------------------------------------------------
        self.validate_limits()?;

        // -- dependencies ------------------------------------------------
        // Validated here rather than left to serde so the error can name the
        // offending *package*, which serde cannot do: the untagged `Dependency`
        // enum reports "data did not match any variant", and the key is out of
        // its scope by then. A user who typo'd a field inside one entry needs
        // to be told which entry.
        Self::validate_dependencies(&self.dependencies, "dependencies")?;
        Self::validate_dependencies(&self.dev_dependencies, "dev-dependencies")?;

        // -- filesystem capabilities -------------------------------------
        for (i, fs) in self.capabilities.fs.iter().enumerate() {
            if fs.path.trim().is_empty() {
                return Err(ManifestError::InvalidPath {
                    path: fs.path.clone(),
                    reason: format!("capabilities.fs[{i}].path must not be empty"),
                });
            }
            if fs.path.contains('\0') {
                return Err(ManifestError::InvalidPath {
                    path: fs.path.clone(),
                    reason: "must not contain a NUL byte".to_owned(),
                });
            }
            if let Some(q) = &fs.quota {
                ByteSize::parse(q).map_err(|reason| ManifestError::InvalidField {
                    field: format!("capabilities.fs[{i}].quota"),
                    reason,
                })?;
            }
        }

        // -- http client hosts must be `host:port` shaped or bare hosts --
        if let Some(http) = &self.capabilities.http {
            for (i, h) in http.client.iter().enumerate() {
                if h.trim().is_empty() {
                    return Err(ManifestError::InvalidField {
                        field: format!("capabilities.http.client[{i}]"),
                        reason: "must not be empty".to_owned(),
                    });
                }
                if h.contains("://") {
                    return Err(ManifestError::InvalidField {
                        field: format!("capabilities.http.client[{i}]"),
                        reason: format!("must be `host` or `host:port`, not a URL — got `{h}`"),
                    });
                }
            }
        }

        // -- env allowlist must not contain wildcards --------------------
        if let Some(env) = &self.capabilities.env {
            for (i, v) in env.allow.iter().enumerate() {
                if v.contains('*') {
                    return Err(ManifestError::InvalidField {
                        field: format!("capabilities.env.allow[{i}]"),
                        reason: "wildcards are not permitted; name each variable, \
                                 because a blanket inherit is ambient authority"
                            .to_owned(),
                    });
                }
            }
        }

        Ok(())
    }

    /// The capabilities this manifest grants, as a concrete set.
    ///
    /// This is step 1's output and step 2's input. Note that it reflects only
    /// what the manifest *declares*; overlays narrow it later.
    #[must_use]
    pub fn declared_capabilities(&self) -> Vec<Capability> {
        let mut out: Vec<Capability> = Vec::new();
        let mut push = |c: Capability| {
            if !out.contains(&c) {
                out.push(c);
            }
        };

        if let Some(http) = &self.capabilities.http {
            if http.server {
                push(Capability::HttpServer);
            }
            if !http.client.is_empty() {
                push(Capability::HttpClient);
            }
        }
        for fs in &self.capabilities.fs {
            match fs.mode {
                FsMode::ReadOnly => push(Capability::FsRead),
                FsMode::AppendOnly => push(Capability::FsWrite),
                FsMode::ReadWrite => {
                    push(Capability::FsRead);
                    push(Capability::FsWrite);
                }
            }
        }
        if let Some(c) = &self.capabilities.crypto {
            if c.random {
                push(Capability::CryptoRandom);
            }
            if !c.hash.is_empty() {
                push(Capability::CryptoHash);
            }
            if !c.hmac.is_empty() {
                push(Capability::CryptoHmac);
            }
            if !c.aead.is_empty() {
                push(Capability::CryptoAead);
            }
            if !c.sign.is_empty() {
                push(Capability::CryptoSign);
            }
            if !c.secrets.is_empty() {
                push(Capability::SecretUse);
            }
        }
        if let Some(c) = &self.capabilities.clock {
            if c.wall {
                push(Capability::ClockWall);
            }
            if c.monotonic {
                push(Capability::ClockMonotonic);
            }
        }
        if let Some(e) = &self.capabilities.env {
            if !e.allow.is_empty() {
                push(Capability::EnvRead);
            }
        }
        if let Some(d) = &self.capabilities.dns {
            if !d.resolve.is_empty() {
                push(Capability::DnsResolve);
            }
        }

        out.sort_unstable();
        out
    }

    /// Count of declared capabilities, for the startup warning.
    ///
    /// Proposal §12.1: `qqqai dev` tells the user when a project declares zero
    /// capabilities, because the failure they will hit next is a denial and
    /// teaching the security model at the moment of confusion beats teaching it
    /// in a README nobody reads.
    #[must_use]
    pub fn declared_capability_count(&self) -> usize {
        self.declared_capabilities().len()
    }

    /// Capabilities declared *and* flagged as covert channels.
    ///
    /// Surfaced loudly by `qqqai audit` and by developer mode.
    #[must_use]
    pub fn covert_channels(&self) -> Vec<Capability> {
        self.declared_capabilities()
            .into_iter()
            .filter(|c| c.is_covert_channel())
            .collect()
    }
}

/// Group capabilities by namespace, for `qqqai caps` output.
#[must_use]
pub fn group_by_namespace(caps: &[Capability]) -> BTreeMap<&'static str, Vec<Capability>> {
    let mut m: BTreeMap<&'static str, Vec<Capability>> = BTreeMap::new();
    for &c in caps {
        m.entry(c.namespace()).or_default().push(c);
    }
    m
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The `[server]` section
// ---------------------------------------------------------------------------
//
// These type declarations live here rather than in `crate::server` because
// `tools/gen_schemas.py` reads this file to build `qqq.toml`'s JSON Schema, and it
// resolves a named type by its **bare name** into a flat `$defs` namespace. A
// declaration in another module is written `crate::server::Server`, which the
// generator refuses -- correctly, rather than publishing a schema with a field it
// cannot describe. `crate::server` keeps the *behaviour*: validation,
// `unauthenticated_routes`, and the CORS table check.
/// `[server]` — the routes and the default authentication mode.
///
/// Absent means no network surface at all; see the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// The route table. Empty means the project serves nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<Route>,
    /// The authentication mode applied to a route that does not name one.
    ///
    /// Defaults to [`AuthMode::Deny`], **not** to a real mode. A manifest that lists
    /// routes and forgets `default_auth` must fail closed: defaulting to `none` would
    /// publish every route unauthenticated because the author omitted a line, and
    /// defaulting to `bearer-jwt` would be a guess about a mechanism the author may
    /// not have implemented. `deny` is the only default that cannot be wrong.
    #[serde(default)]
    pub default_auth: AuthMode,
    /// `[server.cors]` — the cross-origin policy, absent meaning no CORS at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors: Option<Cors>,
}

/// One entry in `[server] routes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// The path pattern, e.g. `/orders/:id`.
    pub path: String,
    /// The methods this route accepts. Empty is an error, not "all".
    #[serde(default)]
    pub methods: Vec<String>,
    /// The handler name in the guest.
    pub handler: String,
    /// This route's authentication mode, overriding `default_auth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthMode>,
}

/// How a request is authenticated before it reaches a handler.
///
/// A closed set, and `deny` is a member of it rather than represented by an absence.
/// An `Option<AuthMode>` where `None` meant "no authentication" would make "the author
/// forgot" and "the author asked for no authentication" the same value — and the
/// difference matters more here than anywhere else in the manifest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMode {
    /// Refuse every request to this route. The default.
    #[default]
    Deny,
    /// No authentication. Explicit, never inferred.
    None,
    /// A bearer JWT, validated against the configured issuer and audience.
    BearerJwt,
    /// A client certificate, verified against the configured trust anchors.
    Mtls,
    /// A signed request (signature over method, path, body digest and timestamp).
    SignedRequest,
}

impl AuthMode {
    /// The name as it appears in `qqq.toml`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::None => "none",
            Self::BearerJwt => "bearer-jwt",
            Self::Mtls => "mtls",
            Self::SignedRequest => "signed-request",
        }
    }

    /// Whether this mode actually authenticates anything.
    ///
    /// `deny` and `none` both stop no attacker; they differ in whether the request is
    /// served. Named as a question a caller asks rather than a `matches!` at each call
    /// site, because "is this route protected?" is the question every audit of a
    /// manifest asks first.
    #[must_use]
    pub const fn validates_a_credential(self) -> bool {
        matches!(self, Self::BearerJwt | Self::Mtls | Self::SignedRequest)
    }
}

/// `[server.cors]` — the cross-origin policy.
///
/// Modelled here as the **file format** it is; `qqq-serve::cors` builds the policy
/// from these values and owns the matching. The two are separate deliberately: whether
/// a manifest *says* `allow_origins = ["*"]` is a parse-time question, and whether a
/// given `Origin` header matches is a request-time one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cors {
    /// The origins allowed to read responses. Empty allows nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_origins: Vec<String>,
    /// Send `Access-Control-Allow-Credentials: true`.
    #[serde(default)]
    pub allow_credentials: bool,
    /// Methods advertised on a preflight. Empty advertises nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_methods: Vec<String>,
    /// Request headers the client may send.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_headers: Vec<String>,
    /// Response headers the browser may expose to script.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expose_headers: Vec<String>,
    /// How long a preflight may be cached, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// The HTTP methods a route may declare, in the spelling `qqq.toml` uses.
///
/// A closed set rather than "any token", because `methods = ["GTE"]` is a typo that
/// would otherwise produce a route no request can reach — the silent-non-existence
/// failure this module exists to prevent, arriving through the front door.
pub const METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT",
];

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[package]
name = "orders-api"
version = "0.1.0"
"#;

    const FULL: &str = r#"
[package]
name = "orders-api"
version = "0.1.0"
description = "Order intake"
license = "Apache-2.0"

[capabilities.http]
server = true
client = ["api.stripe.com:443", "*.internal.example.com:8443"]

[[capabilities.fs]]
path = "/var/lib/orders"
mode = "read-write"
quota = "5GiB"

[[capabilities.fs]]
path = "/etc/orders/config.json"
mode = "read-only"

[capabilities.crypto]
random = true
hash = ["sha256", "blake3"]
hmac = ["sha256"]
aead = ["aes-256-gcm"]
sign = ["ed25519"]
secrets = ["JWT_SIGNING_KEY"]

[capabilities.clock]
wall = true
monotonic = true
timezone = "UTC"

[capabilities.env]
allow = ["LOG_LEVEL", "REGION"]

[capabilities.dns]
resolve = ["api.stripe.com"]

[limits]
memory = "128MiB"
fuel = 50000000
epoch_deadline_ms = 5000
max_instances = 200
max_open_handles = 256

[server]
routes = [
  { path = "/orders",     methods = ["POST"],          handler = "create-order" },
  { path = "/orders/:id", methods = ["GET", "DELETE"], handler = "order-by-id" },
  { path = "/healthz",    methods = ["GET"],           handler = "health", auth = "none" },
]
default_auth = "bearer-jwt"

[server.cors]
allow_origins = ["https://app.example.com"]
"#;

    #[test]
    fn minimal_manifest_parses_and_grants_nothing() {
        let m = Manifest::parse(MINIMAL).expect("minimal manifest must parse");
        assert_eq!(m.package.name, "orders-api");
        assert_eq!(
            m.declared_capabilities(),
            Vec::<Capability>::new(),
            "a manifest that declares nothing must grant nothing"
        );
        assert_eq!(m.declared_capability_count(), 0);
    }

    /// The full example printed in Proposal §5.3 must parse. If this fails,
    /// the documentation is lying to users.
    #[test]
    fn proposal_full_manifest_example_parses() {
        let m = Manifest::parse(FULL).expect("the proposal's example must parse");
        let caps = m.declared_capabilities();
        for expected in [
            Capability::HttpServer,
            Capability::HttpClient,
            Capability::FsRead,
            Capability::FsWrite,
            Capability::CryptoRandom,
            Capability::CryptoHash,
            Capability::CryptoHmac,
            Capability::CryptoAead,
            Capability::CryptoSign,
            Capability::SecretUse,
            Capability::ClockWall,
            Capability::ClockMonotonic,
            Capability::EnvRead,
            Capability::DnsResolve,
        ] {
            assert!(
                caps.contains(&expected),
                "the proposal's example should grant {expected}, but it did not"
            );
        }
    }

    /// **The `[server]` section is parsed, not silently dropped.**
    ///
    /// # Why this is the test that matters most for the section
    ///
    /// Before `Manifest` had a `server` field, a manifest containing `[server]` with
    /// routes parsed **successfully** and every route was discarded: the server would
    /// start, accept connections and 404 everything, with nothing saying why. That is
    /// the same silent-drop defect the `[dependencies]` field's doc comment records,
    /// and it is why this asserts the *values* rather than merely that parsing
    /// succeeded — a parse that succeeds while dropping the table is exactly the bug.
    #[test]
    fn the_server_section_is_parsed_and_not_dropped() {
        let m = Manifest::parse(FULL).expect("the proposal's example must parse");

        assert_eq!(
            m.server.routes.len(),
            3,
            "all three routes must survive parsing"
        );
        assert_eq!(m.server.default_auth, AuthMode::BearerJwt);
        assert_eq!(m.server.routes[0].path, "/orders");
        assert_eq!(m.server.routes[0].handler, "create-order");
        assert_eq!(m.server.routes[1].methods, vec!["GET", "DELETE"]);
        assert_eq!(
            m.server.routes[2].auth,
            Some(AuthMode::None),
            "the per-route override must survive too"
        );
        assert_eq!(
            m.server
                .cors
                .as_ref()
                .expect("cors must be parsed")
                .allow_origins,
            vec!["https://app.example.com"]
        );
    }

    /// A manifest with no `[server]` serves nothing, and is not an error.
    ///
    /// A library has no network surface, and requiring an empty section would be
    /// noise. What must not happen is the *absence* being read as "serve everything".
    #[test]
    fn an_absent_server_section_serves_nothing() {
        let m = Manifest::parse(MINIMAL).expect("must parse");
        assert!(m.server.is_empty());
        assert_eq!(m.server.len(), 0);
        assert_eq!(m.server.default_auth, AuthMode::Deny);
        assert!(m.server.cors.is_none());
    }

    /// **A bad `[server]` section is rejected by `Manifest::parse` itself.**
    ///
    /// The wiring claim: validation is reachable from the entry point a user actually
    /// calls, not merely from `Server::validate`. A check that exists but is not called
    /// is the defect this project keeps finding, so this asserts through `parse`.
    #[test]
    fn a_bad_server_section_is_rejected_at_parse_time() {
        // Each case is a **complete** route literal with exactly one thing wrong, so
        // the only reason for the failure is the field being tested. A first version
        // omitted `path` from some cases and the test failed on that instead —
        // a fixture that cannot isolate the defect proves nothing about it.
        let cases: [(&str, &str); 4] = [
            (r#"{ path = "/a", methods = [], handler = "h" }"#, "methods"),
            (
                r#"{ path = "/a", methods = ["GTE"], handler = "h" }"#,
                "GTE",
            ),
            (r#"{ path = "a", methods = ["GET"], handler = "h" }"#, "/a"),
            (
                r#"{ path = "/a", methods = ["GET"], handler = "" }"#,
                "handler",
            ),
        ];
        for (route, needle) in cases {
            let src = format!("{MINIMAL}\n[server]\nroutes = [{route}]\n");
            let err = Manifest::parse(&src)
                .expect_err(&format!("`{route}` must be refused, got a valid manifest"));
            let text = err.to_string();
            assert!(
                text.contains(needle),
                "for `{route}` expected `{needle}`: {text}"
            );
            assert!(
                text.contains("server.routes[0]"),
                "the error must name the offending route: {text}"
            );
        }
    }

    /// A wildcard origin in `[server.cors]` is rejected by `Manifest::parse`.
    ///
    /// The security-relevant half of the wiring: a manifest is the file an auditor
    /// reads, so `qqqai inspect` must be able to report a wildcard CORS policy without
    /// starting a server.
    #[test]
    fn a_wildcard_cors_policy_is_rejected_at_parse_time() {
        for origins in [
            "allow_origins = [\"*\"]",
            "allow_origins = [\"https://*.example.com\"]",
        ] {
            let src = format!("{MINIMAL}\n[server.cors]\n{origins}\n");
            let err = Manifest::parse(&src).expect_err(&format!("`{origins}` must be refused"));
            assert!(
                err.to_string().contains("allow_origins"),
                "{origins}: {err}"
            );
        }
    }

    #[test]
    fn defaults_are_safe_and_present() {
        let m = Manifest::parse(MINIMAL).unwrap();
        assert_eq!(m.limits.memory, "128MiB");
        assert_eq!(m.limits.fuel, 50_000_000);
        assert_eq!(m.limits.epoch_deadline_ms, 5_000);
        assert_eq!(m.limits.max_instances, 200);
        // Absent capability stanzas stay absent.
        assert!(m.capabilities.http.is_none());
        assert!(m.capabilities.crypto.is_none());
        assert!(m.capabilities.clock.is_none());
    }

    #[test]
    fn crypto_random_and_wall_clock_default_to_denied() {
        // A crypto stanza that asks only for hashing must NOT grant random.
        let src = format!("{MINIMAL}\n[capabilities.crypto]\nhash = [\"sha256\"]\n");
        let m = Manifest::parse(&src).unwrap();
        let caps = m.declared_capabilities();
        assert!(caps.contains(&Capability::CryptoHash));
        assert!(
            !caps.contains(&Capability::CryptoRandom),
            "randomness must be denied unless explicitly requested"
        );

        let src = format!("{MINIMAL}\n[capabilities.clock]\nmonotonic = true\n");
        let m = Manifest::parse(&src).unwrap();
        let caps = m.declared_capabilities();
        assert!(caps.contains(&Capability::ClockMonotonic));
        assert!(!caps.contains(&Capability::ClockWall));
    }

    #[test]
    fn missing_package_is_reported_clearly() {
        let e = Manifest::parse("[limits]\nmemory = \"1MiB\"\n").unwrap_err();
        assert_eq!(
            e,
            ManifestError::MissingField {
                field: "package".to_owned()
            }
        );
        assert!(e.to_string().contains("`package`"));
    }

    #[test]
    fn missing_required_package_fields_are_reported() {
        let e = Manifest::parse("[package]\nversion = \"0.1.0\"\n").unwrap_err();
        assert_eq!(
            e,
            ManifestError::MissingField {
                field: "package.name".to_owned()
            }
        );
    }

    #[test]
    fn invalid_toml_reports_syntax() {
        let e = Manifest::parse("[package\nname = ").unwrap_err();
        assert!(matches!(e, ManifestError::Syntax { .. }), "got {e:?}");
    }

    /// **The line number is a line, not a byte offset.**
    ///
    /// `toml`'s `Span::start` is documented as a byte index, and it was assigned
    /// straight to a field rendered as `qqq.toml line {n}` — so this test is the
    /// one that would have caught the defect, and did not exist until fuzzing the
    /// parser surfaced it.
    ///
    /// The expectation is pinned against **Python's `tomllib`**, whose messages
    /// were checked by hand for the first two cases, so this is not a test
    /// asserting whatever the implementation happens to produce.
    #[test]
    fn a_syntax_error_reports_a_real_line_number_not_a_byte_offset() {
        // The unclosed header is on line 1, at byte 8. The old code reported 8.
        let e = Manifest::parse("[package\nname = \"a\"\n").unwrap_err();
        match e {
            ManifestError::Syntax { line, detail } => {
                assert_eq!(
                    line,
                    Some(1),
                    "an unclosed table header on line 1 was reported as {line:?}; \
                     byte offset 8 is not a line number. Detail: {detail}"
                );
            }
            other => panic!("expected a syntax error, got {other:?}"),
        }

        // `not toml` fails at byte 4, on line 1. The old code reported 4.
        let e = Manifest::parse("not toml at all\n").unwrap_err();
        match e {
            ManifestError::Syntax { line, .. } => assert_eq!(line, Some(1)),
            other => panic!("expected a syntax error, got {other:?}"),
        }
    }

    /// The reported line must **grow with the file**, not with its byte length.
    ///
    /// This is the property a byte offset fails most visibly: the same mistake
    /// made on line 3 of a 10-line file and on line 30 of a 40-line file must
    /// report 3 and 30, and the byte offset would report two numbers differing by
    /// hundreds.
    #[test]
    fn the_reported_line_scales_with_the_line_not_the_offset() {
        // Build a manifest whose error is on a known line: N valid package lines
        // followed by an unclosed table header.
        for target_line in [1_usize, 3, 7, 20] {
            let mut text = String::new();
            for i in 1..target_line {
                // `write!` into the `String` rather than `push_str(&format!(..))`,
                // which allocates a temporary per iteration for no reason —
                // clippy's `format_push_string` says so and is right.
                use std::fmt::Write as _;
                let _ = writeln!(text, "# filler line {i}");
            }
            text.push_str("[unclosed\n");

            let e = Manifest::parse(&text).unwrap_err();
            match e {
                ManifestError::Syntax { line, detail } => {
                    assert_eq!(
                        line,
                        Some(target_line),
                        "the error is on line {target_line} ({target_line} filler lines \
                         then an unclosed header) but was reported as {line:?}. \
                         Detail: {detail}"
                    );
                }
                other => panic!("expected a syntax error, got {other:?}"),
            }
        }
    }

    /// The conversion counts newlines in the **raw** bytes, so `\r\n` is correct.
    ///
    /// # Why this is its own test
    ///
    /// Because the obvious implementation — `text.lines()` — normalises `\r\n`
    /// and would report a line number that is right on Linux and wrong on
    /// Windows for every line after the first. A manifest is a file a developer
    /// writes on whatever platform they use, and a diagnostic that depends on
    /// that is a diagnostic that lies to half its users.
    #[test]
    fn line_numbers_are_correct_for_crlf_files() {
        // Two filler lines then an unclosed header, all `\r\n`.
        let text = "# one\r\n# two\r\n[unclosed\r\n";
        let e = Manifest::parse(text).unwrap_err();
        match e {
            ManifestError::Syntax { line, detail } => assert_eq!(
                line,
                Some(3),
                "the error is on line 3 of a CRLF file but was reported as {line:?}. \
                 Counting over `str::lines()` would normalise the `\\r\\n` away and \
                 give the wrong answer. Detail: {detail}"
            ),
            other => panic!("expected a syntax error, got {other:?}"),
        }
    }

    /// The offset conversion must not panic, whatever offset it is handed.
    ///
    /// A parser is not obliged to report a span inside the text it parsed, and
    /// "unexpected end of input" reports an offset **at** the end. A diagnostic
    /// must not panic on a malformed file — that is precisely the input it exists
    /// to explain.
    #[test]
    fn the_line_conversion_is_total() {
        let text = "a\nb\nc";
        assert_eq!(line_number_at(text, 0), 1);
        assert_eq!(line_number_at(text, 1), 1); // the `\n` itself is still line 1
        assert_eq!(line_number_at(text, 2), 2);
        assert_eq!(line_number_at(text, 4), 3);
        // At and past the end: clamped, not panicking.
        assert_eq!(line_number_at(text, text.len()), 3);
        assert_eq!(line_number_at(text, 10_000), 3);
        // The empty document is line 1, which is what a developer expects for
        // "the file is empty".
        assert_eq!(line_number_at("", 0), 1);
    }

    /// The end-to-end property, across a corpus of malformed manifests.
    ///
    /// Every one must report a line that is **within the file**. A byte offset
    /// exceeds the line count as soon as the file has more bytes than lines,
    /// which is every real manifest — so this single assertion catches the whole
    /// defect class without needing to know the exact right answer for each case.
    ///
    /// # Only inputs that are *syntactically* invalid belong here
    ///
    /// `name = 123` is **valid TOML** that fails *schema* validation, so it
    /// produces `InvalidField`, not `Syntax`. An earlier version of this corpus
    /// included it and the test panicked on its own expectation rather than on
    /// the code. The distinction is real and worth keeping straight: a `Syntax`
    /// error means the file is not TOML at all, while every other variant means
    /// the file is TOML that says something QQQ will not accept.
    #[test]
    fn every_syntax_error_reports_a_line_within_the_file() {
        let corpus: &[&str] = &[
            "[package\nname = \"a\"\n",
            "not toml at all\n",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[[[\n",
            "[package]\nname = \"a\"\nname = \"b\"\nversion = \"0.1.0\"\n",
            "[package]\nname = \"orders\"\nversion = \"1.0.",
            "# a comment\n# another\n# third\n[broken\n",
            "= = =\n",
            "[package]]\n",
        ];

        for text in corpus {
            let line_count = text.lines().count().max(1);
            let e = Manifest::parse(text).unwrap_err();
            match e {
                ManifestError::Syntax {
                    line: Some(line),
                    detail,
                } => {
                    assert!(
                        (1..=line_count).contains(&line),
                        "a malformed manifest with {line_count} line(s) reported a syntax \
                         error at line {line}, which is outside the file. A byte offset \
                         masquerading as a line number is the defect this asserts against. \
                         Input: {text:?}. Detail: {detail}"
                    );
                }
                ManifestError::Syntax { line: None, .. } => {
                    // A parser that gives no span is acceptable; the conversion is
                    // only required to be correct when there IS a span.
                }
                other => panic!(
                    "expected a SYNTAX error for {text:?} — the input is not valid TOML \
                     — but got {other:?}. If this input is in fact valid TOML, it does \
                     not belong in this corpus."
                ),
            }
        }
    }

    #[test]
    fn unknown_field_is_rejected_not_ignored() {
        // The whole point: a typo must fail loudly rather than silently
        // granting nothing and producing a distant runtime denial.
        let src = format!("{MINIMAL}\n[capabilities.crypto]\nhassh = [\"sha256\"]\n");
        let e = Manifest::parse(&src).unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("hassh") || msg.contains("unknown field"),
            "unknown fields must be rejected; got: {msg}"
        );
    }

    #[test]
    fn invalid_package_name_is_rejected() {
        let src = "[package]\nname = \"Bad Name\"\nversion = \"0.1.0\"\n";
        let e = Manifest::parse(src).unwrap_err();
        assert!(
            matches!(e, ManifestError::InvalidField { ref field, .. } if field == "package.name"),
            "got {e:?}"
        );
    }

    #[test]
    fn invalid_version_is_rejected() {
        let src = "[package]\nname = \"app\"\nversion = \"one\"\n";
        let e = Manifest::parse(src).unwrap_err();
        assert!(
            matches!(e, ManifestError::InvalidField { ref field, .. } if field == "package.version"),
            "got {e:?}"
        );
    }

    #[test]
    fn limit_ranges_are_enforced() {
        // Memory too small.
        let src = format!("{MINIMAL}\n[limits]\nmemory = \"1KiB\"\n");
        assert!(matches!(
            Manifest::parse(&src).unwrap_err(),
            ManifestError::LimitOutOfRange { .. }
        ));
        // Memory too large.
        let src = format!("{MINIMAL}\n[limits]\nmemory = \"64GiB\"\n");
        assert!(matches!(
            Manifest::parse(&src).unwrap_err(),
            ManifestError::LimitOutOfRange { .. }
        ));
        // Zero fuel.
        let src = format!("{MINIMAL}\n[limits]\nfuel = 0\n");
        assert!(matches!(
            Manifest::parse(&src).unwrap_err(),
            ManifestError::LimitOutOfRange { .. }
        ));
        // Zero instances would make the host unable to serve.
        let src = format!("{MINIMAL}\n[limits]\nmax_instances = 0\n");
        assert!(matches!(
            Manifest::parse(&src).unwrap_err(),
            ManifestError::LimitOutOfRange { .. }
        ));
    }

    #[test]
    fn boundary_values_are_accepted() {
        let src = format!("{MINIMAL}\n[limits]\nmemory = \"64KiB\"\n");
        assert!(
            Manifest::parse(&src).is_ok(),
            "minimum memory must be accepted"
        );
        let src = format!("{MINIMAL}\n[limits]\nfuel = 1000\n");
        assert!(
            Manifest::parse(&src).is_ok(),
            "minimum fuel must be accepted"
        );
    }

    #[test]
    fn empty_fs_path_is_rejected() {
        let src = format!("{MINIMAL}\n[[capabilities.fs]]\npath = \"\"\nmode = \"read-only\"\n");
        assert!(matches!(
            Manifest::parse(&src).unwrap_err(),
            ManifestError::InvalidPath { .. }
        ));
    }

    #[test]
    fn nul_byte_in_path_is_rejected() {
        let src = format!(
            "{MINIMAL}\n[[capabilities.fs]]\npath = \"/tmp/a\\u0000b\"\nmode = \"read-only\"\n"
        );
        let r = Manifest::parse(&src);
        assert!(r.is_err(), "a NUL byte in a path must be rejected");
    }

    #[test]
    fn url_in_http_client_allowlist_is_rejected_with_guidance() {
        let src =
            format!("{MINIMAL}\n[capabilities.http]\nclient = [\"https://api.example.com\"]\n");
        let e = Manifest::parse(&src).unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("not a URL"),
            "should guide the user; got: {msg}"
        );
    }

    /// A wildcard env allowlist would be ambient authority by another name.
    #[test]
    fn wildcard_env_allowlist_is_rejected() {
        let src = format!("{MINIMAL}\n[capabilities.env]\nallow = [\"*\"]\n");
        let e = Manifest::parse(&src).unwrap_err();
        assert!(
            e.to_string().contains("wildcards are not permitted"),
            "got: {e}"
        );
    }

    #[test]
    fn fs_mode_parsing_and_helpers() {
        assert!(FsMode::ReadOnly.can_read());
        assert!(!FsMode::ReadOnly.can_write());
        assert!(!FsMode::AppendOnly.can_read());
        assert!(FsMode::AppendOnly.can_write());
        assert!(FsMode::ReadWrite.can_read());
        assert!(FsMode::ReadWrite.can_write());
        // Ordering supports narrowing: ReadOnly < AppendOnly < ReadWrite.
        assert!(FsMode::ReadOnly < FsMode::ReadWrite);
    }

    /// `covers` decides whether a grant satisfies a request. Getting this
    /// wrong is a silent privilege escalation or a confusing denial, so the
    /// full 3x3 matrix is asserted explicitly rather than sampled.
    #[test]
    fn fs_mode_covers_full_matrix() {
        use FsMode::{AppendOnly, ReadOnly, ReadWrite};
        // Grant read-only.
        assert!(ReadOnly.covers(ReadOnly));
        assert!(!ReadOnly.covers(AppendOnly));
        assert!(!ReadOnly.covers(ReadWrite));
        // Grant append-only.
        assert!(!AppendOnly.covers(ReadOnly));
        assert!(AppendOnly.covers(AppendOnly));
        assert!(!AppendOnly.covers(ReadWrite), "append cannot satisfy read");
        // Grant read-write.
        assert!(ReadWrite.covers(ReadOnly));
        assert!(ReadWrite.covers(AppendOnly));
        assert!(ReadWrite.covers(ReadWrite));
    }

    #[test]
    fn read_write_fs_grants_both_read_and_write() {
        let src =
            format!("{MINIMAL}\n[[capabilities.fs]]\npath = \"/tmp/x\"\nmode = \"read-write\"\n");
        let caps = Manifest::parse(&src).unwrap().declared_capabilities();
        assert!(caps.contains(&Capability::FsRead));
        assert!(caps.contains(&Capability::FsWrite));
    }

    #[test]
    fn read_only_fs_does_not_grant_write() {
        let src =
            format!("{MINIMAL}\n[[capabilities.fs]]\npath = \"/tmp/x\"\nmode = \"read-only\"\n");
        let caps = Manifest::parse(&src).unwrap().declared_capabilities();
        assert!(caps.contains(&Capability::FsRead));
        assert!(
            !caps.contains(&Capability::FsWrite),
            "read-only must never grant write"
        );
    }

    #[test]
    fn byte_size_parsing_is_correct_and_unambiguous() {
        assert_eq!(
            ByteSize::parse("128MiB").unwrap().as_bytes(),
            128 * 1024 * 1024
        );
        assert_eq!(
            ByteSize::parse("128M").unwrap().as_bytes(),
            128 * 1024 * 1024
        );
        assert_eq!(
            ByteSize::parse("128mib").unwrap().as_bytes(),
            128 * 1024 * 1024
        );
        assert_eq!(
            ByteSize::parse("1GiB").unwrap().as_bytes(),
            1024 * 1024 * 1024
        );
        assert_eq!(ByteSize::parse("512").unwrap().as_bytes(), 512);
        assert_eq!(ByteSize::parse("512B").unwrap().as_bytes(), 512);
        assert_eq!(ByteSize::parse("1_024").unwrap().as_bytes(), 1024);
    }

    #[test]
    fn byte_size_rejects_junk() {
        for bad in ["", "MiB", "abc", "12XiB", "-1MiB", "1.5MiB"] {
            assert!(ByteSize::parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn byte_size_display_round_trips_for_round_numbers() {
        for s in ["64KiB", "1MiB", "128MiB", "1GiB", "2TiB"] {
            let b = ByteSize::parse(s).unwrap();
            assert_eq!(b.to_string(), s, "did not round-trip {s}");
        }
    }

    #[test]
    fn covert_channels_are_surfaced() {
        let m = Manifest::parse(FULL).unwrap();
        let covert = m.covert_channels();
        assert!(covert.contains(&Capability::CryptoRandom));
        assert!(covert.contains(&Capability::ClockWall));
        assert!(covert.contains(&Capability::HttpClient));
        assert!(covert.contains(&Capability::EnvRead));
        assert!(covert.contains(&Capability::DnsResolve));
        // fs.read is an access risk, not a covert channel.
        assert!(!covert.contains(&Capability::FsRead));
    }

    #[test]
    fn grouping_by_namespace_is_stable() {
        let m = Manifest::parse(FULL).unwrap();
        let g = group_by_namespace(&m.declared_capabilities());
        assert_eq!(g["crypto"].len(), 5); // random, hash, hmac, aead, sign
        assert_eq!(g["clock"].len(), 2);
        assert_eq!(g["fs"].len(), 2);
    }

    /// Sorting the output makes `qqqai caps` deterministic, which matters
    /// because agents diff it.
    #[test]
    fn declared_capabilities_are_sorted_and_deduplicated() {
        let m = Manifest::parse(FULL).unwrap();
        let caps = m.declared_capabilities();
        let mut sorted = caps.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(caps, sorted, "must be sorted and deduplicated");
    }

    // -- [build] ---------------------------------------------------------

    /// The compatibility guarantee: a manifest written before `[build]`
    /// existed must parse **identically**, not merely parse. If adding a
    /// section changed the defaults of an existing project, every deployed
    /// manifest would change behaviour on upgrade.
    #[test]
    fn a_manifest_without_a_build_section_still_parses() {
        let m = Manifest::parse(MINIMAL).unwrap();
        assert_eq!(m.build, Build::default());
        assert_eq!(m.build.language, "rust");
        assert_eq!(m.build.target, "wasm32-wasip2");
        assert_eq!(m.build.profile, "release");
        assert!(
            !m.build.reproducible,
            "reproducible opt-in must default off"
        );
    }

    #[test]
    fn a_build_section_overrides_the_defaults() {
        let src = r#"
[package]
name = "app"
version = "0.1.0"

[build]
language = "ts"
target = "wasm32-wasip2"
profile = "debug"
reproducible = true
"#;
        let m = Manifest::parse(src).unwrap();
        assert_eq!(m.build.language, "ts");
        assert_eq!(m.build.target, "wasm32-wasip2");
        assert_eq!(m.build.profile, "debug");
        assert!(m.build.reproducible);
    }

    #[test]
    fn an_unknown_language_lists_the_valid_ones() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [build]\nlanguage = \"cobol\"\n";
        let e = Manifest::parse(src).unwrap_err();
        match &e {
            ManifestError::InvalidField { field, reason } => {
                assert_eq!(field, "build.language");
                assert!(
                    reason.contains("cobol"),
                    "must quote the bad value: {reason}"
                );
                // The message must name every option, or a user is left guessing.
                for lang in Build::LANGUAGES {
                    assert!(reason.contains(lang), "reason omits `{lang}`: {reason}");
                }
            }
            other => panic!("expected InvalidField, got {other:?}"),
        }
    }

    /// `wasm32-wasip3` is named in the Proposal as the future target. Accepting
    /// it now would be a silent stub — the build would fail deep inside a
    /// toolchain invocation. It must be refused up front, *and* the message must
    /// explain that it is anticipated rather than simply unknown, because
    /// "unknown target" for a target the docs mention reads as a bug.
    #[test]
    fn an_anticipated_but_unproducible_target_explains_itself() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [build]\ntarget = \"wasm32-wasip3\"\n";
        let e = Manifest::parse(src).unwrap_err();
        match &e {
            ManifestError::InvalidField { field, reason } => {
                assert_eq!(field, "build.target");
                assert!(
                    reason.contains("anticipated"),
                    "must explain that it is anticipated, not unknown: {reason}"
                );
                assert!(
                    reason.contains("wasm32-wasip2"),
                    "must name the usable target"
                );
            }
            other => panic!("expected InvalidField, got {other:?}"),
        }
    }

    #[test]
    fn a_nonsense_target_is_refused() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [build]\ntarget = \"x86_64-unknown-linux-gnu\"\n";
        let e = Manifest::parse(src).unwrap_err();
        match &e {
            ManifestError::InvalidField { field, reason } => {
                assert_eq!(field, "build.target");
                assert!(
                    !reason.contains("anticipated"),
                    "a native target is not anticipated, it is wrong: {reason}"
                );
            }
            other => panic!("expected InvalidField, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_profile_is_refused() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [build]\nprofile = \"turbo\"\n";
        let e = Manifest::parse(src).unwrap_err();
        match &e {
            ManifestError::InvalidField { field, reason } => {
                assert_eq!(field, "build.profile");
                assert!(reason.contains("debug") && reason.contains("release"));
            }
            other => panic!("expected InvalidField, got {other:?}"),
        }
    }

    /// Unknown fields under `[build]` must be rejected like everywhere else: a
    /// typo'd `targt = ...` that is silently ignored builds for the wrong
    /// target, which is precisely the failure the strictness exists to prevent.
    #[test]
    fn an_unknown_build_field_is_rejected_not_ignored() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [build]\ntargt = \"wasm32-wasip2\"\n";
        assert!(
            Manifest::parse(src).is_err(),
            "a typo'd [build] field must be an error, not silently ignored"
        );
    }

    #[test]
    fn the_two_alternative_lists_are_quoted_readably() {
        assert_eq!(quoted(&[]), "nothing");
        assert_eq!(quoted(&["a"]), "`a`");
        assert_eq!(quoted(&["a", "b"]), "`a` or `b`");
        assert_eq!(quoted(&["a", "b", "c"]), "`a`, `b` or `c`");
    }

    // -- [dependencies] -----------------------------------------------------
    //
    // These exist because of a real defect. `Manifest` did not model
    // `[dependencies]` and is not `deny_unknown_fields` at the top level, so a
    // manifest containing the table parsed **successfully** with the
    // dependencies silently dropped. `qqqai caps` on such a project reported
    // "no capabilities granted" and exited 0 — the user had written a
    // dependency, the tool had read the file, and nothing connected the two.

    /// The regression test for that silence.
    ///
    /// The assertion is deliberately on the *count*, not just on `is_ok`: the
    /// old code also returned `Ok`. A test that only checked for success would
    /// have passed before the fix and would pass again if the field were ever
    /// removed.
    #[test]
    fn a_dependency_table_is_parsed_not_silently_dropped() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [dependencies]\n\"qqqai/json\" = { version = \"1.2\" }\n";
        let m = Manifest::parse(src).expect("must parse");

        assert_eq!(
            m.dependencies.len(),
            1,
            "the dependency must be visible, not dropped: {:?}",
            m.dependencies
        );
        let d = m
            .dependencies
            .get("qqqai/json")
            .expect("the key is present");
        assert_eq!(d.requirement(), "1.2");
        assert_eq!(d.source(), None, "no source was given");
    }

    /// The bare-string form is what every other ecosystem uses; refusing it
    /// would be a gratuitous difference, so it is accepted and means the same.
    #[test]
    fn a_bare_version_string_is_accepted_as_a_dependency() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [dependencies]\n\"qqqai/json\" = \"1.2\"\n";
        let m = Manifest::parse(src).expect("must parse");
        let d = m.dependencies.get("qqqai/json").expect("present");
        assert_eq!(d.requirement(), "1.2");
    }

    #[test]
    fn the_full_dependency_form_carries_features_and_source() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [dependencies]\n\
                   \"qqqai/json\" = { version = \"1.2\", features = [\"simd\"], \
                   source = \"registry+https://pkg.qqq.dev\" }\n";
        let m = Manifest::parse(src).expect("must parse");
        let d = m.dependencies.get("qqqai/json").expect("present");
        assert_eq!(d.source(), Some("registry+https://pkg.qqq.dev"));
        match d {
            Dependency::Full(detail) => assert_eq!(detail.features, vec!["simd"]),
            Dependency::Version(v) => panic!("expected the full form, got version {v}"),
        }
    }

    /// Dev-dependencies are a separate table on purpose.
    ///
    /// A test-only package must not be able to widen the shipped component's
    /// authority, so the two tables must not be merged. If they ever are, this
    /// test fails rather than silently granting production capabilities to a
    /// benchmarking helper.
    #[test]
    fn dev_dependencies_are_a_separate_table() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [dependencies]\n\"qqqai/json\" = \"1.2\"\n\
                   [dev-dependencies]\n\"qqqai/assert\" = \"1.0\"\n";
        let m = Manifest::parse(src).expect("must parse");

        assert_eq!(m.dependencies.len(), 1, "only the real dependency");
        assert_eq!(m.dev_dependencies.len(), 1, "only the dev dependency");
        assert!(m.dependencies.contains_key("qqqai/json"));
        assert!(!m.dependencies.contains_key("qqqai/assert"));
        assert!(m.dev_dependencies.contains_key("qqqai/assert"));
    }

    /// A typo inside a dependency table is an error, matching `[build]`.
    ///
    /// The same argument as `an_unknown_build_field_is_rejected_not_ignored`:
    /// `verison = "1.2"` silently ignored means the dependency resolves at
    /// whatever the registry defaults to, and the user finds out in production.
    #[test]
    fn an_unknown_dependency_field_is_rejected_not_ignored() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [dependencies]\n\"qqqai/json\" = { verison = \"1.2\" }\n";
        assert!(
            Manifest::parse(src).is_err(),
            "a typo'd dependency field must be an error, not silently ignored"
        );
    }

    /// An empty version requirement is refused, and the error names the package.
    ///
    /// Naming the package is the point: serde cannot do it for an untagged enum
    /// (it reports "data did not match any variant"), and a user with several
    /// dependencies needs to know which one to open.
    #[test]
    fn an_empty_requirement_names_its_package() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [dependencies]\n\"qqqai/json\" = { version = \"\" }\n";
        let e = Manifest::parse(src).unwrap_err();
        let text = e.to_string();
        assert!(
            text.contains("qqqai/json"),
            "the error must name the package: {text}"
        );
    }

    /// A dev-dependency error must name the dev table, not the main one.
    ///
    /// The same package name can appear in both tables, so an error that says
    /// only `dependencies.qqqai/json` would send the user to the wrong line.
    #[test]
    fn a_dev_dependency_error_names_the_dev_table() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [dev-dependencies]\n\"qqqai/assert\" = { version = \"\" }\n";
        let e = Manifest::parse(src).unwrap_err();
        let text = e.to_string();
        assert!(
            text.contains("dev-dependencies"),
            "the error must name the dev table: {text}"
        );
    }

    /// A range written without a comma is a common typo and gets its own message.
    #[test]
    fn a_range_without_a_comma_is_explained() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [dependencies]\n\"qqqai/json\" = { version = \">=1.0 <2.0\" }\n";
        let e = Manifest::parse(src).unwrap_err();
        assert!(
            e.to_string().contains("comma"),
            "the error should explain the missing comma: {e}"
        );
    }

    /// Ordinary requirements pass the shape check.
    #[test]
    fn normal_requirements_are_accepted() {
        for req in ["1.2", "1", "^1.2.3", "~1.2.3", ">=1.0, <2.0", "=1.2.3", "*"] {
            let src = format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                 [dependencies]\n\"qqqai/json\" = {{ version = \"{req}\" }}\n"
            );
            assert!(
                Manifest::parse(&src).is_ok(),
                "`{req}` must be accepted as a requirement shape"
            );
        }
    }

    /// A manifest with no dependencies is unchanged: the field defaults empty,
    /// so existing projects parse exactly as they did before the field existed.
    ///
    /// Serialization is asserted through serde directly rather than through a
    /// `to_toml` helper, because no such helper exists yet — an earlier draft of
    /// this test called one that was never written. The `skip_serializing_if`
    /// attributes are what keep the empty tables out of any future writer, so
    /// that is the property worth pinning.
    #[test]
    fn a_manifest_without_dependencies_has_none_and_serializes_clean() {
        let m = Manifest::parse(MINIMAL).expect("must parse");
        assert!(m.dependencies.is_empty());
        assert!(m.dev_dependencies.is_empty());

        let value = serde_json::to_value(&m).expect("must serialize");
        let obj = value.as_object().expect("a manifest is a table");
        assert!(
            !obj.contains_key("dependencies"),
            "an empty dependency table must not appear when serialized: {value}"
        );
        assert!(
            !obj.contains_key("dev-dependencies"),
            "an empty dev-dependency table must not appear when serialized: {value}"
        );
    }
}
