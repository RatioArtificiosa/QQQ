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
    /// `[capabilities]` — the authority declaration. Absent means deny-all.
    #[serde(default)]
    pub capabilities: Capabilities,
    /// `[limits]` — enforceable resource bounds.
    #[serde(default)]
    pub limits: Limits,
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
            max_poll_per_tick: default_poll(),
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing errors
// ---------------------------------------------------------------------------

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
            line: e.span().map(|s| s.start),
        })?;

        // Required-field checks with friendly messages before the strict
        // deserialisation, so a missing `package` reports that rather than a
        // serde type error.
        let table = value
            .as_table()
            .ok_or_else(|| ManifestError::Syntax {
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

        // -- limits ------------------------------------------------------
        let mem = ByteSize::parse(&self.limits.memory).map_err(|reason| {
            ManifestError::InvalidField {
                field: "limits.memory".to_owned(),
                reason,
            }
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
                        reason: format!(
                            "must be `host` or `host:port`, not a URL — got `{h}`"
                        ),
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
        assert!(Manifest::parse(&src).is_ok(), "minimum memory must be accepted");
        let src = format!("{MINIMAL}\n[limits]\nfuel = 1000\n");
        assert!(Manifest::parse(&src).is_ok(), "minimum fuel must be accepted");
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
        let src = format!(
            "{MINIMAL}\n[capabilities.http]\nclient = [\"https://api.example.com\"]\n"
        );
        let e = Manifest::parse(&src).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("not a URL"), "should guide the user; got: {msg}");
    }

    /// A wildcard env allowlist would be ambient authority by another name.
    #[test]
    fn wildcard_env_allowlist_is_rejected() {
        let src = format!("{MINIMAL}\n[capabilities.env]\nallow = [\"*\"]\n");
        let e = Manifest::parse(&src).unwrap_err();
        assert!(e.to_string().contains("wildcards are not permitted"), "got: {e}");
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
        let src = format!("{MINIMAL}\n[[capabilities.fs]]\npath = \"/tmp/x\"\nmode = \"read-write\"\n");
        let caps = Manifest::parse(&src).unwrap().declared_capabilities();
        assert!(caps.contains(&Capability::FsRead));
        assert!(caps.contains(&Capability::FsWrite));
    }

    #[test]
    fn read_only_fs_does_not_grant_write() {
        let src = format!("{MINIMAL}\n[[capabilities.fs]]\npath = \"/tmp/x\"\nmode = \"read-only\"\n");
        let caps = Manifest::parse(&src).unwrap().declared_capabilities();
        assert!(caps.contains(&Capability::FsRead));
        assert!(
            !caps.contains(&Capability::FsWrite),
            "read-only must never grant write"
        );
    }

    #[test]
    fn byte_size_parsing_is_correct_and_unambiguous() {
        assert_eq!(ByteSize::parse("128MiB").unwrap().as_bytes(), 128 * 1024 * 1024);
        assert_eq!(ByteSize::parse("128M").unwrap().as_bytes(), 128 * 1024 * 1024);
        assert_eq!(ByteSize::parse("128mib").unwrap().as_bytes(), 128 * 1024 * 1024);
        assert_eq!(ByteSize::parse("1GiB").unwrap().as_bytes(), 1024 * 1024 * 1024);
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
}
