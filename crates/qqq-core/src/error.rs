//! The QQQ error model.
//!
//! Every failure a user or an agent can observe has a **stable code** of the
//! form `QQQ-<class><nnn>`, documented at a permanent URL, carrying a cause and
//! an actionable remediation.
//!
//! # Why this is a separate module rather than a `thiserror` enum
//!
//! Non-Negotiable #1 (`PRINCIPLES.md`) and Proposal §8.3 require that an AI
//! agent which has never seen QQQ can consume an error and self-correct without
//! a human. That means an error is a **data structure**, not a message: it has
//! a machine-readable code, a stable docs URL, a remediation, and a class that
//! tells a caller how to react (retry? fix the input? give up?).
//!
//! # Stability contract
//!
//! * A code is **never reused, never renumbered, never repurposed** — even if
//!   the message changes or the site that raised it is deleted.
//! * A retired code stays in [`ErrorCode`] with a doc comment explaining that
//!   it is retired, so old logs and old issues still resolve.
//! * Adding a new code is a **minor** change. Changing an existing code's
//!   meaning is a **breaking** change and requires an RFC (Proposal §0.5).
//!
//! See Proposal §8.3 and Checklist `AGENT-021`, `AGENT-022`, `CON-009`.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error classes
// ---------------------------------------------------------------------------

/// The seven stable error classes defined in Proposal §8.3.
///
/// The numeric value is the thousands digit of every code in the class and is
/// part of the wire format — do not change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[repr(u16)]
pub enum ErrorClass {
    /// `1xxx` — build and compile failures.
    Build = 1,
    /// `2xxx` — manifest and configuration failures.
    Manifest = 2,
    /// `3xxx` — runtime guest traps.
    Trap = 3,
    /// `4xxx` — capability denials.
    Capability = 4,
    /// `5xxx` — package manager and registry failures.
    Package = 5,
    /// `6xxx` — host and infrastructure failures.
    Host = 6,
    /// `7xxx` — agent protocol failures.
    Agent = 7,
}

impl ErrorClass {
    /// The class's thousands digit.
    #[must_use]
    pub const fn digit(self) -> u16 {
        self as u16
    }

    /// The stable, lowercase name used in JSON output.
    ///
    /// This is part of the machine contract: an agent matches on it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Manifest => "manifest",
            Self::Trap => "trap",
            Self::Capability => "capability",
            Self::Package => "package",
            Self::Host => "host",
            Self::Agent => "agent",
        }
    }

    /// Whether a caller should consider retrying the same operation.
    ///
    /// A **hint**, not a guarantee. It exists because "should I retry?" is the
    /// single most common decision an automated caller has to make, and making
    /// it guess produces retry storms.
    ///
    /// Only two classes are retryable: [`ErrorClass::Package`] and
    /// [`ErrorClass::Host`]. Every other class is deterministic for the same
    /// input — retrying changes nothing, so a caller that retries is wasting
    /// the budget it should spend on backoff for the classes that need it.
    ///
    /// A guest trap ([`ErrorClass::Trap`]) is deliberately **not** retryable:
    /// the same input traps the same way. A caller retrying with *different*
    /// input is making a product decision, not a retry, and should not be
    /// encouraged by this hint.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Package | Self::Host)
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Every stable QQQ error code.
///
/// # Adding a code
///
/// 1. Append it in numeric order within its class.
/// 2. Document the cause and the remediation in the doc comment — this is the
///    source of truth for `qqqai schema --all` and for the generated docs page.
/// 3. Never insert into the middle of an existing range in a way that renumbers
///    an existing code.
///
/// # Retiring a code
///
/// Mark it `#[deprecated]` and say why. Do not delete it: logs, issues and
/// support threads reference codes indefinitely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    // -- 1xxx: build / compile ------------------------------------------------
    /// The component's imports do not match the interfaces the host provides.
    /// **Remediation:** run `qqqai build` and fix the reported interface, or
    /// check that the manifest declares the right `entrypoint`.
    WitInterfaceMismatch = 1004,
    /// A language toolchain failed to compile the project.
    /// **Remediation:** run the underlying compiler directly for full output;
    /// `qqqai build --verbose` shows the exact invocation.
    CompilationFailed = 1001,
    /// The build produced an artifact that is not a valid Wasm component.
    /// **Remediation:** confirm the toolchain targets the component model
    /// (`wasm32-wasip2` or later), not a core module.
    InvalidComponentArtifact = 1002,
    /// The project's target was not installed for the active toolchain.
    /// **Remediation:** `rustup target add wasm32-wasip2`.
    MissingTarget = 1003,
    /// A reproducible build produced a different digest on a second run.
    /// **Remediation:** find the nondeterminism source; see Proposal §5.4.
    NonReproducibleBuild = 1005,

    // -- 2xxx: manifest / configuration --------------------------------------
    /// `qqq.toml` is not valid TOML.
    /// **Remediation:** the error names the line and column.
    ManifestSyntaxInvalid = 2001,
    /// `qqq.toml` parsed but violates its JSON Schema.
    /// **Remediation:** the error names the offending field and the expected
    /// shape; `qqqai schema --command manifest` prints the schema.
    ManifestSchemaViolation = 2002,
    /// A capability stanza is syntactically valid but semantically wrong —
    /// e.g. a host glob that can never match, or a negative quota.
    /// **Remediation:** run `qqqai why <capability>` for the resolution chain.
    CapabilitySyntaxInvalid = 2007,
    /// A `secret` reference names something the environment does not define.
    /// **Remediation:** set the named environment variable, or correct the
    /// reference. The value itself is never echoed.
    SecretUnresolvable = 2003,
    /// A filesystem capability path does not exist or is not a directory where
    /// one is required.
    /// **Remediation:** create the path, or correct it in `qqq.toml`.
    CapabilityPathInvalid = 2004,
    /// A limit is outside the range the host can enforce — e.g. a memory cap
    /// larger than the configured maximum, or a zero fuel budget.
    /// **Remediation:** the error states the permitted range.
    LimitOutOfRange = 2005,
    /// The manifest requests something only QQQ Fabric can provide.
    /// **Remediation:** grant it locally, or install Fabric.
    RequiresFabric = 2006,

    // -- 3xxx: runtime guest traps -------------------------------------------
    /// The guest exceeded its declared memory limit.
    /// **Remediation:** raise `limits.memory`, or fix the leak. The error
    /// reports the peak observed.
    MemoryLimitExceeded = 3001,
    /// The guest exhausted its deterministic instruction budget.
    /// **Remediation:** raise `limits.fuel`, or optimise the hot path. The
    /// error reports fuel consumed and the operation in flight.
    FuelExhausted = 3002,
    /// The guest exceeded its wall-clock deadline and was preempted.
    /// **Remediation:** raise `limits.epoch_deadline_ms`. A guest that
    /// repeatedly hits this is usually blocked on I/O it was not granted.
    EpochDeadlineExceeded = 3003,
    /// The guest trapped for a reason the host could not classify further.
    /// **Remediation:** the error carries the Wasm backtrace; run with
    /// `--debug` for source-mapped frames.
    GuestTrap = 3004,
    /// The guest attempted to use a resource handle that is invalid, already
    /// closed, or belongs to another instance.
    /// **Remediation:** this is almost always a guest bug; the error names the
    /// handle's expected type.
    InvalidResourceHandle = 3005,
    /// The guest panicked (Wasm `unreachable` from a panic path).
    /// **Remediation:** the backtrace names the panic site when DWARF debug
    /// info is present; build with debug info to get source lines.
    GuestPanic = 3006,
    /// The guest accessed memory outside its own linear memory — a genuine
    /// buffer overrun or null dereference in guest code.
    ///
    /// **Distinct from [`Self::MemoryLimitExceeded`] on purpose.** That code
    /// means "the guest asked for more memory than it was allowed"; this one
    /// means "the guest has a bug". Conflating them would send a developer
    /// hunting for a limit to raise when the real fix is a code change.
    /// **Remediation:** this is a guest bug — fix the indexing or pointer
    /// arithmetic. The backtrace names the faulting function.
    GuestOutOfBounds = 3007,

    // -- 4xxx: capability denials --------------------------------------------
    /// The requested capability is not granted by any configuration layer.
    /// **Remediation:** the error prints the exact stanza to add to
    /// `qqq.toml`, and `qqqai why <capability>` shows the full chain.
    CapabilityDenied = 4003,
    /// A capability was granted, but not for the specific parameter requested —
    /// e.g. an HTTP client grant for a host not on the allowlist.
    /// **Remediation:** the error names the granted set and the requested
    /// value, so the diff is obvious.
    CapabilityOutOfScope = 4001,
    /// An overlay attempted to **widen** a grant. Overlays may only narrow.
    /// **Remediation:** this is a configuration error, not a user error. Move
    /// the grant into `qqq.toml`.
    CapabilityWideningRefused = 4002,
    /// The guest requested a secret it was granted, but the secret value could
    /// not be used for the requested operation.
    /// **Remediation:** check the secret's format and the operation's
    /// requirements. The value is never disclosed.
    SecretUseFailed = 4004,
    /// A capability's runtime quota was exhausted (bytes written, requests
    /// made, tokens used).
    /// **Remediation:** raise the quota, or reduce usage. Retryable after the
    /// quota window resets.
    CapabilityQuotaExhausted = 4005,

    // -- 5xxx: package / registry --------------------------------------------
    /// An artifact's signature did not verify against the configured trust
    /// policy.
    /// **Remediation:** do not bypass this. Verify the publisher, or update the
    /// trust policy if the signer is legitimately new.
    SignatureVerificationFailed = 5002,
    /// The registry could not be reached.
    /// **Remediation:** retryable. Check connectivity or use `--offline`.
    RegistryUnreachable = 5001,
    /// The lockfile and the manifest disagree.
    /// **Remediation:** run `qqqai install` to re-resolve, or `--frozen` to
    /// fail rather than change anything.
    LockfileOutOfDate = 5003,
    /// No version satisfying the requirement exists.
    /// **Remediation:** the error lists available versions.
    VersionUnsatisfiable = 5004,
    /// A package's declared capabilities exceed what the policy allows.
    /// **Remediation:** the error prints the capability diff, so the escalation
    /// is visible before it is accepted.
    DependencyCapabilityEscalation = 5005,
    /// The content-addressed store is corrupt or a digest did not match.
    /// **Remediation:** `qqqai install --force` re-fetches. Report if it
    /// recurs — this indicates a registry or transport problem.
    StoreCorrupted = 5006,

    // -- 6xxx: host / infrastructure -----------------------------------------
    /// The instance pool has no free slot and the request was shed.
    /// **Remediation:** retryable; back off. Raise `limits.max_instances` or
    /// add hosts. The error reports pool occupancy.
    InstancePoolExhausted = 6001,
    /// The host could not bind its listener.
    /// **Remediation:** the error names the address and the OS error.
    ListenerBindFailed = 6002,
    /// A component could not be loaded from the AOT cache and fell back to
    /// compilation, which also failed.
    /// **Remediation:** the error names the cache key and the compile error.
    ComponentLoadFailed = 6003,
    /// An internal invariant was violated. Always a bug in QQQ.
    /// **Remediation:** **please report this.** The error carries a diagnostic
    /// bundle; the host is not compromised, but its state is not trustworthy.
    InternalInvariantViolated = 6004,
    /// The host ran out of a system resource (file descriptors, memory).
    /// **Remediation:** retryable after backoff; otherwise raise OS limits.
    HostResourceExhausted = 6005,

    // -- 7xxx: agent / protocol ----------------------------------------------
    /// An MCP tool call had arguments that failed schema validation.
    /// **Remediation:** the error names the argument and the expected type;
    /// `qqqai schema --command <tool>` prints the schema.
    McpArgumentInvalid = 7001,
    /// A schema was requested for a surface that does not exist.
    /// **Remediation:** `qqqai schema --all` lists every available surface.
    UnknownSchemaSurface = 7002,
    /// The agent protocol version is not supported by this host.
    /// **Remediation:** the error reports both versions.
    ProtocolVersionUnsupported = 7003,
}

impl ErrorCode {
    /// The class this code belongs to.
    #[must_use]
    pub const fn class(self) -> ErrorClass {
        match (self as u16) / 1000 {
            1 => ErrorClass::Build,
            2 => ErrorClass::Manifest,
            3 => ErrorClass::Trap,
            4 => ErrorClass::Capability,
            5 => ErrorClass::Package,
            6 => ErrorClass::Host,
            _ => ErrorClass::Agent,
        }
    }

    /// The numeric code, e.g. `4003`.
    #[must_use]
    pub const fn number(self) -> u16 {
        self as u16
    }

    /// The full stable identifier, e.g. `QQQ-4003`.
    ///
    /// This string is part of the machine contract. Agents match on it.
    #[must_use]
    pub fn id(self) -> String {
        format!("QQQ-{:04}", self.number())
    }

    /// The permanent documentation URL for this code.
    ///
    /// Proposal §8.3: every code has a stable docs URL. The URL shape is
    /// `https://qqq.codes/errors/QQQ-<nnnn>` and must never change shape.
    #[must_use]
    pub fn docs_url(self) -> String {
        format!("https://qqq.codes/errors/{}", self.id())
    }

    /// Whether a caller should consider retrying.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        self.class().is_retryable()
    }

    /// Every code, for schema generation and exhaustiveness tests.
    ///
    /// `qqqai schema --errors` iterates this. A round-trip test asserts that
    /// [`ErrorCode::from_number`] accepts every entry, so a new code cannot be
    /// added without satisfying the contract.
    #[must_use]
    pub const fn all() -> &'static [ErrorCode] {
        &[
            Self::CompilationFailed,
            Self::InvalidComponentArtifact,
            Self::MissingTarget,
            Self::WitInterfaceMismatch,
            Self::NonReproducibleBuild,
            Self::ManifestSyntaxInvalid,
            Self::ManifestSchemaViolation,
            Self::SecretUnresolvable,
            Self::CapabilityPathInvalid,
            Self::LimitOutOfRange,
            Self::RequiresFabric,
            Self::CapabilitySyntaxInvalid,
            Self::MemoryLimitExceeded,
            Self::FuelExhausted,
            Self::EpochDeadlineExceeded,
            Self::GuestTrap,
            Self::InvalidResourceHandle,
            Self::GuestPanic,
            Self::GuestOutOfBounds,
            Self::CapabilityOutOfScope,
            Self::CapabilityWideningRefused,
            Self::CapabilityDenied,
            Self::SecretUseFailed,
            Self::CapabilityQuotaExhausted,
            Self::RegistryUnreachable,
            Self::SignatureVerificationFailed,
            Self::LockfileOutOfDate,
            Self::VersionUnsatisfiable,
            Self::DependencyCapabilityEscalation,
            Self::StoreCorrupted,
            Self::InstancePoolExhausted,
            Self::ListenerBindFailed,
            Self::ComponentLoadFailed,
            Self::InternalInvariantViolated,
            Self::HostResourceExhausted,
            Self::McpArgumentInvalid,
            Self::UnknownSchemaSurface,
            Self::ProtocolVersionUnsupported,
        ]
    }

    /// Parse a numeric code back into an [`ErrorCode`].
    ///
    /// Returns `None` for codes that were never issued or have been retired.
    /// Callers must handle `None` rather than assuming every number is valid,
    /// because a future minor version may add codes this build does not know.
    #[must_use]
    pub const fn from_number(n: u16) -> Option<Self> {
        let mut i = 0;
        while i < Self::all().len() {
            let c = Self::all()[i];
            if c as u16 == n {
                return Some(c);
            }
            i += 1;
        }
        None
    }

    /// Parse a full identifier such as `QQQ-4003` (case-insensitive on the
    /// prefix, tolerant of surrounding whitespace).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let rest = s
            .strip_prefix("QQQ-")
            .or_else(|| s.strip_prefix("qqq-"))
            .or_else(|| s.strip_prefix("Qqq-"))?;
        // Reject `QQQ-4_003` style noise; digits only.
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        rest.parse::<u16>().ok().and_then(Self::from_number)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.id())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: serde::Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown QQQ error code: {s}")))
    }
}

/// The canonical error type for every QQQ crate.
///
/// # Shape
///
/// An [`Error`] is deliberately **structured**, not a message. The fields are
/// the machine contract from Proposal §8.3:
///
/// * `code` — stable identifier, safe to match on
/// * `message` — one human sentence, no jargon, **unstable** (do not parse)
/// * `cause` — the causal chain, when known
/// * `remediation` — what to do, as a runnable step where possible
/// * `context` — ordered key/value pairs describing *where* it happened
///
/// # Why `message` is explicitly unstable
///
/// Because it will change: wording improves, localisation may arrive, and a
/// clearer explanation is always worth shipping. An agent that parses the
/// message is making a mistake we should not encourage. The doc comment says so
/// because the doc comment is what an AI reads first.
///
/// # Naming note
///
/// The crate defines a `Result<T>` alias in [`crate::error`], which shadows
/// `std::result::Result` inside this module. Internal code therefore writes
/// `std::result::Result<T, E>` explicitly where `E` is not [`Error`] — this is
/// a deliberate readability trade, and the alias is re-exported at the crate
/// root where consumers actually want it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Error {
    /// The stable machine-readable code.
    pub code: ErrorCode,
    /// A single human sentence. **Do not parse this.**
    pub message: String,
    /// The causal chain, outermost first. Empty when unknown.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cause: Vec<String>,
    /// An actionable next step. `None` when the fix is genuinely unclear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Ordered context: where it happened, and with what inputs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<(String, String)>,
}

impl Error {
    /// Construct an error from a code and a human sentence.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            cause: Vec::new(),
            remediation: None,
            context: Vec::new(),
        }
    }

    /// Attach a remediation step.
    #[must_use]
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Attach ordered context.
    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.push((key.into(), value.into()));
        self
    }

    /// Append a cause.
    #[must_use]
    pub fn with_cause(mut self, cause: impl Into<String>) -> Self {
        self.cause.push(cause.into());
        self
    }

    /// The stable identifier, e.g. `QQQ-4003`.
    #[must_use]
    pub fn id(&self) -> String {
        self.code.id()
    }

    /// The permanent docs URL for this error's code.
    #[must_use]
    pub fn docs_url(&self) -> String {
        self.code.docs_url()
    }

    /// Whether retrying the same operation may succeed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.code.is_retryable()
    }

    /// Render the human-facing block mandated by Proposal §12.2.
    ///
    /// The order is fixed and load-bearing: *what happened*, the code and docs
    /// URL, *why*, *the fix*. Error output is a product surface, and an
    /// agent-facing benchmark is run against it.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::new();
        // What happened.
        let _ = writeln!(out, "error[{}]: {}", self.id(), self.message);
        // Why.
        for c in &self.cause {
            let _ = writeln!(out, "  caused by: {c}");
        }
        // Where.
        if !self.context.is_empty() {
            let _ = writeln!(out);
            for (k, v) in &self.context {
                let _ = writeln!(out, "  {k}: {v}");
            }
        }
        // The fix.
        if let Some(r) = &self.remediation {
            let _ = writeln!(out);
            let _ = writeln!(out, "  → {r}");
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "  Docs: {}", self.docs_url());
        out
    }
}

impl fmt::Display for Error {
    /// Displays as `<CODE>: <message>`.
    ///
    /// Deliberately terse so it composes inside `anyhow`-style chains without
    /// producing multi-line noise. Use [`Error::render`] for the full block.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.id(), self.message)
    }
}

impl std::error::Error for Error {}

/// The canonical result type for every QQQ crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Convenience constructor mirroring `format!`.
///
/// ```ignore
/// return Err(qqq_err!(ErrorCode::MissingTarget, "target {} not installed", t));
/// ```
#[macro_export]
macro_rules! qqq_err {
    ($code:expr, $($arg:tt)*) => {
        $crate::Error::new($code, format!($($arg)*))
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The code table must be internally consistent. This is the test that
    /// stops a new code from being added incorrectly.
    #[test]
    fn every_code_round_trips() {
        for &c in ErrorCode::all() {
            let n = c.number();
            assert_eq!(
                ErrorCode::from_number(n),
                Some(c),
                "code {c} did not round-trip from number {n}"
            );
            assert_eq!(
                ErrorCode::parse(&c.id()),
                Some(c),
                "code {c} did not round-trip from id {}",
                c.id()
            );
        }
    }

    /// The thousands digit must agree with the declared class. A mismatch would
    /// mean `QQQ-2400` claiming to be a manifest error.
    #[test]
    fn class_matches_numeric_range() {
        for &c in ErrorCode::all() {
            let expected = match c.number() / 1000 {
                1 => ErrorClass::Build,
                2 => ErrorClass::Manifest,
                3 => ErrorClass::Trap,
                4 => ErrorClass::Capability,
                5 => ErrorClass::Package,
                6 => ErrorClass::Host,
                7 => ErrorClass::Agent,
                other => panic!("code {c} has out-of-range class digit {other}"),
            };
            assert_eq!(c.class(), expected, "class mismatch for {c}");
        }
    }

    /// Codes must be unique. A duplicate silently breaks log correlation.
    #[test]
    fn codes_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for &c in ErrorCode::all() {
            assert!(seen.insert(c.number()), "duplicate error code {c}");
        }
    }

    /// Codes must be sorted, so review diffs are readable and `all()` is
    /// obviously complete at a glance.
    #[test]
    fn codes_are_sorted() {
        let nums: Vec<u16> = ErrorCode::all().iter().map(|c| c.number()).collect();
        let mut sorted = nums.clone();
        sorted.sort_unstable();
        assert_eq!(nums, sorted, "ErrorCode::all() is not in numeric order");
    }

    /// Every code must occupy a slot within its class's 1..=999 range.
    #[test]
    fn codes_stay_within_class_range() {
        for &c in ErrorCode::all() {
            let within = c.number() % 1000;
            assert!(
                (1..=999).contains(&within),
                "code {c} has out-of-range suffix {within}"
            );
        }
    }

    #[test]
    fn id_uses_four_digit_padding() {
        assert_eq!(ErrorCode::CapabilityDenied.id(), "QQQ-4003");
        assert_eq!(ErrorCode::CompilationFailed.id(), "QQQ-1001");
        assert_eq!(ErrorCode::McpArgumentInvalid.id(), "QQQ-7001");
    }

    #[test]
    fn docs_url_shape_is_stable() {
        assert_eq!(
            ErrorCode::CapabilityDenied.docs_url(),
            "https://qqq.codes/errors/QQQ-4003"
        );
    }

    /// The documented examples in Proposal §8.3 must actually exist.
    #[test]
    fn proposal_documented_examples_resolve() {
        assert_eq!(
            ErrorCode::parse("QQQ-1004"),
            Some(ErrorCode::WitInterfaceMismatch)
        );
        assert_eq!(
            ErrorCode::parse("QQQ-2007"),
            Some(ErrorCode::CapabilitySyntaxInvalid)
        );
        assert_eq!(
            ErrorCode::parse("QQQ-3001"),
            Some(ErrorCode::MemoryLimitExceeded)
        );
        assert_eq!(
            ErrorCode::parse("QQQ-4003"),
            Some(ErrorCode::CapabilityDenied)
        );
        assert_eq!(
            ErrorCode::parse("QQQ-5002"),
            Some(ErrorCode::SignatureVerificationFailed)
        );
        assert_eq!(
            ErrorCode::parse("QQQ-6001"),
            Some(ErrorCode::InstancePoolExhausted)
        );
        assert_eq!(
            ErrorCode::parse("QQQ-7001"),
            Some(ErrorCode::McpArgumentInvalid)
        );
    }

    #[test]
    fn parse_rejects_malformed_input() {
        for bad in [
            "",
            "QQQ-",
            "QQQ-abc",
            "4003",
            "QQQ-40O3",   // letter O, not zero
            "QQQ-4003x",
            "QQQ-4_003",
            "XQQ-4003",
        ] {
            assert_eq!(ErrorCode::parse(bad), None, "should have rejected {bad:?}");
        }
    }

    #[test]
    fn parse_rejects_unknown_but_wellformed_codes() {
        // 4999 is well-formed but has never been issued.
        assert_eq!(ErrorCode::parse("QQQ-4999"), None);
        assert_eq!(ErrorCode::from_number(9999), None);
    }

    #[test]
    fn parse_tolerates_whitespace_and_case() {
        assert_eq!(ErrorCode::parse("  qqq-4003  "), Some(ErrorCode::CapabilityDenied));
        assert_eq!(ErrorCode::parse("Qqq-4003"), Some(ErrorCode::CapabilityDenied));
    }

    #[test]
    fn serializes_as_the_stable_id() {
        let e = Error::new(ErrorCode::CapabilityDenied, "sql.query not granted")
            .with_remediation("add [[capabilities.sql]] to qqq.toml")
            .with_context("database", "orders");
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["code"], "QQQ-4003");
        assert_eq!(j["message"], "sql.query not granted");
        assert_eq!(j["context"][0][0], "database");
    }

    #[test]
    fn deserializes_from_the_stable_id() {
        let e: Error = serde_json::from_str(r#"{"code":"QQQ-3002","message":"out of fuel"}"#)
            .expect("should parse");
        assert_eq!(e.code, ErrorCode::FuelExhausted);
        assert!(e.cause.is_empty());
        assert!(e.remediation.is_none());
    }

    #[test]
    fn deserialize_rejects_unknown_code() {
        let r: std::result::Result<Error, serde_json::Error> =
            serde_json::from_str(r#"{"code":"QQQ-9999","message":"?"}"#);
        assert!(r.is_err(), "an unknown code must not deserialize silently");
    }

    /// The rendered block must contain all four mandated elements in order.
    #[test]
    fn render_follows_the_mandated_shape() {
        let e = Error::new(ErrorCode::CapabilityDenied, "capability denied")
            .with_cause("no layer grants sql.orders")
            .with_remediation("add [[capabilities.sql]] to qqq.toml")
            .with_context("component", "orders-api");
        let out = e.render();

        let i_head = out.find("error[QQQ-4003]").expect("head");
        let i_cause = out.find("caused by:").expect("cause");
        let i_ctx = out.find("component:").expect("context");
        let i_fix = out.find("→").expect("remediation");
        let i_docs = out.find("Docs:").expect("docs url");

        assert!(
            i_head < i_cause && i_cause < i_ctx && i_ctx < i_fix && i_fix < i_docs,
            "render() elements are out of order:\n{out}"
        );
    }

    #[test]
    fn retryability_is_class_derived() {
        // Deterministic classes never retry.
        assert!(!ErrorCode::CapabilityDenied.is_retryable());
        assert!(!ErrorCode::ManifestSchemaViolation.is_retryable());
        assert!(!ErrorCode::McpArgumentInvalid.is_retryable());
        assert!(!ErrorCode::CompilationFailed.is_retryable());
        assert!(!ErrorCode::GuestTrap.is_retryable());
        // Transient classes do.
        assert!(ErrorCode::InstancePoolExhausted.is_retryable());
        assert!(ErrorCode::RegistryUnreachable.is_retryable());
    }

    #[test]
    fn display_is_terse_and_single_line() {
        let e = Error::new(ErrorCode::FuelExhausted, "guest ran out of fuel")
            .with_remediation("raise limits.fuel");
        let s = e.to_string();
        assert_eq!(s, "QQQ-3002: guest ran out of fuel");
        assert!(!s.contains('\n'), "Display must stay single-line");
    }

    #[test]
    fn class_names_are_stable_strings() {
        assert_eq!(ErrorClass::Capability.as_str(), "capability");
        assert_eq!(ErrorClass::Trap.as_str(), "trap");
        assert_eq!(ErrorClass::Agent.as_str(), "agent");
    }

    #[test]
    fn classes_all_distinct() {
        use std::collections::BTreeSet;
        let digits: BTreeSet<u16> = [
            ErrorClass::Build,
            ErrorClass::Manifest,
            ErrorClass::Trap,
            ErrorClass::Capability,
            ErrorClass::Package,
            ErrorClass::Host,
            ErrorClass::Agent,
        ]
        .iter()
        .map(|c| c.digit())
        .collect();
        assert_eq!(digits.len(), 7, "two classes share a thousands digit");
    }
}
