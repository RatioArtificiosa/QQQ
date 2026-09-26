// SPDX-License-Identifier: Apache-2.0

//! Pipeline step 2: **NORMALIZE** (Proposal §6.2, Checklist `CAP-003`).
//!
//! Turns a syntactically valid manifest into a *resolved configuration* whose
//! values are concrete: paths are canonical and absolute, host patterns are
//! parsed, secret references are checked against the environment, and
//! allowlists are deduplicated and sorted.
//!
//! # Why this is a separate step from PARSE
//!
//! PARSE is pure: the same `qqq.toml` always yields the same `Manifest`. This
//! step touches the **environment** — the filesystem and the process
//! environment — so it can only run on the host where the component will
//! actually execute. Separating them means:
//!
//! * `qqqai build` on a CI machine can validate a manifest without needing the
//!   production paths to exist.
//! * `qqqai deploy` fails loudly on the *target* host, naming the missing path,
//!   rather than at runtime on the first request.
//!
//! # Path canonicalization is a security control
//!
//! A grant of `/var/lib/orders` must not be satisfied by `/var/lib/orders/../../etc`.
//! Canonicalization resolves `..`, symlinks and relative components **once, at
//! bind time**, and the resulting absolute path is what the host compares
//! against. Doing this at call time instead would be both slower and more
//! error-prone — and any disagreement between the check and the use is a
//! vulnerability class.
//!
//! # Secrets are referenced, never read
//!
//! Normalization **checks that a named secret exists**; it never reads or
//! stores the value. The value is fetched by the host at the moment of use,
//! inside `qqq:secrets` (Proposal §6.3), so it never enters guest memory and
//! never appears in a config struct that might be logged or serialized.
//!
//! See Proposal §5.3, §6.2, §6.3.

use std::collections::BTreeMap;
use std::fmt;

use crate::capability::Capability;
use crate::manifest::{ByteSize, FsMode, Manifest};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A manifest could not be normalized against this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizeError {
    /// A granted filesystem path does not exist.
    ///
    /// Deliberately a **hard error**, not a warning: a component granted a
    /// path that is absent will fail on first use, and finding out at bind
    /// time is worth far more than finding out under production load.
    PathMissing {
        /// The path as written in the manifest.
        declared: String,
    },
    /// A granted path exists but could not be canonicalized.
    PathUnresolvable {
        /// The path as written.
        declared: String,
        /// Why canonicalization failed.
        reason: String,
    },
    /// A granted path exists but is not a directory, where one is required.
    PathNotADirectory {
        /// The offending path.
        declared: String,
        /// What it actually is.
        found: String,
    },
    /// A named secret is not present in the host environment.
    ///
    /// The message names the *variable*, never a value.
    SecretMissing {
        /// The secret's logical name as referenced in the manifest.
        name: String,
        /// The environment variable or source that was consulted.
        source: String,
    },
    /// A host pattern in an allowlist could not be parsed.
    InvalidHostPattern {
        /// The offending pattern.
        pattern: String,
        /// Why it is invalid.
        reason: String,
    },
    /// The normalized configuration contradicts itself — for example the same
    /// path granted twice with different modes, which is ambiguous and would
    /// make the effective authority depend on iteration order.
    ConflictingGrants {
        /// The path or name that was granted twice.
        subject: String,
        /// The first grant.
        first: String,
        /// The second, conflicting grant.
        second: String,
    },
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathMissing { declared } => {
                write!(f, "granted path `{declared}` does not exist on this host")
            }
            Self::PathUnresolvable { declared, reason } => {
                write!(
                    f,
                    "granted path `{declared}` could not be resolved: {reason}"
                )
            }
            Self::PathNotADirectory { declared, found } => write!(
                f,
                "granted path `{declared}` must be a directory, but is a {found}"
            ),
            Self::SecretMissing { name, source } => {
                write!(f, "secret `{name}` is not available (consulted {source})")
            }
            Self::InvalidHostPattern { pattern, reason } => {
                write!(f, "invalid host pattern `{pattern}`: {reason}")
            }
            Self::ConflictingGrants {
                subject,
                first,
                second,
            } => write!(
                f,
                "`{subject}` is granted twice with conflicting scopes: {first} vs {second}"
            ),
        }
    }
}

impl std::error::Error for NormalizeError {}

impl NormalizeError {
    /// The stable error code this maps to.
    #[must_use]
    pub const fn code(&self) -> qqq_core::ErrorCode {
        match self {
            Self::PathMissing { .. }
            | Self::PathNotADirectory { .. }
            | Self::PathUnresolvable { .. } => qqq_core::ErrorCode::CapabilityPathInvalid,
            Self::SecretMissing { .. } => qqq_core::ErrorCode::SecretUnresolvable,
            Self::InvalidHostPattern { .. } => qqq_core::ErrorCode::CapabilitySyntaxInvalid,
            Self::ConflictingGrants { .. } => qqq_core::ErrorCode::ManifestSchemaViolation,
        }
    }

    /// Convert to the shared error type, preserving the code and adding a fix.
    #[must_use]
    pub fn to_error(&self) -> qqq_core::Error {
        let e = qqq_core::Error::new(self.code(), self.to_string());
        let e = match self {
            Self::PathMissing { declared } => e
                .with_context("path", declared.clone())
                .with_remediation(format!(
                    "create `{declared}` on this host, or correct the path in qqq.toml"
                )),
            Self::SecretMissing { name, source } => e
                .with_context("secret", name.clone())
                .with_remediation(format!("set {source} in the host environment")),
            Self::PathUnresolvable { declared, .. } => e
                .with_context("path", declared.clone())
                .with_remediation("check permissions on the path and its parents"),
            Self::PathNotADirectory { declared, .. } => e
                .with_context("path", declared.clone())
                .with_remediation("grant a directory, or remove the entry if a file was intended"),
            Self::InvalidHostPattern { pattern, .. } => e
                .with_context("pattern", pattern.clone())
                .with_remediation("use `host` or `host:port`; wildcards are `*.example.com`"),
            Self::ConflictingGrants { subject, .. } => e
                .with_context("subject", subject.clone())
                .with_remediation("grant each path once, with a single mode"),
        };
        e
    }
}

// ---------------------------------------------------------------------------
// Host patterns
// ---------------------------------------------------------------------------

/// A parsed outbound-host pattern such as `api.stripe.com:443` or
/// `*.internal.example.com:8443`.
///
/// # Matching semantics
///
/// * A pattern **with a port** must match the port exactly.
/// * A pattern **without a port** matches any port.
/// * A `*.` prefix matches one or more labels, never the bare domain:
///   `*.example.com` matches `a.example.com` and `a.b.example.com`, but **not**
///   `example.com`. This is deliberate: the common misreading — that `*.x`
///   includes `x` — silently grants a host the user did not intend.
/// * Matching is case-insensitive and ASCII-only, because DNS is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostPattern {
    /// The lowercased host, or `*` for a bare wildcard.
    host: String,
    /// Whether the host begins with the `*.` wildcard.
    wildcard: bool,
    /// The required port, if the pattern specified one.
    port: Option<u16>,
    /// The pattern exactly as written, for error messages and the `why` chain.
    original: String,
}

impl HostPattern {
    /// Parse a pattern.
    ///
    /// # Errors
    ///
    /// Returns a reason string when the pattern is malformed.
    pub fn parse(s: &str) -> Result<Self, String> {
        let original = s.to_owned();
        let t = s.trim();
        if t.is_empty() {
            return Err("empty pattern".to_owned());
        }
        if t.contains("://") {
            return Err("must be `host` or `host:port`, not a URL".to_owned());
        }
        if t.contains('/') {
            return Err("must not contain a path".to_owned());
        }
        if t.contains(char::is_whitespace) {
            return Err("must not contain whitespace".to_owned());
        }

        // Split the port. IPv6 literals are bracketed, so `]` is the tell.
        let (host_part, port) = if let Some(rest) = t.strip_prefix('[') {
            // `[::1]:8080` or `[::1]`
            let (inner, after) = rest
                .split_once(']')
                .ok_or_else(|| "unterminated IPv6 literal".to_owned())?;
            let port = match after.strip_prefix(':') {
                Some(p) => Some(parse_port(p)?),
                None if after.is_empty() => None,
                None => return Err("unexpected characters after IPv6 literal".to_owned()),
            };
            (inner.to_owned(), port)
        } else if let Some((h, p)) = t.rsplit_once(':') {
            // Guard against `a:b:c` which is neither a host:port nor IPv6.
            if h.contains(':') {
                return Err("ambiguous pattern; bracket IPv6 literals as `[::1]:port`".to_owned());
            }
            (h.to_owned(), Some(parse_port(p)?))
        } else {
            (t.to_owned(), None)
        };

        let host_lower = host_part.to_ascii_lowercase();
        // An IPv6 literal is recognised by containing a colon. It is stored
        // verbatim (lowercased) and compared by exact equality, because there
        // is no meaningful wildcard semantics for an address literal.
        let is_ipv6 = host_lower.contains(':');
        let wildcard = !is_ipv6 && host_lower.starts_with("*.");
        let bare = if is_ipv6 {
            host_lower.clone()
        } else if wildcard {
            host_lower.trim_start_matches("*.").to_owned()
        } else if host_lower == "*" {
            // A bare `*` is rejected: it is an unbounded egress grant and the
            // entire point of an allowlist is that it is bounded.
            return Err(
                "a bare `*` is not permitted; name the host or use `*.example.com`".to_owned(),
            );
        } else {
            host_lower.clone()
        };

        if bare.is_empty() {
            return Err("host part is empty".to_owned());
        }
        // DNS names use a restricted alphabet; IPv6 literals use hex and
        // colons. Validate each against its own rule rather than one loose rule
        // that would accept neither correctly.
        let chars_ok = if is_ipv6 {
            bare.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
        } else {
            bare.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        };
        if !chars_ok {
            return Err(format!("host `{bare}` contains invalid characters"));
        }
        if is_ipv6 {
            // `::1` and `::` legitimately begin with a colon — that is IPv6
            // shorthand for a run of zero groups — so a leading colon is NOT
            // an error. What is invalid is three or more consecutive colons,
            // which no IPv6 form permits, or a lone colon.
            if bare.contains(":::") || bare == ":" {
                return Err(format!("`{bare}` is not a valid IPv6 literal"));
            }
        } else {
            if bare.starts_with('.') || bare.ends_with('.') {
                return Err("host must not begin or end with a dot".to_owned());
            }
            if bare.contains("..") {
                return Err("host must not contain an empty label".to_owned());
            }
        }

        Ok(Self {
            host: host_lower,
            wildcard,
            port,
            original,
        })
    }

    /// Whether this pattern permits connecting to `host:port`.
    #[must_use]
    pub fn matches(&self, host: &str, port: u16) -> bool {
        if let Some(required) = self.port {
            if required != port {
                return false;
            }
        }
        let host = host.to_ascii_lowercase();
        if self.wildcard {
            // `*.example.com` -> suffix `.example.com`, and the host must have
            // at least one label *before* the suffix.
            let bare = self.host.trim_start_matches("*.");
            host.len() > bare.len() + 1 && host.ends_with(bare) && {
                let prefix_len = host.len() - bare.len();
                host.as_bytes()[prefix_len - 1] == b'.'
            }
        } else {
            host == self.host
        }
    }

    /// The pattern as the user wrote it.
    #[must_use]
    pub fn as_written(&self) -> &str {
        &self.original
    }

    /// Whether the pattern uses a wildcard.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// The required port, if any.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }
}

fn parse_port(s: &str) -> Result<u16, String> {
    if s.is_empty() {
        return Err("port is empty".to_owned());
    }
    s.parse::<u16>()
        .map_err(|_| format!("`{s}` is not a valid port (0-65535)"))
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.original)
    }
}

// ---------------------------------------------------------------------------
// Secret references
// ---------------------------------------------------------------------------

/// A reference to a secret, resolved without reading its value.
///
/// The manifest writes `env:JWT_SIGNING_KEY`; this type records *which*
/// environment variable that is, so the deployment can resolve it **once**, before the runtime
/// starts.
///
/// # Why this no longer says "at the moment of use"
///
/// It used to: *"so the host can fetch it at the moment of use inside `qqq:secrets` — never storing
/// it in configuration."* **§2.5 forbids that** — *"No hidden global state — No environment-variable
/// reads, no CWD dependencies, no implicit config discovery"* — and `qqq-host`'s `host_secrets`
/// says so explicitly: *"It does not resolve secrets from the environment … would read the
/// environment on every call, which §2.5 forbids … this module touches no ambient state."*
///
/// So two doc comments described opposite mechanisms, and the one on the type that names the
/// variable was the wrong one. A reader following it would have implemented a per-call environment
/// read and believed they were implementing the documented design (`§O-304`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecretRef {
    /// The logical name the guest uses, e.g. `JWT_SIGNING_KEY`.
    pub logical_name: String,
    /// The environment variable that will supply it.
    pub env_var: String,
}

impl SecretRef {
    /// Parse a `scheme:name` reference.
    ///
    /// Only `env:` is supported in V1. A `file:` or `vault:` scheme would be
    /// easy to add, but each raises questions (who reads it? what permissions?)
    /// that deserve their own design rather than a silent default.
    ///
    /// # Errors
    ///
    /// Returns a reason string when the reference is malformed.
    pub fn parse(s: &str) -> Result<Self, String> {
        let t = s.trim();
        let (scheme, name) = t
            .split_once(':')
            .ok_or_else(|| "expected `env:NAME`".to_owned())?;
        if name.is_empty() {
            return Err("secret name is empty".to_owned());
        }
        match scheme {
            "env" => {
                if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return Err(format!(
                        "environment variable `{name}` must contain only A-Z, 0-9 and _"
                    ));
                }
                Ok(Self {
                    logical_name: name.to_owned(),
                    env_var: name.to_owned(),
                })
            }
            other => Err(format!(
                "unknown secret scheme `{other}`; only `env:` is supported"
            )),
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "env:{}", self.env_var)
    }
}

// ---------------------------------------------------------------------------
// Normalized configuration
// ---------------------------------------------------------------------------

/// A canonical, host-resolved filesystem grant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FsGrant {
    /// The canonical absolute path, with `..` and symlinks resolved.
    pub canonical_path: String,
    /// The path as the user wrote it, for error messages and the why chain.
    pub declared_path: String,
    /// The resolved access mode.
    pub mode: FsMode,
    /// The resolved quota in bytes, if any.
    pub quota_bytes: Option<u64>,
}

/// The normalized configuration, ready for resolution and binding.
///
/// All values are concrete. There are no patterns left to expand and no
/// references left to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    /// Outbound HTTP patterns, sorted and deduplicated.
    pub http_client: Vec<HostPattern>,
    /// Whether inbound HTTP is permitted.
    pub http_server: bool,
    /// Filesystem grants, sorted by canonical path.
    pub fs: Vec<FsGrant>,
    /// DNS names the guest may resolve, sorted and deduplicated.
    pub dns: Vec<String>,
    /// Environment variables the guest may read, sorted and deduplicated.
    pub env: Vec<String>,
    /// Secret references, sorted by logical name.
    pub secrets: Vec<SecretRef>,
    /// Capabilities the manifest declared, as a convenience for the caller.
    pub declared: Vec<Capability>,
}

/// The environment this normalization runs against.
///
/// Injected rather than read directly so that normalization is **testable**
/// without touching the real filesystem or process environment — which is also
/// what lets `qqqai build` validate a manifest for a *different* target host.
pub trait HostEnv {
    /// Whether a path exists and is a directory.
    fn is_dir(&self, path: &str) -> bool;
    /// Whether a path exists (as anything).
    fn exists(&self, path: &str) -> bool;
    /// Canonicalize a path to an absolute, symlink-resolved form.
    ///
    /// # Errors
    /// Returns the OS reason on failure.
    fn canonicalize(&self, path: &str) -> Result<String, String>;
    /// Whether an environment variable is set.
    ///
    /// Returning a `bool` rather than the value is deliberate: normalization
    /// must be able to verify a secret exists **without ever touching its
    /// value**, so a bug here cannot leak one into a log line.
    fn has_env(&self, var: &str) -> bool;
}

/// A [`HostEnv`] that touches the real filesystem and process environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealEnv;

impl HostEnv for RealEnv {
    fn is_dir(&self, path: &str) -> bool {
        std::path::Path::new(path).is_dir()
    }
    fn exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }
    fn canonicalize(&self, path: &str) -> Result<String, String> {
        std::fs::canonicalize(path)
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(|e| e.to_string())
    }
    fn has_env(&self, var: &str) -> bool {
        std::env::var_os(var).is_some()
    }
}

impl Normalized {
    /// Normalize a manifest against a host environment.
    ///
    /// # Errors
    ///
    /// Returns [`NormalizeError`] naming the offending path, secret or pattern.
    pub fn from_manifest(manifest: &Manifest, env: &impl HostEnv) -> Result<Self, NormalizeError> {
        let (http_server, http_client) = normalize_http(manifest)?;
        let fs = normalize_fs(manifest, env)?;
        let dns = normalize_list(
            manifest
                .capabilities
                .dns
                .as_ref()
                .map(|d| d.resolve.as_slice()),
            true,
        );
        let env_vars = normalize_list(
            manifest
                .capabilities
                .env
                .as_ref()
                .map(|e| e.allow.as_slice()),
            false,
        );
        let secrets = normalize_secrets(manifest, env)?;

        Ok(Self {
            http_client,
            http_server,
            fs,
            dns,
            env: env_vars,
            secrets,
            declared: manifest.declared_capabilities(),
        })
    }

    /// Whether a host:port pair is permitted by the HTTP client allowlist.
    ///
    /// This is the call-time check. It is deliberately a method on the
    /// *normalized* configuration rather than on the manifest, so it can never
    /// accidentally match against an unexpanded pattern.
    #[must_use]
    pub fn http_client_allows(&self, host: &str, port: u16) -> bool {
        self.http_client.iter().any(|p| p.matches(host, port))
    }

    /// Whether a path is inside a granted filesystem root, with sufficient mode.
    ///
    /// Used as a **defence-in-depth re-check** at call time (Proposal §4.4 step
    /// 11). The primary enforcement is that the guest only ever holds a handle
    /// to a preopened directory; this catches a host bug that mis-built the
    /// preopen table.
    ///
    /// # Semantics
    ///
    /// A grant satisfies a request when the path is contained in the grant's
    /// root **and** the grant's mode covers every right the request needs:
    ///
    /// | Grant | Request `read` | Request `write` |
    /// |---|---|---|
    /// | `read-only` | ✅ | ❌ |
    /// | `append-only` | ❌ | ✅ |
    /// | `read-write` | ✅ | ✅ |
    ///
    /// The comparison is on the *rights*, not on the mode enum's ordering, so
    /// a future mode added to `FsMode` cannot silently inherit permissive
    /// behaviour — it must be taught to `covers` explicitly.
    #[must_use]
    pub fn fs_allows(&self, canonical_path: &str, requested: FsMode) -> bool {
        self.fs
            .iter()
            .any(|g| path_is_within(canonical_path, &g.canonical_path) && g.mode.covers(requested))
    }

    /// Whether an environment variable may be read.
    #[must_use]
    pub fn env_allows(&self, var: &str) -> bool {
        self.env.iter().any(|v| v == var)
    }

    /// Whether a DNS name may be resolved.
    #[must_use]
    pub fn dns_allows(&self, name: &str) -> bool {
        let n = name.trim().to_ascii_lowercase();
        self.dns.iter().any(|d| d == &n)
    }

    /// Look up a secret by its logical name, returning the environment
    /// variable to fetch it from — never the value.
    #[must_use]
    pub fn secret_source(&self, logical_name: &str) -> Option<&str> {
        self.secrets
            .iter()
            .find(|s| s.logical_name == logical_name)
            .map(|s| s.env_var.as_str())
    }

    /// A summary suitable for the `qqqai audit` and `qqqai caps` surfaces.
    #[must_use]
    pub fn summary(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        m.insert("http.server".to_owned(), usize::from(self.http_server));
        m.insert("http.client".to_owned(), self.http_client.len());
        m.insert("fs".to_owned(), self.fs.len());
        m.insert("dns".to_owned(), self.dns.len());
        m.insert("env".to_owned(), self.env.len());
        m.insert("secrets".to_owned(), self.secrets.len());
        m
    }
}

// ---------------------------------------------------------------------------
// Normalization steps, one per capability family
// ---------------------------------------------------------------------------

/// Parse and canonicalize the HTTP capability.
fn normalize_http(manifest: &Manifest) -> Result<(bool, Vec<HostPattern>), NormalizeError> {
    let Some(h) = &manifest.capabilities.http else {
        return Ok((false, Vec::new()));
    };
    let mut patterns = Vec::with_capacity(h.client.len());
    for p in &h.client {
        patterns.push(HostPattern::parse(p).map_err(|reason| {
            NormalizeError::InvalidHostPattern {
                pattern: p.clone(),
                reason,
            }
        })?);
    }
    patterns.sort();
    patterns.dedup();
    Ok((h.server, patterns))
}

/// Resolve filesystem grants against the host, rejecting ambiguous authority.
///
/// Every path is checked to exist, confirmed to be a directory, and
/// canonicalized. The canonical form is what the host will enforce against,
/// so `..` traversal and symlinks are neutralized here rather than at call
/// time — where any disagreement between the check and the use would be a
/// vulnerability.
fn normalize_fs(manifest: &Manifest, env: &impl HostEnv) -> Result<Vec<FsGrant>, NormalizeError> {
    let mut fs = Vec::with_capacity(manifest.capabilities.fs.len());
    for entry in &manifest.capabilities.fs {
        let declared_path = entry.path.clone();

        if !env.exists(&declared_path) {
            return Err(NormalizeError::PathMissing {
                declared: declared_path,
            });
        }
        if !env.is_dir(&declared_path) {
            return Err(NormalizeError::PathNotADirectory {
                declared: declared_path,
                found: "file".to_owned(),
            });
        }
        let canonical_path = env.canonicalize(&declared_path).map_err(|reason| {
            NormalizeError::PathUnresolvable {
                declared: declared_path.clone(),
                reason,
            }
        })?;

        let quota_bytes = match &entry.quota {
            Some(q) => Some(
                ByteSize::parse(q)
                    .map_err(|reason| NormalizeError::InvalidHostPattern {
                        pattern: q.clone(),
                        reason: format!("invalid quota: {reason}"),
                    })?
                    .as_bytes(),
            ),
            None => None,
        };

        fs.push(FsGrant {
            canonical_path,
            declared_path,
            mode: entry.mode,
            quota_bytes,
        });
    }

    // Reject the same canonical path granted twice with different modes: the
    // effective authority would otherwise depend on iteration order, which is
    // exactly the ambiguity a security model must not have.
    fs.sort();
    for pair in fs.windows(2) {
        if pair[0].canonical_path == pair[1].canonical_path && pair[0].mode != pair[1].mode {
            return Err(NormalizeError::ConflictingGrants {
                subject: pair[0].canonical_path.clone(),
                first: pair[0].mode.to_string(),
                second: pair[1].mode.to_string(),
            });
        }
    }
    fs.dedup_by(|a, b| a.canonical_path == b.canonical_path && a.mode == b.mode);
    Ok(fs)
}

/// Trim, optionally lowercase, sort and deduplicate a string allowlist.
///
/// DNS names are case-insensitive per RFC 4343 so they are normalized to
/// lowercase; environment variable names are case-sensitive on POSIX so they
/// are not.
fn normalize_list(items: Option<&[String]>, lowercase: bool) -> Vec<String> {
    let Some(items) = items else {
        return Vec::new();
    };
    let mut out: Vec<String> = items
        .iter()
        .map(|s| {
            let t = s.trim();
            if lowercase {
                t.to_ascii_lowercase()
            } else {
                t.to_owned()
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Verify every referenced secret exists, **without reading a value**.
///
/// The `HostEnv` interface deliberately exposes only `has_env`, never a value
/// getter, so a bug in this function cannot leak a secret into configuration,
/// a log line, or a serialized struct.
fn normalize_secrets(
    manifest: &Manifest,
    env: &impl HostEnv,
) -> Result<Vec<SecretRef>, NormalizeError> {
    let Some(crypto) = &manifest.capabilities.crypto else {
        return Ok(Vec::new());
    };
    let mut secrets = Vec::with_capacity(crypto.secrets.len());
    for s in &crypto.secrets {
        let r = SecretRef::parse(s).map_err(|reason| NormalizeError::InvalidHostPattern {
            pattern: s.clone(),
            reason,
        })?;
        if !env.has_env(&r.env_var) {
            return Err(NormalizeError::SecretMissing {
                name: r.logical_name.clone(),
                source: format!("environment variable {}", r.env_var),
            });
        }
        secrets.push(r);
    }
    secrets.sort();
    secrets.dedup();
    Ok(secrets)
}

/// Whether `candidate` is `root` or lies beneath it.
///
/// Comparison is component-wise rather than a raw prefix match, so
/// `/var/lib/orders-evil` is **not** considered inside `/var/lib/orders` — the
/// classic prefix bug.
///
/// # Traversal is rejected here, not assumed away
///
/// This function used to document *"Operates on already-canonicalized absolute
/// paths"* and rely on the caller. **That was a security defect, and the test
/// corpus in `SEC-010` is what found it.** Measured, before the fix:
///
/// | Input | `path_is_within` |
/// |---|---|
/// | `/var/lib/orders/../../../etc/passwd` | **`true`** |
/// | `/var/lib/orders/../secrets` | **`true`** |
/// | `/var/lib/orders/..` | **`true`** |
/// | `/var/lib/orders/a/../../b` | **`true`** |
///
/// A pure string-prefix check sees `/var/lib/orders/…` and stops. So a caller
/// that forgot to canonicalize — or canonicalized a path that does not exist yet,
/// where `std::fs::canonicalize` fails — would have a traversal **pass a
/// defence-in-depth check**. A defence that passes the attack it exists to stop is
/// worse than none: it looks like protection, so nobody adds the real one.
///
/// The check is now self-contained. It splits both paths into components and
/// refuses any candidate containing a `..` component, then compares
/// component-by-component with `.` skipped.
///
/// # Why refusing `..` rather than resolving it
///
/// Resolving `..` lexically is subtly wrong — `/a/b/..` is `/a` only if `b` is a
/// directory and not a symlink, and the function has no filesystem to ask. Since
/// the caller is *required* to pass a canonical path (which has no `..` at all by
/// construction), refusing is both correct and the stricter direction: a
/// non-canonical input is a caller bug worth surfacing, not something to guess at.
///
/// # What this does NOT defend against
///
/// **Symlinks.** A canonicalized path has them resolved already, but a
/// non-canonical one does not, and this function cannot tell:
/// `/data/link` may point outside `/data`. Symlink safety comes from the
/// *preopen handle* — the guest holds a handle to a directory, and WASI resolves
/// within it — which is the primary enforcement; this remains the
/// defence-in-depth re-check for a mis-built preopen table.
#[must_use]
pub fn path_is_within(candidate: &str, root: &str) -> bool {
    if candidate == root {
        return true;
    }
    // Normalize separators so Windows `\` and POSIX `/` both work.
    let c = candidate.replace('\\', "/");
    let r = root.replace('\\', "/");

    // Split into components, dropping empty segments (so `//a` and `/a` agree)
    // and `.` (which is not a traversal but is also not a component).
    let components = |s: &str| -> Vec<String> {
        s.split('/')
            .filter(|seg| !seg.is_empty() && *seg != ".")
            .map(str::to_owned)
            .collect()
    };

    let cand = components(&c);
    let root_parts = components(&r);

    // **Refuse any traversal outright.** See the doc comment: the caller is
    // required to pass a canonical path, and one containing `..` is not one.
    if cand.iter().any(|seg| seg == "..") || root_parts.iter().any(|seg| seg == "..") {
        return false;
    }

    if root_parts.is_empty() {
        return false;
    }
    // A candidate shorter than the root cannot be beneath it.
    if cand.len() < root_parts.len() {
        return false;
    }

    // Component-wise prefix: every root component must match, in order. This is
    // what makes `/var/lib/orders-evil` fail — `orders-evil` != `orders`.
    cand[..root_parts.len()] == root_parts[..]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A controllable fake host, so normalization is testable without touching
    /// the real filesystem or the process environment.
    #[derive(Default)]
    struct FakeEnv {
        dirs: HashSet<String>,
        files: HashSet<String>,
        canonical: BTreeMap<String, String>,
        vars: HashSet<String>,
    }

    impl FakeEnv {
        fn with_dir(mut self, p: &str) -> Self {
            self.dirs.insert(p.to_owned());
            self.canonical.insert(p.to_owned(), p.to_owned());
            self
        }
        fn with_file(mut self, p: &str) -> Self {
            self.files.insert(p.to_owned());
            self
        }
        fn with_var(mut self, v: &str) -> Self {
            self.vars.insert(v.to_owned());
            self
        }
        fn with_canonical(mut self, from: &str, to: &str) -> Self {
            self.canonical.insert(from.to_owned(), to.to_owned());
            self
        }
    }

    impl HostEnv for FakeEnv {
        fn is_dir(&self, path: &str) -> bool {
            self.dirs.contains(path)
        }
        fn exists(&self, path: &str) -> bool {
            self.dirs.contains(path) || self.files.contains(path)
        }
        fn canonicalize(&self, path: &str) -> Result<String, String> {
            // Fall back to the identity mapping so a registered dir works
            // without registering a canonical form.
            if let Some(c) = self.canonical.get(path) {
                return Ok(c.clone());
            }
            if self.dirs.contains(path) {
                return Ok(path.to_owned());
            }
            Err("no such file or directory".to_owned())
        }
        fn has_env(&self, var: &str) -> bool {
            self.vars.contains(var)
        }
    }

    fn manifest_with(body: &str) -> Manifest {
        let src = format!("[package]\nname = \"app\"\nversion = \"0.1.0\"\n{body}");
        Manifest::parse(&src).expect("test manifest must parse")
    }

    // -- HostPattern -------------------------------------------------------

    #[test]
    fn host_pattern_parses_host_and_port() {
        let p = HostPattern::parse("api.stripe.com:443").unwrap();
        assert_eq!(p.port(), Some(443));
        assert!(!p.is_wildcard());
        assert!(p.matches("api.stripe.com", 443));
        assert!(!p.matches("api.stripe.com", 80));
        assert!(!p.matches("evil.com", 443));
    }

    #[test]
    fn host_pattern_without_port_matches_any_port() {
        let p = HostPattern::parse("api.example.com").unwrap();
        assert_eq!(p.port(), None);
        assert!(p.matches("api.example.com", 80));
        assert!(p.matches("api.example.com", 443));
        assert!(!p.matches("other.example.com", 443));
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        let p = HostPattern::parse("API.Stripe.COM:443").unwrap();
        assert!(p.matches("api.stripe.com", 443));
        assert!(p.matches("API.STRIPE.COM", 443));
    }

    /// The critical wildcard semantic: `*.example.com` must NOT match the bare
    /// domain, because the common misreading silently grants more than asked.
    #[test]
    fn wildcard_matches_subdomains_but_not_the_bare_domain() {
        let p = HostPattern::parse("*.internal.example.com:8443").unwrap();
        assert!(p.is_wildcard());
        assert!(p.matches("a.internal.example.com", 8443));
        assert!(p.matches("a.b.internal.example.com", 8443));
        assert!(
            !p.matches("internal.example.com", 8443),
            "`*.x` must not match the bare `x`"
        );
        assert!(!p.matches("notinternal.example.com", 8443));
        assert!(!p.matches("a.internal.example.com", 443), "port must match");
    }

    /// The classic prefix bug: a pattern for `example.com` must not permit
    /// `example.com.evil.net`, and `foo.example.com` must not match a
    /// non-wildcard `example.com` pattern.
    #[test]
    fn host_pattern_does_not_allow_suffix_confusion() {
        let p = HostPattern::parse("example.com").unwrap();
        assert!(!p.matches("example.com.evil.net", 443));
        assert!(!p.matches("foo.example.com", 443));

        let w = HostPattern::parse("*.example.com").unwrap();
        assert!(!w.matches("example.com.evil.net", 443));
    }

    #[test]
    fn host_pattern_rejects_urls_and_bare_wildcards() {
        assert!(HostPattern::parse("https://api.example.com").is_err());
        assert!(HostPattern::parse("api.example.com/path").is_err());
        let e = HostPattern::parse("*").unwrap_err();
        assert!(e.contains("bare `*`"), "got: {e}");
    }

    #[test]
    fn host_pattern_rejects_invalid_ports() {
        assert!(HostPattern::parse("api.example.com:99999").is_err());
        assert!(HostPattern::parse("api.example.com:").is_err());
        assert!(HostPattern::parse("api.example.com:abc").is_err());
    }

    #[test]
    fn host_pattern_handles_ipv6_literals() {
        let p = HostPattern::parse("[::1]:8080").unwrap();
        assert_eq!(p.port(), Some(8080));
        assert!(p.matches("::1", 8080));
        let p6 = HostPattern::parse("[2001:db8::1]").unwrap();
        assert_eq!(p6.port(), None);
    }

    #[test]
    fn host_pattern_rejects_ambiguous_colons() {
        assert!(HostPattern::parse("a:b:c").is_err());
    }

    // -- SecretRef ---------------------------------------------------------

    #[test]
    fn secret_ref_parses_env_scheme() {
        let r = SecretRef::parse("env:JWT_SIGNING_KEY").unwrap();
        assert_eq!(r.logical_name, "JWT_SIGNING_KEY");
        assert_eq!(r.env_var, "JWT_SIGNING_KEY");
        assert_eq!(r.to_string(), "env:JWT_SIGNING_KEY");
    }

    #[test]
    fn secret_ref_rejects_unknown_schemes_and_malformed_names() {
        assert!(SecretRef::parse("vault:secret/x").is_err());
        assert!(SecretRef::parse("JWT_KEY").is_err());
        assert!(SecretRef::parse("env:").is_err());
        assert!(SecretRef::parse("env:has-dash").is_err());
        assert!(SecretRef::parse("env:has space").is_err());
    }

    // -- path_is_within ----------------------------------------------------

    #[test]
    fn path_containment_is_component_wise_not_prefix() {
        assert!(path_is_within("/var/lib/orders", "/var/lib/orders"));
        assert!(path_is_within("/var/lib/orders/a/b", "/var/lib/orders"));
        // The sibling-prefix trap.
        assert!(!path_is_within("/var/lib/orders-evil", "/var/lib/orders"));
        assert!(!path_is_within("/var/lib/orders2", "/var/lib/orders"));
        assert!(!path_is_within("/etc", "/var/lib"));
        // Trailing slash on the root must not double-count.
        assert!(path_is_within("/var/lib/orders/x", "/var/lib/orders/"));
    }

    /// **`SEC-010`: the traversal corpus.** Every entry is an attack, and every
    /// one of them was **accepted** before the fix.
    ///
    /// # Why this test is the one that matters
    ///
    /// The old implementation was a string-prefix check whose doc said it
    /// "operates on already-canonicalized absolute paths" — a precondition
    /// asserted only in prose. Measured, it returned `true` for all four of the
    /// first entries below. A defence-in-depth check that passes the attack it
    /// exists to stop is worse than no check, because it *looks* like protection
    /// and nobody adds the real one.
    ///
    /// The corpus is a **table** so that adding a case is one line, and so the
    /// count is visible: a traversal corpus of two examples is an anecdote.
    #[test]
    fn path_traversal_is_rejected() {
        // Every one of these must be refused when the root is `/var/lib/orders`.
        let attacks = [
            // -- classic `..` escapes ----------------------------------------
            "/var/lib/orders/../../../etc/passwd",
            "/var/lib/orders/../secrets",
            "/var/lib/orders/..",
            "/var/lib/orders/a/../../b",
            "/var/lib/orders/./../../etc/shadow",
            "/var/lib/orders/a/b/../../../..",
            // -- traversal that lands back inside (still refused) ------------
            //
            // `/var/lib/orders/a/../b` is *lexically* inside the root, so a
            // resolver would admit it. This check refuses it anyway, and that is
            // deliberate: the caller is required to pass a canonical path, and a
            // path containing `..` is not one. Accepting it would mean resolving
            // symlinks lexically, which cannot be done correctly without a
            // filesystem.
            "/var/lib/orders/a/../b",
            "/var/lib/orders/../orders/x",
            // -- separator variants ------------------------------------------
            //
            // A backslash-separated traversal on a POSIX path. The separator
            // normalization at the top turns `\` into `/`, so this becomes a
            // `..` component and is refused by the same rule.
            "/var/lib/orders/..\\..\\etc\\passwd",
        ];
        for attack in attacks {
            assert!(
                !path_is_within(attack, "/var/lib/orders"),
                "`{attack}` must NOT be considered inside `/var/lib/orders`; a \
                 containment check that admits a traversal is a security defect, \
                 not a convenience (SEC-010)"
            );
        }

        // A root that is itself relative or traversing is refused as well, since
        // a grant whose root contains `..` is a manifest bug.
        assert!(!path_is_within("/var/lib/orders/x", "/var/lib/../../../"));
        assert!(!path_is_within("/var/lib/orders/x", "../orders"));
    }

    /// The control for the corpus above: legitimate paths must still be admitted.
    ///
    /// Without it, a `path_is_within` that returned `false` for everything would
    /// satisfy every traversal assertion while making every filesystem grant
    /// useless — the failure mode a one-sided test cannot see.
    #[test]
    fn legitimate_paths_are_still_admitted_after_the_traversal_fix() {
        for good in [
            "/var/lib/orders",
            "/var/lib/orders/",
            "/var/lib/orders/a",
            "/var/lib/orders/a/b/c.txt",
            "/var/lib/orders//double//slash",
            "/var/lib/orders/./a",
        ] {
            assert!(
                path_is_within(good, "/var/lib/orders"),
                "`{good}` IS inside `/var/lib/orders` and must be admitted"
            );
        }
    }

    /// **The regression, without the fix.** The four input classes that the old
    /// prefix check accepted, asserted individually so a future simplification
    /// back to a prefix match fails *here* with a message that names the cause.
    #[test]
    fn the_prefix_implementation_would_have_admitted_these() {
        // The property that distinguishes the two implementations: a prefix
        // check is satisfied by a string that *starts with* the root and then
        // diverges through `..`. Any implementation must look at components.
        let must_fail = [
            "/var/lib/orders/../../../etc/passwd",
            "/var/lib/orders/../secrets",
            "/var/lib/orders/..",
            "/var/lib/orders/a/../../b",
        ];
        for p in must_fail {
            assert!(
                !path_is_within(p, "/var/lib/orders"),
                "`{p}` starts with the root as a STRING, which is exactly what the \
                 old prefix implementation tested. It must fail here as well as in \
                 `path_traversal_is_rejected`, so that reverting to a prefix check \
                 breaks two tests rather than one."
            );
        }
    }

    #[test]
    fn path_containment_handles_windows_separators() {
        assert!(path_is_within(
            "C:\\Users\\a\\data\\x",
            "C:\\Users\\a\\data"
        ));
        assert!(!path_is_within(
            "C:\\Users\\a\\database",
            "C:\\Users\\a\\data"
        ));
    }

    // -- Normalization -----------------------------------------------------

    #[test]
    fn normalization_of_an_empty_manifest_yields_nothing() {
        let m = manifest_with("");
        let n = Normalized::from_manifest(&m, &FakeEnv::default()).unwrap();
        assert!(n.http_client.is_empty());
        assert!(!n.http_server);
        assert!(n.fs.is_empty());
        assert!(n.secrets.is_empty());
        assert!(n.declared.is_empty());
    }

    #[test]
    fn normalization_expands_and_sorts_host_patterns() {
        let m = manifest_with(
            "[capabilities.http]\nclient = [\"zzz.com\", \"aaa.com\", \"zzz.com\"]\n",
        );
        let n = Normalized::from_manifest(&m, &FakeEnv::default()).unwrap();
        assert_eq!(n.http_client.len(), 2, "duplicates must be removed");
        assert_eq!(n.http_client[0].as_written(), "aaa.com", "must be sorted");
        assert!(n.http_client_allows("aaa.com", 80));
        assert!(!n.http_client_allows("bbb.com", 80));
    }

    #[test]
    fn normalization_resolves_paths_and_rejects_missing_ones() {
        let m = manifest_with("[[capabilities.fs]]\npath = \"/data\"\nmode = \"read-only\"\n");
        // Missing path -> hard error, not a warning.
        let e = Normalized::from_manifest(&m, &FakeEnv::default()).unwrap_err();
        assert!(matches!(e, NormalizeError::PathMissing { .. }));
        assert_eq!(e.code(), qqq_core::ErrorCode::CapabilityPathInvalid);

        // Present path -> succeeds, and the grant records BOTH the declared
        // and the canonical form so the why chain can show the mapping.
        let env = FakeEnv::default().with_dir("/data");
        let n = Normalized::from_manifest(&m, &env).unwrap();
        assert_eq!(n.fs.len(), 1);
        assert_eq!(n.fs[0].declared_path, "/data");
        assert_eq!(n.fs[0].canonical_path, "/data");
    }

    #[test]
    fn normalization_rejects_a_file_where_a_directory_is_required() {
        let m = manifest_with(
            "[[capabilities.fs]]\npath = \"/etc/config.json\"\nmode = \"read-only\"\n",
        );
        let env = FakeEnv::default().with_file("/etc/config.json");
        let e = Normalized::from_manifest(&m, &env).unwrap_err();
        assert!(
            matches!(e, NormalizeError::PathNotADirectory { .. }),
            "got {e:?}"
        );
    }

    /// Canonicalization must defeat `..` traversal before the path reaches the
    /// grant table. The fake resolves `/data/../etc` to `/etc` to model what a
    /// real `canonicalize` does.
    #[test]
    fn normalization_uses_the_canonical_path_not_the_declared_one() {
        let m =
            manifest_with("[[capabilities.fs]]\npath = \"/data/../etc\"\nmode = \"read-only\"\n");
        let env = FakeEnv::default()
            .with_dir("/data/../etc")
            .with_canonical("/data/../etc", "/etc");
        let n = Normalized::from_manifest(&m, &env).unwrap();
        assert_eq!(n.fs[0].declared_path, "/data/../etc");
        assert_eq!(
            n.fs[0].canonical_path, "/etc",
            "the canonical form is what the host must enforce against"
        );
        assert!(n.fs_allows("/etc/passwd", FsMode::ReadOnly));
        assert!(!n.fs_allows("/data/x", FsMode::ReadOnly));
    }

    #[test]
    fn normalization_rejects_conflicting_grants_on_the_same_path() {
        let m = manifest_with(
            "[[capabilities.fs]]\npath = \"/data\"\nmode = \"read-only\"\n\
             [[capabilities.fs]]\npath = \"/data\"\nmode = \"read-write\"\n",
        );
        let env = FakeEnv::default().with_dir("/data");
        let e = Normalized::from_manifest(&m, &env).unwrap_err();
        assert!(
            matches!(e, NormalizeError::ConflictingGrants { .. }),
            "ambiguous authority must be rejected, got {e:?}"
        );
    }

    #[test]
    fn normalization_deduplicates_identical_grants() {
        let m = manifest_with(
            "[[capabilities.fs]]\npath = \"/data\"\nmode = \"read-only\"\n\
             [[capabilities.fs]]\npath = \"/data\"\nmode = \"read-only\"\n",
        );
        let env = FakeEnv::default().with_dir("/data");
        let n = Normalized::from_manifest(&m, &env).unwrap();
        assert_eq!(n.fs.len(), 1, "identical grants must collapse");
    }

    #[test]
    fn normalization_checks_secrets_without_reading_them() {
        let m = manifest_with("[capabilities.crypto]\nsecrets = [\"env:JWT_KEY\"]\n");

        // Absent -> error naming the variable, never a value.
        let e = Normalized::from_manifest(&m, &FakeEnv::default()).unwrap_err();
        assert!(matches!(e, NormalizeError::SecretMissing { .. }));
        assert_eq!(e.code(), qqq_core::ErrorCode::SecretUnresolvable);
        assert!(e.to_string().contains("JWT_KEY"));
        assert!(!e.to_string().contains("secret value"));

        // Present -> recorded as a reference only.
        let env = FakeEnv::default().with_var("JWT_KEY");
        let n = Normalized::from_manifest(&m, &env).unwrap();
        assert_eq!(n.secrets.len(), 1);
        assert_eq!(n.secret_source("JWT_KEY"), Some("JWT_KEY"));
        assert_eq!(n.secret_source("nope"), None);
    }

    #[test]
    fn normalization_sorts_and_dedups_env_and_dns() {
        let m = manifest_with(
            "[capabilities.env]\nallow = [\"ZZZ\", \"AAA\", \"ZZZ\"]\n\
             [capabilities.dns]\nresolve = [\"B.com\", \"a.com\", \"A.com\"]\n",
        );
        let n = Normalized::from_manifest(&m, &FakeEnv::default()).unwrap();
        assert_eq!(n.env, vec!["AAA", "ZZZ"]);
        assert_eq!(n.dns, vec!["a.com", "b.com"]);
        assert!(n.env_allows("AAA"));
        assert!(!n.env_allows("BBB"));
        assert!(
            n.dns_allows("A.com"),
            "dns matching must be case-insensitive"
        );
        assert!(!n.dns_allows("c.com"));
    }

    #[test]
    fn fs_allows_respects_mode_and_containment() {
        let m = manifest_with(
            "[[capabilities.fs]]\npath = \"/data\"\nmode = \"read-only\"\n\
             [[capabilities.fs]]\npath = \"/tmp/out\"\nmode = \"read-write\"\n",
        );
        let env = FakeEnv::default().with_dir("/data").with_dir("/tmp/out");
        let n = Normalized::from_manifest(&m, &env).unwrap();

        assert!(n.fs_allows("/data/file.txt", FsMode::ReadOnly));
        assert!(
            !n.fs_allows("/data/file.txt", FsMode::ReadWrite),
            "read-only must not permit writing"
        );
        assert!(n.fs_allows("/tmp/out/x", FsMode::ReadWrite));
        assert!(n.fs_allows("/tmp/out/x", FsMode::ReadOnly), "rw implies r");
        assert!(!n.fs_allows("/etc/passwd", FsMode::ReadOnly));
        assert!(
            !n.fs_allows("/data-evil/x", FsMode::ReadOnly),
            "sibling-prefix escape must be rejected"
        );
    }

    #[test]
    fn normalization_is_deterministic() {
        let m = manifest_with(
            "[capabilities.http]\nserver = true\nclient = [\"b.com\", \"a.com\"]\n\
             [[capabilities.fs]]\npath = \"/data\"\nmode = \"read-only\"\n\
             [capabilities.dns]\nresolve = [\"z.com\", \"a.com\"]\n",
        );
        let env = FakeEnv::default().with_dir("/data");
        let a = Normalized::from_manifest(&m, &env).unwrap();
        let b = Normalized::from_manifest(&m, &env).unwrap();
        assert_eq!(a, b, "normalization must be deterministic");
    }

    #[test]
    fn normalize_error_maps_to_the_right_codes_and_carries_remediation() {
        let cases = vec![
            (
                NormalizeError::PathMissing {
                    declared: "/x".into(),
                },
                qqq_core::ErrorCode::CapabilityPathInvalid,
            ),
            (
                NormalizeError::SecretMissing {
                    name: "K".into(),
                    source: "env:K".into(),
                },
                qqq_core::ErrorCode::SecretUnresolvable,
            ),
            (
                NormalizeError::InvalidHostPattern {
                    pattern: "x".into(),
                    reason: "y".into(),
                },
                qqq_core::ErrorCode::CapabilitySyntaxInvalid,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.code(), expected);
            let e = err.to_error();
            assert_eq!(e.code, expected);
            assert!(
                e.remediation.is_some(),
                "{expected} must carry a remediation"
            );
            assert!(!e.render().is_empty());
        }
    }
}
