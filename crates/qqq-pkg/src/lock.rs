// SPDX-License-Identifier: Apache-2.0

//! The lockfile — `qqq.lock` — and the capability diff.
//!
//! Implements `PKG-004` and the capability-aware half of `PKG-009`; Proposal
//! §5.4.
//!
//! # The feature that matters
//!
//! §5.4: *"`caps` is recorded per dependency. `qqqai install` prints a
//! **capability diff** — 'this update adds `http.client` to `qqqai/telemetry`'.
//! Supply-chain attacks today hide in code; here the **authority** delta is
//! visible in the diff. This is a genuinely new capability for the ecosystem."*
//!
//! Two consequences shape this module:
//!
//! 1. **`caps` is a first-class field, not metadata.** It participates in
//!    equality and in the covering hash, so a version bump that adds authority
//!    produces a different lockfile even if the artifact digest is somehow the
//!    same.
//! 2. **`LockDiff` distinguishes an authority change from a version change.**
//!    A package that updates `1.2.3 -> 1.2.4` and gains `http.client` is a
//!    supply-chain event; one that updates and gains nothing is routine. Those
//!    must be separable in CI without parsing prose, which is why the delta is a
//!    structured value rather than a message.
//!
//! # Why the covering hash excludes itself
//!
//! `lockfile-hash` covers every resolved package. Computing it over a document
//! that contains it is circular, so the hash is computed over the package list
//! and then written. The reader recomputes and compares — which is what makes a
//! hand-edited lockfile detectable rather than silently trusted.
//!
//! # Forward compatibility: there is none within a version
//!
//! A new field is a version bump, not a minor addition. Every deserialized struct
//! in this module carries `#[serde(deny_unknown_fields)]`, and `parse` refuses
//! `version != LOCK_VERSION` — so a lockfile from a newer writer is refused
//! rather than partially understood. The reason is the same one behind the
//! covering hash: silently ignoring a field that carries authority information
//! would be exactly the failure the `caps` field exists to prevent. A reader
//! that tolerated unknown fields could install a package whose authority it
//! cannot see. (`REG-011`.)

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use qqq_core::{Error, ErrorCode, Result, Version};

/// The lockfile format version this build writes.
///
/// Checked on read. A lockfile from a newer schema is refused rather than
/// partially understood: silently ignoring a field that carries authority
/// information would be exactly the failure the `caps` field exists to prevent.
pub const LOCK_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// A locked package
// ---------------------------------------------------------------------------

/// One resolved package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockPackage {
    /// The package name, possibly scoped: `qqqai/json`, `@org/pkg`.
    pub name: String,
    /// The resolved version.
    pub version: String,
    /// Where it came from.
    ///
    /// `registry+https://…`, `path+…`, or `git+…`. Recorded because two
    /// packages with the same name and version from different sources are
    /// different packages, and a lockfile that omitted the source could not tell
    /// them apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The digest of the component artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// The digest of the generated WIT interface.
    ///
    /// Separate from `digest` because the artifact and its interface can change
    /// independently, and an interface change is what breaks composition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wit: Option<String>,
    /// The capabilities this package declares.
    ///
    /// **Sorted and deduplicated on read**, so two lockfiles that describe the
    /// same authority compare equal regardless of how the file was written.
    /// Without that, a diff would report spurious changes from a reordering.
    #[serde(default)]
    pub caps: Vec<String>,
    /// The SPDX licence identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

impl LockPackage {
    /// A package name and version.
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            source: None,
            digest: None,
            wit: None,
            caps: Vec::new(),
            license: None,
        }
    }

    /// Set the declared capabilities.
    #[must_use]
    pub fn with_caps(mut self, caps: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.caps = caps.into_iter().map(Into::into).collect();
        self.caps.sort_unstable();
        self.caps.dedup();
        self
    }

    /// The key this package is identified by.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    /// Whether this package declares any capability at all.
    ///
    /// A dependency declaring `["none"]` grants nothing, and that is worth
    /// distinguishing from a dependency that simply omits the field — the first
    /// is a promise, the second is silence.
    #[must_use]
    pub fn declares_nothing(&self) -> bool {
        self.caps.is_empty() || self.caps == ["none"]
    }
}

// ---------------------------------------------------------------------------
// The lockfile
// ---------------------------------------------------------------------------

/// A parsed `qqq.lock`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lockfile {
    /// The format version.
    pub version: u32,
    /// The resolved packages, sorted by name then version.
    #[serde(rename = "package", default)]
    pub packages: Vec<LockPackage>,
    /// Metadata, including the covering hash.
    #[serde(default)]
    pub metadata: Metadata,
}

/// Lockfile metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// What wrote it, so a bug report can name the version.
    #[serde(
        rename = "generated-by",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub generated_by: Option<String>,
    /// The covering hash over every resolved package **and the build config**.
    #[serde(
        rename = "lockfile-hash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub lockfile_hash: Option<String>,
    /// The build configuration the hash covers — `CON-005`.
    ///
    /// Absent for a lockfile written before this field existed, and an absent
    /// config contributes nothing to the hash so an old lockfile's digest is
    /// unchanged. See [`BuildConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildConfig>,
}

/// The build configuration a lockfile was resolved under — `CON-005`.
///
/// # Why this exists
///
/// §5.4: *"`lockfile-hash` covers **everything**. Any change to any resolved
/// artifact changes the hash, so a build is either reproducible or it loudly is
/// not."* Before this type, "everything" meant every *package* field and the
/// format version — and **no build config at all**. So two builds from one
/// lockfile with different `[build]` settings produced the same hash while
/// producing different artifacts, which is exactly the case that sentence is
/// about. The hash was silent where it promised to be loud.
///
/// # Why it is optional, and why an absent one does not change the hash
///
/// Because every lockfile written before this field existed must keep the hash
/// it had. Folding an empty config block in unconditionally would change the
/// digest of every lockfile in the world on upgrade, and `install` would report
/// every project as dirty — the kind of change a package manager must never make
/// silently. An absent config therefore hashes as *nothing*, and the hash of an
/// old lockfile is bit-for-bit what it was.
///
/// # Why these four fields and not the whole manifest
///
/// Because the hash covers what determines the **artifact**. Language, target and
/// profile are the three inputs `qqqai build` reads that change the bytes
/// produced; the declared grant set changes the authority the artifact is built
/// against. The rest of the manifest — description, license, package name —
/// changes no output byte, and folding it in would make the hash move for edits
/// that cannot affect reproducibility, which trains a reader to ignore it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    /// Source language: `rust`, `ts`, `go`, `python` or `cpp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Compilation target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// `debug` or `release`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// The declared capability names, sorted, as the manifest resolved them.
    ///
    /// # Why `Vec` and not a `BTreeSet`
    ///
    /// Because `serde` on a `BTreeSet` serialises to a TOML array in set order
    /// already, and hashing needs a *deterministic* order rather than an
    /// unordered container. The same reason `LockPackage::caps` is a `Vec`
    /// (`capability_order_does_not_affect_equality` pins that its order is
    /// normalised before comparison).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
}

impl BuildConfig {
    /// Whether every field is absent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.language.is_none()
            && self.target.is_none()
            && self.profile.is_none()
            && self.caps.is_empty()
    }

    /// A config naming a language, target and profile.
    #[must_use]
    pub fn new(
        language: impl Into<String>,
        target: impl Into<String>,
        profile: impl Into<String>,
    ) -> Self {
        Self {
            language: Some(language.into()),
            target: Some(target.into()),
            profile: Some(profile.into()),
            caps: Vec::new(),
        }
    }

    /// Record the declared capability set, normalised.
    ///
    /// Sorts and deduplicates, so two spellings of one grant set hash
    /// identically — the property `the_hash_is_stable_across_capability_reordering`
    /// already pins for packages.
    #[must_use]
    pub fn with_caps(mut self, caps: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let mut set: Vec<String> = caps.into_iter().map(Into::into).collect();
        set.sort_unstable();
        set.dedup();
        self.caps = set;
        self
    }
}

/// Why a lockfile was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockfileError {
    /// The TOML did not parse.
    Syntax(String),
    /// The format version is not one this build understands.
    UnsupportedVersion {
        /// What the file declares.
        found: u32,
        /// What this build writes.
        supported: u32,
    },
    /// Two packages share a name.
    ///
    /// Keyed by name rather than name-and-version because `get` and the diff
    /// both key by name: a second entry under one name would make `get`
    /// return the first while the diff reports the last.
    Duplicate {
        /// The duplicated package name.
        key: String,
    },
    /// A package name or version is empty.
    EmptyField {
        /// Which field.
        field: String,
    },
    /// A package field failed validation: a NUL byte in a name or version,
    /// or a malformed digest.
    InvalidField {
        /// Which field.
        field: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The covering hash does not match the contents.
    HashMismatch {
        /// The hash recorded in the file.
        recorded: String,
        /// The hash computed from the contents.
        computed: String,
    },
}

/// Validate a digest-shaped field (`digest`, `wit`) at the parse boundary.
fn validate_digest_field(field: &str, value: &str) -> std::result::Result<(), LockfileError> {
    crate::store::Digest::parse(value)
        .map(|_| ())
        .map_err(|e| LockfileError::InvalidField {
            field: field.to_owned(),
            reason: e.message,
        })
}

/// Reject a hashed field containing a hash separator.
///
/// NUL (`0x00`), record separator (`0x1E`) and group separator (`0x1D`) are
/// the bytes the covering hash uses as delimiters; a field containing one
/// recreates the split-collision the delimiters exist to prevent.
fn check_field_bytes(field: &str, value: &str) -> std::result::Result<(), LockfileError> {
    if value.bytes().any(|b| b == 0x00 || b == 0x1E || b == 0x1D) {
        return Err(LockfileError::InvalidField {
            field: field.to_owned(),
            reason: "must not contain NUL or hash separators".to_owned(),
        });
    }
    Ok(())
}

impl fmt::Display for LockfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(d) => write!(f, "`qqq.lock` is not valid TOML: {d}"),
            Self::UnsupportedVersion { found, supported } => write!(
                f,
                "`qqq.lock` declares format version {found}, but this build writes {supported}"
            ),
            Self::Duplicate { key } => {
                write!(f, "`{key}` appears more than once in `qqq.lock`")
            }
            Self::EmptyField { field } => write!(f, "a package has an empty `{field}`"),
            Self::InvalidField { field, reason } => {
                write!(f, "a package has an invalid `{field}`: {reason}")
            }
            Self::HashMismatch { recorded, computed } => write!(
                f,
                "`qqq.lock` has been modified: recorded hash {recorded}, computed {computed}"
            ),
        }
    }
}

impl std::error::Error for LockfileError {}

impl LockfileError {
    /// Convert to the shared error type with a remediation.
    #[must_use]
    pub fn to_error(&self) -> Error {
        let remediation = match self {
            Self::Syntax(_) => {
                "the file is not valid TOML — if it was edited by hand, restore it from \
                 version control, otherwise run `qqqai install` to regenerate it"
            }
            Self::UnsupportedVersion { .. } => {
                "upgrade `qqqai`, or delete `qqq.lock` and run `qqqai install`"
            }
            Self::Duplicate { .. } => {
                "run `qqqai install` to regenerate it; a hand-edited lockfile must not \
                 list a package twice"
            }
            Self::EmptyField { .. } => {
                "the field is required; run `qqqai install` to regenerate the lockfile"
            }
            Self::InvalidField { .. } => {
                "fix the field; run `qqqai install` to regenerate the lockfile"
            }
            Self::HashMismatch { .. } => {
                "the lockfile was edited by hand or by another tool; run `qqqai install` \
                 to regenerate it, and check what changed"
            }
        };
        Error::new(ErrorCode::LockfileOutOfDate, self.to_string())
            .with_context("file", "qqq.lock")
            .with_remediation(remediation)
    }
}

impl Lockfile {
    /// An empty lockfile.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: LOCK_VERSION,
            packages: Vec::new(),
            metadata: Metadata::default(),
        }
    }

    /// Add a package, keeping the list sorted.
    ///
    /// `push` does not refuse duplicates: it is the builder used by
    /// `update::apply`, which moves one entry per name and never creates
    /// two. Only *parsed* lockfiles are canonical — `parse` refuses a
    /// repeated name, because `get` returns the first match while the diff
    /// reports the last, and a hand-built lockfile with two entries under
    /// one name would silently disagree with itself depending on the reader.
    pub fn push(&mut self, package: LockPackage) {
        self.packages.push(package);
        self.normalise();
    }
}

/// Order packages for hashing and listing: by name, then semver-aware.
///
/// Unparseable versions fall back to string order — deterministic, never a
/// refusal. Shared by `normalise` and `compute_hash` so the two cannot drift
/// into different orders.
fn package_order(a: &LockPackage, b: &LockPackage) -> std::cmp::Ordering {
    a.name.cmp(&b.name).then_with(|| {
        match (a.version.parse::<Version>(), b.version.parse::<Version>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            _ => a.version.cmp(&b.version),
        }
    })
}

impl Lockfile {
    /// Sort and deduplicate capability lists, then sort the package list.
    ///
    /// # Why this runs on every mutation and on every parse
    ///
    /// So that two lockfiles describing the same resolution compare **equal**.
    /// If capability order or package order were significant, a diff would
    /// report changes that are not changes — and a tool that cries wolf about
    /// authority changes is worse than one that says nothing, because the real
    /// one is buried.
    ///
    /// An absent build config and an empty one are the same absence
    /// (`skip_serializing_if` writes nothing for an empty config, so they
    /// round-trip identically): normalising the empty config to absent keeps
    /// `==` agreeing with the hash, which already folds nothing for either.
    fn normalise(&mut self) {
        for p in &mut self.packages {
            // Capabilities are identifiers: surrounding whitespace is never
            // meaningful, and a blank entry grants nothing while hashing as a
            // separator — so `[""]` and `[]` would compare and hash
            // differently for the same authority. Trim, drop blanks, dedup.
            p.caps = std::mem::take(&mut p.caps)
                .into_iter()
                .map(|c| c.trim().to_owned())
                .filter(|c| !c.is_empty())
                .collect();
            p.caps.sort_unstable();
            p.caps.dedup();
            // An empty or blank string is not a value: `Some("")` and `None`
            // hash identically (both feed nothing) but compare unequally, so
            // a hand-written empty field would make two identical resolutions
            // disagree. Trimmed first, because `" sha256:…" ` validates (the
            // digest parser trims) but would otherwise hash *with* the spaces
            // while the parsed twin hashes without. Normalise to absent at
            // the same boundary that sorts.
            for field in [&mut p.source, &mut p.digest, &mut p.wit, &mut p.license] {
                if let Some(s) = field.as_deref() {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        *field = None;
                    } else if trimmed.len() != s.len() {
                        *field = Some(trimmed.to_owned());
                    }
                }
            }
        }
        // The build config's caps are authority too: an unsorted config
        // would hash — and compare — differently for the same grant set.
        if let Some(build) = &mut self.metadata.build {
            build.caps = std::mem::take(&mut build.caps)
                .into_iter()
                .map(|c| c.trim().to_owned())
                .filter(|c| !c.is_empty())
                .collect();
            build.caps.sort_unstable();
            build.caps.dedup();
            for field in [&mut build.language, &mut build.target, &mut build.profile] {
                if let Some(s) = field.as_deref() {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        *field = None;
                    } else if trimmed.len() != s.len() {
                        *field = Some(trimmed.to_owned());
                    }
                }
            }
            // An explicitly empty config is the same absence as no config:
            // the hash folds nothing for either, and serialisation writes
            // nothing for either, so `==` must agree too.
            if build.is_empty() {
                self.metadata.build = None;
            }
        }
        self.packages.sort_by(package_order);
    }

    /// Look up a package by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&LockPackage> {
        self.packages.iter().find(|p| p.name == name)
    }

    /// How many packages are resolved.
    #[must_use]
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    /// Whether nothing is resolved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    /// Compute the covering hash.
    ///
    /// # What is covered, and what is not
    ///
    /// Covered: every package's **name, version, source, digest, wit digest
    /// and capabilities**. Not covered: the metadata block, because it contains this
    /// hash and covering it would be circular; and the licence identifier,
    /// because it changes neither the artifact's bytes nor its authority —
    /// a licence edit is visible in the diff as `ModifiedInPlace`
    /// (`DependencyChange::is_license_only`), not in the hash.
    ///
    /// The digest and capability fields are covered deliberately. A lockfile
    /// whose artifact digest changed is a different resolution; one whose
    /// *capabilities* changed is a supply-chain event. Both must move the hash.
    /// Covering only name and version — the obvious implementation — would let an
    /// artifact be swapped without the lockfile noticing, which defeats the whole
    /// mechanism.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut h = Sha256::new();
        // The format version, so a schema change moves the hash.
        h.update(LOCK_VERSION.to_le_bytes());

        // Sorted here, not just in `normalise`: `compute_hash` takes `&self`
        // and must not depend on whether the caller normalised first. A
        // hand-built lockfile with packages in insertion order hashes the
        // same as its parsed (normalised) twin — otherwise `stamp` followed
        // by `parse` would compute different hashes for the same resolution.
        let mut ordered: Vec<&LockPackage> = self.packages.iter().collect();
        ordered.sort_by(|a, b| package_order(a, b));
        for p in ordered {
            // NUL separators between fields: without them, ("ab","c") and
            // ("a","bc") hash identically, and a package could be crafted whose
            // fields collide with another's. This is the classic
            // length-extension-shaped bug in ad-hoc hashing.
            h.update(p.name.as_bytes());
            h.update(b"\x00");
            h.update(p.version.as_bytes());
            h.update(b"\x00");
            h.update(p.source.as_deref().unwrap_or("").as_bytes());
            h.update(b"\x00");
            h.update(p.digest.as_deref().unwrap_or("").as_bytes());
            h.update(b"\x00");
            h.update(p.wit.as_deref().unwrap_or("").as_bytes());
            h.update(b"\x00");
            for c in &p.caps {
                h.update(c.as_bytes());
                h.update(b"\x00");
            }
            // A record separator between packages, so ("a@1","b@2") and
            // ("a@1b","2") cannot collide either.
            h.update(b"\x1e");
        }

        // **The build config, when recorded** -- `CON-005`'s "and config".
        //
        // Absent config contributes nothing, so a lockfile written before this
        // field existed keeps its digest. Present config is hashed with the same
        // NUL-separated discipline as the package fields, for the same reason:
        // without separators, ("ab","c") and ("a","bc") collide.
        //
        // # Why the emptiness check is outside the `if let`
        //
        // Because `skip_serializing_if = "is_none"` on a `Some(empty)` writes
        // **nothing** to the file, so an empty config and an absent one
        // round-trip to the same bytes -- and therefore must hash the same, or a
        // lockfile would change its own digest merely by being read and written.
        // The first version wrote the group separator before testing emptiness,
        // so `None` and `Some(BuildConfig::default())` hashed differently; the
        // test asserting they agree is what caught it. A field whose absence is
        // indistinguishable from its emptiness after a round trip must be
        // indistinguishable in the hash too.
        if let Some(build) = &self.metadata.build
            && !build.is_empty()
        {
            h.update(b"\x1d"); // a group separator, so config cannot collide
            // with a package record
            h.update(build.language.as_deref().unwrap_or("").as_bytes());
            h.update(b"\x00");
            h.update(build.target.as_deref().unwrap_or("").as_bytes());
            h.update(b"\x00");
            h.update(build.profile.as_deref().unwrap_or("").as_bytes());
            h.update(b"\x00");
            for c in &build.caps {
                h.update(c.as_bytes());
                h.update(b"\x00");
            }
        }

        let out = h.finalize();
        let mut s = String::with_capacity(7 + 64);
        s.push_str("sha256:");
        for b in out {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Stamp the covering hash into the metadata.
    ///
    /// Normalises first: a hand-built lockfile with unsorted packages would
    /// otherwise hash differently from its own parsed form, and `parse` would
    /// refuse what `stamp` just wrote.
    pub fn stamp(&mut self, generated_by: &str) {
        self.normalise();
        self.metadata.generated_by = Some(generated_by.to_owned());
        self.metadata.lockfile_hash = Some(self.compute_hash());
    }

    /// Parse a lockfile.
    ///
    /// # Errors
    ///
    /// [`LockfileError`] for syntax, schema version, duplicates, empty or
    /// invalid fields, or a covering-hash mismatch.
    pub fn parse(text: &str) -> std::result::Result<Self, LockfileError> {
        let mut lock: Self =
            toml::from_str(text).map_err(|e| LockfileError::Syntax(e.message().to_owned()))?;

        if lock.version != LOCK_VERSION {
            return Err(LockfileError::UnsupportedVersion {
                found: lock.version,
                supported: LOCK_VERSION,
            });
        }

        // Normalise before any comparison, so a hand-written lockfile with
        // capabilities in a different order still compares equal.
        lock.normalise();

        // Duplicates and empty fields are checked here rather than trusted.
        // A lockfile listing a package twice is ambiguous about which one wins,
        // and ambiguity about authority is the thing this file exists to remove.
        //
        // Keyed by name, not by name-and-version: `get` and the diff both key
        // by name (an update changes the version, which is exactly the
        // continuity they depend on), so a second entry under one name would
        // make `get` return the first while the diff reports the last.
        let mut seen = std::collections::BTreeSet::new();
        for p in &lock.packages {
            if p.name.trim().is_empty() || p.version.trim().is_empty() {
                return Err(LockfileError::EmptyField {
                    field: if p.name.trim().is_empty() {
                        "name".to_owned()
                    } else {
                        "version".to_owned()
                    },
                });
            }
            // Every hashed field is separator-clean: the hash joins fields
            // with NUL, record (`0x1E`) and group (`0x1D`) separators, and a
            // field containing one recreates the `("ab","c")` / `("a","bc")`
            // collision the separators exist to prevent. Digests and wits
            // cannot contain them (hex, enforced below); names, versions,
            // sources, licences and capabilities can, so they are rejected.
            check_field_bytes("name", &p.name)?;
            check_field_bytes("version", &p.version)?;
            if let Some(source) = &p.source {
                check_field_bytes("source", source)?;
            }
            if let Some(license) = &p.license {
                check_field_bytes("license", license)?;
            }
            for cap in &p.caps {
                check_field_bytes("caps", cap)?;
            }
            // A pinned version is exact: `major.minor.patch`, canonical, no
            // leading zeros. A lockfile pinning `1.2` or `garbage` could never
            // be resolved to a single artifact, and `1.2` vs `1.2.0` hashing
            // differently while meaning the same thing would make two
            // identical resolutions disagree.
            if p.version.parse::<Version>().is_err() {
                return Err(LockfileError::InvalidField {
                    field: "version".to_owned(),
                    reason: "must be major.minor.patch".to_owned(),
                });
            }
            // Digests and interface hashes are content addresses: malformed
            // ones are caught here, at the boundary, instead of failing pages
            // later when the store tries to use them.
            if let Some(digest) = &p.digest {
                validate_digest_field("digest", digest)?;
            }
            if let Some(wit) = &p.wit {
                validate_digest_field("wit", wit)?;
            }
            if !seen.insert(p.name.clone()) {
                return Err(LockfileError::Duplicate {
                    key: p.name.clone(),
                });
            }
        }
        // The build config is hashed too, so its fields get the same
        // separator-cleanliness check as the package fields.
        if let Some(build) = &lock.metadata.build {
            if let Some(language) = &build.language {
                check_field_bytes("language", language)?;
            }
            if let Some(target) = &build.target {
                check_field_bytes("target", target)?;
            }
            if let Some(profile) = &build.profile {
                check_field_bytes("profile", profile)?;
            }
            for cap in &build.caps {
                check_field_bytes("caps", cap)?;
            }
        }

        // The covering hash, when present, must match. A lockfile that has been
        // edited by hand or by another tool is *detected* rather than trusted.
        //
        // Absent is permitted: a lockfile being generated for the first time has
        // no hash yet, and refusing it would make `install` unable to bootstrap.
        if let Some(recorded) = &lock.metadata.lockfile_hash {
            let computed = lock.compute_hash();
            if recorded != &computed {
                return Err(LockfileError::HashMismatch {
                    recorded: recorded.clone(),
                    computed,
                });
            }
        }

        Ok(lock)
    }

    /// Render to TOML.
    ///
    /// # Errors
    ///
    /// `QQQ-5003` when serialisation fails, which would be a bug in this crate
    /// rather than a user error.
    pub fn render(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| {
            Error::new(
                ErrorCode::InternalInvariantViolated,
                "could not serialise the lockfile",
            )
            .with_cause(e.to_string())
            .with_remediation("this is a QQQ bug; please report it")
        })
    }
}

impl Default for Lockfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// The capability diff
// ---------------------------------------------------------------------------

/// How one package changed between two lockfiles.
///
/// Four independent `*_changed` flags rather than an enum because the flags
/// compose: a single update can move the digest *and* reword the licence.
/// (`struct_excessive_bools` is allowed here for exactly that reason — the
/// alternative, a powerset enum, would be less readable than four names.)
#[allow(
    clippy::struct_excessive_bools,
    reason = "the four change flags are independent and compose; an enum powerset would be less readable"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyChange {
    /// The package name.
    pub name: String,
    /// The version before, absent when added.
    pub from: Option<String>,
    /// The version after, absent when removed.
    pub to: Option<String>,
    /// What happened.
    pub kind: ChangeKind,
    /// Capabilities that appeared.
    pub caps_added: Vec<String>,
    /// Capabilities that disappeared.
    pub caps_removed: Vec<String>,
    /// Whether the artifact digest changed.
    ///
    /// A digest-only swap — same version, same capabilities, different bytes —
    /// is the shape of an artifact substitution, and `ModifiedInPlace` alone
    /// would not distinguish it from a license edit.
    pub digest_changed: bool,
    /// Whether the interface digest changed.
    ///
    /// The `wit` digest is covered by the hash for the same reason the artifact
    /// digest is: an interface change is what breaks composition. Tracked for
    /// the same reason as `digest_changed` — without it a `wit`-only swap
    /// reads as an undescribed `ModifiedInPlace`.
    pub wit_changed: bool,
    /// Whether the source changed.
    ///
    /// Same name and version from a different source is a different package
    /// (see `LockPackage::source`), so a source move is reported, not silent.
    pub source_changed: bool,
    /// Whether the licence identifier changed.
    ///
    /// A licence change alters no bytes and grants no authority, but it is
    /// still a fact a reviewer wants separated from "nothing changed".
    pub license_changed: bool,
}

impl DependencyChange {
    /// Whether this change grants the dependency new authority.
    ///
    /// **The predicate CI should branch on.** A version bump that adds no
    /// authority is routine; one that does is a supply-chain event, and the two
    /// must be separable without reading a message.
    #[must_use]
    pub fn grants_new_authority(&self) -> bool {
        !self.caps_added.is_empty()
    }

    /// Whether the change is limited to the licence identifier.
    ///
    /// A licence edit changes no bytes and grants no authority, but it is
    /// still separated from "nothing changed" so a reviewer can tell a
    /// digest swap (bytes changed) from a paperwork edit.
    ///
    /// ```
    /// # use qqq_pkg::lock::{ChangeKind, DependencyChange};
    /// # let change = DependencyChange {
    /// #     name: "x".into(), from: Some("1.0.0".into()), to: Some("1.0.0".into()),
    /// #     kind: ChangeKind::ModifiedInPlace, caps_added: vec![], caps_removed: vec![],
    /// #     digest_changed: false, wit_changed: false,
    /// #     source_changed: false, license_changed: true,
    /// # };
    /// assert!(change.is_license_only());
    /// ```
    #[must_use]
    pub fn is_license_only(&self) -> bool {
        self.kind == ChangeKind::ModifiedInPlace
            && self.caps_added.is_empty()
            && self.caps_removed.is_empty()
            && !self.digest_changed
            && !self.wit_changed
            && !self.source_changed
            && self.license_changed
    }
}

/// What happened to one package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// It appeared.
    Added,
    /// It disappeared.
    Removed,
    /// Its version changed.
    Updated,
    /// Its version is the same but something else differs — a digest, or a
    /// capability.
    ModifiedInPlace,
}

impl ChangeKind {
    /// The stable name, for JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Updated => "updated",
            Self::ModifiedInPlace => "modified-in-place",
        }
    }
}

/// The authority delta for one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDelta {
    /// The package.
    pub package: String,
    /// Capabilities gained.
    pub added: Vec<String>,
    /// Capabilities lost.
    pub removed: Vec<String>,
}

impl CapabilityDelta {
    /// Whether authority grew.
    #[must_use]
    pub fn is_escalation(&self) -> bool {
        !self.added.is_empty()
    }
}

/// The difference between two lockfiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockDiff {
    /// Every changed package.
    pub changes: Vec<DependencyChange>,
    /// Whether the build configuration changed.
    ///
    /// The diff keys on packages, but a config change moves the covering hash
    /// without touching any package — without this flag that event would be
    /// invisible (`is_empty` true) while the hash moved. A target or profile
    /// change is a reproducibility event, so it is reported, not hidden.
    pub build_changed: bool,
    /// Only the packages whose **authority** changed.
    ///
    /// Derived from `changes` rather than computed separately, so the two cannot
    /// disagree — and a `caps_added` entry that did not appear here would be a
    /// supply-chain event nobody was shown.
    pub capability_changes: Vec<CapabilityDelta>,
}

impl LockDiff {
    /// Whether anything changed at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && !self.build_changed
    }

    /// Whether any dependency gained authority.
    #[must_use]
    pub fn has_escalation(&self) -> bool {
        self.capability_changes
            .iter()
            .any(CapabilityDelta::is_escalation)
    }

    /// The total capabilities gained, across every package.
    #[must_use]
    pub fn total_added(&self) -> usize {
        self.capability_changes.iter().map(|d| d.added.len()).sum()
    }

    /// The total capabilities lost, across every package.
    #[must_use]
    pub fn total_removed(&self) -> usize {
        self.capability_changes
            .iter()
            .map(|d| d.removed.len())
            .sum()
    }

    /// Compute the diff from `old` to `new`.
    #[must_use]
    pub fn compute(old: &Lockfile, new: &Lockfile) -> Self {
        // Normalised clones: the inputs may be hand-built (unsorted, blank
        // fields, empty-vs-absent configs), and the diff must not report
        // formatting as change. `normalise` is idempotent, so parsed inputs
        // pass through unchanged.
        let mut old = old.clone();
        old.normalise();
        let mut new = new.clone();
        new.normalise();
        let build_changed = old.metadata.build != new.metadata.build;
        // Keyed by **name**, not by name-and-version: an update changes the
        // version, and keying on the pair would report every update as a removal
        // plus an addition — losing the fact that it is the same dependency,
        // which is exactly the continuity the capability diff depends on.
        let old_by_name: BTreeMap<&str, &LockPackage> =
            old.packages.iter().map(|p| (p.name.as_str(), p)).collect();
        let new_by_name: BTreeMap<&str, &LockPackage> =
            new.packages.iter().map(|p| (p.name.as_str(), p)).collect();

        let mut changes = Vec::new();

        for (name, after) in &new_by_name {
            match old_by_name.get(name) {
                None => changes.push(DependencyChange {
                    name: (*name).to_owned(),
                    from: None,
                    to: Some(after.version.clone()),
                    kind: ChangeKind::Added,
                    // An added package's capabilities are all "added": there was
                    // no prior state in which they were absent-but-allowed.
                    caps_added: after.caps.clone(),
                    caps_removed: Vec::new(),
                    // Nothing before to differ from.
                    digest_changed: false,
                    wit_changed: false,
                    source_changed: false,
                    license_changed: false,
                }),
                Some(before) => {
                    let caps_added = difference(&after.caps, &before.caps);
                    let caps_removed = difference(&before.caps, &after.caps);
                    let digest_changed = before.digest != after.digest;
                    let wit_changed = before.wit != after.wit;
                    let source_changed = before.source != after.source;
                    let license_changed = before.license != after.license;

                    let kind = if before.version != after.version {
                        ChangeKind::Updated
                    } else if before == after {
                        // Nothing at all changed: not a change.
                        continue;
                    } else {
                        ChangeKind::ModifiedInPlace
                    };

                    changes.push(DependencyChange {
                        name: (*name).to_owned(),
                        from: Some(before.version.clone()),
                        to: Some(after.version.clone()),
                        kind,
                        caps_added,
                        caps_removed,
                        digest_changed,
                        wit_changed,
                        source_changed,
                        license_changed,
                    });
                }
            }
        }

        for (name, before) in &old_by_name {
            if !new_by_name.contains_key(name) {
                changes.push(DependencyChange {
                    name: (*name).to_owned(),
                    from: Some(before.version.clone()),
                    to: None,
                    kind: ChangeKind::Removed,
                    caps_added: Vec::new(),
                    // A removed package's capabilities are gone with it: not an
                    // escalation, but lost authority all the same, and
                    // `total_removed` counts what is gone.
                    caps_removed: before.caps.clone(),
                    digest_changed: false,
                    wit_changed: false,
                    source_changed: false,
                    license_changed: false,
                });
            }
        }

        changes.sort_by(|a, b| a.name.cmp(&b.name));

        let capability_changes: Vec<CapabilityDelta> = changes
            .iter()
            .filter(|c| !c.caps_added.is_empty() || !c.caps_removed.is_empty())
            .map(|c| CapabilityDelta {
                package: c.name.clone(),
                added: c.caps_added.clone(),
                removed: c.caps_removed.clone(),
            })
            .collect();

        Self {
            changes,
            build_changed,
            capability_changes,
        }
    }
}

/// Items in `a` that are not in `b`, both sorted.
fn difference(a: &[String], b: &[String]) -> Vec<String> {
    a.iter().filter(|x| !b.contains(x)).cloned().collect()
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

    fn pkg(name: &str, version: &str, caps: &[&str]) -> LockPackage {
        LockPackage::new(name, version).with_caps(caps.iter().copied())
    }

    fn lock(packages: Vec<LockPackage>) -> Lockfile {
        let mut l = Lockfile::new();
        for p in packages {
            l.push(p);
        }
        l
    }

    // -- construction and normalisation ------------------------------------

    #[test]
    fn a_new_lockfile_has_the_current_version_and_no_packages() {
        let l = Lockfile::new();
        assert_eq!(l.version, LOCK_VERSION);
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
    }

    /// **Why normalisation exists.** If capability order were significant, two
    /// lockfiles describing the same resolution would compare unequal and a diff
    /// would report changes that are not changes — burying the real authority
    /// change under noise.
    #[test]
    fn capability_order_does_not_affect_equality() {
        let a = lock(vec![pkg("x", "1.0.0", &["b", "a", "c"])]);
        let b = lock(vec![pkg("x", "1.0.0", &["c", "b", "a"])]);
        assert_eq!(a, b, "capability order must not be significant");
        assert_eq!(a.packages[0].caps, vec!["a", "b", "c"]);
    }

    #[test]
    fn duplicate_capabilities_are_collapsed() {
        let l = lock(vec![pkg("x", "1.0.0", &["a", "a", "b"])]);
        assert_eq!(l.packages[0].caps, vec!["a", "b"]);
    }

    #[test]
    fn packages_are_sorted_by_name() {
        let l = lock(vec![
            pkg("zebra", "1.0.0", &[]),
            pkg("apple", "1.0.0", &[]),
            pkg("mango", "1.0.0", &[]),
        ]);
        let names: Vec<&str> = l.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["apple", "mango", "zebra"]);
    }

    #[test]
    fn a_package_can_be_looked_up_by_name() {
        let l = lock(vec![pkg("qqqai/json", "1.2.4", &["none"])]);
        let p = l.get("qqqai/json").expect("must find");
        assert_eq!(p.version, "1.2.4");
        assert!(l.get("absent").is_none());
    }

    #[test]
    fn a_package_key_combines_name_and_version() {
        assert_eq!(pkg("x", "1.2.3", &[]).key(), "x@1.2.3");
    }

    #[test]
    fn declaring_none_is_distinguished_from_declaring_nothing() {
        assert!(pkg("a", "1.0.0", &["none"]).declares_nothing());
        assert!(pkg("b", "1.0.0", &[]).declares_nothing());
        assert!(!pkg("c", "1.0.0", &["clock.monotonic"]).declares_nothing());
    }

    // -- the covering hash -------------------------------------------------

    /// **The digest must be covered.** A lockfile whose artifact digest changed
    /// is a different resolution; covering only name and version would let an
    /// artifact be swapped without the lockfile noticing.
    #[test]
    fn the_hash_covers_the_artifact_digest() {
        let mut a = lock(vec![pkg("x", "1.0.0", &[])]);
        a.packages[0].digest = Some(format!("sha256:{}", "aa".repeat(32)));
        let mut b = lock(vec![pkg("x", "1.0.0", &[])]);
        b.packages[0].digest = Some(format!("sha256:{}", "bb".repeat(32)));
        assert_ne!(
            a.compute_hash(),
            b.compute_hash(),
            "swapping an artifact must move the covering hash"
        );
    }

    /// **And the capabilities.** This is the whole point of the feature: a
    /// package that gains authority must produce a different lockfile even if
    /// nothing else about it changed.
    #[test]
    fn the_hash_covers_the_capabilities() {
        let a = lock(vec![pkg("x", "1.0.0", &["clock.monotonic"])]);
        let b = lock(vec![pkg("x", "1.0.0", &["clock.monotonic", "http.client"])]);
        assert_ne!(
            a.compute_hash(),
            b.compute_hash(),
            "gaining authority must move the covering hash"
        );
    }

    #[test]
    fn the_hash_is_stable_across_capability_reordering() {
        let a = lock(vec![pkg("x", "1.0.0", &["b", "a"])]);
        let b = lock(vec![pkg("x", "1.0.0", &["a", "b"])]);
        assert_eq!(
            a.compute_hash(),
            b.compute_hash(),
            "normalised inputs must hash identically"
        );
    }

    #[test]
    fn the_hash_changes_with_every_covered_field() {
        let base = lock(vec![pkg("x", "1.0.0", &[])]);
        let mut others = Vec::new();

        let mut version = lock(vec![pkg("x", "1.0.0", &[])]);
        version.packages[0].version = "1.0.1".to_owned();
        others.push(version);

        let mut name = lock(vec![pkg("x", "1.0.0", &[])]);
        name.packages[0].name = "y".to_owned();
        others.push(name);

        let mut source = lock(vec![pkg("x", "1.0.0", &[])]);
        source.packages[0].source = Some("registry+https://x".to_owned());
        others.push(source);

        let mut wit = lock(vec![pkg("x", "1.0.0", &[])]);
        wit.packages[0].wit = Some(format!("sha256:{}", "cc".repeat(32)));
        others.push(wit);

        for other in &others {
            assert_ne!(
                base.compute_hash(),
                other.compute_hash(),
                "a covered field changed without moving the hash: {other:?}"
            );
        }
    }

    /// Field boundaries are unambiguous — and NUL bytes, the one shape that
    /// could smuggle one field split into another, are refused at parse.
    ///
    /// Without separators, `("ab","c")` and `("a","bc")` would hash
    /// identically. With NUL separators they do not — but a NUL *inside* a
    /// field recreates the ambiguity (`("a\0b","c")` and `("a","b\0c")`
    /// share a preimage), so names and versions carrying NUL are rejected
    /// rather than hashed.
    #[test]
    fn field_boundaries_are_unambiguous() {
        let a = lock(vec![
            LockPackage::new("ab", "c"),
            LockPackage::new("a", "bc"),
        ]);
        let b = lock(vec![
            LockPackage::new("a", "bc"),
            LockPackage::new("ab", "c"),
        ]);
        // Both normalise to the same order, so these are the same lockfile.
        assert_eq!(a.compute_hash(), b.compute_hash());

        // A field split that NUL bytes would make ambiguous never reaches
        // the hash: parse refuses it first.
        let text = format!(
            "version = {LOCK_VERSION}\n\n[[package]]\nname = \"a\\u0000b\"\nversion = \"c\"\n"
        );
        let e = Lockfile::parse(&text).unwrap_err();
        assert!(
            matches!(e, LockfileError::InvalidField { .. }),
            "a NUL split must be refused, got {e:?}"
        );
    }

    #[test]
    fn the_hash_is_prefixed_with_its_algorithm() {
        let l = lock(vec![pkg("x", "1.0.0", &[])]);
        let h = l.compute_hash();
        assert!(h.starts_with("sha256:"), "got {h}");
        assert_eq!(h.len(), "sha256:".len() + 64);
    }

    #[test]
    fn stamping_records_the_hash_and_the_producer() {
        let mut l = lock(vec![pkg("x", "1.0.0", &[])]);
        l.stamp("qqqai 1.0.0");
        assert_eq!(l.metadata.generated_by.as_deref(), Some("qqqai 1.0.0"));
        assert_eq!(
            l.metadata.lockfile_hash.as_deref(),
            Some(l.compute_hash().as_str())
        );
    }

    // -- round-tripping ----------------------------------------------------

    #[test]
    fn a_lockfile_round_trips_through_toml() {
        let mut original = lock(vec![
            pkg("qqqai/json", "1.2.4", &["none"]),
            pkg("qqqai/validate", "2.0.1", &["clock.monotonic"]),
        ]);
        original.packages[0].digest = Some(format!("sha256:{}", "9f2c".repeat(16)));
        original.packages[0].license = Some("Apache-2.0".to_owned());
        original.stamp("qqqai 1.0.0");

        let text = original.render().expect("must render");
        let parsed = Lockfile::parse(&text).expect("must re-parse");
        assert_eq!(original, parsed, "a lockfile must survive a round trip");
    }

    #[test]
    fn the_rendered_form_uses_the_documented_field_names() {
        let mut l = lock(vec![pkg("x", "1.0.0", &["caps.a"])]);
        l.stamp("qqqai 1.0.0");
        let text = l.render().expect("must render");

        // Proposal §5.4's example uses these exact spellings.
        assert!(text.contains("[[package]]"), "got:\n{text}");
        assert!(text.contains("name ="), "got:\n{text}");
        assert!(text.contains("version ="), "got:\n{text}");
        assert!(text.contains("caps ="), "got:\n{text}");
        assert!(text.contains("generated-by"), "got:\n{text}");
        assert!(text.contains("lockfile-hash"), "got:\n{text}");
    }

    // -- parsing failures --------------------------------------------------

    #[test]
    fn malformed_toml_is_reported_as_a_syntax_error() {
        let e = Lockfile::parse("this is not toml [[[").unwrap_err();
        assert!(matches!(e, LockfileError::Syntax(_)));
        assert!(e.to_error().remediation.is_some());
    }

    /// A lockfile from a newer schema is refused rather than partially
    /// understood: silently ignoring a field that carries authority information
    /// is exactly the failure the `caps` field exists to prevent.
    #[test]
    fn an_unsupported_version_is_refused_rather_than_ignored() {
        let text = "version = 99\n";
        let e = Lockfile::parse(text).unwrap_err();
        match e {
            LockfileError::UnsupportedVersion { found, supported } => {
                assert_eq!(found, 99);
                assert_eq!(supported, LOCK_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn a_duplicate_package_is_refused() {
        let text = format!(
            "version = {LOCK_VERSION}\n\n\
             [[package]]\nname = \"x\"\nversion = \"1.0.0\"\n\n\
             [[package]]\nname = \"x\"\nversion = \"1.0.0\"\n"
        );
        let e = Lockfile::parse(&text).unwrap_err();
        assert!(matches!(e, LockfileError::Duplicate { .. }));
    }

    /// Keyed by name, not name-and-version: `get` and the diff both key by
    /// name, so `x@1` plus `x@2` would make `get` return the first while the
    /// diff reports the last. Refuse the ambiguity instead.
    #[test]
    fn a_duplicate_name_with_different_versions_is_refused() {
        let text = format!(
            "version = {LOCK_VERSION}\n\n\
             [[package]]\nname = \"x\"\nversion = \"1.0.0\"\n\n\
             [[package]]\nname = \"x\"\nversion = \"2.0.0\"\n"
        );
        let e = Lockfile::parse(&text).unwrap_err();
        assert!(
            matches!(&e, LockfileError::Duplicate { key } if key == "x"),
            "duplicates key by name: {e:?}"
        );
    }

    #[test]
    fn an_empty_name_or_version_is_refused() {
        let text =
            format!("version = {LOCK_VERSION}\n\n[[package]]\nname = \"\"\nversion = \"1.0.0\"\n");
        let e = Lockfile::parse(&text).unwrap_err();
        assert!(matches!(e, LockfileError::EmptyField { .. }));
    }

    /// A NUL byte in a name or version is refused: NUL collides with the
    /// field separators the covering hash relies on, and no filesystem
    /// accepts NUL in a path a name may become. Written as TOML `\u0000`
    /// escapes — a literal NUL byte would not survive the test file itself.
    #[test]
    fn a_nul_byte_in_a_name_or_version_is_refused() {
        for (name, version) in [("x\\u0000y", "1.0.0"), ("x", "1.0\\u0000")] {
            let text = format!(
                "version = {LOCK_VERSION}\n\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n"
            );
            let e = Lockfile::parse(&text).unwrap_err();
            assert!(
                matches!(e, LockfileError::InvalidField { .. }),
                "NUL must be rejected, got {e:?}"
            );
        }
    }

    /// The hash separators are rejected everywhere they are hashed, not just
    /// in names: a `0x1E` in a capability or a `0x1D` in a source recreates
    /// the split-collision the NUL test pins for names.
    #[test]
    fn hash_separators_are_rejected_in_every_hashed_field() {
        let cases = [
            (
                "caps",
                "[[package]]\nname = \"x\"\nversion = \"1.0.0\"\ncaps = [\"a\\u001eb\"]\n",
            ),
            (
                "source",
                "[[package]]\nname = \"x\"\nversion = \"1.0.0\"\nsource = \"a\\u001db\"\n",
            ),
            (
                "license",
                "[[package]]\nname = \"x\"\nversion = \"1.0.0\"\nlicense = \"a\\u0000b\"\n",
            ),
        ];
        for (field, body) in cases {
            let text = format!("version = {LOCK_VERSION}\n\n{body}");
            let e = Lockfile::parse(&text).unwrap_err();
            assert!(
                matches!(&e, LockfileError::InvalidField { field: f, .. } if f == field),
                "{field} with a separator must be rejected, got {e:?}"
            );
        }
    }

    /// Digest-shaped fields are validated at the parse boundary: a malformed
    /// digest would otherwise fail pages later when the store tries to use
    /// it, far from the lockfile that carried it.
    #[test]
    fn a_malformed_digest_or_wit_is_refused_at_parse() {
        for (field, value) in [("digest", "not-a-digest"), ("wit", "sha256:xyz")] {
            let text = format!(
                "version = {LOCK_VERSION}\n\n[[package]]\nname = \"x\"\nversion = \"1.0.0\"\n{field} = \"{value}\"\n"
            );
            let e = Lockfile::parse(&text).unwrap_err();
            assert!(
                matches!(e, LockfileError::InvalidField { .. }),
                "{field} = {value:?} must be rejected, got {e:?}"
            );
        }
    }

    /// **A hand-edited lockfile is detected, not trusted.** The covering hash is
    /// recomputed on read, so adding a capability to a dependency by editing the
    /// file produces an error rather than silently granting authority.
    #[test]
    fn a_hand_edited_lockfile_is_detected() {
        let mut l = lock(vec![pkg("x", "1.0.0", &[])]);
        l.stamp("qqqai 1.0.0");
        let text = l.render().expect("must render");

        // Edit the capabilities without updating the hash — what a supply-chain
        // attacker with write access would do.
        let tampered = text.replace("caps = []", "caps = [\"http.client\"]");
        assert_ne!(tampered, text, "the test must actually change something");

        let e = Lockfile::parse(&tampered).unwrap_err();
        match e {
            LockfileError::HashMismatch { recorded, computed } => {
                assert_ne!(recorded, computed);
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    /// But an *unstamped* lockfile parses: one being generated for the first
    /// time has no hash yet, and refusing it would make `install` unable to
    /// bootstrap.
    #[test]
    fn an_unstamped_lockfile_parses() {
        let text =
            format!("version = {LOCK_VERSION}\n\n[[package]]\nname = \"x\"\nversion = \"1.0.0\"\n");
        let l = Lockfile::parse(&text).expect("bootstrap must be possible");
        assert_eq!(l.len(), 1);
        assert!(l.metadata.lockfile_hash.is_none());
    }

    #[test]
    fn every_lockfile_error_renders_with_a_remediation() {
        let errors = [
            LockfileError::Syntax("x".to_owned()),
            LockfileError::UnsupportedVersion {
                found: 2,
                supported: 1,
            },
            LockfileError::Duplicate {
                key: "x".to_owned(),
            },
            LockfileError::EmptyField {
                field: "name".to_owned(),
            },
            LockfileError::InvalidField {
                field: "digest".to_owned(),
                reason: "test".to_owned(),
            },
            LockfileError::HashMismatch {
                recorded: "a".to_owned(),
                computed: "b".to_owned(),
            },
        ];
        for e in errors {
            let err = e.to_error();
            assert!(err.remediation.is_some(), "`{e}` has no remediation");
            assert_eq!(err.code, ErrorCode::LockfileOutOfDate);
        }
    }

    // -- the capability diff -----------------------------------------------

    /// **The headline feature.** A version bump that adds authority must be
    /// reported as such, separately from the version change.
    #[test]
    fn an_update_that_adds_authority_is_reported() {
        let before = lock(vec![pkg("qqqai/telemetry", "1.0.0", &["clock.monotonic"])]);
        let after = lock(vec![pkg(
            "qqqai/telemetry",
            "1.0.1",
            &["clock.monotonic", "http.client"],
        )]);

        let diff = LockDiff::compute(&before, &after);
        assert_eq!(diff.changes.len(), 1);

        let c = &diff.changes[0];
        assert_eq!(c.name, "qqqai/telemetry");
        assert_eq!(c.kind, ChangeKind::Updated);
        assert_eq!(c.from.as_deref(), Some("1.0.0"));
        assert_eq!(c.to.as_deref(), Some("1.0.1"));
        assert_eq!(c.caps_added, vec!["http.client"]);
        assert!(c.caps_removed.is_empty());
        assert!(c.grants_new_authority());

        assert!(diff.has_escalation());
        assert_eq!(diff.total_added(), 1);
        assert_eq!(diff.capability_changes.len(), 1);
        assert!(diff.capability_changes[0].is_escalation());
    }

    /// And the converse: a plain version bump must **not** be reported as an
    /// escalation. A tool that cries wolf about authority is worse than one that
    /// says nothing, because the real event gets buried.
    #[test]
    fn a_plain_version_bump_is_not_an_escalation() {
        let before = lock(vec![pkg("x", "1.0.0", &["clock.monotonic"])]);
        let after = lock(vec![pkg("x", "1.0.1", &["clock.monotonic"])]);

        let diff = LockDiff::compute(&before, &after);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].kind, ChangeKind::Updated);
        assert!(!diff.changes[0].grants_new_authority());
        assert!(!diff.has_escalation());
        assert!(diff.capability_changes.is_empty());
    }

    /// **The case that has no version change at all.** A lockfile whose
    /// capabilities changed while the version stayed the same is the most
    /// suspicious shape there is: something edited the resolution without
    /// publishing a new version.
    #[test]
    fn an_authority_change_without_a_version_change_is_reported() {
        let before = lock(vec![pkg("x", "1.0.0", &[])]);
        let after = lock(vec![pkg("x", "1.0.0", &["fs.write"])]);

        let diff = LockDiff::compute(&before, &after);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].kind, ChangeKind::ModifiedInPlace);
        assert_eq!(diff.changes[0].caps_added, vec!["fs.write"]);
        assert!(diff.has_escalation());
    }

    #[test]
    fn a_removed_capability_is_reported_but_is_not_an_escalation() {
        let before = lock(vec![pkg("x", "1.0.0", &["http.client", "fs.read"])]);
        let after = lock(vec![pkg("x", "1.0.0", &["fs.read"])]);

        let diff = LockDiff::compute(&before, &after);
        assert_eq!(diff.changes[0].caps_removed, vec!["http.client"]);
        assert!(diff.changes[0].caps_added.is_empty());
        assert!(
            !diff.has_escalation(),
            "losing authority is not an escalation"
        );
        assert_eq!(diff.total_removed(), 1);
        assert_eq!(diff.total_added(), 0);
    }

    /// An added package's capabilities are all reported as added: there was no
    /// prior state in which they were absent-but-allowed.
    #[test]
    fn a_new_package_reports_all_its_capabilities_as_added() {
        let before = lock(vec![]);
        let after = lock(vec![pkg("new", "1.0.0", &["http.client", "crypto.hash"])]);

        let diff = LockDiff::compute(&before, &after);
        assert_eq!(diff.changes[0].kind, ChangeKind::Added);
        assert_eq!(diff.changes[0].caps_added.len(), 2);
        assert!(diff.has_escalation());
    }

    #[test]
    fn a_removed_package_is_reported_as_removed() {
        let before = lock(vec![pkg("gone", "1.0.0", &["http.client"])]);
        let after = lock(vec![]);

        let diff = LockDiff::compute(&before, &after);
        assert_eq!(diff.changes[0].kind, ChangeKind::Removed);
        assert_eq!(diff.changes[0].from.as_deref(), Some("1.0.0"));
        assert!(diff.changes[0].to.is_none());
        // Removing a dependency is not an escalation.
        assert!(!diff.has_escalation());
        // But its authority is gone, and the totals count what is gone.
        assert_eq!(diff.changes[0].caps_removed, vec!["http.client"]);
        assert_eq!(diff.total_removed(), 1);
    }

    /// An unchanged lockfile must produce an **empty** diff, not a list of
    /// no-op entries.
    #[test]
    fn an_identical_lockfile_produces_no_changes() {
        let a = lock(vec![
            pkg("x", "1.0.0", &["clock.monotonic"]),
            pkg("y", "2.0.0", &[]),
        ]);
        let b = a.clone();
        let diff = LockDiff::compute(&a, &b);
        assert!(diff.is_empty());
        assert!(!diff.has_escalation());
        assert_eq!(diff.total_added(), 0);
    }

    /// **Why the diff keys on name rather than name-and-version.** Keying on the
    /// pair would report every update as a removal plus an addition, losing the
    /// fact that it is the same dependency — which is the continuity the
    /// capability diff depends on.
    #[test]
    fn an_update_is_one_change_not_an_addition_and_a_removal() {
        let before = lock(vec![pkg("x", "1.0.0", &[])]);
        let after = lock(vec![pkg("x", "2.0.0", &[])]);

        let diff = LockDiff::compute(&before, &after);
        assert_eq!(
            diff.changes.len(),
            1,
            "an update must be one change, got {:?}",
            diff.changes
        );
        assert_eq!(diff.changes[0].kind, ChangeKind::Updated);
    }

    #[test]
    fn changes_are_sorted_by_package_name() {
        let before = lock(vec![]);
        let after = lock(vec![
            pkg("zebra", "1.0.0", &[]),
            pkg("apple", "1.0.0", &[]),
            pkg("mango", "1.0.0", &[]),
        ]);
        let diff = LockDiff::compute(&before, &after);
        let names: Vec<&str> = diff.changes.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["apple", "mango", "zebra"]);
    }

    /// A build-config-only change moves the hash but touches no package: the
    /// diff must still report it, or `is_empty` would be true while the hash
    /// moved.
    #[test]
    fn a_build_config_change_is_reported_despite_no_package_change() {
        let before = base_lock();
        let mut after = base_lock();
        after.metadata.build = Some(BuildConfig::new("rust", "wasm32-wasip2", "debug"));

        let diff = LockDiff::compute(&before, &after);
        assert!(diff.build_changed);
        assert!(
            !diff.is_empty(),
            "a hash-moving change is not an empty diff"
        );
        assert!(diff.changes.is_empty());
        assert!(!diff.has_escalation());
    }

    /// Hand-built order does not move the hash: `compute_hash` sorts a copy,
    /// so insertion order is not part of the digest.
    #[test]
    fn insertion_order_does_not_move_the_hash() {
        let mut a = Lockfile::new();
        a.packages = vec![pkg("b", "1.0.0", &[]), pkg("a", "1.0.0", &[])];
        let mut b = Lockfile::new();
        b.packages = vec![pkg("a", "1.0.0", &[]), pkg("b", "1.0.0", &[])];
        assert_eq!(a.compute_hash(), b.compute_hash());
    }

    /// Whitespace-only fields normalise away, and blank capabilities drop:
    /// `[" "]` grants nothing and must compare — and hash — like `[]`.
    #[test]
    fn blank_fields_normalise_to_absent() {
        let mut l = lock(vec![pkg("x", "1.0.0", &[" ", "http.client"])]);
        l.packages[0].source = Some("   ".to_owned());
        l.normalise();
        assert!(l.packages[0].source.is_none());
        assert_eq!(l.packages[0].caps, vec!["http.client"]);
    }

    /// Semver-aware sort: `1.10` follows `1.9`, which lexicographic order
    /// gets backwards.
    #[test]
    fn versions_sort_numerically_not_lexicographically() {
        let l = lock(vec![
            pkg("x", "1.10.0", &[]),
            pkg("x", "1.9.0", &[]),
            pkg("x", "1.2.0", &[]),
        ]);
        let versions: Vec<&str> = l.packages.iter().map(|p| p.version.as_str()).collect();
        assert_eq!(versions, vec!["1.2.0", "1.9.0", "1.10.0"]);
    }

    /// The capability change list must be derived from the change list, so the
    /// two cannot disagree. A `caps_added` entry that did not appear in
    /// `capability_changes` would be a supply-chain event nobody was shown.
    #[test]
    fn every_authority_change_appears_in_the_capability_list() {
        let before = lock(vec![pkg("a", "1.0.0", &["x"]), pkg("b", "1.0.0", &[])]);
        let after = lock(vec![
            pkg("a", "1.0.0", &["x", "y"]),
            pkg("b", "1.0.0", &[]),
            pkg("c", "1.0.0", &["z"]),
        ]);

        let diff = LockDiff::compute(&before, &after);
        let with_authority: Vec<&str> = diff
            .changes
            .iter()
            .filter(|c| !c.caps_added.is_empty() || !c.caps_removed.is_empty())
            .map(|c| c.name.as_str())
            .collect();
        let reported: Vec<&str> = diff
            .capability_changes
            .iter()
            .map(|d| d.package.as_str())
            .collect();
        assert_eq!(with_authority, reported);
        assert_eq!(reported, vec!["a", "c"]);
    }

    #[test]
    fn change_kind_names_are_stable() {
        assert_eq!(ChangeKind::Added.as_str(), "added");
        assert_eq!(ChangeKind::Removed.as_str(), "removed");
        assert_eq!(ChangeKind::Updated.as_str(), "updated");
        assert_eq!(ChangeKind::ModifiedInPlace.as_str(), "modified-in-place");
    }

    /// A digest swap with no version or capability change must still be
    /// reported: it is the shape of an artifact substitution.
    #[test]
    fn a_digest_swap_is_reported_as_a_modified_in_place() {
        let mut before = lock(vec![pkg("x", "1.0.0", &[])]);
        before.packages[0].digest = Some(format!("sha256:{}", "aa".repeat(32)));
        let mut after = lock(vec![pkg("x", "1.0.0", &[])]);
        after.packages[0].digest = Some(format!("sha256:{}", "bb".repeat(32)));

        let diff = LockDiff::compute(&before, &after);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].kind, ChangeKind::ModifiedInPlace);
        assert!(
            diff.changes[0].caps_added.is_empty(),
            "a digest swap grants no authority"
        );
        // And the record says *what* changed: bytes, not paperwork.
        assert!(diff.changes[0].digest_changed);
        assert!(!diff.changes[0].license_changed);
        assert!(!diff.changes[0].is_license_only());
    }

    /// A licence-only edit is a modification in place, but flagged as
    /// paperwork — distinguishable from a digest swap, which moves bytes.
    #[test]
    fn a_license_edit_is_flagged_as_paperwork_not_substitution() {
        let mut before = lock(vec![pkg("x", "1.0.0", &[])]);
        before.packages[0].license = Some("MIT".to_owned());
        let mut after = lock(vec![pkg("x", "1.0.0", &[])]);
        after.packages[0].license = Some("Apache-2.0".to_owned());

        let diff = LockDiff::compute(&before, &after);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].kind, ChangeKind::ModifiedInPlace);
        assert!(diff.changes[0].is_license_only());
        assert!(!diff.changes[0].digest_changed);
        assert!(!diff.changes[0].grants_new_authority());
    }

    /// A `wit`-only swap is a composition break, not paperwork: flagged by
    /// `wit_changed`, excluded from `is_license_only`.
    #[test]
    fn a_wit_swap_is_flagged_as_an_interface_change() {
        let mut before = lock(vec![pkg("x", "1.0.0", &[])]);
        before.packages[0].wit = Some(format!("sha256:{}", "aa".repeat(32)));
        let mut after = lock(vec![pkg("x", "1.0.0", &[])]);
        after.packages[0].wit = Some(format!("sha256:{}", "bb".repeat(32)));

        let diff = LockDiff::compute(&before, &after);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].kind, ChangeKind::ModifiedInPlace);
        assert!(diff.changes[0].wit_changed);
        assert!(!diff.changes[0].digest_changed);
        assert!(!diff.changes[0].is_license_only());
    }
    // -- The build config the hash covers — CON-005 ------------------------

    /// A base lockfile with one package that has a digest.
    ///
    /// The digest is set through the field rather than a `with_digest` builder,
    /// because `LockPackage` has none — the existing tests in this module do the
    /// same, and adding a builder purely for a fixture would be a public API
    /// change made to serve a test.
    fn base_lock() -> Lockfile {
        let mut l = Lockfile::new();
        let mut pkg = LockPackage::new("qqqai/telemetry", "1.0.0");
        pkg.digest = Some(format!("sha256:{}", "aa".repeat(32)));
        l.push(pkg);
        l
    }

    /// **The point of the item: config is part of the hash.**
    ///
    /// Before this, two builds from one lockfile with different `[build]`
    /// settings produced the same hash while producing different artifacts —
    /// silent where §5.4 promises to be loud.
    #[test]
    fn the_hash_covers_the_build_config() {
        let plain = base_lock();
        let configured = {
            let mut l = base_lock();
            l.metadata.build = Some(BuildConfig::new("rust", "wasm32-wasip2", "release"));
            l
        };
        assert_ne!(
            plain.compute_hash(),
            configured.compute_hash(),
            "recording a build config must change the hash"
        );
    }

    /// Each config field participates independently, so a change to any one is
    /// caught. A hash covering only, say, the profile would let a target change
    /// through.
    #[test]
    fn every_config_field_participates_in_the_hash() {
        let make = |c: BuildConfig| {
            let mut l = base_lock();
            l.metadata.build = Some(c);
            l.compute_hash()
        };
        let base = make(BuildConfig::new("rust", "wasm32-wasip2", "release"));
        for variant in [
            BuildConfig::new("ts", "wasm32-wasip2", "release"),
            BuildConfig::new("rust", "wasm32-wasip1", "release"),
            BuildConfig::new("rust", "wasm32-wasip2", "debug"),
        ] {
            assert_ne!(
                base,
                make(variant.clone()),
                "a config change must move the hash: {variant:?}"
            );
        }

        // And the caps list inside the config.
        let with_caps =
            make(BuildConfig::new("rust", "wasm32-wasip2", "release").with_caps(["http.client"]));
        assert_ne!(base, with_caps, "the config's caps must be covered");
    }

    /// **Backward compatibility, which is the decision that mattered most.**
    ///
    /// A lockfile written before this field existed has `build: None` and must
    /// keep the exact digest it had. Otherwise every project in the world
    /// reports as dirty the moment it upgrades.
    #[test]
    fn a_lockfile_without_config_hashes_exactly_as_before() {
        let l = base_lock();
        assert!(l.metadata.build.is_none());

        // An explicitly empty config must ALSO hash the same, because `None` and
        // `Some(empty)` describe the same absence. `skip_serializing_if` means
        // an empty one is not even written, so the two round-trip identically.
        let mut empty = base_lock();
        empty.metadata.build = Some(BuildConfig::default());
        assert!(
            empty.metadata.build.as_ref().expect("set").is_empty(),
            "the fixture must be empty"
        );

        // The two differ only in the in-memory Option, and the hash folds in
        // nothing for either -- because the `if let Some` arm hashes the
        // *contents*, and empty contents hash as the separators alone.
        // Pin the relationship explicitly rather than assuming it.
        let none_hash = l.compute_hash();
        let empty_hash = empty.compute_hash();
        assert_eq!(
            none_hash, empty_hash,
            "`None` and an empty config must agree, or a lockfile would change \
             hash merely by being re-serialised"
        );
    }

    /// Hashing is stable across a config's `caps` reordering, for the same
    /// reason it is stable across a package's.
    #[test]
    fn the_hash_is_stable_across_config_capability_reordering() {
        let make = |caps: Vec<&str>| {
            let mut l = base_lock();
            l.metadata.build =
                Some(BuildConfig::new("rust", "wasm32-wasip2", "release").with_caps(caps));
            l.compute_hash()
        };
        assert_eq!(
            make(vec!["http.client", "sql.query"]),
            make(vec!["sql.query", "http.client"]),
            "a sorted, deduplicated set must hash identically"
        );
    }

    /// The config must not be confusable with a package record: a config whose
    /// caps spell a package's fields must not collide.
    #[test]
    fn the_config_group_is_separated_from_the_package_records() {
        let make = |build: BuildConfig| {
            let mut l = base_lock();
            l.metadata.build = Some(build);
            l.compute_hash()
        };
        // A config whose three fields concatenate to something a package could
        // also spell must still differ, because of the group separator.
        assert_ne!(
            make(BuildConfig::new("ab", "c", "d")),
            make(BuildConfig::new("a", "bc", "d")),
            "config fields must be unambiguously delimited"
        );
    }

    /// A config round-trips through TOML, so the hash a lockfile records is the
    /// hash a reader recomputes.
    #[test]
    fn a_build_config_round_trips_through_toml() {
        let mut l = base_lock();
        l.metadata.build =
            Some(BuildConfig::new("rust", "wasm32-wasip2", "release").with_caps(["http.client"]));
        l.stamp("qqqai 1.0.0");
        let text = toml::to_string(&l).expect("must serialise");
        assert!(text.contains("[metadata.build]"), "{text}");
        assert!(text.contains("language = \"rust\""), "{text}");

        let back = Lockfile::parse(&text).expect("must parse");
        assert_eq!(back.metadata.build, l.metadata.build);
        assert_eq!(
            back.compute_hash(),
            l.compute_hash(),
            "a round trip must not move the hash"
        );
    }

    /// A config with an unknown key is refused, so a typo cannot silently
    /// contribute nothing to the hash while looking recorded.
    #[test]
    fn an_unknown_config_key_is_refused() {
        // No `[lock]` header: the only error source must be the typo'd key,
        // or the test passes for the wrong reason.
        let text = format!(
            "version = {LOCK_VERSION}\n\n[metadata.build]\nlanguage = \"rust\"\nlangauge = \"ts\"\n"
        );
        let err = Lockfile::parse(&text).expect_err("must refuse");
        assert!(matches!(err, LockfileError::Syntax(_)), "{err:?}");
    }

    /// A package with an unknown field is refused: a newer writer's new
    /// field must force a version bump, not slide past an old reader.
    /// This is the forward-compatibility half of `REG-011` (the version half
    /// is `an_unsupported_version_is_refused_rather_than_ignored`).
    #[test]
    fn an_unknown_package_field_is_refused() {
        let text = format!(
            "version = {LOCK_VERSION}\n\n\
             [[package]]\nname = \"x\"\nversion = \"1.0.0\"\nbogus = true\n"
        );
        let err = Lockfile::parse(&text).expect_err("must refuse");
        assert!(matches!(err, LockfileError::Syntax(_)), "{err:?}");
    }

    /// `is_empty` must agree with what serialisation omits, or a lockfile could
    /// write a `[metadata.build]` table that contributes nothing.
    #[test]
    fn an_empty_config_is_recognised_as_empty() {
        assert!(BuildConfig::default().is_empty());
        assert!(!BuildConfig::new("rust", "t", "p").is_empty());
        assert!(!BuildConfig::default().with_caps(["a"]).is_empty());
    }

    /// `with_caps` normalises, so it cannot be used to smuggle a duplicate in.
    #[test]
    fn with_caps_sorts_and_deduplicates() {
        let c = BuildConfig::default().with_caps(["b", "a", "b"]);
        assert_eq!(c.caps, vec!["a".to_owned(), "b".to_owned()]);
    }
}
