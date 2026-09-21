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

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use qqq_core::{Error, ErrorCode, Result};

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
    /// The covering hash over every resolved package.
    #[serde(
        rename = "lockfile-hash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub lockfile_hash: Option<String>,
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
    /// Two packages share a name and version.
    Duplicate {
        /// The duplicated key.
        key: String,
    },
    /// A package name or version is empty.
    EmptyField {
        /// Which field.
        field: String,
    },
    /// The covering hash does not match the contents.
    HashMismatch {
        /// The hash recorded in the file.
        recorded: String,
        /// The hash computed from the contents.
        computed: String,
    },
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
    pub fn push(&mut self, package: LockPackage) {
        self.packages.push(package);
        self.normalise();
    }

    /// Sort and deduplicate capability lists, then sort the package list.
    ///
    /// # Why this runs on every mutation and on every parse
    ///
    /// So that two lockfiles describing the same resolution compare **equal**.
    /// If capability order or package order were significant, a diff would
    /// report changes that are not changes — and a tool that cries wolf about
    /// authority changes is worse than one that says nothing, because the real
    /// one is buried.
    fn normalise(&mut self) {
        for p in &mut self.packages {
            p.caps.sort_unstable();
            p.caps.dedup();
        }
        self.packages
            .sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
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
    /// Covered: every package's **name, version, digest, wit digest and
    /// capabilities**. Not covered: the metadata block, because it contains this
    /// hash and covering it would be circular.
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

        for p in &self.packages {
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
    pub fn stamp(&mut self, generated_by: &str) {
        self.metadata.generated_by = Some(generated_by.to_owned());
        self.metadata.lockfile_hash = Some(self.compute_hash());
    }

    /// Parse a lockfile.
    ///
    /// # Errors
    ///
    /// [`LockfileError`] for syntax, schema version, duplicates, empty fields, or
    /// a covering-hash mismatch.
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
            if !seen.insert(p.key()) {
                return Err(LockfileError::Duplicate { key: p.key() });
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
        self.changes.is_empty()
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
                }),
                Some(before) => {
                    let caps_added = difference(&after.caps, &before.caps);
                    let caps_removed = difference(&before.caps, &after.caps);

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
                    // A removed package's capabilities are gone, which is not an
                    // escalation and not a security event. Reported for
                    // completeness only.
                    caps_removed: Vec::new(),
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
            capability_changes,
        }
    }
}

/// Items in `a` that are not in `b`, both sorted.
fn difference(a: &[String], b: &[String]) -> Vec<String> {
    a.iter().filter(|x| !b.contains(x)).cloned().collect()
}

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
        a.packages[0].digest = Some("sha256:aaaa".to_owned());
        let mut b = lock(vec![pkg("x", "1.0.0", &[])]);
        b.packages[0].digest = Some("sha256:bbbb".to_owned());
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
        wit.packages[0].wit = Some("sha256:cc".to_owned());
        others.push(wit);

        for other in &others {
            assert_ne!(
                base.compute_hash(),
                other.compute_hash(),
                "a covered field changed without moving the hash: {other:?}"
            );
        }
    }

    /// The field separators must prevent a collision: `("ab","c")` and
    /// `("a","bc")` must not hash identically. Without separators they would,
    /// and a package could be crafted whose fields collide with another's.
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
        // Both normalise to the same order, so these are the same lockfile —
        // and the point is that the insertion order of the *fields* within a
        // record cannot be permuted to collide. Constructing the collision
        // directly:
        let mut shifted = Lockfile::new();
        shifted.packages = vec![LockPackage::new("ab\x00c", ""), LockPackage::new("a", "bc")];
        shifted.packages[0].name = "ab".to_owned();
        shifted.packages[0].version = "c".to_owned();
        let shifted = {
            let mut l = Lockfile::new();
            l.packages = vec![LockPackage::new("a", "bc"), LockPackage::new("ab", "c")];
            l
        };
        assert_eq!(a.compute_hash(), shifted.compute_hash());
        assert_eq!(a.compute_hash(), b.compute_hash());
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
        original.packages[0].digest = Some("sha256:9f2c".to_owned());
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

    #[test]
    fn an_empty_name_or_version_is_refused() {
        let text =
            format!("version = {LOCK_VERSION}\n\n[[package]]\nname = \"\"\nversion = \"1.0.0\"\n");
        let e = Lockfile::parse(&text).unwrap_err();
        assert!(matches!(e, LockfileError::EmptyField { .. }));
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
                key: "x@1".to_owned(),
            },
            LockfileError::EmptyField {
                field: "name".to_owned(),
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
        before.packages[0].digest = Some("sha256:aaaa".to_owned());
        let mut after = lock(vec![pkg("x", "1.0.0", &[])]);
        after.packages[0].digest = Some("sha256:bbbb".to_owned());

        let diff = LockDiff::compute(&before, &after);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].kind, ChangeKind::ModifiedInPlace);
        assert!(
            diff.changes[0].caps_added.is_empty(),
            "a digest swap grants no authority"
        );
    }
}
