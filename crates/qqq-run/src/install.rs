// SPDX-License-Identifier: Apache-2.0

//! `qqqai install` — resolve the manifest's dependencies, write `qqq.lock`, and
//! report the capability diff.
//!
//! Implements `CLI-006`; Proposal §5.2 (command table) and §5.4 (the capability
//! diff).
//!
//! # What this command is for, stated honestly
//!
//! §5.4 makes a specific claim, and it is the reason this module exists before
//! the registry does:
//!
//! > *"`caps` is recorded per dependency. `qqqai install` prints a **capability
//! > diff** — 'this update adds `http.client` to `qqqai/telemetry`'.
//! > Supply-chain attacks today hide in code; here the **authority** delta is
//! > visible in the diff."*
//!
//! So the deliverable is not "download packages". It is **showing what an
//! install does to the project's authority**. A version bump that changes no
//! code but gains `http.client` is a supply-chain event, and this command is
//! where it becomes visible.
//!
//! # The registry is not reachable, and this says so
//!
//! There is no registry yet (`PKG-006`), so there is nothing to fetch. Rather
//! than pretend, this command does the half that is real and is precise about
//! the half that is not:
//!
//! * It **resolves** the manifest against the lockfile, which is real work.
//! * It **prints the capability diff** of what would change, which is the
//!   feature §5.4 names.
//! * It **fails** with `QQQ-5001` naming the package it could not fetch, rather
//!   than writing a lockfile that claims packages exist.
//! * Under `--offline` it **places** every pinned package from the local store
//!   into `.qqq/packages` (PKG-014) — digest-verified, atomic per package.
//!   Name and coverage failures place nothing; a failure mid-placement aborts
//!   loud with earlier verified placements left in place (see
//!   [`install_offline`]). New versions still need the registry
//!   (PKG-002); the store only serves what is already in it.
//!
//! Writing a lockfile listing packages that were never fetched would be the
//! worst outcome available: the next command would trust it, and a
//! content-addressed store would report a digest it has never seen. A lockfile
//! is a promise about bytes, and this command does not make promises it cannot
//! keep.
//!
//! # `--locked`, `--frozen` and `--offline`
//!
//! The three flags are related and are easy to conflate, so the distinctions
//! are explicit:
//!
//! | Flag | Missing lockfile | Lockfile out of date | Would write |
//! |---|---|---|---|
//! | *(none)* | resolve | re-resolve and update | yes |
//! | `--locked` | **error** | **error** | no |
//! | `--frozen` | **error** | **error** | no, and no network |
//! | `--offline` | resolve the pins, place from the store | re-resolve the pins, place from the store | yes |
//!
//! `--locked` answers "does the committed lockfile match this manifest?" — the
//! question CI asks. `--frozen` is `--locked` plus "and do not touch the
//! network", for an air-gapped build. `--offline` is different in kind: it
//! permits resolution but forbids fetching, which is why it is not a synonym.
//!
//! Combined flags resolve by strictness (`LockMode::max`): `--frozen --offline`
//! is a frozen run — it verifies the lockfile is current and places nothing,
//! even with a populated store. That is the verify-only contract doing its
//! job, not a skipped step: placing packages writes files, and frozen writes
//! nothing.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use qqq_core::{Error, ErrorCode, Result};
use qqq_pkg::{
    LockDiff, LockPackage, Lockfile,
    store::{Digest, LinkMethod, StoreLayout},
};

/// How strictly `install` treats the lockfile and the network.
///
/// An enum rather than three booleans because the flags are **ordered by
/// strictness**, and independent booleans let a caller construct a
/// contradiction — `frozen` without `locked`, or `frozen` *and* `offline` meaning
/// two different things at once. With one value those states cannot be
/// expressed, which is a stronger guarantee than validating them at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockMode {
    /// Resolve, fetch if needed, and update the lockfile.
    #[default]
    Update,
    /// Resolve and write, but do not touch the network.
    Offline,
    /// The lockfile must already be correct; fail otherwise, and write nothing.
    Locked,
    /// `Locked` plus no network at all, for an air-gapped build.
    Frozen,
}

impl LockMode {
    /// A rank ordered by strictness, so flags can be combined by taking the
    /// strictest.
    ///
    /// Explicit rather than derived from declaration order: `#[derive(Ord)]`
    /// would make the semantics depend on which line the variants happen to sit
    /// on, and reordering them for readability would silently change what
    /// `--frozen --offline` means. `Frozen` is strictest, then `Locked`, then
    /// `Offline`, then `Update`.
    const fn strictness(self) -> u8 {
        match self {
            Self::Update => 0,
            Self::Offline => 1,
            Self::Locked => 2,
            Self::Frozen => 3,
        }
    }

    /// The stricter of two modes.
    #[must_use]
    pub const fn max(self, other: Self) -> Self {
        if other.strictness() > self.strictness() {
            other
        } else {
            self
        }
    }

    /// The stable name, for JSON and messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Offline => "offline",
            Self::Locked => "locked",
            Self::Frozen => "frozen",
        }
    }

    /// Whether the lockfile may be written in this mode.
    #[must_use]
    pub const fn may_write(self) -> bool {
        matches!(self, Self::Update | Self::Offline)
    }

    /// Whether the network is forbidden.
    #[must_use]
    pub const fn forbids_network(self) -> bool {
        matches!(self, Self::Offline | Self::Frozen)
    }

    /// Whether the existing lockfile must already be correct.
    #[must_use]
    pub const fn requires_current(self) -> bool {
        matches!(self, Self::Locked | Self::Frozen)
    }
}

/// How `install` should behave. Decoded from flags by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InstallOptions {
    /// How the lockfile and the network are treated.
    pub mode: LockMode,
    /// Report what would happen without writing anything.
    pub dry_run: bool,
    /// Re-resolve from scratch, ignoring the existing lockfile's pins.
    pub force: bool,
}

impl InstallOptions {
    /// Whether the lockfile may be written.
    ///
    /// A dry run never writes, whatever the mode says. That is the one place a
    /// boolean and a mode interact, and it is handled here so no caller has to
    /// remember it.
    #[must_use]
    pub const fn may_write(self) -> bool {
        self.mode.may_write() && !self.dry_run
    }

    /// Whether the old lockfile pins the resolution.
    ///
    /// A force-reinstall ignores the pins deliberately; everything else prefers
    /// them, because a lockfile exists to make an install reproducible and
    /// silently re-resolving would defeat that.
    #[must_use]
    pub const fn honours_lockfile(self) -> bool {
        !self.force
    }
}

/// The outcome of a resolution, before anything is fetched.
#[derive(Debug, Clone)]
pub struct Resolution {
    /// What the lockfile would contain.
    pub lockfile: Lockfile,
    /// What changes relative to the lockfile on disk. Empty on a first install.
    pub diff: LockDiff,
    /// Dependencies present in the manifest but absent from the lockfile.
    pub unresolved: Vec<String>,
}

/// Where a project's lockfile lives: beside its manifest.
#[must_use]
pub fn lockfile_path(manifest_path: &Path) -> PathBuf {
    manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("qqq.lock")
}

/// Read the lockfile, if there is one.
///
/// A malformed lockfile is an **error**, never silently ignored and rewritten:
/// the file records the authority every package was resolved with, and a
/// command that discards it because it could not be read would erase the
/// evidence of what changed (`§O-033a` in a different guise).
///
/// # Errors
///
/// `QQQ-5003` when the file exists but does not parse or fails its covering
/// hash.
pub fn read_lockfile(path: &Path) -> Result<Option<Lockfile>> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::new(
            ErrorCode::LockfileOutOfDate,
            format!("could not read `{}`", path.display()),
        )
        .with_cause(e.to_string())
    })?;
    let lock = Lockfile::parse(&text).map_err(|e| e.to_error())?;
    Ok(Some(lock))
}

/// Resolve the manifest's dependencies against an existing lockfile.
///
/// # What "resolve" means here, exactly
///
/// With no registry, the only inputs are the manifest and the lockfile. So this
/// function answers a precise question: **which manifest dependencies does the
/// lockfile already pin, and what would change?** It does not invent versions
/// for packages it has never seen — it records them as `unresolved` and lets the
/// caller decide, because guessing a version is how a lockfile ends up
/// describing something that does not exist.
///
/// `previous` being `None` is a first install, and then every manifest
/// dependency is unresolved.
///
/// # `declared_caps`: why this parameter exists, and the defect it repairs
///
/// Earlier, the carried-forward pin was pushed with `pinned.clone()`, so the
/// **recorded** capabilities were copied verbatim into the new lockfile. The
/// subsequent `LockDiff::compute(old, &next)` then compared a package's recorded
/// caps against *the same recorded caps*, and `caps_added` was **structurally
/// always empty** — which means `SEC-015`'s whole purpose was unreachable:
/// `escalation` could never become `true`, and a CI gate branching on it would
/// pass every supply-chain event silently.
///
/// A real escalation is "the authority this dependency needs **now** differs from
/// the authority recorded in the lockfile". That comparison needs a source of
/// truth for "now" which is not the lockfile, and the only such source is the
/// manifest. So `declared_caps` supplies each dependency's currently declared
/// capabilities, and the new lockfile records **those** rather than the old ones.
///
/// # Why the argument is a slice of triples rather than a map
///
/// Because the caller already has the manifest's dependency list in order
/// (`BTreeMap` iteration), and a map here would be a third representation of the
/// same data. The slice keeps the function's input shape identical to the
/// manifest's own iteration and makes the call site a straight pass-through.
#[must_use]
pub fn resolve(
    manifest_deps: &[(String, String, Vec<String>)],
    previous: Option<&Lockfile>,
) -> Resolution {
    let mut next = Lockfile::new();
    let mut unresolved = Vec::new();

    for (name, requirement, declared_caps) in manifest_deps {
        match previous.and_then(|l| l.get(name)) {
            Some(pinned) => {
                // Verify the pin still satisfies the manifest. A manifest edited
                // to demand `2.0` while the lockfile pins `1.2` is a lockfile
                // that must change, and carrying the pin across would make
                // `--locked` pass on a state that is wrong.
                if satisfies(requirement, &pinned.version) {
                    // **Carry the version, but RE-DERIVE the capabilities.**
                    //
                    // A full clone would carry the recorded caps and make the
                    // diff vacuous (see the doc above). The rest of the pinned
                    // record — digest, license, source — is genuinely the
                    // lockfile's business and is carried as-is: those describe
                    // *the bytes that were fetched*, and a re-resolution that
                    // changed them would be inventing a different artifact.
                    //
                    // When the manifest declares no capabilities for a
                    // dependency, the recorded set is preserved rather than
                    // cleared. Clearing it would report every previously-recorded
                    // capability as "removed", which is a false *de*-escalation —
                    // alarming in the opposite direction, and just as wrong.
                    let mut updated = pinned.clone();
                    if !declared_caps.is_empty() {
                        // Sorted and deduplicated, because the lockfile is
                        // compared byte-for-byte by `compute_hash` and read by
                        // `LockDiff`. An unsorted declaration would make two
                        // semantically identical lockfiles hash differently, which
                        // is the property `lockfile-hash` exists to guarantee.
                        //
                        // `clone_from` rather than `=` so the existing allocation
                        // is reused; clippy's `assigning_clones` is right that the
                        // assignment form allocates for nothing.
                        updated.caps.clone_from(declared_caps);
                        updated.caps.sort_unstable();
                        updated.caps.dedup();
                    }
                    next.push(updated);
                } else {
                    unresolved.push(name.clone());
                }
            }
            None => unresolved.push(name.clone()),
        }
    }

    let diff = match previous {
        Some(old) => LockDiff::compute(old, &next),
        None => LockDiff::compute(&Lockfile::new(), &next),
    };

    Resolution {
        lockfile: next,
        diff,
        unresolved,
    }
}

/// Whether `version` satisfies `requirement`.
///
/// A requirement that cannot be parsed does not satisfy anything. Returning
/// `true` on a parse failure would let a malformed requirement silently keep a
/// stale pin, which is the opposite of the intent.
fn satisfies(requirement: &str, version: &str) -> bool {
    let Ok(req) = qqq_pkg::Requirement::parse(requirement) else {
        return false;
    };
    let Ok(v) = version.parse::<qqq_pkg::Version>() else {
        return false;
    };
    req.matches(&v)
}

/// Create a `LockPackage` for a dependency the registry would provide.
///
/// Used by tests and by the future registry path; kept here so the shape of a
/// resolved package is defined in one place.
#[must_use]
pub fn package_for(name: &str, version: &str, caps: &[&str]) -> LockPackage {
    LockPackage::new(name, version).with_caps(caps.iter().copied())
}

// ---------------------------------------------------------------------------
// PKG-014: `install --offline` from the local store
// ---------------------------------------------------------------------------

/// The environment variable overriding the store root.
///
/// Private: the contract callers rely on is [`default_store_dir`]'s documented
/// precedence, not this spelling in isolation — and the remediation text below
/// already names it where a user needs to read it.
const STORE_DIR_ENV: &str = "QQQ_STORE_DIR";

/// The project-relative directory materialized packages land in.
///
/// A hidden directory beside `qqq.toml` rather than a shared cache, so a
/// project carries its own inputs and deleting the directory is a clean
/// uninstall. Scoped names (`qqqai/json`) become subdirectories, which is why
/// [`package_dest`] validates every segment.
const PACKAGES_DIR: &str = ".qqq/packages";

/// Resolve the store root from an explicit override and a home profile.
///
/// Pure so tests drive it without touching the process environment — parallel
/// tests sharing one environment would race on set/remove. [`default_store_dir`]
/// reads the real environment and delegates here.
///
/// * `store_env` — the value of `QQQ_STORE_DIR`, used as-is when present, so
///   tests and operators can point at a scratch store without touching the
///   profile.
/// * `home` — `%USERPROFILE%`/`$HOME`, holding `.qqq/store` when no override
///   is set. `None` means neither is known: there is no store to use, and the
///   caller fails closed naming both variables rather than inventing a
///   relative store beside whatever the working directory happens to be.
///
/// ```
/// use std::ffi::OsStr;
/// use qqq_run::install::store_root_from;
///
/// // An explicit override is used as-is, whatever the profile says.
/// assert_eq!(
///     store_root_from(Some(OsStr::new("/s")), Some(OsStr::new("/h"))),
///     Some(std::path::PathBuf::from("/s"))
/// );
/// // Otherwise the store lives under the home profile.
/// assert_eq!(
///     store_root_from(None, Some(OsStr::new("/h"))),
///     Some(std::path::PathBuf::from("/h/.qqq/store"))
/// );
/// // With neither known there is no store to use.
/// assert_eq!(store_root_from(None, None), None);
/// ```
#[must_use]
pub fn store_root_from(store_env: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    // An explicitly empty override (`QQQ_STORE_DIR=""`) is not a root: it
    // would resolve relative to the working directory, which is ambient state
    // a placement path must never depend on. Same for an empty home.
    if let Some(dir) = store_env.filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    home.filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".qqq").join("store"))
}

/// Where `install --offline` resolves the store from.
///
/// `QQQ_STORE_DIR` wins when it is set; otherwise the store lives under the
/// home profile (`%USERPROFILE%` first, mirroring the toolchain lookup, then
/// `$HOME`). `None` means neither is known — the caller fails closed rather
/// than materializing beside the working directory.
#[must_use]
pub fn default_store_dir() -> Option<PathBuf> {
    let non_empty = |key: &str| std::env::var_os(key).filter(|s| !s.is_empty());
    let home = non_empty("USERPROFILE").or_else(|| non_empty("HOME"));
    store_root_from(std::env::var_os(STORE_DIR_ENV).as_deref(), home.as_deref())
}

/// Map a package name to its destination under the project.
///
/// A name is a relative path under `.qqq/packages`: `qqqai/json` becomes
/// `.qqq/packages/qqqai/json`. Every segment is validated because the lockfile
/// is an input — a name containing `..` (or a separator smuggled past the
/// check as `\`) must be refused rather than followed out of the directory.
///
/// # Errors
///
/// `QQQ-5006` when the name is empty or any segment is empty, `.`, `..`, or
/// contains a backslash. The error names the package: the lockfile pin is
/// suspect, and the remediation says to re-resolve it.
fn package_dest(project_dir: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.contains('\\') {
        return Err(Error::new(
            ErrorCode::StoreCorrupted,
            format!("could not place `{name}`: the package name is not a valid relative path"),
        )
        .with_remediation(
            "re-resolve the dependency so its lockfile pin carries a plain scoped name",
        ));
    }
    let mut dest = project_dir.join(PACKAGES_DIR);
    for part in name.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(Error::new(
                ErrorCode::StoreCorrupted,
                format!(
                    "could not place `{name}`: the package name escapes the packages directory"
                ),
            )
            .with_remediation(
                "re-resolve the dependency so its lockfile pin carries a plain scoped name",
            ));
        }
        dest.push(part);
    }
    Ok(dest)
}

/// One package placed from the local store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflinePlaced {
    /// The package name, as pinned in `qqq.lock`.
    pub package: String,
    /// How the bytes got there: `hardlink`, `copied`, or `already-present`.
    ///
    /// The strings are spelled out rather than `Debug`-formatted so the JSON
    /// contract does not move when a variant is renamed: a machine reader
    /// branches on these, and `HardLink` becoming `hardlink` by accident
    /// would be a silent contract break.
    ///
    /// ```
    /// use qqq_pkg::LockPackage;
    /// use qqq_pkg::store::StoreLayout;
    /// use qqq_run::install::install_offline;
    ///
    /// let base = std::env::temp_dir().join(format!("qqq-doctest-placed-{}", std::process::id()));
    /// let _ = std::fs::remove_dir_all(&base);
    /// let store = base.join("store");
    /// let project = base.join("proj");
    /// std::fs::create_dir_all(&project).unwrap();
    /// let layout = StoreLayout::new(&store);
    /// let digest = layout.write(b"payload").unwrap();
    /// let mut pkg = LockPackage::new("qqqai/json", "1.2.3");
    /// pkg.digest = Some(digest.prefixed());
    /// let mut lock = qqq_pkg::Lockfile::new();
    /// lock.push(pkg);
    ///
    /// let report = install_offline(&store, &project, &lock, false).unwrap();
    /// assert_eq!(report.placed[0].package, "qqqai/json");
    /// assert!(
    ///     ["hardlink", "copied"].contains(&report.placed[0].method.as_str()),
    ///     "a first placement links or copies, never reports a no-op: {}",
    ///     report.placed[0].method
    /// );
    /// let _ = std::fs::remove_dir_all(&base);
    /// ```
    pub method: String,
    /// How many bytes were placed.
    pub bytes: u64,
}

/// The outcome of an `--offline` placement run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineReport {
    /// Every package placed, in lockfile order.
    ///
    /// ```
    /// use qqq_pkg::LockPackage;
    /// use qqq_pkg::store::StoreLayout;
    /// use qqq_run::install::install_offline;
    ///
    /// let base = std::env::temp_dir().join(format!("qqq-doctest-report-{}", std::process::id()));
    /// let _ = std::fs::remove_dir_all(&base);
    /// let store = base.join("store");
    /// let project = base.join("proj");
    /// std::fs::create_dir_all(&project).unwrap();
    /// let layout = StoreLayout::new(&store);
    /// let digest = layout.write(b"payload").unwrap();
    /// let mut pkg = LockPackage::new("qqqai/json", "1.2.3");
    /// pkg.digest = Some(digest.prefixed());
    /// let mut lock = qqq_pkg::Lockfile::new();
    /// lock.push(pkg);
    ///
    /// let report = install_offline(&store, &project, &lock, false).unwrap();
    /// assert_eq!(report.placed.len(), 1);
    /// assert_eq!(report.placed[0].bytes, 7);
    /// let _ = std::fs::remove_dir_all(&base);
    /// ```
    pub placed: Vec<OfflinePlaced>,
}

/// Place every package a lockfile pins, from the local store, into the project.
///
/// This is PKG-014's whole behavior: resolve (done by [`resolve`]) decides
/// *what* the project needs, and this decides *where the bytes come from* —
/// the store, never the network. Fetching new versions is PKG-002's job; this
/// function places what is already here.
///
/// The run is two-phase. First every pin is checked — a digest present, parsing,
/// in the store, and a name that stays inside `.qqq/packages` — and only then
/// is anything placed. A cold or partial store therefore fails with every
/// missing package named and the project untouched; a bad pin (no digest, an
/// unparsable digest, an escaping name) fails on the first offender, which is
/// also before anything is placed.
///
/// What the check cannot cover is the placement itself: a store entry that
/// corrupts between check and link, or an IO failure mid-loop (disk full),
/// aborts loud — naming the package — with the earlier verified placements
/// left in place. Each placement is individually verified by `materialize`,
/// but there is no rollback of bytes already laid down, because a replaced
/// destination's previous bytes are already gone. Name and coverage failures
/// fail before placing anything; placement failures fail loud mid-run.
///
/// `dry_run` verifies coverage without placing: the check phase runs unchanged,
/// so a cold store still fails closed, but nothing is written and the report
/// comes back empty. That is the rehearsal `install --offline --dry-run`
/// needs — "would the store cover these pins?" — without touching the project.
///
/// ```
/// use qqq_pkg::LockPackage;
/// use qqq_pkg::store::StoreLayout;
/// use qqq_run::install::install_offline;
///
/// let base = std::env::temp_dir().join(format!("qqq-doctest-offline-{}", std::process::id()));
/// let _ = std::fs::remove_dir_all(&base);
/// let store = base.join("store");
/// let project = base.join("proj");
/// std::fs::create_dir_all(&project).unwrap();
/// let layout = StoreLayout::new(&store);
/// let digest = layout.write(b"payload").unwrap();
/// let mut pkg = LockPackage::new("qqqai/json", "1.2.3");
/// pkg.digest = Some(digest.prefixed());
/// let mut lock = qqq_pkg::Lockfile::new();
/// lock.push(pkg);
///
/// let report = install_offline(&store, &project, &lock, false).unwrap();
/// assert_eq!(report.placed.len(), 1);
/// assert_eq!(
///     std::fs::read(project.join(".qqq/packages/qqqai/json")).unwrap(),
///     b"payload"
/// );
/// let _ = std::fs::remove_dir_all(&base);
/// ```
///
/// A rehearsal covers the pins and places nothing:
///
/// ```
/// use qqq_pkg::LockPackage;
/// use qqq_pkg::store::StoreLayout;
/// use qqq_run::install::install_offline;
///
/// let base = std::env::temp_dir().join(format!("qqq-doctest-dry-{}", std::process::id()));
/// let _ = std::fs::remove_dir_all(&base);
/// let store = base.join("store");
/// let project = base.join("proj");
/// std::fs::create_dir_all(&project).unwrap();
/// let layout = StoreLayout::new(&store);
/// let digest = layout.write(b"payload").unwrap();
/// let mut pkg = LockPackage::new("qqqai/json", "1.2.3");
/// pkg.digest = Some(digest.prefixed());
/// let mut lock = qqq_pkg::Lockfile::new();
/// lock.push(pkg);
///
/// let report = install_offline(&store, &project, &lock, true).unwrap();
/// assert!(report.placed.is_empty());
/// assert!(
///     !project.join(".qqq").exists(),
///     "a rehearsal must not scaffold the packages directory"
/// );
/// let _ = std::fs::remove_dir_all(&base);
/// ```
///
/// ```should_panic
/// use qqq_pkg::LockPackage;
/// use qqq_run::install::install_offline;
///
/// // A cold store holds nothing, so placing from it must refuse.
/// let base = std::env::temp_dir().join(format!("qqq-doctest-cold-{}", std::process::id()));
/// let _ = std::fs::remove_dir_all(&base);
/// let store = base.join("store");
/// let project = base.join("proj");
/// std::fs::create_dir_all(&project).unwrap();
/// let digest = qqq_pkg::store::Digest::of(b"never stored");
/// let mut pkg = LockPackage::new("qqqai/json", "1.2.3");
/// pkg.digest = Some(digest.prefixed());
/// let mut lock = qqq_pkg::Lockfile::new();
/// lock.push(pkg);
///
/// install_offline(&store, &project, &lock, false).unwrap();
/// ```
///
/// ```should_panic
/// use qqq_pkg::LockPackage;
/// use qqq_pkg::store::StoreLayout;
/// use qqq_run::install::install_offline;
///
/// // A partial store is a cold store for the missing half: the present
/// // package is verified, but nothing is placed until everything is.
/// let base = std::env::temp_dir().join(format!("qqq-doctest-partial-{}", std::process::id()));
/// let _ = std::fs::remove_dir_all(&base);
/// let store = base.join("store");
/// let project = base.join("proj");
/// std::fs::create_dir_all(&project).unwrap();
/// let layout = StoreLayout::new(&store);
/// let present = layout.write(b"present").unwrap();
/// let mut have = LockPackage::new("qqqai/json", "1.2.3");
/// have.digest = Some(present.prefixed());
/// let missing = qqq_pkg::store::Digest::of(b"absent");
/// let mut want = LockPackage::new("qqqai/text", "0.4.0");
/// want.digest = Some(missing.prefixed());
/// let mut lock = qqq_pkg::Lockfile::new();
/// lock.push(have);
/// lock.push(want);
///
/// install_offline(&store, &project, &lock, false).unwrap();
/// ```
///
/// A second run over identical bytes is a no-op that reports itself, so a
/// repeated install is safe and observable:
///
/// ```
/// use qqq_pkg::LockPackage;
/// use qqq_pkg::store::StoreLayout;
/// use qqq_run::install::install_offline;
///
/// let base = std::env::temp_dir().join(format!("qqq-doctest-idem-{}", std::process::id()));
/// let _ = std::fs::remove_dir_all(&base);
/// let store = base.join("store");
/// let project = base.join("proj");
/// std::fs::create_dir_all(&project).unwrap();
/// let layout = StoreLayout::new(&store);
/// let digest = layout.write(b"same").unwrap();
/// let mut pkg = LockPackage::new("qqqai/json", "1.2.3");
/// pkg.digest = Some(digest.prefixed());
/// let mut lock = qqq_pkg::Lockfile::new();
/// lock.push(pkg);
///
/// install_offline(&store, &project, &lock, false).unwrap();
/// let second = install_offline(&store, &project, &lock, false).unwrap();
/// assert_eq!(second.placed[0].method, "already-present");
/// let _ = std::fs::remove_dir_all(&base);
/// ```
///
/// A pin without a digest fails closed: the store is content-addressed, and a
/// digestless pin can never be found in it — scanning by name would pretend
/// the store indexes what it does not:
///
/// ```should_panic
/// use qqq_pkg::LockPackage;
/// use qqq_pkg::store::StoreLayout;
/// use qqq_run::install::install_offline;
///
/// let base = std::env::temp_dir().join(format!("qqq-doctest-nodigest-{}", std::process::id()));
/// let _ = std::fs::remove_dir_all(&base);
/// let store = base.join("store");
/// let project = base.join("proj");
/// std::fs::create_dir_all(&project).unwrap();
/// StoreLayout::new(&store).write(b"unrelated").unwrap();
/// let mut lock = qqq_pkg::Lockfile::new();
/// lock.push(LockPackage::new("qqqai/json", "1.2.3"));
///
/// install_offline(&store, &project, &lock, false).unwrap();
/// ```
///
/// # Errors
///
/// * `QQQ-5001` — a pin carries no digest (the store cannot be searched by
///   name), naming that package; or a digest is absent from the store (cold or
///   partial store), naming every missing package. Nothing is placed on
///   either path.
/// * `QQQ-5001`/`QQQ-5006` — a pin's digest does not parse, carrying the
///   digest parser's own code: the pin is corrupt, not merely absent.
/// * `QQQ-5006` — a package name escapes `.qqq/packages`, or a link, copy,
///   rename, or read-only step failed mid-placement, naming the package.
pub fn install_offline(
    store_root: &Path,
    project_dir: &Path,
    lockfile: &Lockfile,
    dry_run: bool,
) -> Result<OfflineReport> {
    // Phase 1 — check everything before placing anything. A digest is looked
    // up exactly once per package: presence here, then placement below, so a
    // package cannot pass the check against one store state and place from
    // another without `materialize`'s own verification catching it. Names are
    // validated here too, so a bad pin fails before its siblings are placed.
    let store = StoreLayout::new(store_root);
    let mut wanted: Vec<(&str, Digest, PathBuf)> = Vec::with_capacity(lockfile.len());
    for pkg in &lockfile.packages {
        let Some(digest_text) = pkg.digest.as_deref() else {
            return Err(Error::new(
                ErrorCode::RegistryUnreachable,
                format!(
                    "could not place `{}` from the local store: `qqq.lock` pins no digest for it",
                    pkg.name
                ),
            )
            .with_remediation(
                "re-resolve with network access so the pin records a digest (fetching is Checklist PKG-002), then retry `--offline`",
            ));
        };
        let digest = Digest::parse(digest_text).map_err(|parse_err| {
            Error::new(
                parse_err.code,
                format!(
                    "could not place `{}` from the local store: its `qqq.lock` digest does not parse",
                    pkg.name
                ),
            )
            .with_cause(parse_err.message)
            .with_remediation("re-resolve with network access so the pin records a digest, then retry `--offline`")
        })?;
        let dest = package_dest(project_dir, &pkg.name)?;
        wanted.push((pkg.name.as_str(), digest, dest));
    }
    let mut missing: Vec<String> = Vec::new();
    for (name, digest, _) in &wanted {
        if !store.contains(digest) {
            missing.push(format!("`{name}` ({})", digest.prefixed()));
        }
    }
    if !missing.is_empty() {
        return Err(Error::new(
            ErrorCode::RegistryUnreachable,
            format!(
                "could not place {} from the local store: not in the store",
                missing.join(", ")
            ),
        )
        .with_remediation(
            "populate the store first (fetching is Checklist PKG-002), or narrow the manifest to what the store holds",
        ));
    }

    // Phase 2 — every digest is present, so place each one, unless this is a
    // rehearsal. `materialize` re-verifies the bytes at link time, closing the
    // check-then-place window to a loud refusal rather than a silent mismatch.
    if dry_run {
        return Ok(OfflineReport { placed: Vec::new() });
    }
    let mut placed = Vec::with_capacity(wanted.len());
    for (name, digest, dest) in &wanted {
        let materialized = store.materialize(digest, dest).map_err(|e| {
            Error::new(
                e.code,
                format!("could not place `{name}` from the local store"),
            )
            .with_cause(e.message)
        })?;
        placed.push(OfflinePlaced {
            package: (*name).to_owned(),
            method: match materialized.method {
                LinkMethod::HardLink => "hardlink",
                LinkMethod::Copied => "copied",
                LinkMethod::AlreadyPresent => "already-present",
            }
            .to_owned(),
            bytes: materialized.bytes,
        });
    }
    Ok(OfflineReport { placed })
}

// ---------------------------------------------------------------------------
// The error for a package that cannot be fetched
// ---------------------------------------------------------------------------

/// The error reported when a dependency cannot be fetched.
///
/// Names the package and the reason, because "install failed" sends the user
/// looking at their whole manifest.
#[must_use]
pub fn cannot_fetch(name: &str, reason: &str) -> Error {
    Error::new(
        ErrorCode::RegistryUnreachable,
        format!("could not fetch `{name}`: {reason}"),
    )
    .with_remediation(
        "the QQQ registry is not built yet (Checklist `PKG-006`), so only \
         dependencies already in `qqq.lock` resolve; see QQQ-Proposal-V1.md §6.5 \
         for the registry plan",
    )
}

/// The error for a lockfile that must be current and is not.
#[must_use]
pub fn lockfile_stale(detail: &str) -> Error {
    Error::new(ErrorCode::LockfileOutOfDate, detail).with_remediation(
        "run `qqqai install` without `--locked` to update `qqq.lock`, and commit \
         the result",
    )
}

/// The error for a missing lockfile when one was required.
#[must_use]
pub fn lockfile_required(path: &Path) -> Error {
    Error::new(
        ErrorCode::LockfileOutOfDate,
        format!(
            "`--locked` was given but `{}` does not exist",
            path.display()
        ),
    )
    .with_remediation("run `qqqai install` once, commit `qqq.lock`, then use `--locked` in CI")
}

/// One package whose authority changed, shaped for output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CapabilityChangeReport {
    /// The package.
    pub package: String,
    /// Capabilities gained.
    pub added: Vec<String>,
    /// Capabilities lost.
    pub removed: Vec<String>,
}

/// The result of an install, for machine consumption.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InstallOutput {
    /// The manifest, as a display path.
    pub manifest: String,
    /// The lockfile, as a display path.
    pub lockfile: String,
    /// How many packages the resolution pinned.
    pub packages: usize,
    /// Whether the lockfile was written.
    ///
    /// Distinct from `mode`: an `update` run on an already-correct lockfile
    /// writes the same bytes back, and a `--dry-run` never writes at all. This
    /// says what *happened*; `mode` says what was permitted.
    pub wrote_lockfile: bool,
    /// Whether nothing was written because this was a rehearsal.
    pub dry_run: bool,
    /// The lock mode in force: `update`, `offline`, `locked` or `frozen`.
    ///
    /// The single source of truth for how strict the run was. The two
    /// predicates it implies are **not** duplicated as separate fields, because
    /// a value recorded twice is a value that can disagree with itself in the
    /// `--json` output an agent branches on.
    pub mode: String,
    /// How many packages changed.
    pub changes: usize,
    /// The packages whose **authority** changed. This is the feature §5.4
    /// names, so it is a first-class field rather than part of a message.
    pub capability_changes: Vec<CapabilityChangeReport>,
    /// Whether any package gained authority.
    ///
    /// Denormalized deliberately: CI needs to branch on this without walking
    /// the list, and §5.4's whole point is that this must be branchable on.
    pub escalation: bool,
    /// The packages an `--offline` run placed from the local store, in lockfile
    /// order. Empty on every other mode — and on an offline dry run, which
    /// verifies coverage without placing.
    ///
    /// Additive on purpose: the JSON contract only ever gains this field, so a
    /// reader written before PKG-014 ignores it rather than breaking. What it
    /// names is the whole result of the offline path — resolve decides the set
    /// (see `packages`), this decides what reached the project.
    ///
    /// ```
    /// use qqq_run::install::{InstallOutput, LockMode};
    /// use qqq_run::output::CommandOutput;
    ///
    /// let out = InstallOutput {
    ///     manifest: "qqq.toml".to_owned(),
    ///     lockfile: "qqq.lock".to_owned(),
    ///     packages: 1,
    ///     wrote_lockfile: true,
    ///     dry_run: false,
    ///     mode: LockMode::Offline.as_str().to_owned(),
    ///     changes: 0,
    ///     capability_changes: Vec::new(),
    ///     escalation: false,
    ///     offline_placed: vec!["qqqai/json".to_owned()],
    /// };
    /// let json = out.to_json();
    /// assert_eq!(json["offline_placed"][0], "qqqai/json");
    /// assert_eq!(json["mode"], "offline");
    /// ```
    pub offline_placed: Vec<String>,
}

impl crate::output::CommandOutput for InstallOutput {
    fn command(&self) -> crate::output::CommandName {
        crate::output::CommandName::Install
    }

    fn summary(&self) -> String {
        // The capability diff leads when there is one. It is the reason the
        // command prints anything at all, and burying it after "wrote lockfile"
        // would let the supply-chain signal be skimmed past.
        if self.escalation {
            let detail: Vec<String> = self
                .capability_changes
                .iter()
                .filter(|c| !c.added.is_empty())
                .map(|c| format!("{} gains {}", c.package, c.added.join(", ")))
                .collect();
            return format!(
                "{}: {} package(s) resolved; AUTHORITY ESCALATION — {}",
                self.lockfile,
                self.packages,
                detail.join("; ")
            );
        }

        // The offline path places bytes, not just pins: the summary says what
        // reached the project, because a lockfile write alone would report
        // success for work the store may still refuse.
        if self.mode == LockMode::Offline.as_str() && !self.offline_placed.is_empty() {
            return format!(
                "{}: placed {} package(s) from the local store ({})",
                self.lockfile,
                self.offline_placed.len(),
                self.offline_placed.join(", ")
            );
        }

        let action = if self.dry_run {
            "would write"
        } else if self.wrote_lockfile {
            "wrote"
        } else {
            "left unchanged"
        };
        format!(
            "{}: {} package(s) resolved, {action} {}",
            self.lockfile, self.packages, self.lockfile
        )
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deps(pairs: &[(&str, &str)]) -> Vec<(String, String, Vec<String>)> {
        // Most tests care only about name and requirement, so this form declares
        // **no** capabilities. `deps_with_caps` is the form for the tests that
        // exercise `SEC-015`, and keeping two helpers means a test that does not
        // care cannot accidentally assert something about caps it never meant to
        // set.
        pairs
            .iter()
            .map(|(n, r)| ((*n).to_owned(), (*r).to_owned(), Vec::new()))
            .collect()
    }

    /// Dependencies with declared capabilities, for the `SEC-015` tests.
    fn deps_with_caps(pairs: &[(&str, &str, &[&str])]) -> Vec<(String, String, Vec<String>)> {
        pairs
            .iter()
            .map(|(n, r, caps)| {
                (
                    (*n).to_owned(),
                    (*r).to_owned(),
                    caps.iter().map(|c| (*c).to_owned()).collect(),
                )
            })
            .collect()
    }

    // -- option semantics ---------------------------------------------------

    /// `--locked` and `--frozen` must never write.
    ///
    /// This is the whole contract of the flags: a CI job that passes `--locked`
    /// and has the lockfile changed underneath it has been defeated.
    #[test]
    fn locked_and_frozen_never_write() {
        assert!(
            !InstallOptions {
                mode: LockMode::Locked,
                ..Default::default()
            }
            .may_write()
        );
        assert!(
            !InstallOptions {
                mode: LockMode::Frozen,
                ..Default::default()
            }
            .may_write()
        );
        assert!(
            !InstallOptions {
                dry_run: true,
                ..Default::default()
            }
            .may_write()
        );
        assert!(InstallOptions::default().may_write());
    }

    /// The modes are ordered by strictness, and the implications hold in one
    /// direction only.
    ///
    /// Encoding this as an enum rather than three booleans is what makes
    /// "frozen but not locked" unrepresentable rather than merely discouraged.
    #[test]
    fn the_modes_are_ordered_by_strictness() {
        assert!(LockMode::Frozen.requires_current());
        assert!(LockMode::Frozen.forbids_network());
        assert!(!LockMode::Frozen.may_write());

        assert!(LockMode::Locked.requires_current());
        assert!(!LockMode::Locked.forbids_network());
        assert!(!LockMode::Locked.may_write());

        assert!(!LockMode::Offline.requires_current());
        assert!(LockMode::Offline.forbids_network());
        assert!(LockMode::Offline.may_write(), "offline still writes");

        assert!(!LockMode::Update.requires_current());
        assert!(!LockMode::Update.forbids_network());
        assert!(LockMode::Update.may_write());
    }

    /// A dry run overrides even a writable mode.
    ///
    /// The interaction is easy to get wrong in the other order: checking the
    /// mode first and returning early would give a dry run that writes.
    #[test]
    fn a_dry_run_overrides_a_writable_mode() {
        let opts = InstallOptions {
            mode: LockMode::Update,
            dry_run: true,
            ..Default::default()
        };
        assert!(!opts.may_write());
        assert!(opts.mode.may_write(), "the mode itself still permits it");
    }

    /// `--force` is the only thing that ignores the pins.
    #[test]
    fn only_force_ignores_the_lockfile_pins() {
        assert!(InstallOptions::default().honours_lockfile());
        assert!(
            InstallOptions {
                mode: LockMode::Locked,
                ..Default::default()
            }
            .honours_lockfile()
        );
        assert!(
            !InstallOptions {
                force: true,
                ..Default::default()
            }
            .honours_lockfile()
        );
    }

    /// `--offline` is not a synonym for `--locked`: it still writes.
    ///
    /// Conflating them is the easy mistake, and it would make `--offline`
    /// silently refuse to produce a lockfile from the store.
    #[test]
    fn offline_still_writes_unlike_locked() {
        let offline = InstallOptions {
            mode: LockMode::Offline,
            ..Default::default()
        };
        assert!(
            offline.may_write(),
            "offline installs do produce a lockfile"
        );
        assert!(offline.honours_lockfile());

        let locked = InstallOptions {
            mode: LockMode::Locked,
            ..Default::default()
        };
        assert!(!locked.may_write());
    }

    // -- resolution ---------------------------------------------------------

    /// A first install has nothing pinned, so everything is unresolved.
    ///
    /// The important part is that nothing is *invented*: the lockfile stays
    /// empty rather than gaining packages with guessed versions.
    #[test]
    fn a_first_install_resolves_nothing_but_invents_nothing() {
        let r = resolve(&deps(&[("qqqai/json", "1.2")]), None);
        assert_eq!(r.unresolved, vec!["qqqai/json"]);
        assert!(
            r.lockfile.is_empty(),
            "no version may be invented: {:?}",
            r.lockfile
        );
    }

    /// A lockfile that satisfies the manifest is carried across unchanged.
    #[test]
    fn a_satisfying_pin_is_carried_across() {
        let mut old = Lockfile::new();
        old.push(package_for("qqqai/json", "1.2.3", &[]));

        let r = resolve(&deps(&[("qqqai/json", "1.2")]), Some(&old));
        assert!(r.unresolved.is_empty(), "the pin satisfies `1.2`");
        assert_eq!(r.lockfile.len(), 1);
        assert_eq!(r.lockfile.get("qqqai/json").unwrap().version, "1.2.3");
        assert!(r.diff.is_empty(), "nothing changed");
    }

    /// A pin the manifest no longer accepts must not be carried across.
    ///
    /// Otherwise `--locked` would pass on a lockfile that contradicts the
    /// manifest, which is the exact state `--locked` exists to catch.
    #[test]
    fn a_pin_the_manifest_rejects_is_not_carried_across() {
        let mut old = Lockfile::new();
        old.push(package_for("qqqai/json", "1.2.3", &[]));

        let r = resolve(&deps(&[("qqqai/json", "2.0")]), Some(&old));
        assert_eq!(r.unresolved, vec!["qqqai/json"]);
        assert!(r.lockfile.is_empty(), "the stale pin must be dropped");
    }

    /// A malformed requirement satisfies nothing.
    ///
    /// The dangerous alternative is returning `true`, which would keep a stale
    /// pin across a requirement that cannot be understood.
    #[test]
    fn an_unparsable_requirement_satisfies_nothing() {
        assert!(!satisfies("1.2.3.4", "1.2.3"));
        assert!(!satisfies("not a version", "1.2.3"));
        assert!(!satisfies("1.2", "not a version"));
        assert!(satisfies("1.2", "1.2.9"));
    }

    /// A removed dependency shows up as a removal in the diff.
    #[test]
    fn removing_a_dependency_from_the_manifest_shows_in_the_diff() {
        let mut old = Lockfile::new();
        old.push(package_for("qqqai/json", "1.2.3", &[]));

        let r = resolve(&[], Some(&old));
        assert!(r.lockfile.is_empty());
        assert!(!r.diff.is_empty(), "the removal must be reported");
        assert_eq!(r.diff.changes.len(), 1);
    }

    /// The capability diff is the point of the command, so it is asserted here.
    #[test]
    fn an_authority_change_between_lockfiles_is_visible() {
        let mut old = Lockfile::new();
        old.push(package_for("qqqai/telemetry", "1.0.0", &[]));
        let mut new = Lockfile::new();
        new.push(package_for("qqqai/telemetry", "1.1.0", &["http.client"]));

        let diff = LockDiff::compute(&old, &new);
        assert!(
            diff.has_escalation(),
            "gaining http.client is a supply-chain event and must be flagged"
        );
        assert_eq!(diff.total_added(), 1);

        let delta = diff
            .capability_changes
            .iter()
            .find(|d| d.package == "qqqai/telemetry")
            .expect("the package appears in the capability diff");
        assert_eq!(delta.added, vec!["http.client"]);
        assert!(delta.is_escalation());
    }

    /// **`SEC-015`, at the level `install` actually runs — `§O-076`.**
    ///
    /// # The defect this test was written to find, and did
    ///
    /// `LockDiff::compute` was already correct, and the test above already proved
    /// it. But `resolve` pushed the carried-forward pin as `pinned.clone()`, so
    /// the new lockfile recorded **the same caps the old one did** — and
    /// `LockDiff::compute(old, &next)` then compared a value against itself.
    ///
    /// The consequence: `caps_added` was **structurally always empty**, so
    /// `escalation` could never become `true` through the real `qqqai install`
    /// path, and a CI gate branching on that boolean would have passed every
    /// supply-chain event in silence. `SEC-015`'s purpose — *"the authority delta
    /// is visible in the diff"* — was unreachable.
    ///
    /// Nothing in the existing suite could see it: every test either exercised
    /// `LockDiff::compute` directly (correct, and unrelated to `resolve`) or
    /// asserted merely that install *succeeded*.
    ///
    /// # What the test pins
    ///
    /// A dependency whose lockfile record says `none` while the manifest now
    /// declares `http.client` must produce an escalation through `resolve`. That
    /// is the real input shape: the lockfile is the *record*, the manifest is the
    /// *declaration*, and the diff between them is the only observable delta.
    #[test]
    fn resolve_observes_an_escalation_from_the_manifest_declaration() {
        let mut old = Lockfile::new();
        old.push(package_for("qqqai/telemetry", "1.0.0", &["none"]));

        // The manifest now declares that the dependency needs http.client.
        let r = resolve(
            &deps_with_caps(&[("qqqai/telemetry", "1.0", &["http.client"])]),
            Some(&old),
        );

        assert!(
            r.diff.has_escalation(),
            "the dependency's recorded authority was `none` and the manifest now \
             declares `http.client`, so `resolve` MUST observe an escalation. An \
             empty diff here means the recorded caps were carried forward verbatim \
             and compared against themselves — SEC-015 would then be unreachable \
             through the real install path, which is the defect this asserts against."
        );
        let delta = r
            .diff
            .capability_changes
            .iter()
            .find(|d| d.package == "qqqai/telemetry")
            .expect("the package must appear in the diff");
        assert_eq!(delta.added, vec!["http.client"]);
        assert!(
            delta.is_escalation(),
            "gaining authority must be classified as an escalation, not a mere change"
        );

        // And the WRITTEN lockfile records the new declaration, so a subsequent
        // install compares against the new truth rather than re-reporting the same
        // escalation forever. A diff that never converged is one people learn to
        // ignore, which is the same as having none.
        let written = r
            .lockfile
            .get("qqqai/telemetry")
            .expect("the package must be written");
        assert_eq!(
            written.caps,
            vec!["http.client"],
            "the lockfile must record the DECLARED caps, not the superseded ones"
        );

        // Convergence, asserted directly: resolving again against the lockfile
        // just written must produce NO further change.
        let again = resolve(
            &deps_with_caps(&[("qqqai/telemetry", "1.0", &["http.client"])]),
            Some(&r.lockfile),
        );
        assert!(
            again.diff.capability_changes.is_empty(),
            "the second resolution re-reported a change that had already converged; a \
             diff that never settles is noise, and noise is ignored. Found: {:?}",
            again.diff.capability_changes
        );
    }

    /// A **de**-escalation is reported, and is not an escalation.
    ///
    /// # Why the other direction matters, and is not just symmetry
    ///
    /// A dependency losing authority is the *good* case, and a check that flagged
    /// it as an escalation is one people learn to bypass — the same argument
    /// `CLI-015` makes for exiting non-zero on a gain but not on a loss. It must
    /// still be **reported**, because a lockfile that silently dropped a
    /// capability would hide that a dependency's declared needs had changed.
    #[test]
    fn resolve_reports_a_loss_without_calling_it_an_escalation() {
        let mut old = Lockfile::new();
        old.push(package_for(
            "qqqai/telemetry",
            "1.0.0",
            &["http.client", "clock.wall"],
        ));

        let r = resolve(
            &deps_with_caps(&[("qqqai/telemetry", "1.0", &["clock.wall"])]),
            Some(&old),
        );

        assert!(
            !r.diff.has_escalation(),
            "losing http.client is a reduction in authority and must NOT be flagged \
             as an escalation; a check that cries wolf on the good case is one people \
             learn to bypass"
        );
        let delta = r
            .diff
            .capability_changes
            .iter()
            .find(|d| d.package == "qqqai/telemetry")
            .expect("the loss must still be reported");
        assert_eq!(delta.removed, vec!["http.client"]);
        assert!(delta.added.is_empty());
    }

    /// A dependency that declares **nothing** keeps its recorded caps.
    ///
    /// # Why clearing them would be a defect rather than a simplification
    ///
    /// The bare `name = "1.2"` form declares nothing — it has not said "I need no
    /// capabilities", it has said nothing at all. Treating that as an empty
    /// declaration would report every previously recorded capability as
    /// **removed**, a false de-escalation. It is wrong in the opposite direction
    /// from the defect above and just as misleading: an operator would see
    /// authority apparently vanishing on an unrelated manifest edit.
    #[test]
    fn a_dependency_that_declares_nothing_keeps_its_recorded_caps() {
        let mut old = Lockfile::new();
        old.push(package_for("qqqai/validate", "2.0.0", &["clock.monotonic"]));

        // `deps` (not `deps_with_caps`) declares an empty cap set.
        let r = resolve(&deps(&[("qqqai/validate", "2.0")]), Some(&old));

        assert!(
            r.diff.capability_changes.is_empty(),
            "a manifest that declares nothing about a dependency's capabilities must \
             not appear to change them; found {:?}",
            r.diff.capability_changes
        );
        let written = r
            .lockfile
            .get("qqqai/validate")
            .expect("the package must be written");
        assert_eq!(
            written.caps,
            vec!["clock.monotonic"],
            "the recorded caps must be preserved when the manifest declares nothing"
        );
    }

    // -- lockfile reading ---------------------------------------------------

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-install-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    #[test]
    fn an_absent_lockfile_reads_as_none() {
        let dir = temp_dir("absent");
        assert!(read_lockfile(&dir.join("qqq.lock")).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_written_lockfile_reads_back() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("qqq.lock");
        let mut lock = Lockfile::new();
        lock.push(package_for("qqqai/json", "1.2.3", &["crypto.hash"]));
        lock.stamp("qqqai test");
        std::fs::write(&path, lock.render().expect("render")).unwrap();

        let read = read_lockfile(&path).expect("must read").expect("present");
        assert_eq!(read.get("qqqai/json").unwrap().version, "1.2.3");
        assert_eq!(read.get("qqqai/json").unwrap().caps, vec!["crypto.hash"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tampered lockfile is refused, not silently rewritten.
    #[test]
    fn a_tampered_lockfile_is_refused_rather_than_ignored() {
        let dir = temp_dir("tampered");
        let path = dir.join("qqq.lock");
        let mut lock = Lockfile::new();
        lock.push(package_for("qqqai/json", "1.2.3", &[]));
        lock.stamp("qqqai test");
        let text = lock.render().expect("render");
        std::fs::write(
            &path,
            text.replace("caps = []", "caps = [\"fs.read:/etc\"]"),
        )
        .unwrap();

        let e = read_lockfile(&path).unwrap_err();
        assert_eq!(e.code, ErrorCode::LockfileOutOfDate);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A syntactically broken lockfile is an error, not "no lockfile".
    ///
    /// Treating it as absent would let `install` overwrite a file it could not
    /// read, destroying whatever it recorded.
    #[test]
    fn a_malformed_lockfile_is_an_error_not_an_absent_one() {
        let dir = temp_dir("malformed");
        let path = dir.join("qqq.lock");
        std::fs::write(&path, "version = = = broken\n").unwrap();

        assert!(read_lockfile(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_lockfile_sits_beside_the_manifest() {
        let p = lockfile_path(Path::new("/proj/qqq.toml"));
        assert!(p.ends_with("qqq.lock"));
        assert_eq!(p.parent().unwrap(), Path::new("/proj"));
    }

    // -- error messages -----------------------------------------------------

    /// The fetch error must explain the registry gap rather than implying a
    /// network problem the user should debug.
    #[test]
    fn the_cannot_fetch_error_names_the_package_and_the_real_reason() {
        let e = cannot_fetch("qqqai/json", "no registry");
        assert_eq!(e.code, ErrorCode::RegistryUnreachable);
        let text = e.render();
        assert!(text.contains("qqqai/json"), "{text}");
        assert!(
            text.contains("PKG-006"),
            "the error must point at the tracking item: {text}"
        );
    }

    #[test]
    fn the_stale_lockfile_error_gives_the_exact_next_command() {
        let e = lockfile_stale("the lockfile pins 1.2 but the manifest wants 2.0");
        let text = e.render();
        assert!(text.contains("qqqai install"), "{text}");
        assert!(text.contains("--locked"), "{text}");
    }

    #[test]
    fn the_required_lockfile_error_says_what_to_run_once() {
        let e = lockfile_required(Path::new("qqq.lock"));
        let text = e.render();
        assert!(text.contains("--locked"), "{text}");
        assert!(text.contains("qqqai install"), "{text}");
    }

    /// REG-015: no install path spawns a subprocess or compiles anything.
    ///
    /// Installing a Q-Block must never execute publisher code: no
    /// `postinstall`, no `build.rs`, no install-time toolchain. The install
    /// path is `install.rs` + `deps.rs` (this crate) plus the store, lockfile,
    /// version matching and signature verification it resolves through
    /// (`qqq-pkg`: `store`, `lock`, `semver`, `signature`). This test reads
    /// those files and fails on any child-process spawn primitive, so adding
    /// one breaks the build instead of landing silently.
    ///
    /// `std::process::id()` is allowed: reading the caller's own pid for a
    /// temp-dir name forks nothing. What is forbidden is *spawning*, in any
    /// spelling: a full `process::` path, a bare `Command::new` (after an
    /// unaliased import), or an aliased import (`as Cmd`) of anything with
    /// `process` or `Command` in its path.
    ///
    /// The scan covers shipped code only — everything before the test module.
    /// The cut is pinned, not assumed: the remainder must contain this test's
    /// own name, so a `#[cfg(test)]` helper added above the test module moves
    /// the cut loudly instead of silently shrinking the scan. The test itself
    /// names the forbidden patterns (as this paragraph does), so scanning the
    /// test module would fail on the guard itself: a self-defeating check is
    /// one that gets deleted rather than obeyed.
    #[test]
    fn install_path_spawns_no_subprocess() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let files = [
            "src/install.rs",
            "src/deps.rs",
            "../qqq-pkg/src/store.rs",
            "../qqq-pkg/src/lock.rs",
            "../qqq-pkg/src/semver.rs",
            "../qqq-pkg/src/signature.rs",
        ];
        for rel in files {
            let path = root.join(rel);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("install-path source must be readable: {path:?}: {e}"));
            // The cut is pinned, not assumed: everything before the first
            // full `#[cfg(test)]` attribute line is shipped code, and there
            // must be exactly one such line — the test module at the end. A
            // second attribute line (a helper added above the module) would
            // silently shrink the scan, so it fails here instead. (Mentions
            // of the attribute inside comments do not count: the match is on
            // the whole trimmed line.)
            let mut shipped_lines = Vec::new();
            let mut cuts = 0;
            for line in text.lines() {
                if line.trim() == "#[cfg(test)]" {
                    cuts += 1;
                    continue;
                }
                if cuts == 0 {
                    shipped_lines.push(line);
                }
            }
            assert!(
                cuts == 1,
                "expected exactly one #[cfg(test)] attribute line in {rel}; the scan cut moved"
            );
            let shipped = shipped_lines.join("\n");
            for (n, line) in shipped.lines().enumerate() {
                let t = line.trim();
                if t.starts_with("//") || t.starts_with("///") || t.starts_with('*') {
                    continue;
                }
                assert!(
                    !t.contains("Command::new("),
                    "install path must not spawn subprocesses: {rel}:{} contains `Command::new(` outside its tests",
                    n + 1
                );
                if t.contains("process::") {
                    assert!(
                        t.contains("process::id"),
                        "install path must not touch process handles except its own pid: {rel}:{}: {t}",
                        n + 1
                    );
                }
                if t.starts_with("use ") && t.contains(" as ") {
                    assert!(
                        !t.contains("process") && !t.contains("Command"),
                        "install path must not alias a process primitive: {rel}:{}: {t}",
                        n + 1
                    );
                }
            }
        }
    }

    // -- PKG-014: `install --offline` from the local store --------------------

    /// Seed a store with `entries` and pin their digests in a lockfile.
    ///
    /// Returns the lockfile, the store root, and the project directory. The
    /// world is staged with the store's own `write` — the alternative,
    /// hand-rolling the fan-out layout, would duplicate the layout beside it
    /// and pass while the real paths disagree.
    fn offline_world(tag: &str, entries: &[(&str, &str, &[u8])]) -> (Lockfile, PathBuf, PathBuf) {
        let base = temp_dir(&format!("offline-{tag}"));
        let store = base.join("store");
        let project = base.join("proj");
        std::fs::create_dir_all(&project).expect("create project");
        let layout = qqq_pkg::store::StoreLayout::new(&store);
        let mut lock = Lockfile::new();
        for (name, version, bytes) in entries {
            let digest = layout.write(bytes).expect("seed store");
            let mut pkg = LockPackage::new(*name, *version);
            pkg.digest = Some(digest.prefixed());
            lock.push(pkg);
        }
        (lock, store, project)
    }

    /// Remove a tree that may hold read-only materialized files.
    ///
    /// `remove_dir_all` fails on Windows when a file is read-only, and every
    /// placement below leaves its destination read-only by design — so the bit
    /// is cleared first. Only the test trees are walked, never the store.
    #[allow(
        clippy::permissions_set_readonly_false,
        reason = "test cleanup must delete the read-only fixtures materialization leaves; the shipped replacement path goes through settle_destination instead"
    )]
    fn remove_tree(root: &Path) {
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && !path.is_symlink() {
                    stack.push(path);
                } else if let Ok(meta) = std::fs::symlink_metadata(&path) {
                    let mut perms = meta.permissions();
                    perms.set_readonly(false);
                    let _ = std::fs::set_permissions(&path, perms);
                }
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// The whole point: every pinned package lands in the project byte-identical,
    /// in lockfile order.
    #[test]
    fn offline_install_places_every_pinned_package() {
        let (lock, store, project) = offline_world(
            "happy",
            &[
                ("qqqai/json", "1.2.3", b"{\"v\":1}"),
                ("qqqai/text", "0.4.0", b"plain"),
            ],
        );
        let report = install_offline(&store, &project, &lock, false).expect("must place");
        assert_eq!(report.placed.len(), 2);
        assert_eq!(
            report
                .placed
                .iter()
                .map(|p| p.package.as_str())
                .collect::<Vec<_>>(),
            vec!["qqqai/json", "qqqai/text"],
            "the report follows lockfile order"
        );
        assert_eq!(
            std::fs::read(project.join(".qqq/packages/qqqai/json")).expect("read placed"),
            b"{\"v\":1}"
        );
        assert_eq!(
            std::fs::read(project.join(".qqq/packages/qqqai/text")).expect("read placed"),
            b"plain"
        );
        remove_tree(project.parent().expect("base"));
    }

    /// A second run is a no-op that reports itself: nothing is re-fetched because
    /// there is nothing to fetch from, and nothing is re-linked.
    #[test]
    fn offline_install_is_idempotent() {
        let (lock, store, project) =
            offline_world("idempotent", &[("qqqai/json", "1.2.3", b"same")]);
        install_offline(&store, &project, &lock, false).expect("first");
        let second = install_offline(&store, &project, &lock, false).expect("second");
        assert_eq!(second.placed.len(), 1);
        assert_eq!(
            second.placed.first().expect("one package placed").method,
            "already-present",
            "the bytes are already there; the report must say so"
        );
        remove_tree(project.parent().expect("base"));
    }

    /// A cold store fails closed naming the package and its digest — and places
    /// nothing, because the check runs before the first placement.
    #[test]
    fn offline_install_fails_closed_on_a_cold_store() {
        let base = temp_dir("offline-cold");
        let store = base.join("store");
        let project = base.join("proj");
        std::fs::create_dir_all(&project).expect("create project");
        let digest = qqq_pkg::store::Digest::of(b"never stored");
        let mut pkg = LockPackage::new("qqqai/json", "1.2.3");
        pkg.digest = Some(digest.prefixed());
        let mut lock = Lockfile::new();
        lock.push(pkg);

        let e = install_offline(&store, &project, &lock, false).unwrap_err();
        let text = e.render();
        assert!(text.contains("qqqai/json"), "must name the package: {text}");
        assert!(
            text.contains(digest.hex()),
            "must name the missing digest: {text}"
        );
        assert!(
            !project.join(".qqq").exists(),
            "a refusal must not scaffold the packages directory"
        );
        remove_tree(&base);
    }

    /// A partial store fails closed too — and all-or-nothing: the present
    /// package must NOT be placed when its sibling is missing, or a retry
    /// after repopulating the store would inherit a half-installed project.
    #[test]
    fn offline_install_fails_closed_on_a_partial_store() {
        let (mut lock, store, project) =
            offline_world("partial", &[("qqqai/json", "1.2.3", b"present")]);
        let missing = qqq_pkg::store::Digest::of(b"absent");
        let mut pkg = LockPackage::new("qqqai/text", "0.4.0");
        pkg.digest = Some(missing.prefixed());
        lock.push(pkg);

        let e = install_offline(&store, &project, &lock, false).unwrap_err();
        let text = e.render();
        assert!(
            text.contains("qqqai/text"),
            "must name the missing one: {text}"
        );
        assert!(
            !text.contains("qqqai/json"),
            "must not blame the present one: {text}"
        );
        assert!(
            !project.join(".qqq/packages/qqqai/json").exists(),
            "all-or-nothing: the present package stays unplaced: {text}"
        );
        remove_tree(project.parent().expect("base"));
    }

    /// The store is content-addressed: a pin without a digest can never be
    /// found in it, so it fails closed naming the package rather than
    /// scanning the store for a name the store does not index by.
    #[test]
    fn offline_install_needs_a_digest_for_every_package() {
        let base = temp_dir("offline-nodigest");
        let store = base.join("store");
        let project = base.join("proj");
        std::fs::create_dir_all(&project).expect("create project");
        let layout = qqq_pkg::store::StoreLayout::new(&store);
        layout.write(b"unrelated").expect("seed");
        let mut lock = Lockfile::new();
        lock.push(LockPackage::new("qqqai/json", "1.2.3"));

        let e = install_offline(&store, &project, &lock, false).unwrap_err();
        assert!(
            e.render().contains("qqqai/json"),
            "must name the digestless package: {}",
            e.render()
        );
        remove_tree(&base);
    }

    /// A digest that does not parse is a corrupt pin, not a missed lookup.
    #[test]
    fn offline_install_rejects_a_malformed_digest() {
        let base = temp_dir("offline-baddigest");
        let store = base.join("store");
        let project = base.join("proj");
        std::fs::create_dir_all(&project).expect("create project");
        let mut pkg = LockPackage::new("qqqai/json", "1.2.3");
        pkg.digest = Some("not-a-digest".to_owned());
        let mut lock = Lockfile::new();
        lock.push(pkg);

        let e = install_offline(&store, &project, &lock, false).unwrap_err();
        assert!(
            e.render().contains("qqqai/json"),
            "must name the package with the bad pin: {}",
            e.render()
        );
        remove_tree(&base);
    }

    /// A store entry that fails verification aborts loudly: the error names the
    /// package, and the destination is left absent — `materialize` removes its
    /// temp file rather than leaving a suspect file behind.
    #[test]
    fn offline_install_aborts_loud_on_a_corrupt_store_entry() {
        let base = temp_dir("offline-corrupt");
        let store = base.join("store");
        let project = base.join("proj");
        std::fs::create_dir_all(&project).expect("create project");
        let layout = qqq_pkg::store::StoreLayout::new(&store);
        let digest = layout.write(b"the original content").expect("seed");
        // Corrupt the entry in place, the way a truncated write would.
        std::fs::write(layout.artifact_path(&digest), b"tampered").expect("corrupt");
        let mut pkg = LockPackage::new("qqqai/json", "1.2.3");
        pkg.digest = Some(digest.prefixed());
        let mut lock = Lockfile::new();
        lock.push(pkg);

        let e = install_offline(&store, &project, &lock, false).unwrap_err();
        let text = e.render();
        assert!(text.contains("qqqai/json"), "must name the package: {text}");
        assert!(
            !project.join(".qqq/packages/qqqai/json").exists(),
            "a refused placement leaves no destination behind"
        );
        remove_tree(&base);
    }

    /// A bad name fails before its siblings are placed: validation lives in the
    /// check phase, so `[good-pin, ../../evil]` places nothing.
    #[test]
    fn offline_install_validates_every_name_before_placing_anything() {
        let (mut lock, store, project) =
            offline_world("badname", &[("qqqai/json", "1.2.3", b"present")]);
        let layout = qqq_pkg::store::StoreLayout::new(&store);
        let digest = layout.write(b"evil-bytes").expect("seed");
        let mut evil = LockPackage::new("../../evil", "9.9.9");
        evil.digest = Some(digest.prefixed());
        lock.push(evil);

        let e = install_offline(&store, &project, &lock, false).unwrap_err();
        assert!(
            e.render().contains("../../evil"),
            "must name the escaping pin: {}",
            e.render()
        );
        assert!(
            !project.join(".qqq/packages/qqqai/json").exists(),
            "all-or-nothing: the good pin stays unplaced"
        );
        remove_tree(project.parent().expect("base"));
    }

    /// A package name is a relative path under `.qqq/packages` — and `..`
    /// must not escape it. The lockfile is an input, and an input that names
    /// `../../evil` must be refused rather than followed.
    #[test]
    fn offline_package_names_cannot_escape_the_packages_dir() {
        let project = PathBuf::from("/proj");
        assert!(package_dest(&project, "../../evil").is_err());
        assert!(package_dest(&project, "a/../../b").is_err());
        assert!(package_dest(&project, "..\\evil").is_err());
        assert!(package_dest(&project, "").is_err());
        assert_eq!(
            package_dest(&project, "qqqai/json").expect("scoped name"),
            PathBuf::from("/proj/.qqq/packages/qqqai/json")
        );
    }

    /// `QQQ_STORE_DIR` wins when it is set; the home profile is the fallback.
    #[test]
    fn store_root_prefers_the_explicit_override() {
        assert_eq!(
            store_root_from(Some(OsStr::new("/s")), Some(OsStr::new("/h"))),
            Some(PathBuf::from("/s"))
        );
    }

    #[test]
    fn store_root_falls_back_to_the_home_profile() {
        assert_eq!(
            store_root_from(None, Some(OsStr::new("/h"))),
            Some(PathBuf::from("/h/.qqq/store"))
        );
        assert_eq!(store_root_from(None, None), None);
    }

    /// An explicitly empty override is not a root: it would resolve relative
    /// to the working directory, which is ambient state a placement path must
    /// never depend on.
    #[test]
    fn store_root_ignores_empty_values() {
        assert_eq!(
            store_root_from(Some(OsStr::new("")), Some(OsStr::new("/h"))),
            Some(PathBuf::from("/h/.qqq/store"))
        );
        assert_eq!(store_root_from(Some(OsStr::new("")), None), None);
        assert_eq!(store_root_from(None, Some(OsStr::new(""))), None);
    }
}
