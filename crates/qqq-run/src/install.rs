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
//! | `--offline` | resolve from the store | re-resolve from the store | yes |
//!
//! `--locked` answers "does the committed lockfile match this manifest?" — the
//! question CI asks. `--frozen` is `--locked` plus "and do not touch the
//! network", for an air-gapped build. `--offline` is different in kind: it
//! permits resolution but forbids fetching, which is why it is not a synonym.

use std::path::{Path, PathBuf};

use qqq_core::{Error, ErrorCode, Result};
use qqq_pkg::{LockDiff, LockPackage, Lockfile};

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
#[must_use]
pub fn resolve(manifest_deps: &[(String, String)], previous: Option<&Lockfile>) -> Resolution {
    let mut next = Lockfile::new();
    let mut unresolved = Vec::new();

    for (name, requirement) in manifest_deps {
        match previous.and_then(|l| l.get(name)) {
            Some(pinned) => {
                // Verify the pin still satisfies the manifest. A manifest edited
                // to demand `2.0` while the lockfile pins `1.2` is a lockfile
                // that must change, and carrying the pin across would make
                // `--locked` pass on a state that is wrong.
                if satisfies(requirement, &pinned.version) {
                    next.push(pinned.clone());
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

    fn deps(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, r)| ((*n).to_owned(), (*r).to_owned()))
            .collect()
    }

    // -- option semantics ---------------------------------------------------

    /// `--locked` and `--frozen` must never write.
    ///
    /// This is the whole contract of the flags: a CI job that passes `--locked`
    /// and has the lockfile changed underneath it has been defeated.
    #[test]
    fn locked_and_frozen_never_write() {
        assert!(!InstallOptions {
            mode: LockMode::Locked,
            ..Default::default()
        }
        .may_write());
        assert!(!InstallOptions {
            mode: LockMode::Frozen,
            ..Default::default()
        }
        .may_write());
        assert!(!InstallOptions {
            dry_run: true,
            ..Default::default()
        }
        .may_write());
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
        assert!(InstallOptions {
            mode: LockMode::Locked,
            ..Default::default()
        }
        .honours_lockfile());
        assert!(!InstallOptions {
            force: true,
            ..Default::default()
        }
        .honours_lockfile());
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
}
