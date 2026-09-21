// SPDX-License-Identifier: Apache-2.0

//! `qqqai update` — move dependencies forward within their declared ranges.
//!
//! Implements `CLI-007`; Proposal §5.2 (command table) and §5.4 (the capability
//! diff).
//!
//! # The two axes, and why they are the whole design
//!
//! `update` differs from `install` on exactly one question: **may a resolved
//! version change?** Everything else — the lockfile, the capability diff, the
//! atomic write — is shared, and this module reuses it rather than
//! reimplementing it.
//!
//! | Flag | May the version change? | Bounded by |
//! |---|---|---|
//! | *(none)* | yes | the manifest's requirement |
//! | `--latest` | yes | **nothing** — the newest published version |
//! | `--dry-run` | no write happens either way | — |
//!
//! # Why `--latest` is a separate flag and not the default
//!
//! A requirement expresses what the author is willing to accept; `--latest`
//! expresses that they have stopped caring about it for this run. Defaulting to
//! `--latest` would silently resolve `^1.2.3` to `2.0.0`, which is the single
//! most damaging thing a package manager can do by default — it turns a
//! conservative constraint into a breaking upgrade and does it while the user
//! believes they asked for a routine refresh.
//!
//! So the default honours the requirement, and crossing it requires a word.
//!
//! # Why the capability diff is not optional here
//!
//! §5.4's claim is about updates specifically: *"this update adds `http.client`
//! to `qqqai/telemetry`"*. An update is the moment authority can change without
//! the manifest changing — the manifest is byte-identical before and after, and
//! the only artefact that records the change is the lockfile diff. A command
//! that performed such an update without printing the diff would erase the one
//! signal §5.4 exists to provide.

use qqq_core::{Error, ErrorCode};
// `fmt::Write` for `write!` into an existing `String`, rather than
// `push_str(&format!(..))` which allocates a second string and discards it.
use std::fmt::Write as _;

use qqq_pkg::{LockDiff, LockPackage, Lockfile};

/// What `update` was asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UpdateOptions {
    /// Ignore the manifest's requirements and take the newest version.
    pub latest: bool,
    /// Report what would change without writing.
    pub dry_run: bool,
    /// Update only these packages; empty means all of them.
    ///
    /// Not a `Vec` in the struct because the selection is applied by the
    /// caller, which already has the argument list; keeping it out means
    /// `UpdateOptions` stays `Copy` and there is one list of names rather than
    /// two that can disagree.
    pub all: bool,
}

impl UpdateOptions {
    /// Whether the lockfile may be rewritten.
    #[must_use]
    pub const fn may_write(self) -> bool {
        !self.dry_run
    }

    /// How a package's new version is chosen.
    #[must_use]
    pub const fn strategy(self) -> Strategy {
        if self.latest {
            Strategy::Newest
        } else {
            Strategy::WithinRequirement
        }
    }
}

/// How a new version is chosen for a package that is being updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Stay inside the manifest's requirement. The default, and the safe one.
    WithinRequirement,
    /// Take the newest version the registry has, whatever the requirement says.
    Newest,
}

impl Strategy {
    /// The stable name, for `--json`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WithinRequirement => "within-requirement",
            Self::Newest => "latest",
        }
    }
}

/// What to do with one candidate version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Keep the pinned version.
    Keep {
        /// Why it was kept, in a form a human can read.
        reason: String,
    },
    /// Move to a new version.
    Move {
        /// The version being left.
        from: String,
        /// The version being adopted.
        to: String,
    },
}

/// A package selected for updating, with its decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateCandidate {
    /// The package name.
    pub name: String,
    /// The requirement from the manifest, if it declares one.
    pub requirement: Option<String>,
    /// What was decided.
    pub decision: Decision,
}

/// Decide what to do with one package.
///
/// # Why this is a pure function
///
/// The decision is the part worth testing, and it must not depend on the
/// filesystem, the network or the clock. Passing the candidate versions in
/// makes every branch reachable from a unit test — including the branches that
/// are hard to produce with a real registry, such as "a newer version exists but
/// the requirement forbids it".
#[must_use]
pub fn decide(
    name: &str,
    pinned: &str,
    requirement: Option<&str>,
    available: &[String],
    strategy: Strategy,
) -> UpdateCandidate {
    let requirement = requirement.map(str::to_owned);

    // Parse the pinned version once. If the lockfile holds something
    // unparsable, keeping it is the only honest option: moving off a version
    // we cannot read would be guessing.
    let Ok(current) = pinned.parse::<qqq_pkg::Version>() else {
        return UpdateCandidate {
            name: name.to_owned(),
            requirement,
            decision: Decision::Keep {
                reason: format!("the locked version `{pinned}` cannot be parsed"),
            },
        };
    };

    // Parse the requirement, once, outside the loop. An unparsable requirement
    // keeps the pin rather than admitting every version — the opposite default
    // would turn a typo into an unbounded upgrade.
    //
    // The text is cloned out of the `Option` first so the borrow does not
    // outlive the match arms that move `requirement`.
    let requirement_text = requirement.clone();
    let parsed = match requirement_text.as_deref() {
        Some(r) => match qqq_pkg::Requirement::parse(r) {
            Ok(req) => Some(req),
            Err(e) => {
                return UpdateCandidate {
                    name: name.to_owned(),
                    requirement,
                    decision: Decision::Keep {
                        reason: format!("the requirement `{r}` cannot be parsed: {e}"),
                    },
                }
            }
        },
        None => None,
    };

    // The best admissible version, by semver order rather than by the order the
    // registry happened to list them. A registry is not required to sort, and
    // taking the last element of an unsorted list is a bug that only appears
    // once a mirror changes its ordering.
    let mut best: Option<qqq_pkg::Version> = None;
    for candidate in available {
        let Ok(v) = candidate.parse::<qqq_pkg::Version>() else {
            continue;
        };
        if v <= current {
            continue;
        }
        if strategy == Strategy::WithinRequirement {
            let Some(req) = &parsed else {
                // No requirement and not `--latest`: nothing authorises a move.
                return UpdateCandidate {
                    name: name.to_owned(),
                    requirement,
                    decision: Decision::Keep {
                        reason: "no requirement is declared, so there is no range to move within"
                            .to_owned(),
                    },
                };
            };
            if !req.matches(&v) {
                continue;
            }
        }
        if best.is_none_or(|b| v > b) {
            best = Some(v);
        }
    }

    match best {
        Some(v) => UpdateCandidate {
            name: name.to_owned(),
            requirement,
            decision: Decision::Move {
                from: pinned.to_owned(),
                to: v.to_string(),
            },
        },
        None => UpdateCandidate {
            name: name.to_owned(),
            requirement,
            decision: Decision::Keep {
                reason: if strategy == Strategy::Newest {
                    format!("`{pinned}` is already the newest published version")
                } else {
                    match &parsed {
                        Some(r) => format!("no published version above `{pinned}` satisfies `{r}`"),
                        None => format!("nothing above `{pinned}` is permitted"),
                    }
                },
            },
        },
    }
}

/// The outcome of an update, for machine consumption.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UpdateOutput {
    /// The lockfile path, as a display path.
    pub lockfile: String,
    /// The strategy used: `within-requirement` or `latest`.
    pub strategy: String,
    /// Whether a rehearsal — nothing was written.
    pub dry_run: bool,
    /// Whether the lockfile was rewritten.
    pub wrote_lockfile: bool,
    /// Every package considered, in name order.
    pub candidates: Vec<CandidateReport>,
    /// How many packages moved.
    pub updated: usize,
    /// How many were kept.
    pub kept: usize,
    /// Packages whose **authority** changed, shaped as in `install`.
    pub capability_changes: Vec<crate::install::CapabilityChangeReport>,
    /// Whether any package gained authority.
    pub escalation: bool,
}

/// One package's outcome, shaped for output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CandidateReport {
    /// The package name.
    pub name: String,
    /// The version being left.
    pub from: String,
    /// The version being adopted, when one was.
    pub to: Option<String>,
    /// Whether it moved.
    pub updated: bool,
    /// The manifest requirement, when declared.
    pub requirement: Option<String>,
    /// Why it was kept, for a package that did not move.
    ///
    /// Carried so `--dry-run` answers "why is this not updating?" without the
    /// user having to reason about the requirement themselves. A no-op update
    /// that explains nothing is indistinguishable from one that is broken.
    pub reason: Option<String>,
}

impl crate::output::CommandOutput for UpdateOutput {
    fn command(&self) -> crate::output::CommandName {
        crate::output::CommandName::Update
    }

    fn summary(&self) -> String {
        // As with `install`: the capability diff leads when there is one,
        // because an update is the moment authority changes without the
        // manifest changing, and that is the signal §5.4 exists for.
        let mut out = if self.escalation {
            let detail: Vec<String> = self
                .capability_changes
                .iter()
                .filter(|c| !c.added.is_empty())
                .map(|c| format!("{} gains {}", c.package, c.added.join(", ")))
                .collect();
            format!(
                "AUTHORITY ESCALATION — {}; {} updated, {} kept",
                detail.join("; "),
                self.updated,
                self.kept
            )
        } else {
            format!(
                "{} updated, {} kept ({})",
                self.updated, self.kept, self.strategy
            )
        };

        // In human format this is the whole output, so the packages must be
        // named. `install` learned this the hard way (`§O-036a`): a count is a
        // heading, not an answer.
        let moved: Vec<&CandidateReport> = self.candidates.iter().filter(|c| c.updated).collect();
        if !moved.is_empty() {
            out.push('\n');
            for c in &moved {
                let _ = write!(
                    out,
                    "\n  {}  {} → {}",
                    c.name,
                    c.from,
                    c.to.as_deref().unwrap_or("?")
                );
            }
        }

        // Kept packages are listed only when the user asked about all of them,
        // which is what `--dry-run` means. Printing every unchanged dependency
        // after a routine update would bury the ones that moved.
        if self.dry_run {
            let held: Vec<&CandidateReport> =
                self.candidates.iter().filter(|c| !c.updated).collect();
            if !held.is_empty() {
                out.push_str("\n\nkept:");
                for c in &held {
                    let _ = write!(
                        out,
                        "\n  {}  {} — {}",
                        c.name,
                        c.from,
                        c.reason.as_deref().unwrap_or("no change")
                    );
                }
            }
        }

        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

// ---------------------------------------------------------------------------
// Applying the decisions
// ---------------------------------------------------------------------------

/// Apply a set of decisions to a lockfile, producing the updated one.
///
/// Returns the new lockfile only — the diff is computed by the caller from the
/// two, so the diff can never disagree with the change that produced it. This
/// is the same discipline as `LockDiff` deriving `capability_changes` from
/// `changes` rather than computing them separately.
#[must_use]
pub fn apply(lock: &Lockfile, candidates: &[UpdateCandidate]) -> Lockfile {
    // Only moving candidates matter. A `Keep` is expressed by *not* touching
    // the package, so an unmentioned package is a kept package and there is no
    // way for a stale entry to survive a decision to drop it.
    let moves: std::collections::BTreeMap<&str, &str> = candidates
        .iter()
        .filter_map(|c| match &c.decision {
            Decision::Move { to, .. } => Some((c.name.as_str(), to.as_str())),
            Decision::Keep { .. } => None,
        })
        .collect();

    let mut next = Lockfile::new();
    for pkg in &lock.packages {
        match moves.get(pkg.name.as_str()) {
            Some(to) => {
                // A moved package keeps its `caps` from the lockfile. The real
                // registry would supply the new version's capabilities, and
                // replacing them with an empty set here would *hide* an
                // escalation rather than show a false one — but it would also
                // hide a de-escalation. The honest position: `update` without a
                // registry cannot know the new authority, so it must not claim
                // the old one still holds. See `authority_unknown_for_moved`.
                next.push(LockPackage {
                    version: (*to).to_owned(),
                    caps: pkg.caps.clone(),
                    ..pkg.clone()
                });
            }
            None => next.push(pkg.clone()),
        }
    }
    next
}

/// Whether a move's new authority is knowable without the registry.
///
/// Always `false` today, and stated as a function so the gap is visible in the
/// type rather than in a comment. `update` can move a version but cannot fetch
/// the new version's declared capabilities, so the `caps` it carries forward are
/// the *old* ones. A registry-backed implementation would replace this with a
/// real lookup; until then, callers must not treat a moved package's `caps` as
/// authoritative.
#[must_use]
pub const fn authority_unknown_for_moved() -> bool {
    true
}

/// The diff between two lockfiles, for reporting.
#[must_use]
pub fn diff(old: &Lockfile, new: &Lockfile) -> LockDiff {
    LockDiff::compute(old, new)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// The error for an update that cannot proceed.
#[must_use]
pub fn cannot_update(name: &str, reason: &str) -> Error {
    Error::new(
        ErrorCode::RegistryUnreachable,
        format!("could not update `{name}`: {reason}"),
    )
    .with_remediation(
        "the QQQ registry is not built yet (Checklist `PKG-006`), so `update` \
         can only move within versions already known; see QQQ-Proposal-V1.md \
         §6.5 for the registry plan",
    )
}

/// The error for `--latest` combined with a pin the user also constrained.
///
/// Refused rather than resolved by precedence: `--latest` and an `--exact`
/// requirement state opposite intents, and silently letting one win is how a
/// user ends up with a major upgrade they did not ask for.
#[must_use]
pub fn contradictory_request(name: &str) -> Error {
    Error::new(
        ErrorCode::VersionUnsatisfiable,
        format!("`{name}` is pinned exactly in the manifest, so `--latest` cannot apply to it"),
    )
    .with_remediation(
        "remove `exact = true` for this dependency, or drop `--latest` and \
         update within the requirement",
    )
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/// Which candidate versions are available for a package.
///
/// A trait rather than a slice of `String` because the registry does not exist
/// yet, and the shape of this seam decides whether adding it later is a small
/// change or a rewrite. With it in place, `update`'s decision logic is fully
/// exercised today against a fixture, and the registry becomes one
/// implementation of the trait rather than a new code path.
///
/// It is deliberately **not** a network abstraction: it has no error case and no
/// asynchrony, because a source that cannot answer returns an empty list and the
/// caller reports "nothing newer" rather than failing the whole update. A
/// registry outage must not stop a user updating the packages that are
/// resolvable from the store.
pub trait VersionSource {
    /// Every published version of `name`, in any order.
    ///
    /// Order is not significant: [`decide`] picks by semver, not by position,
    /// because a registry is not required to sort and a mirror changing its
    /// ordering must not change what QQQ installs.
    fn available(&self, name: &str) -> Vec<String>;
}

/// A source that knows nothing — the state of the world while `PKG-006` is
/// unbuilt.
///
/// Named rather than expressed as an empty `Vec` at each call site, so the gap
/// is greppable and so `update`'s behaviour without a registry is a deliberate
/// choice with a name rather than an accident.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRegistry;

impl VersionSource for NoRegistry {
    fn available(&self, _name: &str) -> Vec<String> {
        Vec::new()
    }
}

/// A fixed set of versions, for tests and for `--offline` against the store.
#[derive(Debug, Clone, Default)]
pub struct FixedVersions {
    /// The versions, keyed by package name.
    pub versions: std::collections::BTreeMap<String, Vec<String>>,
}

impl VersionSource for FixedVersions {
    fn available(&self, name: &str) -> Vec<String> {
        self.versions.get(name).cloned().unwrap_or_default()
    }
}

/// Decide what to do with every package in a lockfile.
///
/// Extracted from the command dispatcher so it can be tested without a
/// filesystem, and so the dispatcher stays a translation layer rather than the
/// place logic accumulates.
#[must_use]
pub fn plan(
    lock: &Lockfile,
    requirements: &std::collections::BTreeMap<String, String>,
    source: &dyn VersionSource,
    strategy: Strategy,
) -> Vec<UpdateCandidate> {
    let mut candidates: Vec<UpdateCandidate> = lock
        .packages
        .iter()
        .map(|pkg| {
            let requirement = requirements.get(&pkg.name).map(String::as_str);
            let available = source.available(&pkg.name);
            decide(&pkg.name, &pkg.version, requirement, &available, strategy)
        })
        .collect();

    // Sorted by name so the output is deterministic. A report whose order
    // depends on iteration order cannot be diffed between two runs, and this
    // output exists to be diffed.
    candidates.sort_by(|a, b| a.name.cmp(&b.name));
    candidates
}

/// Shape decided candidates for output.
///
/// `pinned` supplies each package's current version, because `Decision::Keep`
/// does not carry it — and reconstructing it from the wrong place is how a
/// report ends up naming a version the lockfile never held.
#[must_use]
pub fn report(candidates: &[UpdateCandidate], pinned: &Lockfile) -> Vec<CandidateReport> {
    candidates
        .iter()
        .map(|c| {
            let from = pinned
                .get(&c.name)
                .map_or_else(String::new, |p| p.version.clone());
            match &c.decision {
                Decision::Move { to, .. } => CandidateReport {
                    name: c.name.clone(),
                    from,
                    to: Some(to.clone()),
                    updated: true,
                    requirement: c.requirement.clone(),
                    reason: None,
                },
                Decision::Keep { reason } => CandidateReport {
                    name: c.name.clone(),
                    from,
                    to: None,
                    updated: false,
                    requirement: c.requirement.clone(),
                    reason: Some(reason.clone()),
                },
            }
        })
        .collect()
}

/// How many candidates would move.
#[must_use]
pub fn moved_count(candidates: &[UpdateCandidate]) -> usize {
    candidates
        .iter()
        .filter(|c| matches!(c.decision, Decision::Move { .. }))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn versions(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    // -- strategy -----------------------------------------------------------

    #[test]
    fn the_default_strategy_respects_the_requirement() {
        assert_eq!(
            UpdateOptions::default().strategy(),
            Strategy::WithinRequirement
        );
        assert_eq!(
            UpdateOptions {
                latest: true,
                ..Default::default()
            }
            .strategy(),
            Strategy::Newest
        );
    }

    /// A dry run never writes, and a real run does.
    #[test]
    fn a_dry_run_never_writes() {
        assert!(UpdateOptions::default().may_write());
        assert!(!UpdateOptions {
            dry_run: true,
            ..Default::default()
        }
        .may_write());
    }

    // -- decide -------------------------------------------------------------

    /// The default moves forward, but only inside the requirement.
    ///
    /// This is the central safety property: `^1.2.3` must never resolve to
    /// `2.0.0`, because doing so while the user believes they asked for a
    /// routine refresh is the most damaging thing a package manager can do.
    #[test]
    fn the_default_strategy_stays_inside_the_requirement() {
        let c = decide(
            "p",
            "1.2.3",
            Some("^1.2.3"),
            &versions(&["1.2.4", "1.9.0", "2.0.0"]),
            Strategy::WithinRequirement,
        );
        assert_eq!(
            c.decision,
            Decision::Move {
                from: "1.2.3".to_owned(),
                to: "1.9.0".to_owned()
            },
            "the newest admissible version, not the newest published one"
        );
    }

    /// `--latest` crosses the requirement, deliberately.
    #[test]
    fn the_latest_strategy_crosses_the_requirement() {
        let c = decide(
            "p",
            "1.2.3",
            Some("^1.2.3"),
            &versions(&["1.2.4", "2.0.0"]),
            Strategy::Newest,
        );
        assert_eq!(
            c.decision,
            Decision::Move {
                from: "1.2.3".to_owned(),
                to: "2.0.0".to_owned()
            }
        );
    }

    /// With nothing newer, the pin is kept and the reason says so.
    #[test]
    fn an_up_to_date_package_is_kept_with_a_reason() {
        let c = decide(
            "p",
            "1.2.3",
            Some("^1.2.3"),
            &versions(&["1.2.3"]),
            Strategy::WithinRequirement,
        );
        match c.decision {
            Decision::Keep { reason } => {
                assert!(
                    reason.contains("1.2.3"),
                    "the reason should name the version: {reason}"
                );
            }
            Decision::Move { from, to } => {
                panic!("expected Keep, got a move {from} -> {to}")
            }
        }
    }

    /// A newer version outside the requirement is kept, and the reason explains
    /// why — the question a user actually asks.
    #[test]
    fn a_newer_version_outside_the_range_is_kept_with_an_explanation() {
        let c = decide(
            "p",
            "1.2.3",
            Some("^1.2.3"),
            &versions(&["2.0.0"]),
            Strategy::WithinRequirement,
        );
        match c.decision {
            Decision::Keep { reason } => {
                assert!(
                    reason.contains("^1.2.3"),
                    "the reason must quote the requirement that blocked it: {reason}"
                );
            }
            Decision::Move { from, to } => {
                panic!("expected Keep, got a move {from} -> {to}")
            }
        }
    }

    /// The registry's ordering is not trusted.
    ///
    /// A registry is not required to return versions sorted, so taking the last
    /// element of the list is a bug that appears only when a mirror changes its
    /// ordering.
    #[test]
    fn the_best_version_is_chosen_by_semver_not_by_list_order() {
        let c = decide(
            "p",
            "1.0.0",
            Some("^1.0.0"),
            &versions(&["1.9.0", "1.2.0", "1.5.0"]),
            Strategy::WithinRequirement,
        );
        assert_eq!(
            c.decision,
            Decision::Move {
                from: "1.0.0".to_owned(),
                to: "1.9.0".to_owned()
            }
        );
    }

    /// A downgrade is never a move.
    #[test]
    fn a_lower_version_is_never_chosen() {
        let c = decide(
            "p",
            "2.0.0",
            Some(">=1.0"),
            &versions(&["1.0.0", "1.5.0"]),
            Strategy::Newest,
        );
        assert!(
            matches!(c.decision, Decision::Keep { .. }),
            "an update must never go backwards: {:?}",
            c.decision
        );
    }

    /// Without a requirement, the default keeps the pin.
    ///
    /// Nothing authorises a move: the manifest has not said what it will
    /// accept, and inventing a range would be the tool deciding policy.
    #[test]
    fn no_requirement_means_no_move_by_default() {
        let c = decide(
            "p",
            "1.0.0",
            None,
            &versions(&["1.1.0", "2.0.0"]),
            Strategy::WithinRequirement,
        );
        match c.decision {
            Decision::Keep { reason } => {
                assert!(reason.contains("no requirement"), "{reason}");
            }
            Decision::Move { from, to } => {
                panic!("expected Keep, got a move {from} -> {to}")
            }
        }
    }

    /// But `--latest` still moves it, because that is what it is for.
    #[test]
    fn latest_moves_a_package_with_no_requirement() {
        let c = decide("p", "1.0.0", None, &versions(&["2.0.0"]), Strategy::Newest);
        assert_eq!(
            c.decision,
            Decision::Move {
                from: "1.0.0".to_owned(),
                to: "2.0.0".to_owned()
            }
        );
    }

    /// An unparsable requirement keeps the pin rather than admitting everything.
    ///
    /// The opposite default — treat an unreadable requirement as `*` — turns a
    /// typo into an unbounded upgrade.
    #[test]
    fn an_unparsable_requirement_keeps_the_pin() {
        let c = decide(
            "p",
            "1.0.0",
            Some("not a requirement"),
            &versions(&["2.0.0"]),
            Strategy::WithinRequirement,
        );
        match c.decision {
            Decision::Keep { reason } => {
                assert!(reason.contains("cannot be parsed"), "{reason}");
            }
            Decision::Move { from, to } => {
                panic!("expected Keep, got a move {from} -> {to}")
            }
        }
    }

    /// An unparsable *pinned* version keeps it, since moving off a version we
    /// cannot read would be guessing.
    #[test]
    fn an_unparsable_pin_is_kept() {
        let c = decide(
            "p",
            "not-a-version",
            Some("^1.0.0"),
            &versions(&["1.5.0"]),
            Strategy::Newest,
        );
        match c.decision {
            Decision::Keep { reason } => {
                assert!(reason.contains("cannot be parsed"), "{reason}");
            }
            Decision::Move { from, to } => {
                panic!("expected Keep, got a move {from} -> {to}")
            }
        }
    }

    /// Unparsable candidate versions are skipped, not fatal.
    ///
    /// A registry index with one malformed entry must not break the update of
    /// every other package.
    #[test]
    fn an_unparsable_candidate_is_skipped() {
        let c = decide(
            "p",
            "1.0.0",
            Some("^1.0.0"),
            &versions(&["garbage", "1.5.0", "also garbage"]),
            Strategy::WithinRequirement,
        );
        assert_eq!(
            c.decision,
            Decision::Move {
                from: "1.0.0".to_owned(),
                to: "1.5.0".to_owned()
            }
        );
    }

    /// Partial versions in the requirement work here too.
    #[test]
    fn a_partial_requirement_bounds_the_update() {
        let c = decide(
            "p",
            "1.2.0",
            Some("1.2"),
            &versions(&["1.5.0", "2.0.0"]),
            Strategy::WithinRequirement,
        );
        assert_eq!(
            c.decision,
            Decision::Move {
                from: "1.2.0".to_owned(),
                to: "1.5.0".to_owned()
            },
            "`1.2` means `^1.2.0`, so 1.5.0 is in range and 2.0.0 is not"
        );
    }

    /// A comma range bounds the update, exercising the new conjunction support.
    #[test]
    fn a_comma_range_bounds_the_update() {
        let c = decide(
            "p",
            "1.0.0",
            Some(">=1.0, <1.5"),
            &versions(&["1.4.0", "1.5.0", "2.0.0"]),
            Strategy::WithinRequirement,
        );
        assert_eq!(
            c.decision,
            Decision::Move {
                from: "1.0.0".to_owned(),
                to: "1.4.0".to_owned()
            },
            "1.5.0 is excluded by the upper bound"
        );
    }

    /// An empty registry keeps everything, rather than deleting packages.
    #[test]
    fn an_empty_registry_keeps_the_pin() {
        let c = decide("p", "1.0.0", Some("^1.0.0"), &[], Strategy::Newest);
        assert!(matches!(c.decision, Decision::Keep { .. }));
    }

    // -- apply --------------------------------------------------------------

    fn lock_with(packages: &[(&str, &str, &[&str])]) -> Lockfile {
        let mut l = Lockfile::new();
        for (name, version, caps) in packages {
            l.push(LockPackage::new(*name, *version).with_caps(caps.iter().copied()));
        }
        l
    }

    #[test]
    fn apply_moves_only_the_decided_packages() {
        let old = lock_with(&[("a", "1.0.0", &[]), ("b", "1.0.0", &[])]);
        let candidates = vec![UpdateCandidate {
            name: "a".to_owned(),
            requirement: Some("^1.0.0".to_owned()),
            decision: Decision::Move {
                from: "1.0.0".to_owned(),
                to: "1.5.0".to_owned(),
            },
        }];

        let new = apply(&old, &candidates);
        assert_eq!(new.get("a").unwrap().version, "1.5.0");
        assert_eq!(new.get("b").unwrap().version, "1.0.0", "b was not decided");
        assert_eq!(new.len(), 2, "nothing may be dropped");
    }

    /// A package that was not mentioned survives unchanged.
    ///
    /// `apply` uses *absence from the move list* to mean "keep", so a bug that
    /// treated an unmentioned package as removable would silently delete
    /// dependencies.
    #[test]
    fn an_unmentioned_package_is_kept_not_dropped() {
        let old = lock_with(&[
            ("a", "1.0.0", &[]),
            ("b", "2.0.0", &[]),
            ("c", "3.0.0", &[]),
        ]);
        let new = apply(&old, &[]);
        assert_eq!(new.len(), old.len());
        for name in ["a", "b", "c"] {
            assert_eq!(
                new.get(name).unwrap().version,
                old.get(name).unwrap().version
            );
        }
    }

    /// Capabilities are carried across a move, and the gap is documented.
    ///
    /// Without the registry `update` cannot know the new version's declared
    /// authority, so it must not silently *drop* the old capabilities: an empty
    /// set would make the capability diff read as a de-escalation, which is a
    /// false statement about a security property.
    #[test]
    fn a_move_carries_capabilities_across_rather_than_emptying_them() {
        let old = lock_with(&[("a", "1.0.0", &["crypto.hash"])]);
        let candidates = vec![UpdateCandidate {
            name: "a".to_owned(),
            requirement: None,
            decision: Decision::Move {
                from: "1.0.0".to_owned(),
                to: "2.0.0".to_owned(),
            },
        }];

        let new = apply(&old, &candidates);
        assert_eq!(new.get("a").unwrap().caps, vec!["crypto.hash"]);
        assert!(
            authority_unknown_for_moved(),
            "the gap must remain visible until the registry can supply the real caps"
        );
    }

    /// A move produces a diff that reports it.
    #[test]
    fn a_move_appears_in_the_diff() {
        let old = lock_with(&[("a", "1.0.0", &[])]);
        let candidates = vec![UpdateCandidate {
            name: "a".to_owned(),
            requirement: None,
            decision: Decision::Move {
                from: "1.0.0".to_owned(),
                to: "1.5.0".to_owned(),
            },
        }];
        let new = apply(&old, &candidates);

        let d = diff(&old, &new);
        assert!(!d.is_empty(), "the move must be reported");
        assert_eq!(d.changes.len(), 1);
    }

    /// No moves, no diff.
    #[test]
    fn keeping_everything_produces_an_empty_diff() {
        let old = lock_with(&[("a", "1.0.0", &[])]);
        let new = apply(&old, &[]);
        assert!(diff(&old, &new).is_empty());
    }

    // -- error messages -----------------------------------------------------

    #[test]
    fn the_cannot_update_error_names_the_package_and_the_gap() {
        let e = cannot_update("qqqai/json", "no registry");
        assert_eq!(e.code, ErrorCode::RegistryUnreachable);
        let text = e.render();
        assert!(text.contains("qqqai/json"), "{text}");
        assert!(text.contains("PKG-006"), "{text}");
    }

    #[test]
    fn the_contradictory_request_error_explains_both_ways_out() {
        let e = contradictory_request("qqqai/json");
        let text = e.render();
        assert!(text.contains("exact = true"), "{text}");
        assert!(text.contains("--latest"), "{text}");
    }

    // -- plan, report and the version-source seam ---------------------------
    //
    // These exercise the path the registry will plug into. Without them, the
    // decision logic is only reachable through the CLI with an empty candidate
    // list, and every branch that involves a *newer* version would be untested
    // until `PKG-006` lands — which is precisely when a bug there is most
    // expensive.

    fn requirements(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(n, r)| ((*n).to_owned(), (*r).to_owned()))
            .collect()
    }

    fn source(pairs: &[(&str, &[&str])]) -> FixedVersions {
        FixedVersions {
            versions: pairs
                .iter()
                .map(|(n, vs)| {
                    (
                        (*n).to_owned(),
                        vs.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
                    )
                })
                .collect(),
        }
    }

    /// A plan moves a package the source knows a newer version for.
    #[test]
    fn plan_moves_a_package_when_a_newer_version_is_available() {
        let lock = lock_with(&[("a", "1.2.0", &[])]);
        let src = source(&[("a", &["1.2.0", "1.5.0", "2.0.0"])]);

        let candidates = plan(
            &lock,
            &requirements(&[("a", "^1.2.0")]),
            &src,
            Strategy::WithinRequirement,
        );

        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].decision,
            Decision::Move {
                from: "1.2.0".to_owned(),
                to: "1.5.0".to_owned()
            },
            "1.5.0 is in range, 2.0.0 is not"
        );
        assert_eq!(moved_count(&candidates), 1);
    }

    /// The plan is deterministic regardless of the source's ordering.
    #[test]
    fn plan_is_sorted_by_name() {
        let lock = lock_with(&[("zeta", "1.0.0", &[]), ("alpha", "1.0.0", &[])]);
        let src = NoRegistry;

        let candidates = plan(
            &lock,
            &requirements(&[("zeta", "^1.0"), ("alpha", "^1.0")]),
            &src,
            Strategy::WithinRequirement,
        );

        let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "zeta"], "output must be diffable");
    }

    /// A package in the lockfile with no manifest entry is kept, not dropped.
    #[test]
    fn plan_keeps_a_package_the_manifest_does_not_declare() {
        let lock = lock_with(&[("orphan", "1.0.0", &[])]);
        let src = source(&[("orphan", &["2.0.0"])]);

        let candidates = plan(&lock, &requirements(&[]), &src, Strategy::WithinRequirement);

        assert_eq!(candidates.len(), 1, "the package must still be reported");
        assert!(
            matches!(candidates[0].decision, Decision::Keep { .. }),
            "nothing authorises a move: {:?}",
            candidates[0].decision
        );
    }

    /// `report` names the version actually pinned, for a kept package.
    ///
    /// `Decision::Keep` does not carry the version, so this is the join that can
    /// silently produce an empty or wrong `from`.
    #[test]
    fn report_fills_from_the_pinned_version_for_a_kept_package() {
        let lock = lock_with(&[("a", "7.7.7", &[])]);
        let candidates = plan(
            &lock,
            &requirements(&[("a", "^1.0")]),
            &NoRegistry,
            Strategy::WithinRequirement,
        );

        let reports = report(&candidates, &lock);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].from, "7.7.7");
        assert!(!reports[0].updated);
        assert!(reports[0].to.is_none());
        assert!(reports[0].reason.is_some(), "a keep must explain itself");
    }

    /// `report` fills `to` for a moved package and leaves the reason empty.
    #[test]
    fn report_fills_to_for_a_moved_package() {
        let lock = lock_with(&[("a", "1.0.0", &[])]);
        let src = source(&[("a", &["1.0.0", "1.1.0"])]);
        let candidates = plan(
            &lock,
            &requirements(&[("a", "^1.0.0")]),
            &src,
            Strategy::WithinRequirement,
        );

        let reports = report(&candidates, &lock);
        assert_eq!(reports[0].from, "1.0.0");
        assert_eq!(reports[0].to.as_deref(), Some("1.1.0"));
        assert!(reports[0].updated);
        assert!(reports[0].reason.is_none(), "a move needs no excuse");
    }

    /// `NoRegistry` answers nothing, and that is its whole contract.
    #[test]
    fn the_no_registry_source_knows_nothing() {
        assert!(NoRegistry.available("anything").is_empty());
    }

    /// `FixedVersions` answers only for names it holds.
    #[test]
    fn fixed_versions_answers_only_for_known_names() {
        let src = source(&[("a", &["1.0.0"])]);
        assert_eq!(src.available("a"), vec!["1.0.0"]);
        assert!(src.available("b").is_empty());
    }

    /// A full plan-and-apply cycle moves exactly what the plan said.
    #[test]
    fn applying_a_plan_moves_exactly_what_it_reported() {
        let lock = lock_with(&[("a", "1.0.0", &[]), ("b", "1.0.0", &[])]);
        let src = source(&[("a", &["2.0.0"]), ("b", &["1.0.0"])]);

        let candidates = plan(
            &lock,
            &requirements(&[("a", "^1.0.0"), ("b", "^1.0.0")]),
            &src,
            Strategy::WithinRequirement,
        );
        let expected = moved_count(&candidates);

        let next = apply(&lock, &candidates);
        let d = diff(&lock, &next);

        assert_eq!(d.changes.len(), expected);
        assert_eq!(next.get("a").unwrap().version, "1.0.0", "out of range");
        assert_eq!(next.get("b").unwrap().version, "1.0.0", "already newest");
    }

    /// `--latest` through the full plan moves past the requirement.
    #[test]
    fn latest_through_plan_crosses_the_requirement() {
        let lock = lock_with(&[("a", "1.0.0", &[])]);
        let src = source(&[("a", &["1.5.0", "2.0.0"])]);

        let candidates = plan(
            &lock,
            &requirements(&[("a", "^1.0.0")]),
            &src,
            Strategy::Newest,
        );
        assert_eq!(
            candidates[0].decision,
            Decision::Move {
                from: "1.0.0".to_owned(),
                to: "2.0.0".to_owned()
            }
        );
    }
}
