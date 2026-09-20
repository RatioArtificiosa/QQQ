//! Semantic versions and requirement matching.
//!
//! Implements the versioning half of `PKG-003` and the version format checked by
//! `CON-007`.
//!
//! # Why this is hand-written rather than using the `semver` crate
//!
//! Three reasons, and the third is decisive:
//!
//! 1. **QQQ already parses semver in `qqq-core`.** A second, independent parser
//!    in a dependency would be a second source of truth for "is this a valid
//!    version", and the two would eventually disagree about a pre-release.
//! 2. **The requirement syntax is narrower than crates.io's.** QQQ's manifest
//!    accepts a deliberate subset, and accepting the full grammar would mean
//!    supporting forms nobody should write.
//! 3. **Version comparison is a compatibility surface.** Two versions comparing
//!    differently in different QQQ releases would change which packages install.
//!    Owning the comparison means owning that guarantee, and a hand-written
//!    implementation of `major.minor.patch` plus a pre-release is small enough
//!    to review in one sitting.
//!
//! # The subset, stated explicitly
//!
//! | Form | Meaning | Example |
//! |---|---|---|
//! | `1.2.3` | exactly | `=1.2.3` |
//! | `^1.2.3` | compatible | `>=1.2.3, <2.0.0` |
//! | `~1.2.3` | patch-level | `>=1.2.3, <1.3.0` |
//! | `>=1.2.3` | at least | |
//! | `>`, `<`, `<=` | the usual meanings | |
//! | `*` | any | |
//!
//! **Deliberately absent:** `1.2.*` wildcards, `||` unions, and comma lists. A
//! requirement that needs a union is a requirement that should be two
//! dependencies, and a wildcard patch is how a build silently picks up a
//! different version than the author tested.

use std::fmt;

use qqq_core::{Error, ErrorCode, Result};

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// A semantic version.
///
/// Re-exported from `qqq-core` so the whole workspace has **one** version type.
/// Two types would mean a conversion at every boundary, and a conversion is
/// where two representations of "1.0.0" quietly become different.
pub use qqq_core::Version;

// ---------------------------------------------------------------------------
// Requirement
// ---------------------------------------------------------------------------

/// A version requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// The comparison operator.
    op: Op,
    /// The version it compares against, absent for `*`.
    version: Option<Version>,
}

/// A comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `=1.2.3` — exactly this version.
    Exact,
    /// `^1.2.3` — compatible: same major, and at least this minor.
    Caret,
    /// `~1.2.3` — patch-level: same major and minor, at least this patch.
    Tilde,
    /// `>=1.2.3`
    GreaterOrEqual,
    /// `>1.2.3`
    Greater,
    /// `<=1.2.3`
    LessOrEqual,
    /// `<1.2.3`
    Less,
    /// `*` — any version.
    Any,
}

impl Op {
    /// The operator as written.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "=",
            Self::Caret => "^",
            Self::Tilde => "~",
            Self::GreaterOrEqual => ">=",
            Self::Greater => ">",
            Self::LessOrEqual => "<=",
            Self::Less => "<",
            Self::Any => "*",
        }
    }
}

impl Requirement {
    /// Parse a requirement.
    ///
    /// # Errors
    ///
    /// `QQQ-5004` when the requirement is malformed, naming the offending part.
    /// The code is `VersionUnsatisfiable`'s neighbour — a requirement that
    /// cannot be parsed is a requirement that cannot be satisfied.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(bad(s, "a requirement cannot be empty"));
        }
        if s == "*" {
            return Ok(Self {
                op: Op::Any,
                version: None,
            });
        }

        // Longest operator first: `>=` must not be read as `>` followed by `=`.
        // This is the classic off-by-one in operator lexing, and it produces a
        // requirement that parses and means something different.
        let (op, rest) = if let Some(r) = s.strip_prefix(">=") {
            (Op::GreaterOrEqual, r)
        } else if let Some(r) = s.strip_prefix("<=") {
            (Op::LessOrEqual, r)
        } else if let Some(r) = s.strip_prefix('^') {
            (Op::Caret, r)
        } else if let Some(r) = s.strip_prefix('~') {
            (Op::Tilde, r)
        } else if let Some(r) = s.strip_prefix('>') {
            (Op::Greater, r)
        } else if let Some(r) = s.strip_prefix('<') {
            (Op::Less, r)
        } else if let Some(r) = s.strip_prefix('=') {
            (Op::Exact, r)
        } else {
            // A bare version means "compatible with", which is what every
            // package manager converges on because it is what the author
            // almost always means.
            (Op::Caret, s)
        };

        let rest = rest.trim();
        if rest.is_empty() {
            return Err(bad(s, "the operator has no version after it"));
        }

        let version: Version = rest.parse().map_err(|e| {
            Error::new(
                ErrorCode::VersionUnsatisfiable,
                format!("`{rest}` is not a valid version"),
            )
            .with_cause(format!("{e}"))
            .with_remediation("versions look like `1.2.3`, optionally with `-pre` or `+build`")
        })?;

        Ok(Self {
            op,
            version: Some(version),
        })
    }

    /// Whether a version satisfies this requirement.
    ///
    /// # Pre-releases are not representable, and that is a recorded gap
    ///
    /// `qqq_core::Version` is strictly `major.minor.patch` — it has no
    /// pre-release field and its parser rejects `1.2.3-beta` outright. So this
    /// function cannot express the usual rule that a pre-release is opted into
    /// explicitly rather than adopted by a caret requirement.
    ///
    /// That is a **deliberate deferral rather than an oversight**, and it is
    /// recorded in Observations §O-032 along with what has to change when it is
    /// lifted: adding a pre-release component to `Version` changes a
    /// compatibility surface (`PKG-007` immutable versions would have to
    /// distinguish `2.0.0-rc.1` from `2.0.0`), so it belongs in a change that
    /// reviews that surface rather than in this crate's first commit.
    ///
    /// Writing the check against a field that does not exist would have been
    /// dead code that looked like support.
    #[must_use]
    pub fn matches(&self, candidate: &Version) -> bool {
        let Some(base) = &self.version else {
            return true; // `*`
        };

        match self.op {
            Op::Any => true,
            Op::Exact => candidate == base,
            Op::GreaterOrEqual => candidate >= base,
            Op::Greater => candidate > base,
            Op::LessOrEqual => candidate <= base,
            Op::Less => candidate < base,
            Op::Caret => {
                // `^0.x.y` is special: below 1.0, the minor is the breaking
                // boundary. `^0.2.3` means `>=0.2.3, <0.3.0`, not `<1.0.0`.
                //
                // This is the single most-violated rule in semver handling, and
                // getting it wrong means a 0.x dependency silently upgrades
                // across a breaking change. Every ecosystem that got this wrong
                // shipped a wave of broken builds.
                if base.major == 0 {
                    if base.minor == 0 {
                        // `^0.0.x` pins the patch: only that exact version.
                        candidate.major == 0
                            && candidate.minor == 0
                            && candidate.patch == base.patch
                    } else {
                        candidate.major == 0 && candidate.minor == base.minor && candidate >= base
                    }
                } else {
                    candidate.major == base.major && candidate >= base
                }
            }
            Op::Tilde => {
                candidate.major == base.major && candidate.minor == base.minor && candidate >= base
            }
        }
    }

    /// The operator.
    #[must_use]
    pub const fn op(&self) -> Op {
        self.op
    }

    /// The version the requirement compares against.
    #[must_use]
    pub const fn version(&self) -> Option<&Version> {
        self.version.as_ref()
    }
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.op, &self.version) {
            (Op::Any, _) => f.write_str("*"),
            (op, Some(v)) => write!(f, "{}{v}", op.as_str()),
            // Unreachable: a non-`Any` operator always carries a version.
            (op, None) => f.write_str(op.as_str()),
        }
    }
}

/// Build a parse error with the shared shape.
fn bad(input: &str, detail: &str) -> Error {
    Error::new(
        ErrorCode::VersionUnsatisfiable,
        format!("`{input}` is not a valid version requirement"),
    )
    .with_cause(detail.to_owned())
    .with_remediation("requirements look like `1.2.3`, `^1.2.3`, `~1.2.3`, `>=1.2.3` or `*`")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        s.parse().expect("test version must parse")
    }

    fn req(s: &str) -> Requirement {
        Requirement::parse(s).expect("test requirement must parse")
    }

    // -- parsing -----------------------------------------------------------

    #[test]
    fn a_bare_version_means_caret() {
        // What every package manager converges on: the author almost always
        // means "compatible with", not "exactly this".
        let r = req("1.2.3");
        assert_eq!(r.op(), Op::Caret);
        assert_eq!(r.version(), Some(&v("1.2.3")));
    }

    #[test]
    fn every_operator_parses() {
        assert_eq!(req("=1.2.3").op(), Op::Exact);
        assert_eq!(req("^1.2.3").op(), Op::Caret);
        assert_eq!(req("~1.2.3").op(), Op::Tilde);
        assert_eq!(req(">=1.2.3").op(), Op::GreaterOrEqual);
        assert_eq!(req(">1.2.3").op(), Op::Greater);
        assert_eq!(req("<=1.2.3").op(), Op::LessOrEqual);
        assert_eq!(req("<1.2.3").op(), Op::Less);
        assert_eq!(req("*").op(), Op::Any);
    }

    /// **The operator-lexing trap.** `>=` must not be read as `>` followed by
    /// `=`, which produces a requirement that parses and means something else.
    #[test]
    fn two_character_operators_are_not_split() {
        let r = req(">=1.2.3");
        assert_eq!(r.op(), Op::GreaterOrEqual, "`>=` must not become `>`");
        assert_eq!(r.version(), Some(&v("1.2.3")));

        let l = req("<=1.2.3");
        assert_eq!(l.op(), Op::LessOrEqual, "`<=` must not become `<`");
    }

    #[test]
    fn whitespace_is_tolerated() {
        assert_eq!(req("  >=  1.2.3  ").op(), Op::GreaterOrEqual);
        assert_eq!(req("^ 1.2.3").op(), Op::Caret);
    }

    #[test]
    fn an_empty_requirement_is_refused() {
        let e = Requirement::parse("").unwrap_err();
        assert_eq!(e.code, ErrorCode::VersionUnsatisfiable);
        assert!(e.remediation.is_some());
        assert!(Requirement::parse("   ").is_err());
    }

    #[test]
    fn an_operator_without_a_version_is_refused() {
        for s in [">=", "^", "~", ">", "<", "="] {
            let e = Requirement::parse(s).unwrap_err();
            assert!(
                e.message.contains(s),
                "the error must quote `{s}`: {}",
                e.message
            );
        }
    }

    #[test]
    fn a_nonsense_version_is_refused_with_the_shape() {
        let e = Requirement::parse("^not-a-version").unwrap_err();
        assert!(e.remediation.as_deref().unwrap_or("").contains("1.2.3"));
    }

    #[test]
    fn requirements_round_trip_through_display() {
        for s in ["1.2.3", "=1.2.3", "^1.2.3", "~1.2.3", ">=1.2.3", "*"] {
            let r = req(s);
            let rendered = r.to_string();
            let again = Requirement::parse(&rendered)
                .unwrap_or_else(|e| panic!("`{rendered}` did not re-parse: {e}"));
            assert_eq!(r, again, "`{s}` did not round-trip");
        }
    }

    // -- caret, the compatibility rule -------------------------------------

    #[test]
    fn caret_allows_a_minor_and_patch_bump_within_a_major() {
        let r = req("^1.2.3");
        assert!(r.matches(&v("1.2.3")), "the base matches itself");
        assert!(r.matches(&v("1.2.4")));
        assert!(r.matches(&v("1.5.0")));
        assert!(r.matches(&v("1.99.99")));
    }

    #[test]
    fn caret_refuses_a_major_bump_and_a_downgrade() {
        let r = req("^1.2.3");
        assert!(!r.matches(&v("2.0.0")), "a major bump is breaking");
        assert!(!r.matches(&v("1.2.2")), "a caret is at least, not exactly");
    }

    /// **The 0.x rule.** Below 1.0 the minor is the breaking boundary, so
    /// `^0.2.3` means `>=0.2.3, <0.3.0` — not `<1.0.0`.
    ///
    /// This is the most-violated rule in semver handling. Getting it wrong means
    /// a 0.x dependency silently upgrades across a breaking change, and every
    /// ecosystem that got it wrong shipped a wave of broken builds.
    #[test]
    fn caret_below_one_treats_the_minor_as_breaking() {
        let r = req("^0.2.3");
        assert!(r.matches(&v("0.2.3")));
        assert!(r.matches(&v("0.2.9")));
        assert!(!r.matches(&v("0.3.0")), "0.2 -> 0.3 is breaking below 1.0");
        assert!(!r.matches(&v("1.0.0")));
    }

    /// `^0.0.x` pins the patch, because below 0.1 *everything* is breaking.
    #[test]
    fn caret_at_zero_zero_pins_the_patch() {
        let r = req("^0.0.3");
        assert!(r.matches(&v("0.0.3")));
        assert!(
            !r.matches(&v("0.0.4")),
            "0.0.x has no compatibility promise"
        );
        assert!(!r.matches(&v("0.1.0")));
    }

    #[test]
    fn caret_at_zero_one_allows_patch_bumps_only() {
        let r = req("^0.1.0");
        assert!(r.matches(&v("0.1.0")));
        assert!(r.matches(&v("0.1.5")));
        assert!(!r.matches(&v("0.2.0")));
    }

    // -- tilde -------------------------------------------------------------

    #[test]
    fn tilde_allows_patch_bumps_within_a_minor() {
        let r = req("~1.2.3");
        assert!(r.matches(&v("1.2.3")));
        assert!(r.matches(&v("1.2.99")));
        assert!(!r.matches(&v("1.3.0")), "a tilde does not cross a minor");
        assert!(!r.matches(&v("1.2.2")));
    }

    // -- the comparison operators ------------------------------------------

    #[test]
    fn comparison_operators_behave_as_written() {
        assert!(req(">=1.2.3").matches(&v("1.2.3")));
        assert!(req(">=1.2.3").matches(&v("9.9.9")));
        assert!(!req(">=1.2.3").matches(&v("1.2.2")));

        assert!(!req(">1.2.3").matches(&v("1.2.3")), "strictly greater");
        assert!(req(">1.2.3").matches(&v("1.2.4")));

        assert!(req("<=1.2.3").matches(&v("1.2.3")));
        assert!(!req("<=1.2.3").matches(&v("1.2.4")));

        assert!(!req("<1.2.3").matches(&v("1.2.3")));
        assert!(req("<1.2.3").matches(&v("1.2.2")));
    }

    #[test]
    fn exact_matches_only_the_exact_version() {
        let r = req("=1.2.3");
        assert!(r.matches(&v("1.2.3")));
        assert!(!r.matches(&v("1.2.4")));
        assert!(!r.matches(&v("1.2.2")));
    }

    #[test]
    fn any_matches_everything_released() {
        let r = req("*");
        for s in ["0.0.1", "1.0.0", "99.99.99"] {
            assert!(r.matches(&v(s)), "`*` must match {s}");
        }
    }

    // -- the pre-release gap, asserted rather than assumed -----------------
    //
    // An earlier draft of this module had the usual semver opt-in rule and
    // tests for it. Both were written against `Version.pre`, a field
    // `qqq_core::Version` does **not** have — it is strictly
    // `major.minor.patch` and its parser rejects `1.2.3-beta` outright. The
    // tests failed on the first run, which is the only reason the assumption was
    // caught: the module compiled because nothing referenced the field.
    //
    // What replaces them asserts the *current* behaviour, so the gap is recorded
    // where it will be noticed rather than in a document nobody reads at the
    // moment of the change. See Observations §O-032.

    /// **`Version` has no pre-release component, and this test says so.**
    ///
    /// It will fail the moment someone adds pre-release support — which is the
    /// point. Implementing the opt-in rule (a plain `^1.0.0` must not adopt
    /// `1.1.0-beta.1`) is a change to a compatibility surface, and it should be
    /// made deliberately rather than inherited.
    #[test]
    fn pre_releases_are_not_representable_and_this_records_it() {
        assert!(
            "1.1.0-beta.1".parse::<Version>().is_err(),
            "if this now parses, `qqq-core` gained pre-release support and \
             `Requirement::matches` must implement the opt-in rule (Observations §O-032)"
        );
        assert!("2.0.0-rc.1".parse::<Version>().is_err());
        assert!("1.0.0-alpha".parse::<Version>().is_err());
        // Build metadata is likewise absent.
        assert!("1.2.3+build.99".parse::<Version>().is_err());
    }

    /// The positive control for the test above: ordinary versions still parse,
    /// so the assertion is about the suffix rather than about the parser being
    /// broken outright.
    #[test]
    fn ordinary_versions_still_parse() {
        for s in ["0.0.0", "1.2.3", "99.99.99"] {
            assert!(s.parse::<Version>().is_ok(), "`{s}` must parse");
        }
    }

    /// A requirement naming a pre-release is refused at *parse* time rather than
    /// silently matched as though the suffix were absent — which is the failure
    /// mode that would matter if the parser kept the prefix and dropped the
    /// suffix.
    #[test]
    fn a_requirement_naming_a_pre_release_is_refused_rather_than_truncated() {
        let e = Requirement::parse("^1.1.0-beta.1").unwrap_err();
        assert_eq!(e.code, ErrorCode::VersionUnsatisfiable);
        assert!(
            e.message.contains("1.1.0-beta.1"),
            "the error must quote what was written: {}",
            e.message
        );
    }
}
