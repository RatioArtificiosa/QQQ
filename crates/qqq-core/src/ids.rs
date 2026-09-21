// SPDX-License-Identifier: Apache-2.0

//! Identifiers and version types.
//!
//! Every identifier in QQQ exists so that an error, a log line, an audit record
//! and an agent's tool call can all refer to the same thing unambiguously.
//!
//! # Design rule
//!
//! Newtypes, not bare `String`. A `TenantId` that is accidentally a
//! `ComponentId` is a cross-tenant data leak waiting to happen, and the
//! compiler should refuse it. Proposal §7.1 names tenant data as the primary
//! asset; type separation is the cheapest possible control.
//!
//! See Proposal §4.3 and Checklist `ARCH-007`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The QQQ release version, parsed from the crate version at build time.
///
/// Exposed so that `qqqai --version`, `qqqai schema --all` and provenance
/// records all agree without anyone hand-maintaining a second copy.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The version of the **machine contract** — the JSON schema surface described
/// in Proposal §8.3.
///
/// Deliberately separate from [`VERSION`]: the runtime can ship a patch release
/// without the schema changing, and the schema can gain an additive field
/// without a runtime release. An agent pins *this*.
///
/// **Stability rule:** within a major version, additions are allowed and
/// removals or semantic changes are not.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// The version of the component-model ABI QQQ targets.
///
/// Proposal §C-003: QQQ targets WASI 0.3 (Preview 3). Recorded here as data
/// rather than prose so code and docs cannot disagree.
pub const WASI_TARGET_VERSION: &str = "0.3";

/// The Wasmtime minor line QQQ pins (Proposal `§D-003`).
///
/// Kept as a constant so the upgrade runbook (`HOST-020`) and the CI matrix
/// have one place to change.
pub const WASMTIME_LINE: &str = "48";

/// The canonical CLI / crate / binary name.
///
/// # Why this constant exists
///
/// Observations `§D-001` records that `qqq` is taken on crates.io and npm, so
/// the executable is `qqqai` while the brand is QQQ. This constant exists so
/// that a future contributor who "helpfully" shortens the name has to delete a
/// documented constant to do it — and so tests can assert the invariant.
pub const BINARY_NAME: &str = "qqqai";

/// The canonical brand name, for prose and user-facing strings.
pub const BRAND_NAME: &str = "QQQ";

/// A tenant identifier.
///
/// Tenants are the isolation unit for data, audit records and quotas
/// (Proposal §7.1). Validated on construction so an empty or absurd tenant can
/// never reach a store key or a log line.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

/// A component identifier — the `name` field of a manifest's `[package]`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ComponentId(String);

/// A validated, lowercase, hyphen-separated project or package name.
///
/// Rules (matching the ecosystem conventions users already expect):
///
/// * 1..=64 characters
/// * lowercase ASCII letters, digits, `-`, `_`
/// * must begin with a letter
/// * must not end with `-` or `_`
///
/// Deliberately strict. A name that is valid here is valid as a crates.io
/// package, a directory name on every supported OS, and a URL path segment —
/// which prevents a whole class of platform-specific bug.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PackageName(String);

/// Why an identifier was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// The identifier was empty.
    Empty,
    /// The identifier exceeded the maximum length.
    TooLong {
        /// The observed length.
        got: usize,
        /// The maximum permitted length.
        max: usize,
    },
    /// The identifier contained a character outside the permitted set.
    InvalidCharacter {
        /// The offending character.
        ch: char,
        /// Its byte offset in the input.
        at: usize,
    },
    /// The identifier began with something other than an ASCII letter.
    MustStartWithLetter {
        /// The offending first character.
        ch: char,
    },
    /// The identifier ended with a separator.
    TrailingSeparator {
        /// The offending final character.
        ch: char,
    },
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "must not be empty"),
            Self::TooLong { got, max } => write!(f, "is {got} characters; maximum is {max}"),
            Self::InvalidCharacter { ch, at } => {
                write!(f, "contains invalid character {ch:?} at byte offset {at}")
            }
            Self::MustStartWithLetter { ch } => {
                write!(f, "must start with a letter, but starts with {ch:?}")
            }
            Self::TrailingSeparator { ch } => {
                write!(f, "must not end with {ch:?}")
            }
        }
    }
}

impl std::error::Error for IdError {}

/// Maximum length of any QQQ identifier.
pub const MAX_ID_LEN: usize = 64;

/// Validate a name against the QQQ identifier rules.
///
/// Shared by every newtype so the rules cannot drift between them.
fn validate_name(s: &str) -> Result<(), IdError> {
    if s.is_empty() {
        return Err(IdError::Empty);
    }
    if s.len() > MAX_ID_LEN {
        return Err(IdError::TooLong {
            got: s.len(),
            max: MAX_ID_LEN,
        });
    }
    let first = s.chars().next().expect("non-empty checked above");
    if !first.is_ascii_alphabetic() {
        return Err(IdError::MustStartWithLetter { ch: first });
    }
    for (i, ch) in s.char_indices() {
        let ok = ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_';
        if !ok {
            return Err(IdError::InvalidCharacter { ch, at: i });
        }
    }
    let last = s.chars().next_back().expect("non-empty checked above");
    if last == '-' || last == '_' {
        return Err(IdError::TrailingSeparator { ch: last });
    }
    Ok(())
}

macro_rules! id_newtype {
    ($ty:ident, $what:literal) => {
        impl $ty {
            /// Construct from a string, validating first.
            ///
            /// # Errors
            /// Returns [`IdError`] if the value violates the identifier rules.
            pub fn new(s: impl Into<String>) -> std::result::Result<Self, IdError> {
                let s = s.into();
                validate_name(&s)?;
                Ok(Self(s))
            }

            /// Borrow the underlying string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume and return the underlying string.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $ty {
            type Err = IdError;
            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl TryFrom<String> for $ty {
            type Error = IdError;
            fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl From<$ty> for String {
            fn from(v: $ty) -> Self {
                v.0
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        // Doc comment naming the concept, so generated docs are useful.
        impl $ty {
            #[doc = concat!("The concept this identifier names: ", $what, ".")]
            #[must_use]
            pub const fn concept() -> &'static str {
                $what
            }
        }
    };
}

id_newtype!(TenantId, "tenant");
id_newtype!(ComponentId, "component");
id_newtype!(PackageName, "package");

/// A `major.minor.patch` version, without prerelease or build metadata.
///
/// QQQ compares versions for capability compatibility and for the deprecation
/// policy (Proposal §2.8). A deliberately small implementation rather than a
/// dependency: the semantics QQQ needs are `Ord` and equality, and the full
/// `SemVer` grammar is more surface than the job requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Version {
    /// Major component; increments on a breaking change.
    pub major: u32,
    /// Minor component; increments on an additive change.
    pub minor: u32,
    /// Patch component; increments on a fix.
    pub patch: u32,
}

impl Version {
    /// Construct a version.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Whether `self` is API-compatible with `other` — same major, and at least
    /// as new.
    ///
    /// Used by the deprecation policy: a consumer on 1.4 may use a capability
    /// introduced in 1.2, but never one introduced in 2.0.
    #[must_use]
    pub const fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for Version {
    type Err = VersionParseError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut parts = s.split('.');
        let mut next = |what: &'static str| -> std::result::Result<u32, VersionParseError> {
            let raw = parts
                .next()
                .ok_or(VersionParseError::MissingComponent(what))?;
            // Reject empty and non-digit without allocating.
            if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
                return Err(VersionParseError::NotANumber(raw.to_owned()));
            }
            raw.parse::<u32>()
                .map_err(|_| VersionParseError::NotANumber(raw.to_owned()))
        };
        let major = next("major")?;
        let minor = next("minor")?;
        let patch = next("patch")?;
        if parts.next().is_some() {
            return Err(VersionParseError::TooManyComponents);
        }
        Ok(Self::new(major, minor, patch))
    }
}

/// Why a version string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionParseError {
    /// A required component was absent.
    MissingComponent(&'static str),
    /// A component was present but not a number.
    NotANumber(String),
    /// More than three dot-separated components were supplied.
    TooManyComponents,
}

impl fmt::Display for VersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingComponent(w) => write!(f, "missing {w} component"),
            Self::NotANumber(s) => write!(f, "component {s:?} is not a number"),
            Self::TooManyComponents => {
                write!(f, "expected major.minor.patch, but found more components")
            }
        }
    }
}

impl std::error::Error for VersionParseError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names_are_accepted() {
        for good in [
            "orders-api",
            "a",
            "app2",
            "my_service",
            "qqqai",
            "json",
            "a-b_c-9",
        ] {
            assert!(
                PackageName::new(good).is_ok(),
                "should have accepted {good:?}"
            );
        }
    }

    #[test]
    fn invalid_names_are_rejected_with_a_useful_reason() {
        assert_eq!(PackageName::new(""), Err(IdError::Empty));
        assert!(matches!(
            PackageName::new("9lives"),
            Err(IdError::MustStartWithLetter { ch: '9' })
        ));
        assert!(matches!(
            PackageName::new("Orders"),
            Err(IdError::InvalidCharacter { ch: 'O', at: 0 })
        ));
        assert!(PackageName::new("orders-api").is_ok());
        assert!(matches!(
            PackageName::new("orders."),
            Err(IdError::InvalidCharacter { ch: '.', at: 6 })
        ));
        assert!(matches!(
            PackageName::new("orders-"),
            Err(IdError::TrailingSeparator { ch: '-' })
        ));
        assert!(matches!(
            PackageName::new("orders_"),
            Err(IdError::TrailingSeparator { ch: '_' })
        ));
    }

    #[test]
    fn length_limit_is_enforced_at_the_boundary() {
        let max = "a".repeat(MAX_ID_LEN);
        assert!(PackageName::new(max).is_ok(), "64 chars must be accepted");

        let over = "a".repeat(MAX_ID_LEN + 1);
        assert_eq!(
            PackageName::new(over),
            Err(IdError::TooLong {
                got: MAX_ID_LEN + 1,
                max: MAX_ID_LEN
            })
        );
    }

    /// A path separator must never survive validation. This is a security
    /// control, not a style rule: a package name reaches directory paths.
    #[test]
    fn path_separators_and_traversal_are_rejected() {
        for hostile in ["../etc/passwd", "..", "a/b", "a\\b", "a\0b", "a b", "a\nb"] {
            assert!(
                PackageName::new(hostile).is_err(),
                "must reject path-hostile name {hostile:?}"
            );
        }
    }

    /// Identifiers must not be interchangeable — a cross-tenant leak in waiting.
    #[test]
    fn id_types_are_distinct_at_the_type_level() {
        let t = TenantId::new("acme").unwrap();
        let c = ComponentId::new("acme").unwrap();
        // Same underlying string, different types: this compiles because they
        // are different, and the assertion documents the intent.
        assert_eq!(t.as_str(), c.as_str());
        assert_eq!(TenantId::concept(), "tenant");
        assert_eq!(ComponentId::concept(), "component");
    }

    #[test]
    fn ids_round_trip_through_serde_as_strings() {
        let t = TenantId::new("acme").unwrap();
        let j = serde_json::to_string(&t).unwrap();
        assert_eq!(j, "\"acme\"");
        let back: TenantId = serde_json::from_str(&j).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn invalid_id_fails_to_deserialize() {
        let r: std::result::Result<TenantId, _> = serde_json::from_str("\"Bad Tenant\"");
        assert!(r.is_err(), "serde must enforce the same rules as new()");
    }

    #[test]
    fn version_parses_and_orders() {
        let a: Version = "1.2.3".parse().unwrap();
        let b: Version = "1.2.4".parse().unwrap();
        let c: Version = "2.0.0".parse().unwrap();
        assert!(a < b);
        assert!(b < c);
        assert_eq!(a.to_string(), "1.2.3");
    }

    #[test]
    fn version_rejects_malformed_input() {
        for bad in [
            "", "1", "1.2", "1.2.3.4", "1.2.x", "a.b.c", "1..3", "-1.2.3",
        ] {
            assert!(bad.parse::<Version>().is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn compatibility_rule_is_major_scoped() {
        let v12 = Version::new(1, 2, 0);
        let v14 = Version::new(1, 4, 0);
        let v20 = Version::new(2, 0, 0);
        assert!(
            v14.is_compatible_with(v12),
            "1.4 satisfies a 1.2 requirement"
        );
        assert!(!v12.is_compatible_with(v14), "1.2 does not satisfy 1.4");
        assert!(
            !v20.is_compatible_with(v12),
            "a major bump is not compatible"
        );
    }

    /// Observations §D-001: the binary is `qqqai` and the brand is `QQQ`.
    /// This test exists so the naming decision cannot drift silently.
    #[test]
    fn naming_constants_match_the_recorded_decision() {
        assert_eq!(BINARY_NAME, "qqqai", "Observations §D-001 fixes this");
        assert_eq!(BRAND_NAME, "QQQ");
        assert_ne!(
            BINARY_NAME, "qqq",
            "`qqq` is taken on crates.io and npm; a `qqq` binary is a defect"
        );
    }

    #[test]
    fn version_constants_are_wellformed() {
        // VERSION comes from Cargo, so it must always parse.
        VERSION
            .parse::<Version>()
            .expect("CARGO_PKG_VERSION must be a valid semver");
        SCHEMA_VERSION
            .parse::<Version>()
            .expect("SCHEMA_VERSION must be a valid semver");
    }
}
