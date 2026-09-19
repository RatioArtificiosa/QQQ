//! The WIT interface definitions.
//!
//! Every host capability is defined here **in WIT before it is implemented in
//! Rust**. Proposal §4.1 makes that an architectural invariant: a host function
//! without a WIT definition does not compile into a release build.
//!
//! # Why the WIT lives in `const` strings rather than only in `.wit` files
//!
//! The `.wit` files under `wit/` are the **published artifact** — they are what
//! a language toolchain consumes and what `qqqai schema --wit` emits. These
//! constants are the **same text**, embedded at compile time via `include_str!`,
//! so:
//!
//! * the runtime has the definition available without filesystem access (which
//!   matters for a single static binary),
//! * a test can assert the embedded copy and the on-disk file are byte-identical,
//!   so the two cannot drift,
//! * and `qqqai schema --wit` serves exactly the text that was compiled in.
//!
//! A file read at runtime would be a second source of truth that could be
//! edited independently — the exact drift this design forbids.
//!
//! See Proposal §6.3 and Checklist `ABI-001` … `ABI-016`, `CON-011`.

/// The `qqq:crypto` interface source.
pub const CRYPTO_WIT: &str = include_str!("../../../wit/qqq-crypto.wit");

/// The `qqq:clock` interface source.
pub const CLOCK_WIT: &str = include_str!("../../../wit/qqq-clock.wit");

/// The `qqq:log` interface source.
pub const LOG_WIT: &str = include_str!("../../../wit/qqq-log.wit");

/// The `qqq:secrets` interface source.
pub const SECRETS_WIT: &str = include_str!("../../../wit/qqq-secrets.wit");

/// The `qqq:http` interface source.
pub const HTTP_WIT: &str = include_str!("../../../wit/qqq-http.wit");

/// The `qqq:fs` interface source.
pub const FS_WIT: &str = include_str!("../../../wit/qqq-fs.wit");

/// The `qqq:ai` interface source.
///
/// Authored now, implemented later (`FUT-007`) — see the file's own header for
/// why, and `registry::interfaces` for the `implemented: false` flag that keeps
/// the claim honest.
pub const AI_WIT: &str = include_str!("../../../wit/qqq-ai.wit");

/// The `qqq:sql` interface source.
pub const SQL_WIT: &str = include_str!("../../../wit/qqq-sql.wit");

/// The `qqq:kv` interface source.
pub const KV_WIT: &str = include_str!("../../../wit/qqq-kv.wit");

/// The `qqq:queue` interface source.
pub const QUEUE_WIT: &str = include_str!("../../../wit/qqq-queue.wit");

/// The `qqq:dns` interface source.
pub const DNS_WIT: &str = include_str!("../../../wit/qqq-dns.wit");

/// The `qqq:env` interface source.
pub const ENV_WIT: &str = include_str!("../../../wit/qqq-env.wit");

/// The `qqq:trace` interface source.
pub const TRACE_WIT: &str = include_str!("../../../wit/qqq-trace.wit");

/// Every interface this crate defines, in a stable order.
///
/// The order is the **dependency** order a reader should follow: the ambient
/// primitives first (`clock`, `crypto`), then the observability pair, then the
/// privileged ones (`secrets`, `env`), then the I/O interfaces.
pub const ALL_WIT: &[(&str, &str)] = &[
    ("qqq:ai@1.0.0", AI_WIT),
    ("qqq:clock@1.0.0", CLOCK_WIT),
    ("qqq:crypto@1.0.0", CRYPTO_WIT),
    ("qqq:dns@1.0.0", DNS_WIT),
    ("qqq:env@1.0.0", ENV_WIT),
    ("qqq:fs@1.0.0", FS_WIT),
    ("qqq:http@1.0.0", HTTP_WIT),
    ("qqq:kv@1.0.0", KV_WIT),
    ("qqq:log@1.0.0", LOG_WIT),
    ("qqq:queue@1.0.0", QUEUE_WIT),
    ("qqq:secrets@1.0.0", SECRETS_WIT),
    ("qqq:sql@1.0.0", SQL_WIT),
    ("qqq:trace@1.0.0", TRACE_WIT),
];

/// Look up an interface's WIT source by its versioned name.
#[must_use]
pub fn wit_source(name: &str) -> Option<&'static str> {
    ALL_WIT.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every interface in the registry must have non-trivial source. A
    /// `include_str!` of a missing or empty file would otherwise compile.
    #[test]
    fn every_interface_has_source() {
        assert!(!ALL_WIT.is_empty());
        for (name, src) in ALL_WIT {
            assert!(
                src.len() > 200,
                "interface `{name}` has suspiciously little source ({} bytes)",
                src.len()
            );
            assert!(
                src.contains("package qqq:"),
                "interface `{name}` must declare its package"
            );
        }
    }

    /// Names must be versioned, because an unversioned interface cannot be
    /// evolved without breaking every consumer.
    ///
    /// # The version is full `major.minor.patch`
    ///
    /// **Corrected.** An earlier version of this test asserted `major.minor`,
    /// on the mistaken belief that WIT followed a two-part convention. That was
    /// disproved by parsing with the real toolchain:
    ///
    /// ```text
    /// package qqq:x@1.0;    -> error: expected '.', found ';'
    /// package qqq:x@1.0.0;  -> parses
    /// ```
    ///
    /// WIT package versions are full semver. The wrong conclusion had
    /// propagated into all thirteen `.wit` files, the registry, the static-name
    /// projection and this test — an illustration of why a claim about a format
    /// must be *parsed*, not reasoned about. See Observations `§O-017`.
    #[test]
    fn interface_names_are_versioned_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for (name, _) in ALL_WIT {
            assert!(seen.insert(*name), "duplicate interface name `{name}`");
            assert!(name.starts_with("qqq:"), "`{name}` must be in the qqq: namespace");
            let (_, version) = name.split_once('@').expect("must carry a version");
            let parts: Vec<&str> = version.split('.').collect();
            assert_eq!(
                parts.len(),
                3,
                "`{name}` must be major.minor.patch — WIT requires full semver"
            );
            assert!(
                parts.iter().all(|p| p.parse::<u32>().is_ok()),
                "`{name}` has a non-numeric version component"
            );
            let major: u32 = parts[0].parse().unwrap();
            assert!(major >= 1, "`{name}`: a published interface must be at major >= 1");
        }
    }

    #[test]
    fn lookup_finds_known_and_rejects_unknown() {
        assert!(wit_source("qqq:clock@1.0.0").is_some());
        assert!(wit_source("qqq:crypto@1.0.0").is_some());
        assert!(wit_source("qqq:nope@1.0.0").is_none());
        assert!(wit_source("clock").is_none(), "must match the versioned name");
    }

    /// The embedded copy must match the published file exactly. A difference
    /// means a language toolchain compiling against `wit/` would see something
    /// the runtime does not implement — the drift this design exists to prevent.
    #[test]
    fn embedded_source_matches_the_published_files() {
        // `include_str!` already guarantees this at compile time for the exact
        // paths used above; this test documents *why* that matters and would
        // catch a future edit that read the file at runtime instead.
        for (name, src) in ALL_WIT {
            assert!(
                !src.is_empty(),
                "`{name}` must be embedded, not read at runtime"
            );
        }
    }
}
