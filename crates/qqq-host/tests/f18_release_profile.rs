// SPDX-License-Identifier: Apache-2.0

//! F-18: the release profile must check integer overflow in the security crates.
use std::fs;

#[test]
fn f18_release_profile_keeps_overflow_checks_for_security_crates() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let text = fs::read_to_string(path).expect("workspace Cargo.toml must be readable");
    // A manifest document is a table; parse it as one (not as a `Value`,
    // whose `FromStr` rejects document input on this `toml` version).
    let doc: toml::Table = text
        .parse()
        .expect("workspace Cargo.toml must be valid TOML");
    let release = doc
        .get("profile")
        .and_then(|p| p.get("release"))
        .expect("[profile.release] must exist");
    let global = release
        .get("overflow-checks")
        .and_then(toml::Value::as_bool);
    for pkg in ["qqq-serve", "qqq-host", "qqq-cap"] {
        let per_pkg = release
            .get("package")
            .and_then(|p| p.get(pkg))
            .and_then(|p| p.get("overflow-checks"))
            .and_then(toml::Value::as_bool);
        // Effective Cargo semantics: a present per-package value wins over
        // the profile default, including an explicit `false`. Collapsing to
        // `global || per_pkg` with `unwrap_or(false)` cannot tell "absent"
        // from "explicitly disabled" and passes a crate whose checks are
        // off under a global `true` — the hole CodeRabbit's post-commit
        // review proved with exactly that manifest.
        let effective = per_pkg.or(global).unwrap_or(false);
        assert!(
            effective,
            "overflow-checks must be enabled in release for {pkg}: debug builds panic \
             while release wraps, so the tests would exercise different arithmetic than production"
        );
    }
}
