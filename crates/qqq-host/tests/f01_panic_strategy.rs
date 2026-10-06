// SPDX-License-Identifier: Apache-2.0
//!
//! F-01: the release profile must keep unwinding so the HOST-011 panic guard works.
use std::fs;

#[test]
fn f01_release_profile_does_not_abort_on_panic() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let text = fs::read_to_string(path).expect("workspace Cargo.toml must be readable");
    // A manifest document is a table; parse it as one (not as a `Value`,
    // whose `FromStr` rejects document input on this `toml` version).
    let doc: toml::Table = text
        .parse()
        .expect("workspace Cargo.toml must be valid TOML");
    let panic = doc
        .get("profile")
        .and_then(|p| p.get("release"))
        .and_then(|r| r.get("panic"))
        .and_then(|v| v.as_str());
    assert_ne!(
        panic,
        Some("abort"),
        "[profile.release] panic = \"abort\" makes catch_unwind inert: the HOST-011 \
         panic guard and the handler JoinError recovery would not run in the shipped binary"
    );
}
