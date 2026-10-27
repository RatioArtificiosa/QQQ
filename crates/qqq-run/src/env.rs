// SPDX-License-Identifier: Apache-2.0

//! Resolve `qqq:env` values at the deploy layer — `HOST-029`.
//!
//! The manifest names variables; the host serves them. Resolution reads the
//! process environment once, at startup, and hands the runtime a plain map —
//! never per call — because `§2.5` forbids ambient reads inside the runtime
//! (`tools/check_no_ambient.py` enforces it) and `std::env` in `qqq-host`
//! would fail that gate.
//!
//! A listed-but-unset variable is **absent** from the map, which is the safe
//! direction: the guest's `get` reports `unset` and `get-or` substitutes the
//! fallback, rather than receiving an empty string that looks like a real
//! value. The lookup is a parameter so the rule is testable without mutating
//! the process environment.

use std::collections::BTreeMap;

use qqq_cap::manifest::Manifest;

/// Resolve the manifest's `[capabilities.env] allow` list to values.
///
/// Returns one entry per allowed name: `Some` bytes when set, `None` when the
/// variable is unset. Unlisted names are never consulted. The map — not a
/// separate list — is the allowlist the host enforces, so `None` (listed but
/// absent, guest observes `unset`) and a missing key (unlisted, guest observes
/// `not-allowed`) stay distinguishable by construction.
pub fn resolve_env_map(
    manifest: &Manifest,
    lookup: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut out = BTreeMap::new();
    if let Some(env) = manifest.capabilities.env.as_ref() {
        for name in &env.allow {
            out.insert(name.clone(), lookup(name));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with(allow: &str) -> Manifest {
        Manifest::parse(&format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[capabilities.env]\nallow = [{allow}]\n"
        ))
        .expect("fixture manifest parses")
    }

    fn lookup<'a>(pairs: &'a [(&'a str, &'a [u8])]) -> impl Fn(&str) -> Option<Vec<u8>> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_vec())
        }
    }

    /// Allowed and set resolves; allowed-but-unset maps to None, never to an
    /// empty string a guest could mistake for a value.
    #[test]
    fn allowlist_resolves_set_and_marks_unset() {
        let m = manifest_with("\"A\", \"B\"");
        let map = resolve_env_map(&m, &lookup(&[("A", b"1")]));
        assert_eq!(
            map.get("A").and_then(|v| v.as_deref()),
            Some(b"1".as_slice())
        );
        assert!(
            map.get("B").is_some_and(Option::is_none),
            "unset must be listed-but-empty, not absent: {map:?}"
        );
    }

    /// Unlisted names are never consulted, even when set.
    #[test]
    fn unlisted_names_are_not_read() {
        let m = manifest_with("\"A\"");
        let map = resolve_env_map(&m, &lookup(&[("A", b"1"), ("C", b"2")]));
        assert!(!map.contains_key("C"), "the allowlist is the boundary");
    }

    /// No env stanza resolves to nothing.
    #[test]
    fn missing_stanza_resolves_empty() {
        let m = Manifest::parse("[package]\nname = \"app\"\nversion = \"0.1.0\"\n")
            .expect("manifest parses");
        assert!(resolve_env_map(&m, &lookup(&[("A", b"1")])).is_empty());
    }
}
