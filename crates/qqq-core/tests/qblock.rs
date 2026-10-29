// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! Q-Block level tests — the five levels of Proposal §4.8.5, checked as
//! tests rather than asserted in prose.
//!
//! Implements Checklist `REG-004`.
//!
//! # Why these tests live in `qqq-core`
//!
//! Same reason as `architecture.rs`: the levels are statements about the
//! *workspace* (WIT declarations, the manifest schema, the registry table),
//! and `qqq-core` is the only crate that depends on nothing, so a test here
//! cannot create a cycle. Putting them in `qqq-cap` would make them hostages
//! of the capability table they check; putting them in `qqq-abi` would make
//! them hostages of the registry they pin.
//!
//! # Why these read the filesystem instead of using the types
//!
//! The levels relate *three separate definitions* of the same vocabulary:
//! `wit/*.wit` (declared), `Capabilities` in `qqq-cap/src/manifest.rs` plus
//! the `Capability::name` arms in `qqq-cap/src/capability.rs` (bindable), and
//! the `implemented` flags in `qqq-abi/src/registry.rs` (bound). A test that
//! used the types could only see one definition at a time; reading the three
//! sources lets one test assert they agree — which is the property §4.8.5
//! exists to state. A new namespace that lands in only two of the three
//! fails here, which is the correct response to a half-landed vocabulary.
//!
//! # What the numbers are
//!
//! At the time of writing: 15 declared packages / 22 declared interfaces
//! (`wit/*.wit`), 13 bindable namespaces (the manifest's `[capabilities]`
//! tables), 10 bound interfaces (registry `implemented: true`, pinned by
//! `implemented_flags_match_reality`). Every count below names its source,
//! because §4.8.5's rule is that a capability fact names its level.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// The repository root, derived from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // root
    p
}

/// Read a tree file or fail naming it.
fn read_tree(rel: &str) -> String {
    let path = workspace_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Declared level: `(package roots, interface count)` from `wit/*.wit`.
///
/// Package roots are the `qqq:<ns>` prefixes without versions; the interface
/// count uses the same grammar as `tools/gen_wit_reference.py` (a top-level
/// `interface <name> {` line), so the two cannot silently disagree about what
/// an interface is.
fn declared() -> (BTreeSet<String>, usize) {
    let dir = workspace_root().join("wit");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "wit"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "wit/ contains no .wit files");

    let mut packages = BTreeSet::new();
    let mut interfaces = 0;
    for path in &files {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("package ") {
                let rest = rest.trim_end_matches(';').trim();
                let root = rest
                    .split('@')
                    .next()
                    .unwrap_or_else(|| panic!("bad package line in {}: {line}", path.display()));
                packages.insert(root.to_owned());
            } else if line.starts_with("interface ") && line.ends_with('{') {
                interfaces += 1;
            }
        }
    }
    (packages, interfaces)
}

/// Bindable level, first definition: the distinct namespace roots of the
/// `Self::X => "<ns>.<op>"` arms of `Capability::name` in
/// `qqq-cap/src/capability.rs`.
///
/// Scoped to the `name()` function body: `kind()` arms share the `Self::`
/// prefix but carry no string literal, and the sibling `CapabilityKind`
/// enum's own string arms (`Self::Resource => "resource"`) would pollute an
/// unscoped scan with a namespace that is a kind, not an authority.
fn bindable_from_capability_names() -> BTreeSet<String> {
    let text = read_tree("crates/qqq-cap/src/capability.rs");
    let start = text
        .find("pub const fn name(self)")
        .expect("Capability::name not found");
    let end = text[start..]
        .find("pub fn namespace(self)")
        .expect("Capability::namespace not found");
    let body = &text[start..start + end];
    let mut out = BTreeSet::new();
    for line in body.lines() {
        let line = line.trim();
        // `Self::ClockWall => "clock.wall",`
        if line.starts_with("Self::") && line.contains("=> \"") && line.ends_with("\",") {
            let quoted = line
                .split('"')
                .nth(1)
                .unwrap_or_else(|| panic!("bad name arm: {line}"));
            let (ns, _) = quoted
                .split_once('.')
                .unwrap_or_else(|| panic!("name without namespace: {line}"));
            out.insert(ns.to_owned());
        }
    }
    out
}

/// Bindable level, second definition: the typed stanza fields of
/// `pub struct Capabilities` in `qqq-cap/src/manifest.rs`, up to (excluding)
/// the flattened `other` catch-all.
fn bindable_from_manifest_stanzas() -> BTreeSet<String> {
    let text = read_tree("crates/qqq-cap/src/manifest.rs");
    let mut in_struct = false;
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line == "pub struct Capabilities {" {
            in_struct = true;
            continue;
        }
        if !in_struct {
            continue;
        }
        if line.starts_with("pub other:") {
            break;
        }
        if let Some(rest) = line.strip_prefix("pub ") {
            let field: String = rest
                .chars()
                .take_while(|c| *c != ':' && *c != ' ')
                .collect();
            if !field.is_empty() {
                out.insert(field);
            }
        }
    }
    assert!(
        in_struct && !out.is_empty(),
        "Capabilities struct not found or has no stanza fields"
    );
    out
}

/// Bound level: the `iface("qqq:<ns>@<ver>", &[..], true|false, ..)` flags in
/// `qqq-abi/src/registry.rs`, in file order.
fn bound_flags() -> Vec<(String, bool)> {
    let text = read_tree("crates/qqq-abi/src/registry.rs");
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(line) = lines.get(i) {
        if line.trim() == "iface(" {
            let mut name: Option<String> = None;
            let mut seen_caps = false;
            let mut j = i + 1;
            while j < lines.len() && j < i + 40 {
                let Some(inner) = lines.get(j) else { break };
                let t = inner.trim();
                if t.starts_with("\"qqq:") && name.is_none() {
                    name = Some(t.trim_matches(|c| c == '"' || c == ',').to_owned());
                } else if t.starts_with("&[") {
                    seen_caps = true;
                } else if seen_caps && (t == "true," || t == "false,") {
                    out.push((
                        name.clone().unwrap_or_else(|| {
                            panic!("iface( at registry.rs:{} has no name", i + 1)
                        }),
                        t == "true,",
                    ));
                    break;
                }
                j += 1;
            }
            i = j;
        }
        i += 1;
    }
    assert!(!out.is_empty(), "no iface( entries parsed from registry.rs");
    out
}

/// The §4.8.5 section text, cut at the next `###` heading.
fn section_485() -> String {
    let text = read_tree("QQQ-Proposal-V1.md");
    let marker = "### §4.8.5 The five levels";
    let start = text
        .find(marker)
        .unwrap_or_else(|| panic!("{marker} not found in QQQ-Proposal-V1.md"));
    let rest = &text[start + marker.len()..];
    let end = rest.find("\n### ").unwrap_or(rest.len());
    rest[..end].to_owned()
}

// ---------------------------------------------------------------------------
// REG-004 — five tests, the first a control on the harness itself
// ---------------------------------------------------------------------------

/// CONTROL: the declared level parses to 15 packages and 22 interfaces, and
/// every package line has the `package qqq:<ns>@1.0.0;` shape.
///
/// This test validates the file-walking grammar the other four tests share:
/// if WIT gains a syntax this walk cannot see (a `world` block with inline
/// interfaces, a second package statement per file), this fails first, before
/// any level comparison can report a misleading agreement.
#[test]
fn wit_declares_fifteen_packages_and_22_interfaces() {
    let (packages, interfaces) = declared();
    let mut sorted: Vec<&str> = packages.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    assert_eq!(
        packages.len(),
        15,
        "declared packages changed; update §4.8.5 and this test together: {sorted:?}"
    );
    assert_eq!(
        interfaces, 22,
        "declared interfaces changed; update §4.8.5 and this test together"
    );
    for p in &sorted {
        assert!(
            p.starts_with("qqq:"),
            "declared package {p} is outside the qqq: scope"
        );
    }
}

/// The two bindable definitions agree: 13 namespaces in the capability names
/// and the same 13 as typed manifest stanzas.
#[test]
fn bindable_namespaces_are_thirteen_in_both_definitions() {
    let from_names = bindable_from_capability_names();
    let from_stanzas = bindable_from_manifest_stanzas();
    assert_eq!(
        from_names.len(),
        13,
        "capability namespaces changed: {from_names:?}"
    );
    assert_eq!(
        from_names, from_stanzas,
        "capability names and manifest stanzas disagree about what is bindable"
    );
}

/// The bound level is 10 interfaces, pinned by name: flipping one flag
/// without landing (or removing) the host code fails here as well as in
/// `implemented_flags_match_reality`.
#[test]
fn bound_interfaces_are_ten_pinned_by_name() {
    let flags = bound_flags();
    let mut implemented: Vec<&str> = flags
        .iter()
        .filter(|(_, b)| *b)
        .map(|(n, _)| n.as_str())
        .collect();
    implemented.sort_unstable();
    assert_eq!(
        implemented,
        vec![
            "qqq:clock@1.0.0",
            "qqq:crypto@1.0.0",
            "qqq:dns@1.0.0",
            "qqq:env@1.0.0",
            "qqq:kv@1.0.0",
            "qqq:log@1.0.0",
            "qqq:queue@1.0.0",
            "qqq:secrets@1.0.0",
            "qqq:sql@1.0.0",
            "qqq:trace@1.0.0",
        ],
        "bound set changed; land the host code (or remove it) with the flag"
    );
    let by_name: BTreeMap<&str, bool> = flags.iter().map(|(n, b)| (n.as_str(), *b)).collect();
    // Modelled but unbound: a registry row with `implemented: false`.
    for unbound in ["qqq:http@1.0.0", "qqq:fs@1.0.0", "qqq:ai@1.0.0"] {
        assert_eq!(
            by_name.get(unbound),
            Some(&false),
            "{unbound} must stay declared-but-unbound until its host code lands"
        );
    }
    // Not even modelled: declared in WIT with no registry row at all.
    // (Neither has a capability behind it, so there is no row to flip.)
    for unmodelled in ["qqq:agent@1.0.0", "qqq:test@1.0.0"] {
        assert!(
            !by_name.contains_key(unmodelled),
            "{unmodelled} gained a registry row; the separation moved"
        );
    }
}

/// The levels are distinct: each separation §4.8.5 claims holds in the tree.
///
/// Declared-but-not-bindable (`agent`, `test`: a WIT package with no manifest
/// stanza), declared-and-bindable-but-not-bound (`fs`, `http`, `ai`), and
/// bound-implies-bindable for every bound package. The `secrets`/`secret`
/// spelling asymmetry (WIT package `qqq:secrets`, stanza `[capabilities.secret]`)
/// is normalised explicitly rather than hidden: it is the one place the three
/// sources spell the same authority differently.
#[test]
fn level_separations_hold_where_claimed() {
    let (declared_pkgs, _) = declared();
    let mut declared_roots: BTreeSet<String> = declared_pkgs
        .iter()
        .map(|p| {
            p.strip_prefix("qqq:")
                .unwrap_or_else(|| panic!("package {p} outside qqq: scope"))
                .to_owned()
        })
        .collect();
    // The one spelling asymmetry, stated once: the package is `secrets`, the
    // namespace (capability name root and stanza) is `secret`.
    assert!(
        declared_roots.remove("secrets"),
        "qqq:secrets package missing; the asymmetry moved"
    );
    declared_roots.insert("secret".to_owned());

    let bindable = bindable_from_manifest_stanzas();
    let by_name: BTreeMap<String, bool> = bound_flags().into_iter().collect();

    for ns in ["agent", "test"] {
        assert!(
            declared_roots.contains(ns),
            "{ns} is no longer declared; the separation moved"
        );
        assert!(
            !bindable.contains(ns),
            "{ns} gained a manifest stanza; it is bindable now"
        );
    }
    for ns in ["fs", "http", "ai"] {
        assert!(bindable.contains(ns), "{ns} lost its manifest stanza");
        assert_eq!(
            by_name.get(&format!("qqq:{ns}@1.0.0")),
            Some(&false),
            "{ns} is bound now; the separation moved"
        );
    }
    // Bound implies bindable: every bound package root (modulo the asymmetry)
    // has a manifest stanza.
    for (name, bound) in bound_flags() {
        if !bound {
            continue;
        }
        let root = name
            .strip_prefix("qqq:")
            .and_then(|s| s.split('@').next())
            .unwrap_or(&name);
        let ns = if root == "secrets" { "secret" } else { root };
        assert!(
            bindable.contains(ns),
            "{name} is bound but has no manifest stanza"
        );
    }
    // Bindable implies declared (modulo the asymmetry): no stanza names an
    // authority no interface exists for.
    for ns in &bindable {
        assert!(
            declared_roots.contains(ns.as_str()),
            "stanza [{ns}] names an authority with no declared package"
        );
    }
}

/// §4.8.5 names all five levels as table rows: a sentence stating a
/// capability fact must name its level, so the section itself must contain
/// the five names — as the level column of its table, not as passing words
/// (`Boundary` contains `Bound`; word-presence would accept it).
#[test]
fn proposal_section_485_names_all_five_levels() {
    let section = section_485();
    for level in ["Declared", "Bindable", "Bound", "Granted", "Observed"] {
        assert!(
            section.contains(&format!("| **{level}** |")),
            "§4.8.5 no longer carries the | **{level}** | table row"
        );
    }
}

/// The three host-module counts agree, each named for its level (`REG-012`).
///
/// `HOST_MODULES` in `qqq-host/src/arch003.rs` (the scanned source files),
/// the `host_X::register(` calls in `qqq-host/src/linker.rs` (the bound
/// modules), and the `iface(` rows in `qqq-abi/src/registry.rs` (the modelled
/// interfaces) count different units on purpose: a module can exist without
/// a registration, and a row can exist without a module. This test pins the
/// exact mapping rather than the bare numbers, so a new module, registration
/// or row that lands in only one of the three fails here:
///
/// - scanned modules and linker registrations are the same 14-strong set;
/// - registry rows minus `{ai, fs}` are all backed by a module — `ai` has no
///   module yet (`FUT-007`), `fs` has none until its WIT gains a constructor
///   (`HOST-034`);
/// - modules minus registry rows are exactly `{wasi, wasi03, test}` — the
///   non-`qqq:` and test-runner surface, which has rows nowhere by design.
#[test]
fn host_module_linker_and_registry_sets_agree() {
    let arch = read_tree("crates/qqq-host/src/arch003.rs");
    let mut modules: BTreeSet<String> = BTreeSet::new();
    let mut in_array = false;
    for line in arch.lines() {
        let line = line.trim();
        if line.starts_with("pub const HOST_MODULES") {
            in_array = true;
            continue;
        }
        if in_array {
            if line.starts_with("];") {
                break;
            }
            if let Some(rest) = line.strip_prefix("\"host_") {
                let file = rest.split('"').next().unwrap_or("");
                if let Some(root) = file.strip_suffix(".rs") {
                    modules.insert(root.to_owned());
                }
            }
        }
    }
    assert_eq!(modules.len(), 14, "HOST_MODULES changed: {modules:?}");

    let linker_text = read_tree("crates/qqq-host/src/linker.rs");
    let mut linker: BTreeSet<String> = BTreeSet::new();
    for line in linker_text.lines() {
        let line = line.trim();
        // Comment lines discuss registration without performing it; only
        // call sites (which all pass `&mut linker`) count.
        if line.starts_with("//") || line.starts_with('*') {
            continue;
        }
        if !line.contains("::register(&mut linker") {
            continue;
        }
        let Some(at) = line.find("host_") else {
            continue;
        };
        let root: String = line[at + 5..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !root.is_empty() {
            linker.insert(root);
        }
    }
    assert_eq!(
        modules, linker,
        "scanned modules and linker registrations disagree"
    );

    let rows: BTreeSet<String> = bound_flags()
        .iter()
        .map(|(name, _)| {
            name.strip_prefix("qqq:")
                .and_then(|s| s.split('@').next())
                .unwrap_or(name)
                .to_owned()
        })
        .collect();
    let missing: BTreeSet<String> = rows.difference(&modules).cloned().collect();
    assert_eq!(
        missing,
        BTreeSet::from(["ai".to_owned(), "fs".to_owned()]),
        "unbacked registry rows changed; ai (FUT-007) and fs (HOST-034) are the only ones allowed"
    );
    let extra: BTreeSet<String> = modules.difference(&rows).cloned().collect();
    assert_eq!(
        extra,
        BTreeSet::from(["test".to_owned(), "wasi".to_owned(), "wasi03".to_owned()]),
        "non-registry modules changed; wasi/wasi03/test are the only ones allowed"
    );
}
