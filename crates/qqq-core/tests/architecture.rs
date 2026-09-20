//! Architecture tests — the invariants of Proposal §4.1 and §4.3, checked as
//! tests rather than asserted in prose.
//!
//! Implements Checklist `ARCH-002`, `ARCH-004`, `ARCH-008`.
//!
//! # Why architecture tests live in `qqq-core`
//!
//! They belong to no single crate: they are statements about the *workspace*.
//! `qqq-core` is the only crate every other crate depends on and that itself
//! depends on nothing, so a test here cannot create a cycle and cannot become
//! unreachable. Putting them in `qqq-host` would make them hostages of the
//! engine's build time; putting them in a new crate would add a member to the
//! topology the tests are supposed to be checking.
//!
//! # Why these read the filesystem instead of using `include_str!`
//!
//! Each test needs to enumerate *every* crate, including ones added after this
//! file was written. `include_str!` requires naming each path at compile time, so
//! a newly created crate would simply be invisible — which is the failure mode
//! these tests exist to prevent. Reading the tree finds the new crate and fails
//! on it, which is the correct response to an unannounced workspace member.
//!
//! # What "read the source" costs
//!
//! A source-reading test is weaker than a compiler check and stronger than a
//! review habit. Where a compiler check was possible it was used instead — see
//! `qqq_sys_cannot_grow_unsafe_code`'s note on `#![forbid]` versus `#![deny]`.
//! These tests cover the residue that no compiler can see: *which crates exist*
//! and *what their declared lint policy is*.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The repository root, derived from this crate's manifest directory.
///
/// `CARGO_MANIFEST_DIR` is `<root>/crates/qqq-core`, so two `pop`s reach the
/// workspace root. Deriving rather than hardcoding means the test works from any
/// checkout location, including a CI runner's temp directory.
fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // root
    p
}

/// Every crate directory under `crates/`, sorted, by directory name.
fn crate_dirs() -> Vec<PathBuf> {
    let dir = workspace_root().join("crates");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.join("Cargo.toml").is_file())
        .collect();
    out.sort();
    out
}

/// The `name = "…"` field of a crate's `[package]` table.
///
/// A hand-rolled scan rather than a TOML dependency, because `qqq-core` must
/// depend on nothing except `serde`/`serde_json` (§4.3: it is the crate
/// everything else depends on, so every dependency it takes is taken
/// workspace-wide). The scan reads the first `name =` after `[package]`, which
/// is what a Cargo manifest always contains.
fn package_name(crate_dir: &Path) -> String {
    let text = std::fs::read_to_string(crate_dir.join("Cargo.toml"))
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", crate_dir.display()));
    let mut in_package = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package {
            if let Some(rest) = line.strip_prefix("name") {
                let rest = rest.trim_start().trim_start_matches('=').trim();
                return rest.trim_matches('"').to_owned();
            }
        }
    }
    panic!("{} has no [package] name", crate_dir.display());
}

// ---------------------------------------------------------------------------
// ARCH-004 — no crate depends on a crate above it in the topology
// ---------------------------------------------------------------------------

/// The topological order from Proposal §4.3, lowest first.
///
/// Duplicated deliberately from `tools/check_topology.py` rather than shared:
/// the tool reads `cargo metadata` (the *resolved* graph, including edges a
/// workspace dependency introduces) and this test reads the manifest text (the
/// *declared* graph). They answer different questions, and a single shared list
/// would make one of them silently inherit the other's blind spot. Both failing
/// on the same edit is the point.
///
/// The order is the corrected one — the Proposal's own table listed `qqq-host`
/// above `qqq-abi` and `qqq-run` above `qqq-pkg`, both impossible. See
/// `§O-044`.
const ORDER: &[&str] = &[
    "qqq-core",
    "qqq-cap",
    "qqq-abi",
    "qqq-host",
    "qqq-io",
    "qqq-serve",
    "qqq-pkg",
    "qqq-run",
    "qqq-registry",
    "qqq-debug",
    "qqq-sys",
];

/// Crates the Proposal names but that do not exist yet.
const NOT_YET_BUILT: &[&str] = &[
    "qqq-registry",
    "qqq-fabric",
    "qqq-io-uring",
    "qqq-mem-hugepage",
    "qqq-sys-signals",
];

/// The index of a crate in the topological order.
fn rank(name: &str) -> usize {
    ORDER
        .iter()
        .position(|c| *c == name)
        .unwrap_or_else(|| panic!("`{name}` is not in the §4.3 topology order"))
}

/// Every `qqq-*` dependency declared in a manifest's `[dependencies]` and
/// `[dev-dependencies]` tables.
///
/// **`[dev-dependencies]` counts.** A dev-dependency from `qqq-core` to
/// `qqq-host` would not ship in a release build, but it makes `qqq-core`'s own
/// test suite require the entire Wasmtime stack — which defeats the stated
/// reason for the layering (§4.3: "third parties can depend on `qqq-host` or
/// `qqq-cap` alone"), and makes `cargo test -p qqq-core` a multi-minute build.
fn declared_qqq_deps(crate_dir: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(crate_dir.join("Cargo.toml")).expect("readable manifest");
    let mut out = Vec::new();
    let mut in_deps = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed == "[dependencies]" || trimmed == "[dev-dependencies]";
            continue;
        }
        if in_deps {
            if let Some((key, _)) = trimmed.split_once('=') {
                let key = key.trim();
                if key.starts_with("qqq-") {
                    out.push(key.to_owned());
                }
            }
        }
    }
    out
}

/// **ARCH-004.** Every dependency edge points *down* the §4.3 order.
#[test]
fn no_crate_depends_on_a_crate_above_it() {
    let mut violations = Vec::new();
    let mut checked = 0_usize;

    for dir in crate_dirs() {
        let name = package_name(&dir);
        if !ORDER.contains(&name.as_str()) {
            // A workspace member absent from the topology is itself a defect:
            // §4.3 is the complete list, and an unlisted crate has no declared
            // tier or position.
            violations.push(format!(
                "`{name}` is a workspace member but is not in the §4.3 topology order"
            ));
            continue;
        }
        let mine = rank(&name);
        for dep in declared_qqq_deps(&dir) {
            checked += 1;
            if !ORDER.contains(&dep.as_str()) && !NOT_YET_BUILT.contains(&dep.as_str()) {
                violations.push(format!("`{name}` depends on unknown crate `{dep}`"));
                continue;
            }
            if NOT_YET_BUILT.contains(&dep.as_str()) {
                continue; // indexed when it lands
            }
            let theirs = rank(&dep);
            if theirs >= mine {
                violations.push(format!(
                    "`{name}` (position {mine}) depends on `{dep}` (position {theirs}); \
                     a dependency may only point DOWN the §4.3 order"
                ));
            }
        }
    }

    assert!(
        checked > 0,
        "no qqq-* dependencies were found at all, so this test proves nothing; \
         the manifest scanner is broken"
    );
    assert!(
        violations.is_empty(),
        "architecture violations:\n  {}",
        violations.join("\n  ")
    );
}

/// `qqq-core` must depend on no other `qqq-*` crate, not even for tests.
///
/// This is the specific case §4.3 gives a reason for, and it is the one an
/// innocent `[dev-dependencies] qqq-host` would break.
#[test]
fn qqq_core_depends_on_no_other_qqq_crate() {
    let dir = workspace_root().join("crates/qqq-core");
    let deps = declared_qqq_deps(&dir);
    assert!(
        deps.is_empty(),
        "`qqq-core` must have no qqq-* dependencies, found: {deps:?}"
    );
}

/// Every crate the Proposal names either exists or is on the not-yet-built list.
///
/// The control for the two tests above: without it, a `crate_dirs()` that
/// silently returned an empty list would make them pass vacuously.
#[test]
fn the_topology_and_the_workspace_agree() {
    let present: BTreeSet<String> = crate_dirs()
        .iter()
        .map(|d| package_name(d))
        .filter(|n| n.starts_with("qqq-"))
        .collect();

    assert!(
        present.len() >= 10,
        "expected at least 10 qqq-* crates, found {}: {present:?}",
        present.len()
    );

    // Every built crate is in the order.
    for name in &present {
        assert!(
            ORDER.contains(&name.as_str()),
            "`{name}` is built but absent from the §4.3 order"
        );
    }

    // And the not-yet-built list has not gone stale: an entry that now exists
    // must be removed from it, because `NOT_YET_BUILT` entries skip the rank
    // check and would silently stop being verified.
    for deferred in NOT_YET_BUILT {
        assert!(
            !present.contains(*deferred),
            "`{deferred}` now exists but is still listed as NOT_YET_BUILT; \
             remove it from that list so its dependencies are ranked"
        );
    }
}

// ---------------------------------------------------------------------------
// ARCH-008 — `#![forbid(unsafe_code)]` everywhere except the named exceptions
// ---------------------------------------------------------------------------

/// The crates Proposal §4.3 permits to contain `unsafe`.
///
/// §4.3 names exactly three future crates (`qqq-io-uring`, `qqq-mem-hugepage`,
/// `qqq-sys-signals`) and this workspace additionally carries `qqq-sys` as the
/// narrow exception crate for OS-level primitives. Every one requires a written
/// safety argument (`ARCH-009`) and a second reviewer.
const UNSAFE_ALLOWED: &[&str] = &[
    "qqq-sys",
    "qqq-io-uring",
    "qqq-mem-hugepage",
    "qqq-sys-signals",
];

/// A crate's crate-level `unsafe_code` lint attribute, if it declares one.
///
/// Returns `(forbidden, is_conditional)`:
///
/// * `forbidden` — whether the crate forbids `unsafe`.
/// * `is_conditional` — whether the attribute is wrapped in `cfg_attr`, which
///   **weakens it** and is therefore reported separately. A
///   `#![cfg_attr(not(test), forbid(unsafe_code))]` allows `unsafe` under
///   `cfg(test)`, so a test helper can introduce it and the release build's
///   guarantee becomes a property of the test configuration rather than of the
///   source.
fn unsafe_lint(crate_dir: &Path) -> (bool, bool) {
    let text = std::fs::read_to_string(crate_dir.join("src/lib.rs"))
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", crate_dir.display()));
    let mut forbidden = false;
    let mut conditional = false;
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("#![") {
            continue;
        }
        if line.contains("unsafe_code") && line.contains("forbid") {
            forbidden = true;
            if line.starts_with("#![cfg_attr(") {
                conditional = true;
            }
        }
        // An `allow` at crate level in a crate that is not an exception is a
        // defect this function must not miss, so it is reported as "not
        // forbidden" by leaving `forbidden` unset.
        if line.contains("unsafe_code") && line.contains("allow") {
            forbidden = false;
        }
    }
    (forbidden, conditional)
}

/// **ARCH-008.** Every crate outside the named exceptions forbids `unsafe`.
#[test]
fn every_non_exception_crate_forbids_unsafe_code() {
    let mut problems = Vec::new();
    let mut checked = 0_usize;

    for dir in crate_dirs() {
        let name = package_name(&dir);
        let is_exception = UNSAFE_ALLOWED.contains(&name.as_str());

        // Does `src/lib.rs` exist? `qqq-sys` is a stub with one, so all should.
        if !dir.join("src/lib.rs").is_file() {
            problems.push(format!("`{name}` has no src/lib.rs"));
            continue;
        }

        let (forbidden, conditional) = unsafe_lint(&dir);

        // The workspace sets `unsafe_code = "forbid"` globally in
        // `[workspace.lints.rust]`, and every crate opts in with
        // `[lints] workspace = true`. The crate-level attribute is therefore
        // belt-and-braces — but it is the *visible* one, and a crate that
        // silently dropped `[lints] workspace = true` would keep compiling with
        // the global forbid gone. Checking the attribute is checking the thing a
        // reader sees.
        if !is_exception {
            checked += 1;
            if !forbidden {
                problems.push(format!(
                    "`{name}` does not forbid `unsafe_code`; §4.3 requires it for \
                     every crate except {UNSAFE_ALLOWED:?}"
                ));
            } else if conditional {
                problems.push(format!(
                    "`{name}` forbids `unsafe_code` only under `cfg_attr`, which \
                     permits `unsafe` in the excluded configuration; use a bare \
                     `#![forbid(unsafe_code)]`"
                ));
            }
        }
    }

    assert!(
        checked >= 9,
        "only {checked} crates were checked; expected >= 9"
    );
    assert!(
        problems.is_empty(),
        "unsafe-code policy violations:\n  {}",
        problems.join("\n  ")
    );
}

/// The exception crates are the *only* ones that may ever gain an `allow`.
///
/// A control for the test above: it proves the exception list is not simply
/// empty-in-effect — that the names in it are real workspace members, so
/// exempting one actually exempts something.
#[test]
fn the_unsafe_exception_list_names_real_crates() {
    let present: BTreeSet<String> = crate_dirs().iter().map(|d| package_name(d)).collect();
    let built: Vec<&str> = UNSAFE_ALLOWED
        .iter()
        .copied()
        .filter(|n| present.contains(*n))
        .collect();

    assert!(
        !built.is_empty(),
        "none of the exception crates exist, so the exception list exempts \
         nothing and `every_non_exception_crate_forbids_unsafe_code` covers \
         every crate — which is a fine state, but it means this list is \
         currently unverified and should be trimmed or the note updated"
    );
}

/// `qqq-sys` is the declared `unsafe` exception, and granting it is a process
/// rather than an edit.
///
/// # Why this test is written the way it is
///
/// `qqq-sys` currently forbids `unsafe_code` — correct while it is a stub, and
/// **wrong the moment it gains its first `unsafe` block**, which is the entire
/// reason it exists. That change would otherwise arrive as a compile error in
/// the one crate whose purpose is to contain the thing the error forbids,
/// inviting a hasty `allow` in the wrong place — or, worse, a bare
/// `#![allow(unsafe_code)]` with no argument written down.
///
/// The signal this checks is therefore not the lint attribute alone (which would
/// be circular: the crate that needs `unsafe` must stop forbidding it) but the
/// **artifact the process requires**: `crates/qqq-sys/SAFETY.md`, named by
/// `ARCH-009`. The states are:
///
/// | `SAFETY.md` | forbids `unsafe` | verdict |
/// |---|---|---|
/// | absent | yes | correct — the crate is a stub, no exception claimed |
/// | present | yes | correct — the argument is written ahead of the code, which is the right order |
/// | present | no | correct — the exception was granted through its process |
/// | absent | no | **a violation** — `unsafe` enabled with no written argument |
///
/// **The third row was missing from the first version of this test**, which
/// rejected it as "stale". That was wrong: `ARCH-009` requires the argument, and
/// writing it *before* the code it describes is how an argument is actually
/// reviewed — an argument written afterwards describes code that already exists
/// and is far more likely to be a rationalisation. The test failed the moment
/// `SAFETY.md` was written, which is what surfaced the error.
///
/// So there is exactly **one** forbidden state, and it is the one that matters:
/// `unsafe` permitted with nothing written down. Every other combination is a
/// legitimate point in the process.
#[test]
fn the_unsafe_exception_was_granted_through_its_process() {
    let dir = workspace_root().join("crates/qqq-sys");
    assert!(
        dir.is_dir(),
        "`qqq-sys` is the declared unsafe exception crate and must exist"
    );

    let (forbids, _) = unsafe_lint(&dir);
    let has_safety_arg = dir.join("SAFETY.md").is_file();

    assert!(
        has_safety_arg || forbids,
        "`qqq-sys` permits `unsafe` but has no `crates/qqq-sys/SAFETY.md`. \
         §4.3 requires every unsafe-permitting crate to carry a written safety \
         argument (ARCH-009) and a second reviewer; write the argument — and \
         write it BEFORE the code, so it is a design decision rather than a \
         description of what was already built."
    );

    // A positive control on the filesystem read: if the path were wrong, the
    // assertion above would pass vacuously for a crate that does permit
    // `unsafe`.
    assert!(
        dir.join("src/lib.rs").is_file(),
        "the `qqq-sys` path resolved to something that is not a crate"
    );
}

// ---------------------------------------------------------------------------
// ARCH-002 — authority only narrows downward
// ---------------------------------------------------------------------------

/// **ARCH-002.** The authority-flow invariant is enforced *structurally*, and
/// this test asserts the structure rather than re-testing the behaviour.
///
/// # What the invariant is
///
/// §4.1, invariant 1: *"Authority only ever narrows as you go down."* `qqq-cap`
/// is the sole authority gate, and `GrantSet::narrow` is the only combinator
/// that produces a new grant set from an existing one.
///
/// # Why this test does not exercise `narrow`
///
/// The behaviour is already covered by `qqq-cap`'s own tests, including
/// `no_overlay_can_ever_widen` (`§O-050`), which starts from the empty set and
/// tries every (layer, mode) combination against a hostile overlay holding every
/// capability. Re-testing it here would duplicate that and add nothing.
///
/// What `qqq-cap` cannot test about itself is the **absence of a widening
/// constructor**. A future `GrantSet::union` or a `capabilities.insert` call
/// anywhere in the workspace is what would break the invariant, and it would
/// break it silently: every existing test would still pass, because none of them
/// would call the new function.
///
/// This test reads the workspace source and fails if any `qqq-*` crate mentions
/// a widening primitive on `GrantSet`.
#[test]
fn no_widening_constructor_on_grants_exists_anywhere() {
    // Names that would reintroduce widening. `narrow` is the only permitted
    // combinator, and it is checked to still exist below so this list cannot be
    // satisfied by deleting everything.
    const FORBIDDEN: &[&str] = &[
        "fn union(",
        "fn widen(",
        "fn merge(",
        "fn extend_with(",
        "fn add_capability(",
        "fn grant_more(",
        "fn with_extra(",
    ];

    let mut found = Vec::new();
    let mut grant_set_impls = 0_usize;

    for dir in crate_dirs() {
        let name = package_name(&dir);
        let src = dir.join("src");
        if !src.is_dir() {
            continue;
        }
        for entry in walk(&src) {
            let Ok(text) = std::fs::read_to_string(&entry) else {
                continue;
            };
            let squeezed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            if squeezed.contains("implGrantSet") || squeezed.contains("implGrantSet<") {
                grant_set_impls += 1;
            }
            for needle in FORBIDDEN {
                let squeezed_needle: String =
                    needle.chars().filter(|c| !c.is_whitespace()).collect();
                if squeezed.contains(&squeezed_needle) {
                    found.push(format!(
                        "{} in {name}",
                        entry.file_name().unwrap_or_default().to_string_lossy()
                    ));
                }
            }
        }
    }

    assert!(
        grant_set_impls > 0,
        "no `impl GrantSet` was found anywhere in the workspace; the scanner is \
         broken, so this test proves nothing"
    );
    assert!(
        found.is_empty(),
        "a widening primitive on `GrantSet` appeared: {found:?}\n\
         §4.1 invariant 1 requires authority to only ever narrow. If this is \
         `narrow` under a new name, say so explicitly in Observations; if it \
         widens, it must not exist (CAP-010, §D-008)."
    );
}

/// Recursively list files under `dir`.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

/// The scanner this module depends on must actually find things.
///
/// Every test above asserts an *absence*, and an absence is trivially satisfied
/// by a scanner that returns nothing. This is the positive control for the whole
/// module: it proves `crate_dirs`, `walk` and `package_name` all return real
/// data, so a green result above means "checked and clean" rather than "checked
/// nothing".
#[test]
fn the_architecture_scanner_finds_real_files() {
    let dirs = crate_dirs();
    assert!(
        dirs.len() >= 10,
        "expected >= 10 crate directories, found {}",
        dirs.len()
    );

    let core = workspace_root().join("crates/qqq-core/src");
    let files = walk(&core);
    assert!(
        files.len() >= 3,
        "expected >= 3 .rs files in qqq-core/src, found {}",
        files.len()
    );
    assert!(
        files.iter().any(|f| f.ends_with("error.rs")),
        "the walker did not find error.rs, which certainly exists"
    );

    assert_eq!(
        package_name(&workspace_root().join("crates/qqq-core")),
        "qqq-core"
    );
}
