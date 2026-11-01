// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

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
        let line = strip_toml_comment(line).trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        // `split_once('=')` plus a key comparison: `strip_prefix("name")` also
        // matches `names =`, and a quoted `#` or trailing comment must not leak
        // into the value.
        if in_package
            && let Some((key, value)) = line.split_once('=')
            && key.trim() == "name"
        {
            return value
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_owned();
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
    // The benchmark harness (`PERF-001`). Second because `qqq-core` is its only
    // dependency: it defines the §9.1 methodology as a type and the §9.2 budgets
    // as data, and measures other crates from outside their dependency chain.
    // Siting it as low as possible is what keeps it able to measure everything --
    // a harness that depended on the server could not time the server's startup.
    //
    // Adding it required updating **two** lists: this one and
    // `tools/check_topology.py`'s. Both failed loudly until they were corrected,
    // which is the duplication working as the doc comment above intends -- but it
    // is worth knowing that a new crate is a two-file change.
    "qqq-bench",
    // **Moved here, and this list is what caught the move being incomplete.**
    //
    // `qqq-debug` sat last, below `qqq-run`, which made the `HOST-009` edge
    // `qqq-run -> qqq-debug` point *upward* and fail. The crate's real graph is
    // `qqq-debug -> qqq-core` and nothing else, with nothing depending on it, so
    // a position above the CLI asserted a layering the manifest never had.
    //
    // The ordering was corrected in `tools/check_topology.py` first, and the
    // full gate then failed **here**: this list had the same wrong position, and
    // the two-list duplication caught an incomplete fix. That is the duplication
    // earning its keep a second time -- the first was `qqq-bench` above.
    "qqq-debug",
    "qqq-cap",
    "qqq-abi",
    "qqq-host",
    "qqq-io",
    "qqq-serve",
    "qqq-pkg",
    "qqq-run",
    "qqq-registry",
    "qqq-sys",
    // Developer tooling (`I-08`): no `qqq-*` dependencies, nothing depends on
    // it, so any position passes — last keeps the product order untouched.
    // Registered here AND in `tools/check_topology.py`'s `ORDER`: a new crate
    // is a two-file change, and the duplication is the point (see above).
    "xtask",
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
/// `[dev-dependencies]` counts, and so do target-gated tables and renames
/// (see `manifest_section_is_deps` and `parse_qqq_dep_edge`): a dev-dependency
/// from `qqq-core` to `qqq-host` would not ship in a release build, but it
/// makes `qqq-core`'s own test suite require the entire Wasmtime stack — which
/// defeats the stated reason for the layering (§4.3: "third parties can depend
/// on `qqq-host` or `qqq-cap` alone"), and makes `cargo test -p qqq-core` a
/// multi-minute build.
fn declared_qqq_deps(crate_dir: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(crate_dir.join("Cargo.toml")).expect("readable manifest");
    parse_manifest_deps(&text)
}

/// Every `qqq-*` edge in a manifest's text.
///
/// Split out so the joining rules are unit-testable without fixtures: a
/// `package =` value may span lines (`foo = {\n package = "qqq-host"\n}`), a
/// dependency may live in a dotted table (`[dependencies.foo]`), and only
/// brace-balanced logical lines are parsed as edges.
fn parse_manifest_deps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_deps = false;
    let mut pending: Option<String> = None;
    // The dep a dotted table declares (`[dependencies.foo]` declares `foo`;
    // a `package =` line inside it renames to the real crate).
    let mut table_dep: Option<String> = None;
    let flush_table_dep = |out: &mut Vec<String>, table_dep: &mut Option<String>| {
        if let Some(name) = table_dep.take()
            && name.starts_with("qqq-")
        {
            out.push(name);
        }
    };
    for line in text.lines() {
        let code = strip_toml_comment(line).trim();
        if code.starts_with('[') && pending.is_none() {
            flush_table_dep(&mut out, &mut table_dep);
            in_deps = manifest_section_is_deps(code);
            table_dep = dotted_table_dep(code);
            continue;
        }
        if !in_deps {
            continue;
        }
        let logical = match pending.take() {
            Some(prev) => prev + " " + code,
            None => code.to_owned(),
        };
        // A value split across lines is one edge, not none: hold the line
        // until its braces balance, then parse the whole.
        if logical.matches('{').count() > logical.matches('}').count() {
            pending = Some(logical);
            continue;
        }
        if let Some(edge) = parse_qqq_dep_edge(&logical) {
            out.push(edge);
        } else if table_dep.is_some() {
            // No inline edge: a `package =` line renames the dotted table's
            // dep, satisfying (and clearing) it either way.
            if let Some((key, value)) = logical.split_once('=')
                && key.trim() == "package"
            {
                let name = value
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'')
                    .to_owned();
                if name.starts_with("qqq-") {
                    out.push(name);
                }
                table_dep = None;
            }
        }
    }
    flush_table_dep(&mut out, &mut table_dep);
    out
}

/// The dependency a dotted table header declares, if any.
///
/// `[dependencies.foo]` declares `foo`; `[target.…]` tables and multi-segment
/// headers declare nothing by themselves.
fn dotted_table_dep(header: &str) -> Option<String> {
    for prefix in [
        "[dependencies.",
        "[dev-dependencies.",
        "[build-dependencies.",
    ] {
        if let Some(rest) = header.strip_prefix(prefix) {
            let name = rest.strip_suffix(']').unwrap_or(rest);
            if !name.is_empty() && !name.contains(['.', '"', '\'']) {
                return Some(name.to_owned());
            }
        }
    }
    None
}

/// Whether a manifest section header opens a dependency table.
///
/// Exact `[dependencies]` / `[dev-dependencies]` / `[build-dependencies]`,
/// dotted tables (`[dependencies.foo]`), and target-gated tables
/// (`[target.'cfg(unix)'.dependencies]`): the prefix still names a dependency
/// table, and an edge under any of them is still a layering edge.
fn manifest_section_is_deps(header: &str) -> bool {
    const TABLES: &[&str] = &[
        "[dependencies]",
        "[dev-dependencies]",
        "[build-dependencies]",
    ];
    const PREFIXES: &[&str] = &[
        "[dependencies.",
        "[dev-dependencies.",
        "[build-dependencies.",
        "[target.",
    ];
    if TABLES.contains(&header) {
        return true;
    }
    PREFIXES.iter().any(|p| header.starts_with(p)) && header.contains("dependencies")
}

/// A `qqq-*` edge on one manifest line, or `None`.
///
/// The key names the edge directly (`qqq-host = { version … }`); a table value
/// with `package = "qqq-host"` names it through a rename (`alias = {…}`).
/// Comment-tolerant: callers pass stripped lines, but stripping again is
/// harmless and keeps this unit-testable on raw manifest text.
fn parse_qqq_dep_edge(line: &str) -> Option<String> {
    let line = strip_toml_comment(line);
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.starts_with("qqq-") {
        return Some(key.to_owned());
    }
    let table = value.trim().strip_prefix('{')?;
    for part in table.split(',') {
        let (k, v) = part.split_once('=')?;
        if k.trim() == "package" {
            // The table's closing `}` trails the last value; package names
            // cannot contain it, so it is structural rather than data.
            let raw = v.trim();
            let raw = raw.strip_suffix('}').map_or(raw, str::trim);
            let name = raw.trim_matches(|c| c == '"' || c == '\'');
            if name.starts_with("qqq-") {
                return Some(name.to_owned());
            }
        }
    }
    None
}

/// Strip a trailing `#` comment, ignoring `#` inside quotes.
///
/// TOML values in the scanned positions (names, package refs) never
/// legitimately contain `#`, but URLs in neighbouring values do — so the
/// stripper must be quote-aware rather than a bare `split('#')`. (Twin of the
/// helper in `tests/naming.rs`; both test targets need it and neither may grow
/// a dependency for it.)
fn strip_toml_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (i, c) in line.char_indices() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return line[..i].trim_end(),
            _ => {}
        }
    }
    line
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

/// A crate's crate-level `unsafe_code` lint attributes, if it declares them.
///
/// Scans every crate root (`src/lib.rs` and, where it exists, `src/main.rs`)
/// plus the build script: a binary is a separate crate root, and a `forbid`
/// in `lib.rs` does not cover it — `unsafe` in argument parsing would run
/// before any capability exists to constrain it. The same holds for
/// `build.rs`, which compiles into every downstream build.
///
/// Returns `(forbidden, is_conditional)`:
///
/// * `forbidden` — whether every crate root forbids `unsafe`.
/// * `is_conditional` — whether any attribute is wrapped in `cfg_attr`, which
///   **weakens it** and is therefore reported separately. A
///   `#![cfg_attr(not(test), forbid(unsafe_code))]` allows `unsafe` under
///   `cfg(test)`, so a test helper can introduce it and the release build's
///   guarantee becomes a property of the test configuration rather than of the
///   source.
fn unsafe_lint(crate_dir: &Path) -> (bool, bool) {
    let mut forbidden = false;
    let mut saw_allow = false;
    let mut conditional = false;
    let mut roots = 0_usize;
    for target in ["src/lib.rs", "src/main.rs", "build.rs"] {
        let path = crate_dir.join(target);
        if !path.is_file() {
            continue;
        }
        roots += 1;
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let mut root_forbidden = false;
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("#![") {
                continue;
            }
            if line.contains("unsafe_code") && line.contains("forbid") {
                root_forbidden = true;
                if line.starts_with("#![cfg_attr(") {
                    conditional = true;
                }
            }
            // An `allow` at crate level in a crate that is not an exception is a
            // defect this function must not miss. Tracked separately from the
            // `forbid` above because order must not matter: a `forbid` followed
            // by an `allow` must not report "forbidden", and neither may an
            // `allow` the `forbid` precedes.
            if line.contains("unsafe_code") && line.contains("allow") {
                saw_allow = true;
            }
        }
        forbidden = root_forbidden;
        if !forbidden {
            break;
        }
    }
    // No crate root at all is itself reported by the caller; here it means
    // nothing was checked.
    if roots == 0 {
        return (false, false);
    }
    (forbidden && !saw_allow, conditional)
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

/// **ARCH-002 (companion).** `lock_recover()` may only appear where recovery
/// is sound.
///
/// `qqq_core::sync` documents the rule — counters, idle lists and tenant maps
/// behind RAII guards recover; the audit chain head and multi-field invariants
/// fail closed — but a blanket `impl<T> LockRecover for Mutex<T>` lets any
/// call site recover any lock, and prose does not enforce. So this test pins
/// the complete set of call sites: `pool.rs` (pool counters, idle lists) and
/// `guest_output.rs` (tenant maps behind RAII guards). A new call site anywhere
/// else fails here first, and landing it means either proving the lock's
/// critical sections are panic-free between statements or changing the rule
/// deliberately.
///
/// Comment lines are ignored: prose may discuss recovery anywhere; only code
/// may perform it.
#[test]
fn lock_recover_call_sites_are_the_sound_ones() {
    const ALLOWED: &[&str] = &[
        "crates/qqq-core/src/sync.rs",
        "crates/qqq-host/src/pool.rs",
        "crates/qqq-host/src/guest_output.rs",
    ];
    let mut found = BTreeSet::new();
    for dir in crate_dirs() {
        let src = dir.join("src");
        if !src.is_dir() {
            continue;
        }
        for entry in walk(&src) {
            let Ok(text) = std::fs::read_to_string(&entry) else {
                continue;
            };
            // Bare `lock_recover`: the qualified `LockRecover::lock_recover`
            // and a spaced `lock_recover ()` are the same call and must trip
            // the same wire. (Comment lines are skipped so prose cannot trip
            // it; the allowlist names whole files, not lines.)
            let uses = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.starts_with("//") && !l.starts_with('*'))
                .any(|l| l.contains("lock_recover"));
            if uses {
                let rel = entry
                    .strip_prefix(workspace_root())
                    .unwrap_or(&entry)
                    .to_string_lossy()
                    .replace('\\', "/");
                found.insert(rel);
            }
        }
    }
    let allowed: BTreeSet<String> = ALLOWED.iter().map(ToString::to_string).collect();
    assert_eq!(
        found, allowed,
        "`lock_recover()` call sites changed: recovery is only sound for \
         counters, idle lists and tenant maps (see `qqq_core::sync`). A new \
         site must prove its critical sections panic-free or change this list \
         deliberately — silently recovering the audit chain head would hide a \
         broken invariant."
    );
}

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
///
/// Whether a file opens the inherent `impl GrantSet` block.
///
/// Line-based and comment-stripped: `impl GrantSet` and `impl<T> GrantSet`
/// both match, while `impl PartialEq for GrantSet` (a trait impl, not the
/// inherent block) and prose mentioning both words do not. Checking the whole
/// file at once would conflate an `impl<T> Foo` with a `-> GrantSet` return
/// type on another line, so each line must contain the whole shape.
fn file_has_grantset_impl(text: &str) -> bool {
    text.lines().any(|line| {
        let squeezed: String = strip_rust_comment(line)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        is_grantset_impl(&squeezed)
    })
}

/// Whether a whitespace-squeezed, comment-free line opens the inherent
/// `impl GrantSet` block, with optional `unsafe` and generics.
fn is_grantset_impl(squeezed: &str) -> bool {
    let rest = squeezed.strip_prefix("unsafe").unwrap_or(squeezed);
    let Some(rest) = rest.strip_prefix("impl") else {
        return false;
    };
    let rest = match rest.strip_prefix('<') {
        Some(after) => match after.find('>') {
            Some(i) => &after[i + 1..],
            None => return false,
        },
        None => rest,
    };
    // Exact, modulo the opening brace: a hypothetical `impl GrantSetters` is a
    // different type, not the inherent impl this scanner exists to find. Real
    // declarations end the line with `{` (or a `where` clause, which still
    // starts with the bare name).
    let rest = rest.strip_suffix('{').unwrap_or(rest);
    rest == "GrantSet" || rest.starts_with("GrantSetwhere")
}

/// Strip a trailing `//` comment, ignoring `//` inside strings.
///
/// (Twin of `strip_toml_comment`, which strips `#`, and of `strip_inline_comment`
/// in `tests/qblock.rs`; every test target carries its own rather than a
/// dependency.)
fn strip_rust_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'/' if !in_single && !in_double && bytes.get(i + 1) == Some(&b'/') => {
                return line.get(..i).map_or(line, str::trim_end);
            }
            _ => {}
        }
        i += 1;
    }
    line
}

#[test]
fn no_widening_constructor_on_grants_exists_anywhere() {
    // Names that would reintroduce widening. `narrow` is the only permitted
    // combinator, and it is checked to still exist below so this list cannot be
    // satisfied by deleting everything.
    //
    // `fn union` has no call paren on purpose: a generic `fn union<T>` must be
    // caught too — and so must generics on every other widening name. Each
    // base is matched with `(` or `<` immediately after, so a hypothetical
    // `fn merger` does not trip the `merge` needle.
    const FORBIDDEN_FN: &[&str] = &[
        "fn union",
        "fn widen",
        "fn merge",
        "fn extend_with",
        "fn add_capability",
        "fn grant_more",
        "fn with_extra",
    ];
    // `capabilities.insert(` (not bare `insert(`, which every map uses
    // legitimately) is the method-call half of the documented threat: a new
    // widening method would not be a `fn` definition at all.
    const FORBIDDEN_CALL: &str = "capabilities.insert(";

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
            // Line-based and comment-stripped: a file-level `contains("impl")`
            // plus `contains("GrantSet")` would conflate an `impl<T> Foo` with
            // a `-> GrantSet` return type on another line. Each line must carry
            // the whole `impl…GrantSet` shape (with optional `unsafe` and
            // generics); prose mentioning both words does not count.
            if file_has_grantset_impl(&text) {
                grant_set_impls += 1;
            }
            // Squeezed once per file for the substring needles below; the
            // impl-shape check above stays line-based (see its comment).
            let squeezed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            for needle in FORBIDDEN_FN {
                let base: String = needle.chars().filter(|c| !c.is_whitespace()).collect();
                // A widening definition, generic or not: `fn union(` and
                // `fn union<T>` both match, while a hypothetical `fn merger`
                // does not (the `(` / `<` must follow immediately).
                if squeezed.contains(&format!("{base}(")) || squeezed.contains(&format!("{base}<"))
                {
                    found.push(format!(
                        "{} in {name}",
                        entry.file_name().unwrap_or_default().to_string_lossy()
                    ));
                }
            }
            if squeezed.contains(FORBIDDEN_CALL) {
                found.push(format!(
                    "{} in {name}",
                    entry.file_name().unwrap_or_default().to_string_lossy()
                ));
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

// ---------------------------------------------------------------------------
// Scanner unit tests — the manifest helpers above, pinned directly
// ---------------------------------------------------------------------------

/// Section headers: exact tables plus dotted and target-gated tables, never
/// anything else.
#[test]
fn manifest_section_header_matching() {
    assert!(manifest_section_is_deps("[dependencies]"));
    assert!(manifest_section_is_deps("[dev-dependencies]"));
    assert!(manifest_section_is_deps("[build-dependencies]"));
    assert!(manifest_section_is_deps("[dependencies.foo]"));
    assert!(manifest_section_is_deps("[dev-dependencies.foo]"));
    assert!(manifest_section_is_deps(
        "[target.'cfg(unix)'.dependencies]"
    ));
    assert!(manifest_section_is_deps(
        "[target.cfg(windows).dev-dependencies]"
    ));
    // Headers arrive comment-stripped (the caller strips first), so the
    // contract is asserted on stripped input.
    assert!(manifest_section_is_deps(
        strip_toml_comment("[target.'cfg(unix)'.dependencies] # linux only").trim()
    ));
    assert!(!manifest_section_is_deps("[package]"));
    assert!(!manifest_section_is_deps("[features]"));
    assert!(!manifest_section_is_deps("[patch.crates-io]"));
}

/// The `impl GrantSet` shape check: inherent impls (generic or not) count;
/// trait impls and prose do not.
#[test]
fn grantset_impl_shape_matching() {
    assert!(is_grantset_impl("implGrantSet{"));
    assert!(is_grantset_impl("impl<T>GrantSet{"));
    assert!(is_grantset_impl("unsafeimplGrantSet{"));
    assert!(is_grantset_impl("impl<'a>GrantSet{"));
    assert!(!is_grantset_impl("implPartialEqforGrantSet{"));
    assert!(!is_grantset_impl("implGrantSetters{"));
    assert!(!is_grantset_impl("structGrantSet"));
    assert!(!is_grantset_impl("//implGrantSet{"));
}

/// Dependency edges: direct names and `package =` renames.
#[test]
fn dep_edge_parsing() {
    assert_eq!(
        parse_qqq_dep_edge("qqq-host = { version = \"1\" }"),
        Some("qqq-host".to_owned())
    );
    // A rename: the local name is not a qqq crate, the package is the edge.
    assert_eq!(
        parse_qqq_dep_edge("host = { package = \"qqq-host\", version = \"1\" }"),
        Some("qqq-host".to_owned())
    );
    assert_eq!(parse_qqq_dep_edge("serde = { workspace = true }"), None);
    assert_eq!(
        parse_qqq_dep_edge("alias = { package = \"other-crate\" }"),
        None
    );
    // Single quotes and trailing comments must not leak into the name.
    assert_eq!(
        parse_qqq_dep_edge("alias = { package = 'qqq-cap' } # renamed"),
        Some("qqq-cap".to_owned())
    );
}

/// Comment stripping respects quotes: a `#` in a URL is data, not a comment.
#[test]
fn toml_comment_stripping_respects_quotes() {
    assert_eq!(
        strip_toml_comment("name = \"qqqai\" # the binary"),
        "name = \"qqqai\""
    );
    assert_eq!(
        strip_toml_comment("foo = { git = \"https://x/y#branch\" } # pinned"),
        "foo = { git = \"https://x/y#branch\" }"
    );
    assert_eq!(strip_toml_comment("no comment here"), "no comment here");
}

/// Whole-manifest parsing: dotted tables, target-gated tables, renames split
/// across lines, and sections that must NOT count.
#[test]
fn manifest_edges_cover_tables_renames_and_splits() {
    let text = "[package]\nname = \"demo\"\n\
        [dependencies]\nqqq-core = \"1\"\n\
        [dependencies.alias]\npackage = \"qqq-host\"\nversion = \"1\"\n\
        [dependencies.qqq-toml]\nversion = \"1\"\n\
        [target.'cfg(unix)'.dependencies]\nrenamed = { package = \"qqq-cap\" }\n\
        [target.'cfg(windows)'.dependencies]\nsplit = {\n package = \"qqq-io\",\n}\n\
        [features]\ndefault = []\n";
    let mut edges = parse_manifest_deps(text);
    edges.sort_unstable();
    assert_eq!(
        edges,
        vec!["qqq-cap", "qqq-core", "qqq-host", "qqq-io", "qqq-toml"]
    );
}
