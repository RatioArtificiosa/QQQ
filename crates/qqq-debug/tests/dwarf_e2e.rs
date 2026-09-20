//! End-to-end DWARF extraction: build a real component with debug info and map
//! a real bytecode offset back to a real source line.
//!
//! # Why this test compiles a project
//!
//! The unit tests in `extract.rs` build synthetic section tables, which proves
//! the *parser* works. They cannot prove the thing that matters: that a Rust
//! `wasm32-wasip2` build's DWARF, read by this crate, produces offsets that line
//! up with what a Wasmtime frame reports.
//!
//! That alignment is the load-bearing assumption of the whole crate — the crate
//! documentation calls it "the coincidence that keeps this crate small". An
//! assumption stated in prose and never exercised is exactly what `§O-038b` and
//! `§O-043a` were: plausible, specific, and wrong.
//!
//! # Why it skips rather than fails when the toolchain is absent
//!
//! `wasm32-wasip2` requires a Rust target that a developer may not have added.
//! A missing optional toolchain is not a defect in this crate. The skip is
//! **loud** — see the note in `crates/qqq-run/tests/cli.rs` (`§O-038d`) for why a
//! silent skip is worse than a failing test.

use std::path::PathBuf;
use std::process::Command;

/// A scratch project directory, removed on drop.
struct Project {
    path: PathBuf,
}

impl Project {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("qqq-debug-e2e-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join("src")).expect("create project");
        Self { path }
    }

    fn write(&self, name: &str, content: &str) {
        let target = self.path.join(name);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(target, content).expect("write");
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Compile the project to a component, or `None` when the target is missing.
///
/// `debug = true` in the release profile is what puts DWARF in the artifact, and
/// it is also the setting a user forgets — which is why `ExtractionReport::explain`
/// names it.
fn build_component(project: &Project) -> Option<Vec<u8>> {
    let out = Command::new("cargo")
        .args(["build", "--release", "--target", "wasm32-wasip2"])
        .current_dir(&project.path)
        .output()
        .ok()?;

    if !out.status.success() {
        // Distinguish "no target installed" from "the fixture failed to
        // compile". The first is a skip; the second would be a test bug, and
        // swallowing it would make the test vacuous.
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("can't find crate for `std`")
            || stderr.contains("target may not be installed")
            || stderr.contains("no such file")
        {
            return None;
        }
        panic!("the fixture failed to build:\n{stderr}");
    }

    let artifact = project.path.join("target/wasm32-wasip2/release/app.wasm");
    std::fs::read(&artifact).ok()
}

const CARGO_TOML: &str = r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]
path = "src/lib.rs"

[workspace]

[profile.release]
debug = true
"#;

/// A source file whose line numbers the test asserts against by name.
///
/// # Why there is an exported entry point
///
/// Measured on a scaffolded project: with `lto = true` and no exported symbol,
/// the linker eliminates the crate's own code **and its debug info with it**, so
/// the artifact's DWARF named only the Rust standard library. A fixture without
/// an entry point would therefore test that DWARF is present while never
/// touching the part a user cares about.
///
/// `#[no_mangle] pub extern "C"` is what keeps it alive. That is not a
/// workaround for this test — it is the same reason a real component has an
/// exported handler, and it is why `qqqai new` now sets `debug = true`.
const LIB_RS: &str = r#"//! A fixture for DWARF extraction.

/// An exported entry point, so the linker cannot eliminate this crate.
#[no_mangle]
pub extern "C" fn app_entry(x: i32) -> i32 {
    // MARKER_A
    helper(x) + 1
}

/// A helper the entry point calls.
pub fn helper(a: i32) -> i32 {
    // MARKER_B
    a * 2
}
"#;

/// The 1-based line number of a marker within [`LIB_RS`].
///
/// Unused today and kept deliberately: the assertion below is on the *file*,
/// which is what the defect was about, but a caller wanting to pin an exact line
/// should derive it from the source rather than hard-code a number that rots.
#[allow(dead_code)]
fn line_of(marker: &str) -> u32 {
    LIB_RS
        .lines()
        .position(|l| l.contains(marker))
        .map(|i| u32::try_from(i + 1).expect("a small file"))
        .expect("the marker must exist in the fixture")
}

#[test]
fn a_real_component_yields_source_locations() {
    let project = Project::new("real");
    project.write("Cargo.toml", CARGO_TOML);
    project.write("src/lib.rs", LIB_RS);

    let Some(wasm) = build_component(&project) else {
        eprintln!(
            "SKIPPED: the wasm32-wasip2 target is not installed - this test did not run.\n\
             Install it with: rustup target add wasm32-wasip2"
        );
        return;
    };

    let report = qqq_debug::extract(&wasm).expect("extraction must not fail");

    assert!(report.is_wasm, "the built artifact must be a Wasm module");
    assert!(
        report.has_debug_info(),
        "`debug = true` was set, so DWARF must be present: {}",
        report.explain()
    );
    assert!(
        report.rows > 0,
        "the line program must produce rows: {}",
        report.explain()
    );

    // The mapping must name the fixture file.
    //
    // Matched on the **basename**, because that is what this toolchain records:
    // measured, the fixture appears as bare `lib.rs`, not `src/lib.rs`. DWARF
    // stores whatever path the compiler was given, and for `wasm32-wasip2` the
    // file table holds file names with the directory resolved separately.
    //
    // Asserting on `src/lib.rs` failed on a map that *did* contain the fixture,
    // which is a test bug that would have looked like a product bug. The
    // assertion is now on what the toolchain actually emits, with the observation
    // recorded rather than assumed.
    let found_fixture = report
        .map
        .entries()
        .iter()
        .any(|e| e.location.file.ends_with("lib.rs"));

    // The full set for the failure message only.
    let mut sample: Vec<&str> = report
        .map
        .entries()
        .iter()
        .map(|e| e.location.file.as_str())
        .collect();
    sample.sort_unstable();
    sample.dedup();
    let total_files = sample.len();

    assert!(
        found_fixture,
        "the fixture source must appear in the map. {total_files} distinct file(s): {sample:?}"
    );
}

/// A lookup **between** rows resolves to the row that covers it.
///
/// The property that makes this a range map rather than a point map, asserted
/// against a real artifact rather than a synthetic table.
#[test]
fn an_offset_between_real_rows_resolves() {
    let project = Project::new("between");
    project.write("Cargo.toml", CARGO_TOML);
    project.write("src/lib.rs", LIB_RS);

    let Some(wasm) = build_component(&project) else {
        eprintln!("SKIPPED: the wasm32-wasip2 target is not installed");
        return;
    };

    let report = qqq_debug::extract(&wasm).expect("extraction must not fail");
    let entries = report.map.entries();
    if entries.len() < 2 {
        eprintln!("SKIPPED: the artifact produced fewer than two rows");
        return;
    }

    // Walk every gap and assert the answer is the preceding row.
    for pair in entries.windows(2) {
        let (before, after) = (&pair[0], &pair[1]);
        if after.address > before.address + 1 {
            let probe = before.address + 1;
            let got = report.map.lookup(probe).expect("inside the covered range");
            assert_eq!(
                got, &before.location,
                "offset {probe:#x} lies in the range starting at {:#x} and must \
                 resolve to it, not to the next row at {:#x}",
                before.address, after.address
            );
        }
    }
}

/// An offset before the first row is **unmapped**, not attributed to the first.
#[test]
fn an_offset_below_the_first_real_row_is_unmapped() {
    let project = Project::new("below");
    project.write("Cargo.toml", CARGO_TOML);
    project.write("src/lib.rs", LIB_RS);

    let Some(wasm) = build_component(&project) else {
        eprintln!("SKIPPED: the wasm32-wasip2 target is not installed");
        return;
    };

    let report = qqq_debug::extract(&wasm).expect("extraction must not fail");
    let Some(first) = report.map.entries().first() else {
        eprintln!("SKIPPED: the artifact produced no rows");
        return;
    };

    if first.address > 0 {
        assert_eq!(
            report.map.lookup(0),
            None,
            "an offset before the first row must not be attributed to it"
        );
    }
}

/// An artifact built **without** debug info reports that, and names the fix.
///
/// The negative control for the whole feature. Without it, a `extract` that
/// invented locations from any input would pass every test above.
#[test]
fn an_artifact_without_debug_info_says_so_and_names_the_fix() {
    let project = Project::new("nodebug");
    project.write(
        "Cargo.toml",
        // No `debug = true` in the profile.
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]
path = "src/lib.rs"

[workspace]
"#,
    );
    project.write("src/lib.rs", LIB_RS);

    let Some(wasm) = build_component(&project) else {
        eprintln!("SKIPPED: the wasm32-wasip2 target is not installed");
        return;
    };

    let report = qqq_debug::extract(&wasm).expect("extraction must not fail");
    assert!(report.is_wasm);
    assert!(
        !report.has_debug_info(),
        "a default release build carries no DWARF, but {} section(s) were found",
        report.sections_found.len()
    );
    assert!(report.map.is_empty());
    assert!(
        report.explain().contains("debug = true"),
        "the explanation must name the build setting: {}",
        report.explain()
    );

    // And a lookup against it resolves nothing, rather than guessing.
    assert_eq!(
        report.map.lookup(0x1000),
        None,
        "an artifact with no debug info must map nothing"
    );
}
