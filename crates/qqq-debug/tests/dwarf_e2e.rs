// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

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
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// A scratch project directory, removed on drop.
struct Project {
    path: PathBuf,
}

/// Disambiguates concurrent or repeated runs: pid alone collides when a
/// previous run's directory survives (a crash between create and drop) or two
/// agents share a machine.
static PROJECT_SEQ: AtomicU64 = AtomicU64::new(0);

impl Project {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let seq = PROJECT_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "qqq-debug-e2e-{tag}-{}-{nanos}-{seq}",
            std::process::id()
        ));
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

/// Whether the `wasm32-wasip2` target is verifiably absent.
///
/// Probes `rustup target list --installed` first, because the build-stderr
/// sniff in `build_component` is version-fragile: a new cargo may word the
/// missing-target error differently and turn a skip into a false failure.
/// Only a *positive* listing without the target skips — if rustup itself is
/// missing or fails, the build is attempted and its outcome decides, exactly
/// as before.
fn wasm_target_missing() -> bool {
    let Ok(out) = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
    else {
        return false;
    };
    out.status.success() && !String::from_utf8_lossy(&out.stdout).contains("wasm32-wasip2")
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

/// The `debug = true` fixture artifact, built once per test-binary run.
///
/// Three tests need the same bytes; building three throwaway projects costs a
/// `cargo build --release` each (seconds apiece) and litters three temp dirs.
/// The build is a pure function of the fixture sources below, so sharing it
/// changes no outcome. The directory is removed right after the bytes are
/// read — only the bytes are shared, never a path.
fn shared_debug_wasm() -> Option<Vec<u8>> {
    static BUILT: OnceLock<Option<Vec<u8>>> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            if wasm_target_missing() {
                return None;
            }
            let project = Project::new("shared");
            project.write("Cargo.toml", CARGO_TOML);
            project.write("src/lib.rs", LIB_RS);
            let bytes = build_component(&project);
            // `project` drops here and removes its directory; only the bytes
            // are shared, never a path.
            bytes
        })
        .clone()
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
/// Live again: the accuracy assertion below derives the expected line from the
/// source rather than hard-coding a number that rots.
fn line_of(marker: &str) -> u32 {
    LIB_RS
        .lines()
        .position(|l| l.contains(marker))
        .map(|i| u32::try_from(i + 1).expect("a small file"))
        .expect("the marker must exist in the fixture")
}

#[test]
fn a_real_component_yields_source_locations() {
    let Some(wasm) = shared_debug_wasm() else {
        println!(
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
    // The extractor records the line program's own end marker: offsets past
    // the artifact's code must resolve to nothing, not to the last row.
    assert!(
        report.map.upper_bound().is_some(),
        "a real line program ends with an end_sequence marker"
    );

    // The mapping must name the fixture file at the fixture line.
    //
    // Matched exactly, not by basename: the extractor joins the directory
    // table, so the fixture records as `src/lib.rs` — measured on a real
    // build. A basename match would also catch a standard library `lib.rs`
    // at the same line; the exact relative path plus the exact line makes a
    // false positive vanishingly unlikely, and the failure message prints
    // every distinct file so a toolchain that records differently is obvious
    // instead of mysterious.
    let expected_line = line_of("helper(x) + 1");
    let fixture_row = report
        .map
        .entries()
        .iter()
        .find(|e| e.location.file == "src/lib.rs" && e.location.line == expected_line);

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

    let fixture_row = fixture_row.unwrap_or_else(|| {
        panic!(
            "the fixture source must appear in the map at line {expected_line}. \
             {total_files} distinct file(s): {sample:?}"
        )
    });

    // And the map round-trips through its own lookup: the row's address must
    // resolve back to the row's location, proving `lookup` agrees with the
    // table rather than merely re-reading it.
    assert_eq!(
        report.map.lookup(fixture_row.address),
        Some(&fixture_row.location),
        "lookup must agree with the table it searches"
    );

    // The helper's body line is pinned too: `line_of` serves both markers,
    // and a one-marker test would leave the helper's accuracy unproven.
    let helper_line = line_of("a * 2");
    assert!(
        report
            .map
            .entries()
            .iter()
            .any(|e| e.location.file == "src/lib.rs" && e.location.line == helper_line),
        "the helper body (line {helper_line}) must appear in the map"
    );
}

/// A lookup **between** rows resolves to the row that covers it — or to
/// nothing when the probe falls in a gap between line-program sequences.
///
/// The oracle is split deliberately. Whether `before.address + 1` is covered
/// depends on the extractor's sequence data, which this test cannot see — so
/// asserting coverage here would enshrine one toolchain's padding layout.
/// What this test pins on real DWARF is the no-guessing property: the probe
/// must resolve to the covering row or to nothing, never to a *different*
/// row. Exact gap semantics live in the unit test
/// `an_offset_in_a_sequence_gap_is_unmapped`, which controls the sequences.
/// The row-start assertion below guards the other side: a gate that denied
/// row starts would deny everything.
#[test]
fn an_offset_between_real_rows_resolves() {
    let Some(wasm) = shared_debug_wasm() else {
        println!("SKIPPED: the wasm32-wasip2 target is not installed");
        return;
    };

    let report = qqq_debug::extract(&wasm).expect("extraction must not fail");
    let entries = report.map.entries();
    if entries.len() < 2 {
        println!("SKIPPED: the artifact produced fewer than two rows");
        return;
    }

    // Walk every gap: the answer is the preceding row or nothing.
    for pair in entries.windows(2) {
        let (before, after) = (&pair[0], &pair[1]);
        if after.address > before.address + 1 {
            // The row's own start always resolves: sequences begin at their
            // first row, so a gate that denied this would deny everything.
            assert_eq!(
                report.map.lookup(before.address),
                Some(&before.location),
                "a row's own start must resolve: {:#x}",
                before.address
            );
            let probe = before.address + 1;
            let got = report.map.lookup(probe);
            assert!(
                got == Some(&before.location) || got.is_none(),
                "offset {probe:#x} must resolve to its covering row or to \
                 nothing (a sequence gap), never to another row"
            );
        }
    }
}

/// An offset before the first row is **unmapped**, not attributed to the first.
///
/// Both branches assert: a first row above zero leaves `0` uncovered, while a
/// first row *at* zero covers it — the test cannot pass vacuously either way.
#[test]
fn an_offset_below_the_first_real_row_is_unmapped() {
    let Some(wasm) = shared_debug_wasm() else {
        println!("SKIPPED: the wasm32-wasip2 target is not installed");
        return;
    };

    let report = qqq_debug::extract(&wasm).expect("extraction must not fail");
    let Some(first) = report.map.entries().first() else {
        println!("SKIPPED: the artifact produced no rows");
        return;
    };

    if first.address > 0 {
        assert_eq!(
            report.map.lookup(0),
            None,
            "an offset before the first row must not be attributed to it"
        );
    } else {
        assert_eq!(
            report.map.lookup(0),
            Some(&first.location),
            "a first row at zero covers offset zero"
        );
    }

    // Past the recorded bound, resolution reports nothing — the extractor's
    // end marker gates `resolve_frames`, so a garbage offset never guesses at
    // the last row. (`lookup` itself keeps range semantics for boundless maps;
    // the gate lives where the bound is known.)
    if let Some(bound) = report.map.upper_bound() {
        let frame = qqq_debug::ReportedFrame {
            module: None,
            func: "tail".to_owned(),
            offset: Some(bound),
            file: None,
            line: None,
        };
        let (out, gated) = qqq_debug::resolve_frames(&[frame], &report.map);
        assert_eq!(
            out[0].file, None,
            "the bound is exclusive: {bound:#x} is outside every range"
        );
        assert_eq!(gated.unmapped, 1);
    }
}

/// An artifact built **without** debug info reports that, and names the fix.
///
/// The negative control for the whole feature. Without it, a `extract` that
/// invented locations from any input would pass every test above.
#[test]
fn an_artifact_without_debug_info_says_so_and_names_the_fix() {
    if wasm_target_missing() {
        println!("SKIPPED: the wasm32-wasip2 target is not installed");
        return;
    }
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
        println!("SKIPPED: the wasm32-wasip2 target is not installed");
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

/// Wrapping the artifact in a component envelope changes nothing.
///
/// `cargo build --target wasm32-wasip2` emits a **core module**, not a
/// component — so no test above exercises the nested-module path that made
/// this feature report "no debug info" for a 265 KB artifact. Rather than
/// shell out to `wasm-tools` (a CLI dependency the test suite must not grow),
/// this wraps the real bytes by hand: a component preamble plus one section
/// id `1` carrying the module. `extract` must descend and produce the byte-
/// identical map — entries, end bound, and row count.
///
/// The envelope encoding is the Component Model preamble (magic, version
/// `0x0d00`, layer `0x0001`) plus the section id from the walk the unit tests
/// pin byte by byte.
#[test]
fn an_extract_through_a_component_wrapper_matches_direct_extraction() {
    fn push_uleb(out: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = u8::try_from(value & 0x7f).expect("seven bits fit");
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    let Some(wasm) = shared_debug_wasm() else {
        println!("SKIPPED: the wasm32-wasip2 target is not installed");
        return;
    };

    let mut wrapped = vec![0x00, b'a', b's', b'm', 0x0d, 0x00, 0x01, 0x00];
    wrapped.push(0x01); // nested core module
    push_uleb(&mut wrapped, wasm.len() as u64);
    wrapped.extend_from_slice(&wasm);

    let direct = qqq_debug::extract(&wasm).expect("direct extraction must not fail");
    let via_wrapper = qqq_debug::extract(&wrapped).expect("wrapped extraction must not fail");

    assert!(via_wrapper.is_wasm);
    assert!(via_wrapper.has_debug_info(), "{}", via_wrapper.explain());
    assert_eq!(
        via_wrapper.map, direct.map,
        "the nested path must yield the same table — rows and end bound"
    );
    assert_eq!(via_wrapper.rows, direct.rows);
}
