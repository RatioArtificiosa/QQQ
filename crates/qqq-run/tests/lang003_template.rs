// SPDX-License-Identifier: Apache-2.0

//! `LANG-003` — the Rust project template, with **tests and CI**.
//!
//! # What was wrong with the scaffold, measured
//!
//! `qqqai new --template http` produced six files and **no `wit/` tree**, and its source defined its
//! own `Request`/`Response` without implementing the world's export. `qqqai build` succeeded on it —
//! and the artifact was a component that exported **nothing**:
//!
//! ```text
//! $ qqqai inspect target/qqq/probe-app.component.wasm
//! probe-app.component.wasm: component (287062 bytes), 0 required capabilities
//! $ wasm-tools component wit target/qqq/probe-app.component.wasm
//! package root:component;
//! world root {
//! }
//! ```
//!
//! **A QQQ app is a component that exports `qqq:http/incoming-handler`.** One that exports nothing
//! is a wasm module that happens to compile, and `qqqai serve` has nothing to call. The template's
//! own comment said the ABI export was *"tracked separately"* (`§O-362`).
//!
//! The scaffold also shipped **no CI**, which is the other half of the item: a project whose tests
//! run only on the machine that wrote them is a project whose tests do not run.
//!
//! # What this test asserts
//!
//! 1. The scaffold carries the files a QQQ application needs: `wit/app.wit`, the vendored
//!    `wit/deps/qqq-http/qqq-http.wit`, `rust-toolchain.toml`, and a CI workflow.
//! 2. The scaffolded project **passes its own CI steps** — `cargo fmt --check`,
//!    `cargo clippy -D warnings`, `cargo test`. Running them here is the difference between
//!    shipping a workflow and shipping a workflow that passes.
//! 3. `qqqai build` on it produces a component that **exports `qqq:http/incoming-handler@1.0.0`**.
//! 4. The `wit-bindgen` requirement the scaffold emits equals the reference application's — the
//!    scaffold cannot hold a second opinion about the version (`§O-361`).
//!
//! # Why assertion 4 is a separate, non-ignored test
//!
//! Because it is pure text and costs milliseconds, so it runs in the ordinary workspace suite. The
//! other three compile a guest and are `#[ignore]`d, like `LANG-001`'s and `LANG-002`'s.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the repository root")
}

/// The interface a QQQ application exports, and the string the artifact's WIT must name.
const EXPORTED_INTERFACE: &str = "qqq:http/incoming-handler@1.0.0";

/// The eight bytes a **component** starts with, and what a core module starts with instead.
const COMPONENT_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
const CORE_MODULE_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// The `wit-bindgen` requirement declared in a `Cargo.toml`.
fn wit_bindgen_requirement(manifest: &Path) -> String {
    let text = fs::read_to_string(manifest)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", manifest.display()));
    let needle = "wit-bindgen = { version = \"";
    let start = text
        .find(needle)
        .unwrap_or_else(|| panic!("{} must declare `wit-bindgen`", manifest.display()))
        + needle.len();
    let rest = &text[start..];
    let end = rest.find('"').expect("the version is quoted");
    rest[..end].to_owned()
}

/// The scaffold cannot hold a second opinion about `wit-bindgen`'s version.
///
/// # Why this is asserted rather than removed by construction
///
/// `LANG-002`'s test **reads** the requirement from `examples/orders-api/Cargo.toml`, because a test
/// runs inside this repository. A scaffold runs on a user's machine, where that file does not exist,
/// so `new.rs` has to *emit* a value — and an emitted value can drift.
///
/// This is the guard for that drift. It is the same shape as `§O-361`: the repository has two places
/// that know a version, and only a test can keep them equal.
#[test]
fn the_scaffold_pins_the_same_wit_bindgen_as_the_reference_app() {
    let root = repo_root();
    let reference =
        wit_bindgen_requirement(&root.join("examples").join("orders-api").join("Cargo.toml"));

    // The scaffold's value is a `const` in `new.rs`, so the source is the artifact under test.
    let source = fs::read_to_string(
        root.join("crates")
            .join("qqq-run")
            .join("src")
            .join("new.rs"),
    )
    .expect("`new.rs` must be readable");
    let needle = "const WIT_BINDGEN_REQUIREMENT: &str = \"";
    let start = source
        .find(needle)
        .expect("`new.rs` must declare the scaffold's `wit-bindgen` requirement")
        + needle.len();
    let rest = &source[start..];
    let end = rest.find('"').expect("the requirement is quoted");
    let scaffold = &rest[..end];

    assert!(
        !scaffold.is_empty() && scaffold.starts_with(|c: char| c.is_ascii_digit()),
        "the scaffold's requirement is not a version: {scaffold:?}"
    );
    assert_eq!(
        scaffold, reference,
        "the scaffold emits `wit-bindgen = \"{scaffold}\"` and the reference application pins \
         `\"{reference}\"`. Two places know this version and only one of them is measured by \
         `LANG-002`'s test, so they must agree here."
    );
}

/// Run a `cargo` subcommand in `dir`, returning its output.
fn cargo(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("`cargo` must be runnable")
}

/// Assert a `cargo` invocation succeeded, naming the step and showing its output.
fn assert_ok(what: &str, out: &std::process::Output) {
    assert!(
        out.status.success(),
        "the scaffolded project must pass `{what}`.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Assert the scaffold wrote everything a QQQ application needs, and that its world is canonical.
///
/// # Why the world is compared byte for byte
///
/// Because a paraphrase of the world is a *different* application contract that happens to compile.
/// `new.rs` embeds the canonical file with `include_str!`, so this is a check that the embedding is
/// the thing it claims to be rather than a copy that can drift.
fn assert_the_application_files_are_written(project: &Path, root: &Path) {
    for required in [
        "wit/app.wit",
        "wit/deps/qqq-http/qqq-http.wit",
        "rust-toolchain.toml",
        ".github/workflows/ci.yml",
        "Cargo.toml",
        "qqq.toml",
        "tests/smoke.rs",
    ] {
        assert!(
            project.join(required).is_file(),
            "the scaffold must write `{required}`; it wrote {:?}",
            fs::read_dir(project)
                .map(|d| {
                    d.filter_map(Result::ok)
                        .map(|e| e.file_name())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        );
    }

    let canonical = fs::read_to_string(root.join("wit").join("app").join("app.wit"))
        .expect("the canonical world must be readable");
    let scaffolded = fs::read_to_string(project.join("wit").join("app.wit"))
        .expect("the scaffolded world must be readable");
    assert_eq!(
        scaffolded, canonical,
        "the scaffolded world must be the canonical `wit/app/app.wit`, byte for byte"
    );
}

/// **The Rust template scaffolds a servable QQQ application that passes its own CI — `LANG-003`.**
#[test]
#[ignore = "compiles a guest; runs in the rust CI job on all three platforms"]
fn a_scaffolded_project_is_a_servable_application_that_passes_its_own_ci() {
    let root = repo_root();
    let parent = std::env::temp_dir().join(format!("qqq-lang003-{}", std::process::id()));
    let _ = fs::remove_dir_all(&parent);
    fs::create_dir_all(&parent).expect("the temp parent");

    // `qqqai new` takes a *name* and creates it under the working directory, so the test runs it
    // from the temp parent rather than passing a path.
    let created = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args([
            "new",
            "probe-app",
            "--language",
            "rust",
            "--template",
            "http",
        ])
        .current_dir(&parent)
        .output()
        .expect("`qqqai new` must be runnable");
    assert_ok("qqqai new probe-app", &created);

    let project = parent.join("probe-app");

    // --- 1. the files a QQQ application needs --------------------------------
    assert_the_application_files_are_written(&project, &root);

    // --- 2. the scaffold's own CI steps -------------------------------------
    assert_ok(
        "cargo fmt --all -- --check",
        &cargo(&project, &["fmt", "--all", "--", "--check"]),
    );
    assert_ok(
        "cargo clippy --all-targets --all-features -- -D warnings",
        &cargo(
            &project,
            &[
                "clippy",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
    );
    assert_ok(
        "cargo test --all-features",
        &cargo(&project, &["test", "--all-features"]),
    );

    // --- 3. the artifact is a component that EXPORTS the handler -------------
    let built = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .arg("build")
        .current_dir(&project)
        .output()
        .expect("`qqqai build` must be runnable");
    assert_ok("qqqai build", &built);

    let artifact = project
        .join("target")
        .join("qqq")
        .join("probe-app.component.wasm");
    let bytes =
        fs::read(&artifact).unwrap_or_else(|e| panic!("{} must exist: {e}", artifact.display()));
    let preamble: [u8; 8] = bytes[..8].try_into().expect("at least eight bytes");
    assert_ne!(
        preamble, CORE_MODULE_PREAMBLE,
        "a core module is not a component"
    );
    assert_eq!(
        preamble, COMPONENT_PREAMBLE,
        "the artifact must be a COMPONENT, not a core module: {preamble:02x?}"
    );

    // The export, read with the same instrument the `reference-app` CI job uses. **This is the
    // assertion the old scaffold failed**: its world was empty, so nothing exported anything.
    let wit = Command::new("wasm-tools")
        .args(["component", "wit"])
        .arg(&artifact)
        .output()
        .expect("`wasm-tools` must be runnable; `qqqai build` needs it too");
    let wit_text = String::from_utf8_lossy(&wit.stdout);
    assert!(
        wit.status.success(),
        "`wasm-tools component wit` must read the artifact: {}",
        String::from_utf8_lossy(&wit.stderr)
    );
    assert!(
        wit_text.contains(&format!("export {EXPORTED_INTERFACE}")),
        "the scaffolded application must EXPORT `{EXPORTED_INTERFACE}`; the artifact's world is:\n\
         {wit_text}"
    );

    let _ = fs::remove_dir_all(&parent);
}
