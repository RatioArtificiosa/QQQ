// SPDX-License-Identifier: Apache-2.0

//! `LANG-002` — Rust bindings generated from `wit/` via `wit-bindgen`.
//!
//! # What this test is for, and what it found the first time it was written
//!
//! `LANG-002` says bindings are **generated from `wit/` via `wit-bindgen`**. The first version of
//! this test copied the canonical `wit/qqq-crypto.wit` into a probe and built it, and the build
//! failed:
//!
//! ```text
//! error: failed to resolve directory while parsing WIT for path [...\wit]
//!   Caused by: failed to parse package: ...\wit\deps\qqq-crypto
//!   Caused by: invalid character in identifier '2'
//!      --> ...\wit\deps\qqq-crypto\qqq-crypto.wit:118:5
//!       |     aes-256-gcm,
//! ```
//!
//! **`wit-bindgen` could not generate bindings from the canonical `wit/` at all.** The repository
//! pinned `wit-bindgen = "0.44"`, whose `wit-parser` is 0.236.1; `wit/qqq-crypto.wit` names an
//! AEAD construction `aes-256-gcm`, and 0.236.1 requires every hyphen-separated segment of an
//! identifier to start with a letter — so the segment `256` is refused. The grammar was **relaxed**
//! upstream to allow exactly that, and `wit-bindgen` 0.62 (whose `wit-parser` is 0.259.0) accepts
//! it. The pin was simply older than the relaxation.
//!
//! # The part worth keeping: the guard used a different parser than the consumer
//!
//! `tools/check_wit.py` validates every file in `wit/` with `wasm-tools`, and it has always been
//! **green** — `wasm-tools 1.259.0` bundles `wit-parser` 0.259.0, which accepts `aes-256-gcm`. So
//! the repository's WIT validator and its guest toolchain were parsing the same files with
//! **different grammars**, and only one of them was on the critical path.
//!
//! > **A guard that uses a different parser than the consumer is a guard that measures a different
//! > language.**
//!
//! This is `§O-282`'s shape one level up: not a guard that is too narrow in its file list, but a
//! guard that is too *permissive* in its grammar.
//!
//! # Why it builds a probe rather than testing the reference application
//!
//! Because the reference application binds **one** interface — `qqq:http`, for its export's types —
//! and imports **nothing**. A test of the app would therefore have proved bindability for the one
//! canonical file that happened to work, which is exactly how the defect survived. The probe
//! vendors **every** `wit/*.wit`, so the build parses all of them.
//!
//! It also imports a capability, which the app does not: `qqq:crypto/hashing`. That is the half of
//! "bindings generated from `wit/`" the export alone cannot demonstrate, and it is the half a guest
//! author reaches for first.
//!
//! # Why the canonical `wit/` is COPIED rather than pointed at
//!
//! Because `wit/` is a `wasm-tools` layout, not a `wit-bindgen` layout. WIT resolves dependencies
//! only from a `deps/` directory beside the package, and `wit/` holds fifteen **different**
//! packages as siblings plus one world package under `app/` — which is legal for `wasm-tools` and
//! is not something `wit-bindgen` can resolve. Copying each file into `deps/<stem>/<stem>.wit` is
//! the same vendoring a real project does, and `tools/check_wit_vendoring.py` is what keeps a
//! checked-in copy honest.
//!
//! Copying into a **temporary directory** is deliberate: a checked-in copy would be fifteen files
//! that must be re-synced on every WIT edit, and this test reads the canonical tree directly, so
//! drift is impossible rather than merely detected.
//!
//! # Why the second half deliberately breaks the probe
//!
//! Because the first half asserts that a build **succeeds**, and a build that succeeds for the
//! wrong reason — a `deps/` directory `wit-bindgen` never read, a world that resolves to nothing —
//! would pass it. The second half adds one deliberately unparseable interface and asserts the same
//! build **fails**. That is the repository's own rule for a checker: *the valid half is what makes
//! the invalid half mean something.*
//!
//! The injected defect is a missing semicolon rather than `aes-256-gcm`, and the reason is stated
//! rather than left implicit: `aes-256-gcm` is **valid** under the current pin, so it can no longer
//! be used to make a build fail. What the injection proves is that this test's build path reaches
//! the parser; what the *first* half proves is the pin is new enough for the canonical tree. Those
//! are two different claims and they need two different halves.
//!
//! # Ignored by default
//!
//! Because it **compiles a guest**, which needs the `wasm32-wasip2` target and takes tens of
//! seconds. The `rust` CI job runs it with `--ignored`, on all three platforms.
//!
//! # `wasm-tools` must be installed
//!
//! `qqqai inspect` is used to read the artifact's import table, and it is the same prerequisite
//! `qqqai build` declares for a Rust build. The `rust` job installs it.

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

/// The eight bytes a **component** starts with, and what a core module starts with instead.
const COMPONENT_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
const CORE_MODULE_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// The capability the probe imports, and the QQQ capability name `qqqai inspect` must report.
const IMPORTED_INTERFACE: &str = "qqq:crypto/hashing@1.0.0";
const IMPORTED_CAPABILITY: &str = "crypto.hash";

/// The `wit-bindgen` requirement, **read from the one place it is declared**.
///
/// # Why it is read rather than written here
///
/// Because a second copy of a version is a second copy that can drift. `examples/orders-api` is the
/// reference application and the only crate in this repository that pins `wit-bindgen`; the probe
/// is a *measurement instrument* for that pin, so it must not carry an opinion about it.
///
/// A missing or unreadable declaration is a **failure**, not a default: defaulting would make this
/// test measure whatever version it felt like while claiming to measure the project's.
fn wit_bindgen_requirement() -> String {
    let manifest = repo_root()
        .join("examples")
        .join("orders-api")
        .join("Cargo.toml");
    let text = fs::read_to_string(&manifest)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", manifest.display()));

    let needle = "wit-bindgen = { version = \"";
    let start = text.find(needle).unwrap_or_else(|| {
        panic!(
            "{} must pin `wit-bindgen` in the `{needle}` form; the probe reads its version \
                 from there rather than holding a second copy",
            manifest.display()
        )
    }) + needle.len();
    let rest = &text[start..];
    let end = rest.find('"').expect("the version is quoted");
    let version = rest[..end].to_owned();
    assert!(
        !version.is_empty() && version.starts_with(|c: char| c.is_ascii_digit()),
        "the requirement read from {} is not a version: {version:?}",
        manifest.display()
    );
    version
}

/// Every canonical interface, as `(stem, source)`.
///
/// The stem is the file name without `.wit`, and it becomes the `deps/<stem>/<stem>.wit` directory.
/// WIT resolves by the `package` declaration inside the file rather than by the directory name, so
/// the stem is a convention — but it is the convention `check_wit_vendoring.py` and
/// `examples/orders-api/wit/` both use.
fn canonical_interfaces(wit: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = fs::read_dir(wit)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", wit.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|e| e == "wit"))
        .map(|p| {
            let stem = p
                .file_stem()
                .and_then(|s| s.to_str())
                .expect("a UTF-8 file stem")
                .to_owned();
            let source = fs::read_to_string(&p)
                .unwrap_or_else(|e| panic!("{} must be readable: {e}", p.display()));
            (stem, source)
        })
        .collect();
    out.sort();
    out
}

/// The world the probe declares: the app export, plus one **imported capability**.
const WORLD: &str = r"// SPDX-License-Identifier: Apache-2.0
package qqq:bindings-probe@1.0.0;

world bindings-probe {
  export qqq:http/incoming-handler@1.0.0;
  import qqq:crypto/hashing@1.0.0;
}
";

/// The probe's Rust body. It calls the imported capability, so the import cannot be optimised away.
const PROBE_LIB: &str = r#"// SPDX-License-Identifier: Apache-2.0
wit_bindgen::generate!({
    world: "bindings-probe",
    path: "wit",
    generate_all,
});

struct Probe;

impl exports::qqq::http::incoming_handler::Guest for Probe {
    fn handle(
        _request: exports::qqq::http::incoming_handler::Request,
    ) -> Result<
        exports::qqq::http::incoming_handler::Response,
        exports::qqq::http::incoming_handler::HttpError,
    > {
        let body = match qqq::crypto::hashing::digest(
            qqq::crypto::hashing::Algorithm::Sha256,
            b"abc",
        ) {
            Ok(bytes) => bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            Err(_) => "hashing was refused".to_owned(),
        };
        Ok(exports::qqq::http::incoming_handler::Response {
            status: 200,
            headers: Vec::new(),
            body: body.into_bytes(),
        })
    }
}

export!(Probe);
"#;

/// The probe's manifest, with the project's own `wit-bindgen` requirement.
fn probe_manifest(requirement: &str) -> String {
    format!(
        r#"# SPDX-License-Identifier: Apache-2.0
[package]
name = "bindings-probe"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[workspace]

[dependencies]
wit-bindgen = {{ version = "{requirement}", features = ["macros"] }}
"#
    )
}

/// Write the probe, with every canonical interface vendored under `deps/`.
fn write_probe(dir: &Path, interfaces: &[(String, String)], requirement: &str) {
    for (stem, source) in interfaces {
        let dep = dir.join("wit").join("deps").join(stem);
        fs::create_dir_all(&dep).expect("the deps directory");
        // `fs::write` writes the bytes it is given. There is no newline translation here, which is
        // why this is not a `write_text`-shaped hazard (`§O-357`).
        fs::write(dep.join(format!("{stem}.wit")), source).expect("the vendored interface");
    }
    fs::create_dir_all(dir.join("src")).expect("the src directory");
    fs::write(dir.join("wit").join("app.wit"), WORLD).expect("the world");
    fs::write(dir.join("src").join("lib.rs"), PROBE_LIB).expect("the probe body");
    fs::write(dir.join("Cargo.toml"), probe_manifest(requirement)).expect("the probe manifest");
}

/// Build the probe for `wasm32-wasip2`, returning the command's output.
fn build(dir: &Path) -> std::process::Output {
    Command::new("cargo")
        .args(["build", "--release", "--target", "wasm32-wasip2"])
        .current_dir(dir)
        // The probe's own target dir, not the ambient one.
        //
        // The assertion below reads the artifact back from `dir/target/...`. With a
        // globally set `CARGO_TARGET_DIR` (the Linux bridge), cargo writes to the shared
        // root instead and the read fails — measured red with a decoy target dir. Same
        // per-child mechanism as the serve-spawn isolations (`§O-574`, `§O-575`).
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .output()
        .expect("`cargo` must be runnable")
}

/// Read the artifact's import table through the product's own surface, and assert the capability.
///
/// # Why `qqqai inspect` rather than a byte scan
///
/// Because the claim is not "the string `qqq:crypto/hashing` appears somewhere in the file" — it is
/// "**QQQ maps that import to a capability**". `qqqai inspect` is the component that knows the
/// mapping, so asking it is the only version of this assertion that can fail for the right reason.
fn assert_the_artifact_imports_the_capability(dir: &Path) {
    let artifact = dir
        .join("target")
        .join("wasm32-wasip2")
        .join("release")
        .join("bindings_probe.wasm");
    let bytes =
        fs::read(&artifact).unwrap_or_else(|e| panic!("{} must exist: {e}", artifact.display()));
    assert!(
        bytes.len() > 1024,
        "a component is not a stub: {} bytes",
        bytes.len()
    );

    // The assertion that distinguishes a component from a core module. They share `\0asm`.
    let preamble: [u8; 8] = bytes[..8].try_into().expect("at least eight bytes");
    assert_ne!(
        preamble, CORE_MODULE_PREAMBLE,
        "a core module is not a component"
    );
    assert_eq!(
        preamble, COMPONENT_PREAMBLE,
        "the artifact must be a COMPONENT, not a core module: {preamble:02x?}"
    );

    let inspect = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .arg("inspect")
        .arg(&artifact)
        .arg("--json")
        .output()
        .expect("`qqqai inspect` must be runnable");
    let parsed: serde_json::Value = serde_json::from_slice(&inspect.stdout)
        .unwrap_or_else(|e| panic!("`qqqai inspect --json` must emit JSON: {e}"));
    let required = parsed["data"]["required"]
        .as_array()
        .unwrap_or_else(|| panic!("`data.required` must be an array: {parsed}"));

    assert!(
        required
            .iter()
            .any(|r| r["interface"].as_str() == Some(IMPORTED_INTERFACE)),
        "the artifact must import `{IMPORTED_INTERFACE}`; it requires {:?}",
        required
            .iter()
            .filter_map(|r| r["interface"].as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        required
            .iter()
            .any(|r| r["name"].as_str() == Some(IMPORTED_CAPABILITY)),
        "and QQQ must map it to the `{IMPORTED_CAPABILITY}` capability; it requires {:?}",
        required
            .iter()
            .filter_map(|r| r["name"].as_str())
            .collect::<Vec<_>>()
    );
}

/// The second half: prove the build above **can fail**.
///
/// # Why this is not optional
///
/// The first half asserts that a build succeeds, and a build that succeeds for the wrong reason — a
/// `deps/` directory `wit-bindgen` never read, a world that resolves to nothing — would satisfy it.
/// One deliberately unparseable interface is added and the same build must be refused.
fn assert_an_unparseable_interface_is_refused(dir: &Path) {
    let broken = dir.join("wit").join("deps").join("qqq-broken");
    fs::create_dir_all(&broken).expect("the broken deps directory");
    fs::write(
        broken.join("qqq-broken.wit"),
        // A missing semicolon, and nothing else. See the module doc for why the injection is not
        // `aes-256-gcm`: that identifier is VALID under the current pin, so it can no longer make a
        // build fail, and an injection that does not fire is not a measurement.
        "package qqq:broken@1.0.0;\n\ninterface broken {\n  ping: func() -> string\n}\n",
    )
    .expect("the broken interface");

    // # Why the probe's source is touched before rebuilding
    //
    // Measured: with only `wit/deps/qqq-broken/qqq-broken.wit` added, the second build printed
    // `Finished \`release\` profile [optimized] target(s) in 0.13s` and **succeeded**. The macro
    // reads `wit/` while it expands, but `wit/` is not a declared dependency of the crate, so
    // **cargo's fingerprint does not include it and a WIT edit alone does not re-run the macro**.
    //
    // That is worth knowing on its own -- a guest author who edits `wit/` and rebuilds gets a stale
    // artifact -- and it is why the injection changes the *source* as well: the point of this half
    // is to make the parser run again, and adding a file it never looks at cannot.
    let lib = dir.join("src").join("lib.rs");
    let mut body = fs::read_to_string(&lib).expect("the probe body");
    body.push_str("\n// Forces the macro to re-expand: a `wit/` edit alone does not.\n");
    fs::write(&lib, body).expect("the probe body");

    let out = build(dir);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "an unparseable interface in `deps/` must fail the build, or the successful build above \
         proves nothing.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("qqq-broken"),
        "and the failure must NAME the file it refused, so a reader knows which one:\n{stderr}"
    );
}

/// **Every canonical `wit/*.wit` binds with the pinned `wit-bindgen`, and an imported capability
/// reaches the artifact — `LANG-002`.**
#[test]
#[ignore = "compiles a guest; runs in the rust CI job on all three platforms"]
fn every_canonical_interface_binds_and_an_import_reaches_the_artifact() {
    let wit = repo_root().join("wit");

    let interfaces = canonical_interfaces(&wit);
    // Anti-vacuity first: an empty list would make the build below succeed while proving nothing,
    // which is the failure mode this whole test exists to end.
    assert!(
        interfaces.len() >= 10,
        "expected the canonical `wit/` tree, found {} interface file(s)",
        interfaces.len()
    );
    assert!(
        interfaces.iter().any(|(stem, _)| stem == "qqq-crypto"),
        "`wit/qqq-crypto.wit` must be among the canonical interfaces: {:?}",
        interfaces.iter().map(|(s, _)| s).collect::<Vec<_>>()
    );

    let requirement = wit_bindgen_requirement();
    let dir = std::env::temp_dir().join(format!("qqq-lang002-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    write_probe(&dir, &interfaces, &requirement);

    let out = build(&dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "`wit-bindgen` {} must generate bindings for all {} canonical interface(s).\n\
         stdout: {stdout}\nstderr: {stderr}",
        requirement,
        interfaces.len()
    );

    assert_the_artifact_imports_the_capability(&dir);
    assert_an_unparseable_interface_is_refused(&dir);

    let _ = fs::remove_dir_all(&dir);
}
