// SPDX-License-Identifier: Apache-2.0

//! `LANG-005` — the Rust reference application, and the one claim in it that was false.
//!
//! # What was measured
//!
//! `examples/orders-api/qqq.toml` said:
//!
//! > *"every stanza below is load-bearing, and a reader can check that claim by deleting one and
//! > watching a route fail."*
//!
//! It was false for two of the three capability stanzas:
//!
//! ```text
//! $ qqqai caps --manifest examples/orders-api/qqq.toml --json
//! data.grants = ["clock.monotonic", "http.server", "crypto.hash"]     3 GRANTED
//!
//! $ qqqai inspect examples/orders-api/target/qqq/orders-api.component.wasm
//! required capabilities: http.server                                  1 IMPORTED
//! ```
//!
//! `crypto.hash` was declared for a SHA-256 the app implements **in-tree**, and `clock.monotonic`
//! for a clock no workload reads. **An inert grant is an over-grant**: this runtime's model is
//! *absent, not denied*, so a capability a guest cannot exercise is one it should not hold — and the
//! reference application cannot be the one place that grants more than it uses.
//!
//! # What this test asserts
//!
//! That the manifest's declared capabilities and the artifact's required capabilities are the
//! **same set**, in both directions:
//!
//! * an import with no grant is a guest reaching past the capability model, and
//! * a grant with no import is a capability granted for nothing.
//!
//! Both are read through the product's own surface — `qqqai caps --json` and `qqqai inspect --json`
//! — so the assertion is about what QQQ resolves, not about what the TOML appears to say.
//!
//! # Why the equality is the right assertion *here*
//!
//! For a general application, granting a capability whose code path is not yet written is
//! legitimate. For the **reference** application it is not, because `qqq.toml` makes exactly the
//! stronger claim and because the app is what a reader copies. The comment in that file now says so,
//! and this test is what makes it true.
//!
//! # Ignored by default
//!
//! Because it **builds a guest**. The `rust` CI job runs it with `--ignored`, on all three
//! platforms, and `wasm-tools` is its prerequisite — `qqqai build` needs it.

use std::collections::BTreeSet;
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

/// Run `qqqai` with `args` and parse its JSON envelope.
fn qqq_json(args: &[&str]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("`qqqai {}` must be runnable: {e}", args.join(" ")));
    assert!(
        out.status.success(),
        "`qqqai {}` must succeed.\nstdout: {}\nstderr: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("`qqqai {} --json` must emit JSON: {e}", args.join(" ")))
}

/// The names in one JSON array field, sorted and deduplicated.
fn names(value: &serde_json::Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected an array, got {value}"))
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

/// **The Rust reference application grants exactly what it imports — `LANG-005`.**
#[test]
#[ignore = "builds a guest; runs in the rust CI job on all three platforms"]
fn the_reference_application_grants_exactly_what_it_imports() {
    let root = repo_root();
    let app = root.join("examples").join("orders-api");
    assert!(
        app.join("qqq.toml").is_file(),
        "the Rust reference application must exist: {}",
        app.display()
    );

    // --- the artifact, built by the product's own command --------------------
    let built = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .arg("build")
        .current_dir(&app)
        .output()
        .expect("`qqqai build` must be runnable");
    assert!(
        built.status.success(),
        "the reference application must build.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );

    let artifact = app
        .join("target")
        .join("qqq")
        .join("orders-api.component.wasm");
    assert!(artifact.is_file(), "{} must exist", artifact.display());

    // --- GRANTED, from the manifest -----------------------------------------
    let manifest = app.join("qqq.toml");
    let granted = names(
        &qqq_json(&["caps", "--manifest", &manifest.to_string_lossy(), "--json"])["data"]["grants"],
    );

    // --- IMPORTED, from the artifact ----------------------------------------
    //
    // `data.required` is an array of **objects** (`{interface, name}`), so the capability names are
    // one level down. `data.grants` is a plain array of strings.
    let inspected = qqq_json(&["inspect", &artifact.to_string_lossy(), "--json"]);
    let imported: BTreeSet<String> = inspected["data"]["required"]
        .as_array()
        .unwrap_or_else(|| panic!("`data.required` must be an array: {inspected}"))
        .iter()
        .filter_map(|r| r["name"].as_str().map(str::to_owned))
        .collect();
    assert!(
        !imported.is_empty(),
        "the artifact must import at least one capability, or this test measures nothing"
    );

    // --- and they must be the same set --------------------------------------
    let ungranted: Vec<&String> = imported.difference(&granted).collect();
    let inert: Vec<&String> = granted.difference(&imported).collect();

    assert!(
        ungranted.is_empty(),
        "the artifact imports {ungranted:?}, which the manifest does not grant. A guest reaching \
         past its grant set is the failure the capability model exists to prevent.\n\
         granted:  {granted:?}\nimported: {imported:?}"
    );
    assert!(
        inert.is_empty(),
        "the manifest grants {inert:?}, which the artifact does not import. **An inert grant is an \
         over-grant** — this runtime is *absent, not denied*, so a capability the guest cannot \
         exercise is one it should not hold.\n\
         granted:  {granted:?}\nimported: {imported:?}"
    );
}
