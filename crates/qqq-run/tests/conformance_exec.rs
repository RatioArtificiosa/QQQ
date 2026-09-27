// SPDX-License-Identifier: Apache-2.0

//! `TEST-016` — the conformance suite's **execution** half.
//!
//! # Why the suite needed a second half, and why this file is it
//!
//! `conformance/suite.json` and `tools/check_conformance.py` make three of Proposal §2.4's
//! commitments checkable: that every obligation names the checker enforcing it, that every
//! obligation's checker runs in **both** gates, and that every gap carries an owner and a date.
//! All three are about the *fixture*.
//!
//! What none of them does is **run a case against a built guest**. `TEST-010` says so itself: a
//! matrix of obligations is a **definition**, and `LANG-004` — *"Rust conformance-suite pass"* —
//! cannot be earned from a definition, because there is nothing for a guest to pass. This file is
//! the execution half, and `conformance/suite.json` gained a `kind` field so the two halves are
//! distinguishable in one document rather than two.
//!
//! # Why it drives the CLI rather than calling `qqq-host` directly
//!
//! The subject is **a language's output**, not the host's internals. `qqqai build` is the thing a
//! Rust guest is built by, and `qqqai inspect --json` is the runtime's own reading of the artifact
//! — the same reading `qqqai audit` and `qqqai caps` publish. Asserting on that document means the
//! case is about what the toolchain *produced*, which is what a language conformance case is for.
//! A case that reached into `qqq-host` would be testing the host twice and the guest not at all.
//!
//! # Why the build is invoked rather than `plan`ed
//!
//! Because a plan is an **intention**. `build::plan_pure` is already tested for its arguments; what
//! is untested is that the toolchain turns those arguments into an artifact a case can run against.
//!
//! # The two tests here, and why the fast one is not decoration
//!
//! [`every_execution_case_is_implemented_here`] runs **everywhere**, in milliseconds, and fails when
//! `conformance/suite.json` declares an execution case this file does not implement. Without it the
//! suite and the runner drift: a case is added to the fixture, nothing runs it, and the fixture
//! reports an obligation that is enforced by nobody — the exact shape `tools/check_conformance.py`
//! exists to prevent for the *definition* half, and which the execution half would otherwise
//! reintroduce one level down.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/<name> has a repository root")
        .to_path_buf()
}

/// The `kind` a case carries when it is run rather than merely defined.
const EXECUTION: &str = "execution";

/// One conformance case, reduced to what the runner needs.
#[derive(Debug, Clone)]
struct Case {
    id: String,
    kind: String,
    summary: String,
}

/// Every case in the fixture, in document order.
///
/// # Why this reads `kind` with a default rather than requiring it
///
/// The six original cases predate the field and are definition cases. Defaulting to `definition`
/// means adding `kind` was not a breaking edit to a document three gates already read — and the
/// default is the *safe* one: a case with no `kind` is not run by this file, so a forgotten field
/// cannot silently become an unexecuted obligation reported as executed.
fn cases() -> Vec<Case> {
    let path = repo_root().join("conformance").join("suite.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{} must be valid JSON: {e}", path.display()));

    let list = doc
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("{} must carry a `cases` array", path.display()));

    list.iter()
        .map(|c| Case {
            id: c
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            kind: c
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("definition")
                .to_owned(),
            summary: c
                .get("summary")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        })
        .collect()
}

/// The ids this file implements. A case in the fixture and absent here is a **defect**, not a
/// skip: see the module docs.
const IMPLEMENTED: [&str; 2] = ["component-layer", "qqq-imports-all-mapped"];

/// **The drift guard.** Runs everywhere, in milliseconds.
///
/// A fixture that declares an execution case nothing runs is the same defect as a checker no gate
/// invokes, one level down: an obligation reported and enforced by nobody.
#[test]
fn every_execution_case_is_implemented_here() {
    let execution: Vec<Case> = cases()
        .into_iter()
        .filter(|c| c.kind == EXECUTION)
        .collect();

    assert!(
        !execution.is_empty(),
        "the fixture declares no execution case at all, so `TEST-016` is unmeasured"
    );

    for case in &execution {
        assert!(
            IMPLEMENTED.contains(&case.id.as_str()),
            "`conformance/suite.json` declares execution case `{}` ({}), which this runner does \
             not implement. An obligation nothing runs is enforced by nobody",
            case.id,
            case.summary
        );
    }

    // And the converse: an id implemented here that the fixture dropped is dead code claiming to
    // satisfy a case that no longer exists.
    for id in IMPLEMENTED {
        assert!(
            execution.iter().any(|c| c.id == id),
            "this runner implements `{id}`, which the fixture no longer declares"
        );
    }
}

/// **`TEST-016` — every execution case, run against the built Rust guest.**
#[test]
#[ignore = "compiles a guest; runs in the rust CI job on all three platforms"]
fn every_execution_case_passes_against_the_rust_guest() {
    let root = repo_root();
    let guest = root.join("examples").join("orders-api");
    assert!(
        guest.join("qqq.toml").is_file(),
        "the reference guest must exist: {}",
        guest.display()
    );

    // **A separate target directory**, so this build cannot contend with the workspace's own cargo
    // invocation for the package-cache lock.
    let out = guest.join("target").join("qqq");
    let _ = std::fs::remove_dir_all(&out);

    let built = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .arg("build")
        .current_dir(&guest)
        .output()
        .expect("`qqqai build` must be runnable");
    assert!(
        built.status.success(),
        "the build must succeed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );

    let artifact = out.join("orders-api.component.wasm");
    let inspected = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .args(["inspect", "--json"])
        .arg(&artifact)
        .current_dir(&root)
        .output()
        .expect("`qqqai inspect` must be runnable");
    assert!(
        inspected.status.success(),
        "`qqqai inspect` must read the artifact it was just handed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&inspected.stdout),
        String::from_utf8_lossy(&inspected.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&inspected.stdout)
        .expect("`inspect --json` emits one JSON document");

    let mut failures: Vec<String> = Vec::new();
    let execution: Vec<Case> = cases()
        .into_iter()
        .filter(|c| c.kind == EXECUTION)
        .collect();

    // **A vacuity guard, and it is not redundant with the drift test.** The two run separately --
    // this one only under `--ignored`, in the `rust` CI job -- so a fixture that lost its execution
    // cases would leave this test passing over an empty loop and reporting a green `TEST-016`.
    // A loop over nothing asserts nothing (`§O-280`).
    assert!(
        !execution.is_empty(),
        "the fixture declares no execution case, so this test would pass over an empty loop"
    );

    for case in &execution {
        if let Err(why) = run_case(&case.id, &report) {
            failures.push(format!("  {} ({}) -- {why}", case.id, case.summary));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of the fixture's execution cases failed against the Rust guest:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Run one case against the runtime's own reading of the artifact.
///
/// An unknown id is an **error**, not a pass: this is the function that would otherwise turn the
/// drift guard into a formality.
fn run_case(id: &str, report: &serde_json::Value) -> Result<(), String> {
    let data = report
        .get("data")
        .ok_or_else(|| "the report carries no `data`".to_owned())?;

    match id {
        // The eight-byte preamble says component rather than core module. `LANG-001` asserts this
        // on the bytes; the case asserts it through the runtime's own classification, so the
        // *fixture* carries the obligation rather than one test's private knowledge.
        "component-layer" => {
            let kind = data
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if kind == "component" {
                Ok(())
            } else {
                Err(format!(
                    "the runtime classified the artifact as `{kind}`, not `component`"
                ))
            }
        }

        // Every `qqq:` interface a guest imports must map to a capability. An unmapped one is a
        // guest reaching for something the capability model does not name — which is a hole in the
        // model, not a property of the guest, and exactly what this suite exists to make visible.
        "qqq-imports-all-mapped" => {
            let unmapped = data
                .get("unmapped_interfaces")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            let holes: Vec<String> = unmapped
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|i| i.starts_with("qqq:"))
                .map(str::to_owned)
                .collect();
            if holes.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "the guest imports {} `qqq:` interface(s) no capability describes: {}",
                    holes.len(),
                    holes.join(", ")
                ))
            }
        }

        other => Err(format!("no check is implemented for case `{other}`")),
    }
}
