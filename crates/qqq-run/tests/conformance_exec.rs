// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

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
    /// A committed fixture guest this case runs against instead of the
    /// reference application, relative to the repository root.
    ///
    /// The default guest is the built reference app — right for language
    /// conformance, wrong for the dual-ABI cases: no toolchain emits 0.3
    /// (every LANG-041..045 verdict is BLOCKED), so the 0.3 guest is a
    /// committed fixture built from committed WAT. A case that needs a 0.3
    /// guest and does not name one silently runs against the 0.2 reference
    /// app and passes vacuously — the defect this field exists to prevent.
    guest: Option<String>,
    /// **The assertion, read from the fixture rather than hard-coded here.** An execution case used
    /// to mean whatever a `match id` in this file said it meant, so every other consumer of the
    /// suite would have had to re-derive it -- and two derivations of one fact can disagree while
    /// both look authoritative. `TEST-016` asks for the runner to be *"an independently usable
    /// tool"*, and a tool cannot reuse an assertion that lives inside a test.
    assertion: serde_json::Value,
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
            guest: c
                .get("guest")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            assertion: c.get("assert").cloned().unwrap_or(serde_json::Value::Null),
        })
        .collect()
}

/// The ids this file implements. A case in the fixture and absent here is a **defect**, not a
/// skip: see the module docs.
const IMPLEMENTED: [&str; 4] = [
    "component-layer",
    "qqq-imports-all-mapped",
    "dual-abi-03-clock-required",
    "dual-abi-03-unserved-reported",
];

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

/// **`TEST-016` — every execution case, run against its guest.**
///
/// Cases without their own `guest` run against the reference application,
/// built here by the product's own command. Cases naming a fixture guest
/// (the dual-ABI 0.3 cases — no toolchain emits 0.3, so the guest is
/// committed) run against that file instead, inspected by the same binary
/// through the same report shape. One runner, one report contract, no
/// per-case special handling beyond resolving which artifact to read.
#[test]
#[ignore = "compiles a guest; runs in the rust CI job on all three platforms"]
fn every_execution_case_passes() {
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

    let reference = out.join("orders-api.component.wasm");

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
        let artifact = match &case.guest {
            Some(g) => {
                let path = root.join(g);
                assert!(
                    path.is_file(),
                    "case `{}` names fixture guest `{g}`, which does not exist",
                    case.id
                );
                path
            }
            None => reference.clone(),
        };
        let inspected = Command::new(env!("CARGO_BIN_EXE_qqqai"))
            .args(["inspect", "--json"])
            .arg(&artifact)
            .current_dir(&root)
            .output()
            .expect("`qqqai inspect` must be runnable");
        assert!(
            inspected.status.success(),
            "`qqqai inspect` must read the artifact it was just handed ({}).\nstdout: {}\nstderr: {}",
            artifact.display(),
            String::from_utf8_lossy(&inspected.stdout),
            String::from_utf8_lossy(&inspected.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&inspected.stdout)
            .expect("`inspect --json` emits one JSON document");
        if let Err(why) = run_case(case, &report) {
            failures.push(format!(
                "  {} ({}) on {} -- {why}",
                case.id,
                case.summary,
                artifact.display()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of the fixture's execution cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Run one case against the runtime's own reading of the artifact.
///
/// # Why this dispatches on the FIXTURE rather than on the case's id
///
/// Because `TEST-016` wants the runner to be *"an independently usable tool"*, and a tool cannot
/// reuse an assertion that is a `match id` arm inside a test file. The vocabulary is declared in
/// `conformance/suite.json`; every consumer reads the same statement, so they cannot drift.
///
/// An unknown assertion is an **error**, not a pass: this is the function that would otherwise turn
/// the drift guard into a formality.
///
/// The 0.3 assertions live in helpers rather than inline arms so this dispatch
/// stays readable as the vocabulary grows: each new interface set adds arms,
/// and a 100-line match is where new arms stop being reviewed.
fn run_case(case: &Case, report: &serde_json::Value) -> Result<(), String> {
    let data = report
        .get("data")
        .ok_or_else(|| "the report carries no `data`".to_owned())?;

    let assertion = &case.assertion;
    let id = assertion
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            format!(
                "case `{}` declares no `assert.kind`, so this runner would have to guess what it \
                 means -- which is the defect the declarative form removes",
                case.id
            )
        })?;

    match id {
        // The eight-byte preamble says component rather than core module. `LANG-001` asserts this
        // on the bytes; the case asserts it through the runtime's own classification, so the
        // *fixture* carries the obligation rather than one test's private knowledge.
        "runtime-classification-is" => {
            let want = assertion
                .get("value")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "`runtime-classification-is` needs a `value`".to_owned())?;
            let kind = data
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if kind == want {
                Ok(())
            } else {
                Err(format!(
                    "the runtime classified the artifact as `{kind}`, not `{want}`"
                ))
            }
        }

        // Every `qqq:` interface a guest imports must map to a capability. An unmapped one is a
        // guest reaching for something the capability model does not name — which is a hole in the
        // model, not a property of the guest, and exactly what this suite exists to make visible.
        "no-unmapped-qqq-interfaces" => {
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

        // A 0.3 clock import resolves to clock.monotonic (**CON-019**). The 0.2 twin is served
        // and reported the same way; matching on the `0.3.` revision prefix (not the exact
        // version) is what keeps a patch release from silently dropping out of the report —
        // the same rule `AbiVersion::detect` routes by.
        "wasi03-clock-required" => check_wasi03_clock_required(data),

        // Unserved 0.3 imports are reported, never claimed and never dropped (**CON-019**).
        //
        // See `check_wasi03_unserved_reported`: the fixture declares the names it expects,
        // an entry that vanishes is the defect, and an empty `value` is an error.
        "wasi03-unserved-reported" => check_wasi03_unserved_reported(case, assertion, data),

        other => Err(format!(
            "no check is implemented for the assertion `{other}`; the vocabulary is declared in `conformance/suite.json`"
        )),
    }
}

/// The committed 0.3 fixture bytes declare exactly the imports its WAT source does.
///
/// The `.wasm` is what both runners execute against; the `.wat` is what a human
/// reviews. If either drifts — a hand-edited binary, a fixture edit without a
/// rebuild — the suite would assert against imports nobody wrote (or miss ones
/// somebody did), which is the defect committed binaries are notorious for.
/// Compared as import sets rather than bytes, so an encoder upgrade that
/// reorders bytes cannot fail this for the wrong reason.
///
/// The set itself is pinned exactly, not as a subset: an extra import would be
/// an unreviewed authority in the fixture, and a missing one would leave a
/// case asserting over imports that are not there.
#[test]
fn fixture_wat_and_bytes_agree_on_imports() {
    let root = repo_root();
    let wat_path = root
        .join("conformance")
        .join("fixtures")
        .join("wasi03-clock.component.wat");
    let wasm_path = wat_path.with_extension("wasm");
    let wat = std::fs::read_to_string(&wat_path)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", wat_path.display()));
    let from_wat =
        wat::parse_str(&wat).unwrap_or_else(|e| panic!("the fixture WAT must assemble: {e}"));
    let committed = std::fs::read(&wasm_path)
        .unwrap_or_else(|e| panic!("{} must exist: {e}", wasm_path.display()));

    let mut engine_config = wasmtime::Config::new();
    engine_config.wasm_component_model(true);
    let engine = wasmtime::Engine::new(&engine_config).expect("engine builds");

    let mut from_wat_names: Vec<String> = wasmtime::component::Component::new(&engine, &from_wat)
        .expect("assembled fixture must parse")
        .component_type()
        .imports(&engine)
        .map(|(name, _ty)| name.to_owned())
        .collect();
    from_wat_names.sort();
    from_wat_names.dedup();
    let mut committed_names: Vec<String> = wasmtime::component::Component::new(&engine, &committed)
        .expect("committed fixture must parse")
        .component_type()
        .imports(&engine)
        .map(|(name, _ty)| name.to_owned())
        .collect();
    committed_names.sort();
    committed_names.dedup();

    assert_eq!(
        from_wat_names, committed_names,
        "fixture source and bytes disagree on imports"
    );
    assert_eq!(
        committed_names,
        vec![
            "wasi:clocks/monotonic-clock@0.3.2",
            "wasi:http/incoming-handler@0.3.2",
        ],
        "the fixture must declare exactly the served clock and one unserved 0.3 name: {committed_names:?}"
    );
}

/// A 0.3 clock import resolves to clock.monotonic (**CON-019**).
///
/// Matching on the `0.3.` revision prefix (not the exact version) is what keeps
/// a patch release from silently dropping out of the report — the same rule
/// `AbiVersion::detect` routes by. The 0.2 twin is served and reported the same
/// way, so this arm says nothing about 0.2 names by design.
fn check_wasi03_clock_required(data: &serde_json::Value) -> Result<(), String> {
    let required: Vec<serde_json::Value> = data
        .get("required")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let found = required.iter().any(|r| {
        r.get("name").and_then(serde_json::Value::as_str) == Some("clock.monotonic")
            && r.get("interface")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|i| i.starts_with("wasi:clocks/monotonic-clock@0.3."))
    });
    if found {
        Ok(())
    } else {
        Err(format!(
            "no required clock.monotonic from a wasi:clocks/monotonic-clock@0.3.x import: {data}"
        ))
    }
}

/// Unserved 0.3 imports are reported as unmapped, never claimed and never dropped (**CON-019**).
///
/// The fixture declares the names it expects under `unmapped_interfaces` in `value`:
/// an entry that vanishes from the report entirely is the defect this case exists to
/// catch (a surface the auditor cannot see), while an entry that moves to `required`
/// would claim an authority the host cannot provide. An empty `value` list is an
/// error here, not a pass — a case that asserts nothing over an empty loop proves
/// nothing (§O-280).
#[allow(
    clippy::needless_pass_by_value,
    reason = "matches run_case arm shape; the caller holds the owned report"
)]
fn check_wasi03_unserved_reported(
    case: &Case,
    assertion: &serde_json::Value,
    data: &serde_json::Value,
) -> Result<(), String> {
    let want: Vec<String> = assertion
        .get("value")
        .and_then(serde_json::Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if want.is_empty() {
        return Err(format!(
            "case `{}` declares no `value`, so there is nothing to check",
            case.id
        ));
    }
    let unmapped: Vec<String> = data
        .get("unmapped_interfaces")
        .and_then(serde_json::Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let missing: Vec<String> = want
        .into_iter()
        .filter(|w| !unmapped.iter().any(|u| u == w))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "these 0.3 imports are neither required nor reported as unmapped: {}",
            missing.join(", ")
        ))
    }
}
