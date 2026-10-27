// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! `qqq:trace` end to end — `HOST-031` — against the real probe guest.
//!
//! The probe (`examples/iface-probe/guests/trace`) is compiled by the real
//! toolchain through `wit-bindgen`, so resource handles use the true canonical
//! ABI rather than hand-written lowering.

use qqq_cap::manifest::Manifest;
use qqq_cap::resolve::GrantSet;
use qqq_host::{Instance, LimitSet, PreparedComponent};

fn probe_component() -> Option<Vec<u8>> {
    use std::sync::OnceLock;
    static BUILT: OnceLock<bool> = OnceLock::new();
    let workspace =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/iface-probe");
    let artifact = workspace.join("target/wasm32-wasip2/release/probe_trace.wasm");
    if !artifact.is_file() {
        // Built once per test process: concurrent tests share the single
        // build rather than racing cargo against itself.
        let target_present = *BUILT.get_or_init(|| {
            let has_target = std::process::Command::new("rustc")
                .args(["--print", "target-list"])
                .output()
                .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("wasm32-wasip2"));
            if !has_target {
                println!("SKIP: no wasm32-wasip2 target; probe guest cannot build");
                return false;
            }
            // The toolchain is present (checked above), so a build failure
            // is a real breakage, not a missing prerequisite: fail loudly
            // rather than skipping green over a guest that no longer
            // compiles.
            let output = std::process::Command::new("cargo")
                .args([
                    "build",
                    "--release",
                    "--target",
                    "wasm32-wasip2",
                    "--locked",
                ])
                .current_dir(&workspace)
                .output()
                .expect("cargo runs");
            assert!(
                output.status.success(),
                "probe trace guest build failed with the toolchain present: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            true
        });
        if !target_present {
            return None;
        }
    }
    Some(std::fs::read(&artifact).expect("probe component reads"))
}

fn engine() -> wasmtime::Engine {
    let cfg = qqq_host::config::EngineConfig::default()
        .to_wasmtime_config()
        .expect("default engine config builds");
    wasmtime::Engine::new(&cfg).expect("engine builds")
}

fn limits() -> LimitSet {
    LimitSet {
        memory_bytes: 16 * 1024 * 1024,
        fuel: 1_000_000_000,
        epoch_deadline_ms: 10_000,
        max_open_handles: 64,
        max_subrequests: 16,
    }
}

fn manifest() -> Manifest {
    Manifest::parse(
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\
         [capabilities.trace]\n\
         [capabilities.http]\nserver = true\n",
    )
    .expect("probe manifest parses")
}

/// Run the probe and return its summary plus a copy of the recorded logs
/// (trace events mirror there for operator visibility).
fn call_probe(grants: &GrantSet) -> Option<(String, Vec<qqq_host::host_log::LogRecord>)> {
    let bytes = probe_component()?;
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("probe component compiles");
    let instance = Instance::create_with(
        &engine,
        &prepared,
        grants,
        limits(),
        &qqq_host::instance::InstanceOptions::default(),
    )
    .expect("probe must instantiate");
    let mut out: Option<(String, Vec<qqq_host::host_log::LogRecord>)> = None;
    instance
        .run(|mut store, wasm| {
            let (_, interface) = wasm
                .get_export(&mut store, None, "qqq:iface-probe-trace/probe-api@1.0.0")
                .expect("the probe export instance exists");
            let index = wasm
                .get_export_index(&mut store, Some(&interface), "probe-trace")
                .expect("the probe export exists");
            let func = wasm
                .get_typed_func::<(), (String,)>(&mut store, index)
                .expect("the probe export is a lifted function");
            let (summary,) = func.call(&mut store, ()).expect("the probe runs");
            let logs = std::mem::take(&mut store.data_mut().logs);
            out = Some((summary, logs));
            Ok(())
        })
        .expect("the run succeeds");
    out
}

/// A granted guest starts spans, nests them, records events, and propagates
/// the W3C context; the mirrored log carries the trace id.
#[test]
fn granted_guest_traces() {
    let grants = GrantSet::from_manifest(&manifest());
    let Some((summary, logs)) = call_probe(&grants) else {
        return;
    };
    for expected in [
        "tp-start=none",
        "root=ok",
        "tp-root=ok",
        "child=ok",
        "event=ok",
        "attrs=ok",
        "set-error=ok",
    ] {
        assert!(
            summary.contains(expected),
            "the guest must report {expected}: {summary}"
        );
    }
    // Mirrored to the log with trace context: one event plus one error.
    assert!(
        logs.iter().any(|r| r.message.contains("event ev")),
        "the event must be mirrored to the log: {summary}"
    );
    let err = logs
        .iter()
        .find(|r| r.message.contains("boom"))
        .expect("error mirrored");
    assert!(
        err.message.contains("error"),
        "errors are marked: {}",
        err.message
    );
    assert!(err.trace_id.is_some(), "mirrored rows carry the trace id");
}

/// An ungranted guest fails before execution, naming the interface.
#[test]
fn ungranted_guest_fails_closed_by_name() {
    let Some(bytes) = probe_component() else {
        return;
    };
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("probe component compiles");
    let err = Instance::create_with(
        &engine,
        &prepared,
        &GrantSet::empty(),
        limits(),
        &qqq_host::instance::InstanceOptions::default(),
    )
    .expect_err("no grant means no instance");
    let text = format!("{err:?}");
    assert!(
        text.contains("qqq:trace/tracing"),
        "the refusal must name the interface: {text}"
    );
}
