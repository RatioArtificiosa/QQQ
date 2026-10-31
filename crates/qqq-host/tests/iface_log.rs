// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! `qqq:log` end to end — `HOST-030` — against the real probe guest.
//!
//! The probe (`examples/iface-probe/guests/log`) is compiled by the real
//! toolchain through `wit-bindgen`, so its calls use the true canonical ABI.
//! Redaction is host-observable only: the guest reports what it sent, and the
//! test reads what the store kept.

use qqq_cap::manifest::Manifest;
use qqq_cap::resolve::GrantSet;
use qqq_host::{Instance, LimitSet, PreparedComponent};

fn probe_component() -> Option<Vec<u8>> {
    use std::sync::OnceLock;
    // Built once per test process and cached as bytes: concurrent tests
    // share one build, and every run rebuilds — a stale artifact from an
    // edited guest can never pass silently, because no presence check
    // short-circuits the build. Cargo itself no-ops when fresh.
    static ARTIFACT: OnceLock<Option<Vec<u8>>> = OnceLock::new();
    ARTIFACT
        .get_or_init(|| {
            let workspace =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/iface-probe");
            let has_target = std::process::Command::new("rustc")
                .args(["--print", "target-list"])
                .output()
                .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("wasm32-wasip2"));
            if !has_target {
                println!("SKIP: no wasm32-wasip2 target; probe guest cannot build");
                return None;
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
                "probe log guest build failed with the toolchain present: {} (on a cold cargo cache this is the probe workspace's uncached dependencies, not the guest: warm once with `cargo fetch --manifest-path examples/iface-probe/Cargo.toml`)",
                String::from_utf8_lossy(&output.stderr)
            );
            let artifact = workspace.join("target/wasm32-wasip2/release/probe_log.wasm");
            Some(std::fs::read(&artifact).expect("probe component reads"))
        })
        .clone()
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
         [capabilities.log]\n\
         [capabilities.secret]\nsecrets = [\"env:LEAK\"]\n\
         [capabilities.crypto]\nsign = [\"ed25519\"]\n\
         [capabilities.http]\nserver = true\n",
    )
    .expect("probe manifest parses")
}

fn material() -> qqq_host::host_secrets::SecretStore {
    use qqq_host::host_secrets::{PermittedOp, SecretMaterial, SecretStore};
    // Named LEAK like the granted ref, valued exactly like the guest's
    // literal: redaction matches values, and the test must prove the
    // store's copy is what triggers, not the name.
    SecretStore::with_grants(
        vec!["LEAK".to_owned()],
        vec![SecretMaterial::new(
            "LEAK".to_owned(),
            b"test-only-leak-value-4f6d".to_vec(),
            PermittedOp::all().to_vec(),
        )],
    )
}

/// Run the probe and return its summary plus a copy of the recorded logs.
fn call_probe(grants: &GrantSet) -> Option<(String, Vec<qqq_host::host_log::LogRecord>)> {
    let bytes = probe_component()?;
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("probe component compiles");
    let opts = qqq_host::instance::InstanceOptions {
        secrets: material(),
        ..Default::default()
    };
    let instance = Instance::create_with(&engine, &prepared, grants, limits(), &opts)
        .expect("probe must instantiate");
    let mut out: Option<(String, Vec<qqq_host::host_log::LogRecord>)> = None;
    instance
        .run(|mut store, wasm| {
            let (_, interface) = wasm
                .get_export(&mut store, None, "qqq:iface-probe-log/probe-api@1.0.0")
                .expect("the probe export instance exists");
            let index = wasm
                .get_export_index(&mut store, Some(&interface), "probe-log")
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

/// A granted guest emits, batches, and is bounded; secrets redact in storage.
#[test]
fn granted_guest_logs_and_redacts() {
    let grants = GrantSet::from_manifest(&manifest());
    let Some((summary, logs)) = call_probe(&grants) else {
        return;
    };
    for expected in [
        "emit=ok",
        "emit-secret=ok",
        "emit-many=ok",
        "emit-big=err:record-too-large",
        "emit-attrs=err:record-too-large",
        "enabled-trace=true",
        "enabled-error=true",
    ] {
        assert!(
            summary.contains(expected),
            "the guest must report {expected}: {summary}"
        );
    }
    // The summary says `ok`; the STORE must hold the redacted form.
    let secret = logs
        .iter()
        .find(|r| r.message.contains("redacted") || r.message.contains("test-only"));
    let Some(redacted) = secret else {
        panic!("a redacted record must exist: {summary}");
    };
    assert_eq!(redacted.message, "[redacted:secret]");
    assert!(redacted.redacted, "the flag travels with the record");
    // Ordinary records pass through verbatim.
    let hello = logs
        .iter()
        .find(|r| r.message == "hello")
        .expect("hello logged");
    assert!(!hello.redacted);
    assert_eq!(hello.attributes.len(), 4, "all four attribute kinds kept");
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
        text.contains("qqq:log/logging"),
        "the refusal must name the interface: {text}"
    );
}
