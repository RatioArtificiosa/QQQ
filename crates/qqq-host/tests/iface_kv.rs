// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! `qqq:kv` end to end — `HOST-032` — against the real probe guest.
//!
//! The probe (`examples/iface-probe/guests/kv`) is compiled by the real
//! toolchain through `wit-bindgen`, so its calls use the true canonical ABI.
//! Cross-call visibility is host-observable: the guest reports what each
//! call returned, and the backend is shared the way `serve` shares it.

use std::sync::Arc;

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
                "probe kv guest build failed with the toolchain present: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let artifact = workspace.join("target/wasm32-wasip2/release/probe_kv.wasm");
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
         [capabilities.kv]\nstores = [\"s\"]\nwrite = true\n\
         [capabilities.http]\nserver = true\n",
    )
    .expect("probe manifest parses")
}

fn kv_view() -> qqq_host::host_kv::KvView {
    qqq_host::host_kv::KvView::new(
        Arc::new(qqq_host::host_kv::KvConfig::new(vec!["s".to_owned()], true)),
        Arc::new(std::sync::Mutex::new(qqq_host::host_kv::KvBackend::new())),
    )
}

/// Run the probe and return its summary.
fn call_probe(grants: &GrantSet) -> Option<String> {
    let bytes = probe_component()?;
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("probe component compiles");
    let opts = qqq_host::instance::InstanceOptions {
        kv: kv_view(),
        ..Default::default()
    };
    let instance = Instance::create_with(&engine, &prepared, grants, limits(), &opts)
        .expect("probe must instantiate");
    let mut out: Option<String> = None;
    instance
        .run(|mut store, wasm| {
            let (_, interface) = wasm
                .get_export(&mut store, None, "qqq:iface-probe-kv/probe-api@1.0.0")
                .expect("the probe export instance exists");
            let index = wasm
                .get_export_index(&mut store, Some(&interface), "probe-kv")
                .expect("the probe export exists");
            let func = wasm
                .get_typed_func::<(), (String,)>(&mut store, index)
                .expect("the probe export is a lifted function");
            let (summary,) = func.call(&mut store, ()).expect("the probe runs");
            out = Some(summary);
            Ok(())
        })
        .expect("the run succeeds");
    out
}

/// A granted guest reads its writes, lists in order, batches, and is
/// bounded; unconfigured stores and oversize values fail by name.
#[test]
fn granted_guest_stores_and_loads() {
    let grants = GrantSet::from_manifest(&manifest());
    let Some(summary) = call_probe(&grants) else {
        return;
    };
    for expected in [
        "set=ok",
        "get=ok:hello",
        "get-missing=ok:none",
        "exists=true",
        "exists-missing=false",
        "keys=ok:a,b",
        "ttl=ok:v",
        "get-many=ok:2",
        "delete=ok",
        "get-after-delete=ok:none",
        "stores=s",
        "unlisted=err:store-not-configured",
        "big-value=err:entry-too-large",
        "big-key=err:entry-too-large",
    ] {
        assert!(
            summary.contains(expected),
            "the guest must report {expected}: {summary}"
        );
    }
}

/// A read-only guest reads but never writes, by name.
#[test]
fn read_only_guest_is_refused_writes_by_name() {
    let manifest = Manifest::parse(
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\
         [capabilities.kv]\nstores = [\"s\"]\n\
         [capabilities.http]\nserver = true\n",
    )
    .expect("probe manifest parses");
    let grants = GrantSet::from_manifest(&manifest);
    let Some(summary) = call_probe(&grants) else {
        return;
    };
    assert!(
        summary.contains("set-a=err:read-only"),
        "a read-only store refuses writes by name: {summary}"
    );
    assert!(
        summary.contains("set=err:read-only"),
        "every write in the scenario refuses the same way: {summary}"
    );
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
        text.contains("qqq:kv/store"),
        "the refusal must name the interface: {text}"
    );
}
