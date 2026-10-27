// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! `qqq:env` end to end — `HOST-029` — against the real probe guest.
//!
//! The probe (`examples/iface-probe/guests/env`) is compiled by the real
//! toolchain through `wit-bindgen`, so its imports use the true canonical
//! ABI. Absent component: skip with a reason; the gate builds it.

use std::collections::BTreeMap;

use qqq_cap::manifest::Manifest;
use qqq_cap::resolve::GrantSet;
use qqq_host::{Instance, LimitSet, PreparedComponent};

fn probe_component() -> Option<Vec<u8>> {
    use std::sync::OnceLock;
    static BUILT: OnceLock<bool> = OnceLock::new();
    let workspace =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/iface-probe");
    let artifact = workspace.join("target/wasm32-wasip2/release/probe_env.wasm");
    if !artifact.is_file() {
        let ok = *BUILT.get_or_init(|| {
            let has_target = std::process::Command::new("rustc")
                .args(["--print", "target-list"])
                .output()
                .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("wasm32-wasip2"));
            if !has_target {
                println!("SKIP: no wasm32-wasip2 target; probe guest cannot build");
                return false;
            }
            std::process::Command::new("cargo")
                .args([
                    "build",
                    "--release",
                    "--target",
                    "wasm32-wasip2",
                    "--locked",
                ])
                .current_dir(&workspace)
                .output()
                .is_ok_and(|o| o.status.success())
        });
        if !ok {
            println!("SKIP: probe guest build failed");
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
         [capabilities.env]\nallow = [\"REGION\", \"MISSING\", \"BINARY\"]\n\
         [capabilities.http]\nserver = true\n",
    )
    .expect("probe manifest parses")
}

/// REGION set, BINARY invalid UTF-8, MISSING listed-but-unset.
fn values() -> BTreeMap<String, Option<Vec<u8>>> {
    BTreeMap::from([
        ("REGION".to_owned(), Some(b"us-east-1".to_vec())),
        ("MISSING".to_owned(), None),
        ("BINARY".to_owned(), Some(vec![0xff, 0xfe])),
    ])
}

fn call_probe(grants: &GrantSet, env: BTreeMap<String, Option<Vec<u8>>>) -> Option<String> {
    let bytes = probe_component()?;
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("probe component compiles");
    let opts = qqq_host::instance::InstanceOptions {
        env,
        ..Default::default()
    };
    let instance = Instance::create_with(&engine, &prepared, grants, limits(), &opts)
        .expect("probe must instantiate");
    let mut slot: Option<String> = None;
    instance
        .run(|mut store, wasm| {
            let (_, interface) = wasm
                .get_export(&mut store, None, "qqq:iface-probe-env/probe-api@1.0.0")
                .expect("the probe export instance exists");
            let index = wasm
                .get_export_index(&mut store, Some(&interface), "probe-env")
                .expect("the probe export exists");
            let func = wasm
                .get_typed_func::<(), (String,)>(&mut store, index)
                .expect("the probe export is a lifted function");
            let (out,) = func.call(&mut store, ()).expect("the probe runs");
            slot = Some(out);
            Ok(())
        })
        .expect("the run succeeds");
    slot
}

/// A granted guest reads allowed names, observes unset, and cannot probe
/// unlisted names; invalid UTF-8 is named, not lossy.
#[test]
fn granted_guest_reads_allowlist() {
    let grants = GrantSet::from_manifest(&manifest());
    let Some(summary) = call_probe(&grants, values()) else {
        return;
    };
    for expected in [
        "get-region=ok:us-east-1",
        "get-missing=err:unset",
        "get-unlisted=err:not-allowed",
        "get-or-missing=ok:fallback",
        "get-or-unlisted=err:not-allowed",
        "get-binary=err:invalid-utf8",
        "allowed=BINARY,MISSING,REGION",
    ] {
        assert!(
            summary.contains(expected),
            "scenario must report {expected}: {summary}"
        );
    }
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
    .expect_err("no grant must fail");
    let text = format!("{err:?}");
    assert!(
        text.contains("qqq:env"),
        "the refusal must name the interface: {text}"
    );
}
