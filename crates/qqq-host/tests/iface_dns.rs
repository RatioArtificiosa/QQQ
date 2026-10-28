// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! `qqq:dns` end to end — `HOST-035` — against the real probe guest.
//!
//! The probe (`examples/iface-probe/guests/dns`) is compiled by the real
//! toolchain through `wit-bindgen`, so its calls use the true canonical ABI.
//! The resolver behind the instance is the static table, so no test touches
//! the network: the boundary under test is guest → host → grant check →
//! resolver, and the resolver half is pinned hermetically.

use std::collections::BTreeMap;
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
                "probe dns guest build failed with the toolchain present: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let artifact = workspace.join("target/wasm32-wasip2/release/probe_dns.wasm");
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
         [capabilities.dns]\nresolve = [\"api.example.com\", \"missing.example.com\"]\n\
         [capabilities.http]\nserver = true\n",
    )
    .expect("probe manifest parses")
}

fn dns_view() -> qqq_host::host_dns::DnsView {
    use std::net::IpAddr;
    let mut records: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    records.insert(
        "api.example.com".to_owned(),
        vec![
            "192.0.2.10".parse().expect("fixture parses"),
            "2001:db8::10".parse().expect("fixture parses"),
        ],
    );
    qqq_host::host_dns::DnsView::new(
        Arc::new(qqq_host::host_dns::DnsConfig::new(vec![
            "api.example.com".to_owned(),
            "missing.example.com".to_owned(),
        ])),
        Arc::new(qqq_host::host_dns::StaticResolver::new(records)),
    )
}

/// Run the probe and return its summary.
fn call_probe(grants: &GrantSet) -> Option<String> {
    let bytes = probe_component()?;
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("probe component compiles");
    let opts = qqq_host::instance::InstanceOptions {
        dns: dns_view(),
        ..Default::default()
    };
    let instance = Instance::create_with(&engine, &prepared, grants, limits(), &opts)
        .expect("probe must instantiate");
    let mut out: Option<String> = None;
    instance
        .run(|mut store, wasm| {
            let (_, interface) = wasm
                .get_export(&mut store, None, "qqq:iface-probe-dns/probe-api@1.0.0")
                .expect("the probe export instance exists");
            let index = wasm
                .get_export_index(&mut store, Some(&interface), "probe-dns")
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

/// A granted guest resolves listed names through the static table, tells
/// unlisted from missing apart by name, preserves batch order, and fails
/// oversize batches and hostile names before any lookup.
#[test]
fn granted_guest_resolves_listed_names() {
    let grants = GrantSet::from_manifest(&manifest());
    let Some(summary) = call_probe(&grants) else {
        return;
    };
    for expected in [
        "resolve=ok:2",
        "resolve-v4-first=ok",
        "resolve-missing=err:not-found",
        "resolve-unlisted=err:name-not-allowed",
        "resolve-many=ok:2",
        "resolve-many-order=ok",
        "allowed-names=ok",
        "batch-too-big=err:resolver-failed",
        "big-name=err:name-not-allowed",
    ] {
        assert!(
            summary.contains(expected),
            "the guest must report {expected}: {summary}"
        );
    }
    for unexpected in [
        "unexpected",
        "err:timeout",
        "err:backend-failed",
        "none-unexpected",
    ] {
        assert!(
            !summary.contains(unexpected),
            "the guest must never report {unexpected}: {summary}"
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
    .expect_err("no grant means no instance");
    let text = format!("{err:?}");
    assert!(
        text.contains("qqq:dns/resolver"),
        "the refusal must name the interface: {text}"
    );
}
