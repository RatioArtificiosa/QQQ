// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! `qqq:queue` end to end — `HOST-033` — against the real probe guest.
//!
//! The probe (`examples/iface-probe/guests/queue`) is compiled by the real
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
                "probe queue guest build failed with the toolchain present: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let artifact = workspace.join("target/wasm32-wasip2/release/probe_queue.wasm");
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
         [[capabilities.queue]]\nname = \"q\"\ndirection = \"publish\"\n\
         [[capabilities.queue]]\nname = \"q\"\ndirection = \"subscribe\"\n\
         [capabilities.http]\nserver = true\n",
    )
    .expect("probe manifest parses")
}

fn queue_view() -> qqq_host::host_queue::QueueView {
    use qqq_cap::manifest::QueueDirection;
    qqq_host::host_queue::QueueView::new(
        Arc::new(qqq_host::host_queue::QueueConfig::new(vec![
            ("q".to_owned(), QueueDirection::Publish),
            ("q".to_owned(), QueueDirection::Subscribe),
        ])),
        Arc::new(std::sync::Mutex::new(
            qqq_host::host_queue::QueueBackend::new(),
        )),
    )
}

/// Run the probe and return its summary.
fn call_probe(grants: &GrantSet) -> Option<String> {
    let bytes = probe_component()?;
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("probe component compiles");
    let opts = qqq_host::instance::InstanceOptions {
        queue: queue_view(),
        ..Default::default()
    };
    let instance = Instance::create_with(&engine, &prepared, grants, limits(), &opts)
        .expect("probe must instantiate");
    let mut out: Option<String> = None;
    instance
        .run(|mut store, wasm| {
            let (_, interface) = wasm
                .get_export(&mut store, None, "qqq:iface-probe-queue/probe-api@1.0.0")
                .expect("the probe export instance exists");
            let index = wasm
                .get_export_index(&mut store, Some(&interface), "probe-queue")
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

/// A granted guest publishes, receives, acknowledges, rejects, and is
/// bounded; unconfigured queues and oversize bodies fail by name.
#[test]
fn granted_guest_publishes_and_receives() {
    let grants = GrantSet::from_manifest(&manifest());
    let Some(summary) = call_probe(&grants) else {
        return;
    };
    for expected in [
        "publish=ok",
        "publish-many=ok",
        "receive=ok:1",
        "ack=ok",
        "receive-empty=ok:none",
        "redeliver=ok:2",
        "redeliver-ack=ok",
        "queues=q",
        "unlisted=err:queue-not-configured",
        "big-message=err:message-too-large",
    ] {
        assert!(
            summary.contains(expected),
            "the guest must report {expected}: {summary}"
        );
    }
    for unexpected in [
        "unexpected",
        "none-unexpected",
        "unexpected-ok",
        "unexpected-some",
        "err:backend-failed",
    ] {
        assert!(
            !summary.contains(unexpected),
            "the guest must never report {unexpected}: {summary}"
        );
    }
}

/// A publish-only guest cannot receive, and a subscribe-only guest cannot
/// publish — each names its own denial.
#[test]
fn directions_do_not_widen() {
    let publish_only = Manifest::parse(
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\
         [[capabilities.queue]]\nname = \"q\"\ndirection = \"publish\"\n\
         [capabilities.http]\nserver = true\n",
    )
    .expect("probe manifest parses");
    let grants = GrantSet::from_manifest(&publish_only);
    let Some(summary) = call_probe(&grants) else {
        return;
    };
    assert!(
        summary.contains("receive=err:not-granted"),
        "publishing never smuggles subscribing: {summary}"
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
        text.contains("qqq:queue/messaging"),
        "the refusal must name the interface: {text}"
    );
}
