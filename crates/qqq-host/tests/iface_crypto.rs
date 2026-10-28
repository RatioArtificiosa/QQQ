// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! `qqq:crypto` hmac/aead/signing end to end — `HOST-037` — against the real probe guest.
//!
//! The probe (`examples/iface-probe/guests/crypto`) is compiled by the real
//! toolchain through `wit-bindgen`, so its calls use the true canonical ABI.
//! The boundary under test is guest → host → grant check → allowlist →
//! primitive, with known-answer vectors asserting the primitives rather
//! than their invariance.

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
                    "--offline",
                ])
                .current_dir(&workspace)
                .output()
                .expect("cargo runs");
            assert!(
                output.status.success(),
                "probe crypto guest build failed with the toolchain present: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let artifact = workspace.join("target/wasm32-wasip2/release/probe_crypto.wasm");
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
         [capabilities.crypto]\nrandom = true\n\
         hash = [\"sha256\"]\n\
         hmac = [\"sha256\", \"sha512\"]\n\
         aead = [\"aes-256-gcm\"]\n\
         sign = [\"ed25519\"]\n\
         [capabilities.http]\nserver = true\n",
    )
    .expect("probe manifest parses")
}

fn crypto_view() -> qqq_host::host_crypto::CryptoView {
    use qqq_host::host_crypto::{CryptoConfig, CryptoView};
    CryptoView::new(Arc::new(CryptoConfig::from_manifest(&manifest())))
}

/// Run the probe and return its summary.
fn call_probe(grants: &GrantSet) -> Option<String> {
    let bytes = probe_component()?;
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("probe component compiles");
    let opts = qqq_host::instance::InstanceOptions {
        crypto: crypto_view(),
        ..Default::default()
    };
    let instance = Instance::create_with(&engine, &prepared, grants, limits(), &opts)
        .expect("probe must instantiate");
    let mut out: Option<String> = None;
    instance
        .run(|mut store, wasm| {
            let (_, interface) = wasm
                .get_export(&mut store, None, "qqq:iface-probe-crypto/probe-api@1.0.0")
                .expect("the probe export instance exists");
            let index = wasm
                .get_export_index(&mut store, Some(&interface), "probe-crypto")
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

/// A granted guest computes, verifies, encrypts, decrypts, signs, and
/// verifies through the real canonical ABI, and tells unlisted algorithms
/// apart from ungranted calls by name.
#[test]
fn granted_guest_drives_hmac_aead_signing() {
    let manifest = manifest();
    let grants = GrantSet::from_manifest(&manifest);
    let Some(summary) = call_probe(&grants) else {
        return;
    };
    for expected in [
        "hmac-sha256=ok",
        "hmac-sha512=ok",
        "hmac-blake3-unlisted=err:algorithm-not-allowed",
        "hmac-verify=ok",
        "aes-roundtrip=ok",
        "aes-zero=ok",
        "aes-tamper=err:authentication-failed",
        "chacha-unlisted=err:construction-not-allowed",
        "ed25519-pubkey=ok",
        "ed25519-sign=ok",
        "ed25519-verify=ok",
        "ed25519-wrong-msg=ok:false",
        "lengths=ok",
    ] {
        assert!(
            summary.contains(expected),
            "the guest must report {expected}: {summary}"
        );
    }
    for unexpected in ["unexpected", "err:not-granted", "none-"] {
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
        text.contains("qqq:crypto/hmac")
            || text.contains("qqq:crypto/aead")
            || text.contains("qqq:crypto/signing"),
        "the refusal must name the interface: {text}"
    );
}

/// A guest granted only hashing cannot reach hmac: the missing grant fails
/// closed at instantiation, naming the hmac interface.
#[test]
fn hash_only_grant_cannot_reach_hmac() {
    let Some(bytes) = probe_component() else {
        return;
    };
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("probe component compiles");
    let manifest = Manifest::parse(
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\
         [capabilities.crypto]\nhash = [\"sha256\"]\n\
         [capabilities.http]\nserver = true\n",
    )
    .expect("probe manifest parses");
    let grants = GrantSet::from_manifest(&manifest);
    let err = Instance::create_with(
        &engine,
        &prepared,
        &grants,
        limits(),
        &qqq_host::instance::InstanceOptions::default(),
    )
    .expect_err("hash-only grants must not bind hmac");
    let text = format!("{err:?}");
    assert!(
        text.contains("qqq:crypto/hmac"),
        "the refusal must name the hmac interface: {text}"
    );
}
