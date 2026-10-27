// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! `qqq:secrets` end to end — `HOST-028` — against the real probe guest.
//!
//! The probe (`examples/iface-probe/guests/secrets`) is compiled by the real
//! toolchain through `wit-bindgen`, so its imports use the true canonical
//! ABI rather than a hand-written lowering (which this repository has
//! measured getting wrong: `hostile_guests.rs`). If the component is absent
//! the tests skip with a printed reason — the same contract the reference-app
//! tests use — because building a guest needs the `wasm32-wasip2` target.

use qqq_cap::manifest::Manifest;
use qqq_cap::resolve::GrantSet;
use qqq_host::host_secrets::{PermittedOp, SecretMaterial, SecretStore};
use qqq_host::{Instance, LimitSet, PreparedComponent};

/// The probe component, built by the real toolchain on first use. A
/// separate workspace, so the build does not contend with the host build;
/// built once per test binary behind a lock. Skipped loudly when the
/// `wasm32-wasip2` target is absent, because a test that cannot run
/// everywhere must say so rather than fail everywhere.
fn probe_component() -> Option<Vec<u8>> {
    use std::sync::OnceLock;
    static BUILT: OnceLock<bool> = OnceLock::new();
    let workspace =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/iface-probe");
    let artifact = workspace.join("target/wasm32-wasip2/release/probe_secrets.wasm");
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
                "probe secrets guest build failed with the toolchain present: {}",
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
        memory_bytes: 64 * 1024 * 1024,
        fuel: 1_000_000_000,
        epoch_deadline_ms: 10_000,
        max_open_handles: 64,
        max_subrequests: 16,
    }
}

fn manifest() -> Manifest {
    Manifest::parse(
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\
         [capabilities.secret]\nsecrets = [\"env:K\", \"env:UNRESOLVED\"]\n\
         [capabilities.crypto]\nhmac = [\"sha256\"]\naead = [\"aes-256-gcm\"]\nsign = [\"ed25519\"]\n\
         [capabilities.http]\nserver = true\n",
    )
    .expect("probe manifest parses")
}

fn material() -> SecretStore {
    SecretStore::with_grants(
        vec!["K".to_owned(), "UNRESOLVED".to_owned()],
        vec![SecretMaterial::new(
            "K".to_owned(),
            [9u8; 32].to_vec(),
            PermittedOp::all().to_vec(),
        )],
    )
}

fn call_probe(grants: &GrantSet, store: SecretStore, export: &str) -> Option<String> {
    let bytes = probe_component()?;
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("probe component compiles");
    let opts = qqq_host::instance::InstanceOptions {
        secrets: store,
        ..Default::default()
    };
    let instance = Instance::create_with(&engine, &prepared, grants, limits(), &opts)
        .expect("probe must instantiate");
    let mut slot: Option<String> = None;
    instance
        .run(|mut store, wasm| {
            let (_, interface) = wasm
                .get_export(&mut store, None, "qqq:iface-probe-secrets/probe-api@1.0.0")
                .expect("the probe export instance exists");
            let index = wasm
                .get_export_index(&mut store, Some(&interface), export)
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

/// The WIT the probe guests compile against must be byte-identical to the
/// canonical `wit/` tree: a drifted copy would test a different interface
/// than the host implements. Covers every probe guest, present and future —
/// a new guest with a stale copy fails here, not in a confusing guest test.
#[test]
fn probe_wit_copies_match_the_canonical_tree() {
    let guests =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/iface-probe/guests");
    let mut checked = 0;
    let Ok(guest_dirs) = std::fs::read_dir(&guests) else {
        println!("SKIP: no probe guests under {}", guests.display());
        return;
    };
    for guest in guest_dirs {
        let deps = guest
            .expect("guest dir reads")
            .path()
            .join("wit")
            .join("deps");
        let Ok(entries) = std::fs::read_dir(&deps) else {
            continue;
        };
        for entry in entries {
            let entry = entry.expect("probe wit entry reads");
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "wit") {
                continue;
            }
            let name = path.file_name().expect("wit file has a name");
            let canonical = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../wit")
                .join(name);
            let theirs = std::fs::read(&path).expect("probe wit copy reads");
            let ours = std::fs::read(&canonical)
                .unwrap_or_else(|_| panic!("canonical {} must exist", canonical.display()));
            assert_eq!(
                theirs,
                ours,
                "probe copy {} drifted from canonical {}",
                path.display(),
                canonical.display()
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "the probe tree must contain WIT copies");
}

/// A granted guest runs the full scenario: sign, verify, hmac, encrypt,
/// decrypt, tamper refusal, public key, exists, and the ungranted name.
#[test]
fn granted_guest_runs_the_full_scenario() {
    let grants = GrantSet::from_manifest(&manifest());
    let Some(summary) = call_probe(&grants, material(), "probe-secrets") else {
        return;
    };
    for expected in [
        "exists-k=true",
        "exists-unknown=false",
        "ops-k=6",
        "ops-unknown=0",
        "sign=ok:64",
        "verify=ok:01",
        "hmac=ok:32",
        "decrypt=ok:hello",
        "tamper=err:unavailable",
        "public-key=ok:32",
        "unknown=err:not-granted",
    ] {
        assert!(
            summary.contains(expected),
            "scenario must report {expected}: {summary}"
        );
    }
    assert!(
        summary.contains("encrypt=ok:"),
        "encrypt reports its length: {summary}"
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
    .expect_err("no grant must fail");
    let text = format!("{err:?}");
    assert!(
        text.contains("qqq:secrets"),
        "the refusal must name the interface: {text}"
    );
}

/// A use grant without the crypto grant cannot reach the primitive.
#[test]
fn secret_use_without_crypto_grant_is_operation_not_permitted() {
    let m = Manifest::parse(
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\
         [capabilities.secret]\nsecrets = [\"env:K\"]\n\
         [capabilities.http]\nserver = true\n",
    )
    .expect("manifest parses");
    let grants = GrantSet::from_manifest(&m);
    let Some(summary) = call_probe(&grants, material(), "probe-secrets") else {
        return;
    };
    for expected in [
        "sign=err:operation-not-permitted",
        "hmac=err:operation-not-permitted",
        "exists-k=true",
    ] {
        assert!(
            summary.contains(expected),
            "without crypto grants every op refuses: {summary}"
        );
    }
}

/// A granted-but-unresolved secret is unavailable, not granted.
#[test]
fn granted_but_unresolved_secret_is_unavailable() {
    let grants = GrantSet::from_manifest(&manifest());
    let Some(summary) = call_probe(&grants, material(), "probe-secrets") else {
        return;
    };
    for expected in ["exists-unresolved=false", "unresolved=err:unavailable"] {
        assert!(
            summary.contains(expected),
            "a granted name with no material is unavailable, never granted: {summary}"
        );
    }
}
