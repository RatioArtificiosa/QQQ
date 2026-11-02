// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test setup unwraps fixtures and asserts inline"
)]

//! `wasi:random` is grant-gated: wasmtime's stock registration answers every
//! guest regardless of grants, so QQQ shadows it with five `func_wrap`
//! shims that check `crypto.random` on every call.
//!
//! The version below is load-bearing: the shims must name exactly what
//! wasmtime links (`wasi:random@0.2.12`), or they sit beside the stock
//! registration instead of replacing it. A wasmtime upgrade that moves the
//! version fails these tests loudly instead of silently un-shadowing.

use qqq_cap::manifest::Manifest;
use qqq_cap::resolve::GrantSet;
use qqq_host::{Instance, LimitSet, PreparedComponent};

/// A component importing every shadowed `wasi:random` method, plus nothing else.
const RANDOM_GUEST: &str = r#"(component
  (import "wasi:random/random@0.2.12" (instance $r
    (export "get-random-bytes" (func (param "len" u64) (result (list u8))))
    (export "get-random-u64" (func (result u64)))))
  (import "wasi:random/insecure@0.2.12" (instance $i
    (export "get-insecure-random-bytes" (func (param "len" u64) (result (list u8))))
    (export "get-insecure-random-u64" (func (result u64)))))
  (import "wasi:random/insecure-seed@0.2.12" (instance $s
    (export "insecure-seed" (func (result (tuple u64 u64))))))
  (core module $m (func (export "f") (result i32) i32.const 1))
  (core instance $i (instantiate $m))
)"#;

/// A guest that calls `get-random-u64` and re-exports the answer, so the test
/// can invoke the shim through a real call and observe granted-vs-denied.
/// The core `run` wrapper calls the canon-lowered import; the lowered
/// function travels through an argument instance, which is the only shape
/// the text format accepts for core instantiation arguments.
const CALLING_GUEST: &str = r#"(component
  (import "wasi:random/random@0.2.12" (instance $r
    (export "get-random-u64" (func (result u64)))))
  (core module $m
    (import "h" "g" (func $g (result i64)))
    (func (export "run") (result i64) call $g))
  (core func $lowered (canon lower (func $r "get-random-u64")))
  (core instance $args (export "g" (func $lowered)))
  (core instance $i (instantiate $m (with "h" (instance $args))))
  (func $run (result u64) (canon lift (core func $i "run")))
  (export "run" (func $run))
)"#;

fn engine() -> wasmtime::Engine {
    let mut cfg = wasmtime::Config::new();
    cfg.wasm_component_model(true);
    cfg.consume_fuel(true);
    cfg.epoch_interruption(true);
    wasmtime::Engine::new(&cfg).unwrap()
}

fn grants(toml: &str) -> GrantSet {
    GrantSet::from_manifest(&Manifest::parse(toml).unwrap())
}

fn random_grant() -> GrantSet {
    grants("[package]\nname = \"r\"\nversion = \"0.1.0\"\n[capabilities.crypto]\nrandom = true\n")
}

fn limits() -> LimitSet {
    LimitSet {
        memory_bytes: 16 * 1024 * 1024,
        fuel: 10_000_000,
        epoch_deadline_ms: 5_000,
        max_open_handles: 64,
        max_subrequests: 32,
    }
}

#[test]
fn shadowed_random_imports_resolve_at_the_linked_version() {
    // If the shims named any other version, this guest — importing the
    // stock version — would fail with an unknown import, and the bypass
    // would be open while looking closed.
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, RANDOM_GUEST.as_bytes()).unwrap();
    Instance::create(&engine, &prepared, &GrantSet::empty(), limits())
        .unwrap_or_else(|e| panic!("an ungranted guest must still instantiate: {e}"));
}

#[test]
fn ungranted_random_traps_instead_of_answering() {
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, CALLING_GUEST.as_bytes()).unwrap();
    let instance = Instance::create(&engine, &prepared, &GrantSet::empty(), limits()).unwrap();
    let mut trapped = false;
    instance
        .run(|store, wasm| {
            let f = wasm
                .get_typed_func::<(), (u64,)>(&mut *store, "run")
                .unwrap();
            if f.call(&mut *store, ()).is_err() {
                trapped = true;
            }
            Ok(())
        })
        .unwrap();
    assert!(trapped, "an ungranted get-random-u64 must trap, not answer");
}

/// An older patch version resolves onto the same shims: wasmtime matches
/// `wasi:random` semver-compatibly, so a guest importing `0.2.9` lands on
/// the `0.2.12` shadow registration rather than on a second, unguarded copy.
/// If that ever changed, this guest would either fail to link (loud) or —
/// worse — answer ungranted (silent bypass); the test pins the deny.
#[test]
fn an_older_patch_version_is_covered_by_the_same_shims() {
    let engine = engine();
    let wat = CALLING_GUEST.replace("0.2.12", "0.2.9");
    let prepared = PreparedComponent::compile(&engine, wat.as_bytes()).unwrap();
    let instance = Instance::create(&engine, &prepared, &GrantSet::empty(), limits()).unwrap();
    let mut trapped = false;
    instance
        .run(|store, wasm| {
            let f = wasm
                .get_typed_func::<(), (u64,)>(&mut *store, "run")
                .unwrap();
            if f.call(&mut *store, ()).is_err() {
                trapped = true;
            }
            Ok(())
        })
        .unwrap();
    assert!(
        trapped,
        "a 0.2.9 guest must hit the same grant gate, not a parallel unguarded copy"
    );
}

#[test]
fn granted_random_answers() {
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, CALLING_GUEST.as_bytes()).unwrap();
    let instance = Instance::create(&engine, &prepared, &random_grant(), limits()).unwrap();
    let answer = instance
        .run(|store, wasm| {
            let f = wasm
                .get_typed_func::<(), (u64,)>(&mut *store, "run")
                .unwrap();
            f.call(&mut *store, ())
        })
        .unwrap();
    // Any u64 is a valid answer; the property is that the call succeeds.
    let _ = answer;
}
