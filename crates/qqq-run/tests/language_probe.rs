// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]
//! Opt-in language probe. Runs actual compiled guests; never treats compilation as conformance.

use std::time::Instant;

use qqq_cap::{manifest::Manifest, resolve::GrantSet};
use qqq_host::{LimitSet, config::EngineConfig};
use qqq_run::guest_handler::GuestApp;

/// The probe is an inbound HTTP server, so its test manifest must grant the
/// capability that makes the `qqq:http/http` type instance linkable.
///
/// C and `AssemblyScript` happen to lower the handler without importing that
/// instance. Python and TypeScript retain the imported type interface, which
/// exposed that the old empty grant set was testing an impossible deployment.
/// Keeping the grant in the test (rather than widening the host linker) makes
/// the probe exercise the same least-privilege policy as a real server.
fn server_grants() -> GrantSet {
    let manifest = Manifest::parse(
        "[package]\nname = \"language-probe\"\nversion = \"0.0.0\"\n\n[capabilities.http]\nserver = true\n",
    )
    .expect("the probe manifest is static and valid");
    GrantSet::from_manifest(&manifest)
}

#[test]
#[ignore = "requires QQQ_LANGUAGE_COMPONENT from the language probe builder"]
fn compiled_language_handles_real_requests() {
    let path = std::env::var("QQQ_LANGUAGE_COMPONENT").expect("QQQ_LANGUAGE_COMPONENT is required");
    let bytes = std::fs::read(&path).expect("read compiled guest");
    let start = Instant::now();
    let engine = wasmtime::Engine::new(&EngineConfig::default().to_wasmtime_config().unwrap())
        .expect("engine");
    let app = GuestApp::with_capacity(
        engine,
        &bytes,
        server_grants(),
        LimitSet {
            memory_bytes: 128 * 1024 * 1024,
            fuel: 100_000_000,
            epoch_deadline_ms: 5_000,
            max_open_handles: 32,
            max_subrequests: 16,
        },
        "localhost:3000",
        2,
    )
    .unwrap_or_else(|error| {
        println!(
            "QQQ_LANGUAGE_REJECTION={}",
            serde_json::json!({
                "prepare_rejected_ms": start.elapsed().as_secs_f64() * 1000.0,
                "stage": "link", "cases_passed": 0,
            })
        );
        panic!("guest must link under the same policy as Rust: {error:?}");
    });
    let prepare_ms = start.elapsed().as_secs_f64() * 1000.0;
    let large = (0_u8..=255).cycle().take(65_536).collect::<Vec<_>>();
    let cases = [
        ("GET", "/", None, 200, b"ok".to_vec()),
        (
            "GET",
            "/unicode",
            None,
            200,
            "Hello, 世界 👋".as_bytes().to_vec(),
        ),
        ("GET", "/missing", None, 404, b"not found".to_vec()),
        ("POST", "/echo", Some(Vec::new()), 200, Vec::new()),
        ("POST", "/echo", Some(large.clone()), 200, large),
    ];
    let mut call_ms = Vec::new();
    for (method, route, body, status, expected) in &cases {
        let wire = format!("{method} {route} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let head = qqq_serve::http1::parse_head(wire.as_bytes()).unwrap().0;
        let start = Instant::now();
        let response = app
            .handle_request(&head, body.clone(), "test-tenant")
            .expect("execute guest");
        call_ms.push(start.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(
            response.status,
            *status,
            "{route} expected {} bytes: {:?}",
            expected.len(),
            String::from_utf8_lossy(&response.body)
        );
        assert_eq!(response.body, *expected, "{route}");
    }
    println!(
        "QQQ_LANGUAGE_RESULT={}",
        serde_json::json!({
            "bytes": bytes.len(), "prepare_ms": prepare_ms, "call_ms": call_ms,
            "cases_passed": cases.len(),
            "measurement": "fresh engine, no disk cache; fresh Store per call; one sample, not an SLO",
        })
    );
}
