// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]
//! Real component calls, failed admission, generation lifetime, and cache reuse.

use qqq_cap::resolve::GrantSet;
use qqq_host::{LimitSet, config::EngineConfig};
use qqq_run::{guest_handler::GuestApp, live::LiveApp};
use std::sync::Arc;

const V1: &str = include_str!("fixtures/live-http.wat");

fn app(source: &str) -> GuestApp {
    let engine =
        wasmtime::Engine::new(&EngineConfig::default().to_wasmtime_config().unwrap()).unwrap();
    GuestApp::with_capacity(
        engine,
        source.as_bytes(),
        GrantSet::empty(),
        LimitSet {
            memory_bytes: 16 * 1024 * 1024,
            fuel: 1_000_000,
            epoch_deadline_ms: 5_000,
            max_open_handles: 32,
            max_subrequests: 16,
        },
        "localhost:3000",
        2,
    )
    .unwrap()
}

fn request() -> qqq_serve::http1::RequestHead {
    qqq_serve::http1::parse_head(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap()
        .0
}

#[test]
fn replaced_code_answers_while_old_session_keeps_its_version() {
    let live = LiveApp::new(app(V1)).unwrap();
    let old = live.acquire().unwrap();
    let weak = Arc::downgrade(&old);
    assert_eq!(
        old.value()
            .handle_request(&request(), None, "test-tenant")
            .unwrap()
            .body,
        b"v1"
    );
    live.replace(V1.replace("\"v1\"", "\"v2\"").as_bytes())
        .unwrap();
    let next = live.acquire().unwrap();
    assert_ne!(old.revision(), next.revision());
    assert_eq!(
        next.value()
            .handle_request(&request(), None, "test-tenant")
            .unwrap()
            .body,
        b"v2"
    );
    assert_eq!(
        old.value()
            .handle_request(&request(), None, "test-tenant")
            .unwrap()
            .body,
        b"v1"
    );
    assert_eq!(
        next.value().audit_snapshot().0.len(),
        3,
        "one shared audit history"
    );
    assert_eq!(live.draining().unwrap(), 1);
    drop(old);
    assert!(weak.upgrade().is_none());
    assert_eq!(live.draining().unwrap(), 0);
    live.remove().unwrap();
    assert!(live.acquire().is_err());
    assert_eq!(
        (live.dispatch_with_body())(&request(), &qqq_serve::BodyBytes::Absent, "test-tenant")
            .status,
        503
    );
    assert_eq!(
        next.value()
            .handle_request(&request(), None, "test-tenant")
            .unwrap()
            .body,
        b"v2"
    );
}

#[test]
fn malformed_and_wrong_abi_candidates_preserve_active_code() {
    let live = LiveApp::new(app(V1)).unwrap();
    let revision = live.acquire().unwrap().revision();
    for candidate in [
        "broken",
        "(component)",
        &V1.replace("\"status\" u16", "\"status\" u32"),
    ] {
        assert!(live.replace(candidate.as_bytes()).is_err());
        assert_eq!(live.acquire().unwrap().revision(), revision);
        assert_eq!(
            live.acquire()
                .unwrap()
                .value()
                .handle_request(&request(), None, "test-tenant")
                .unwrap()
                .body,
            b"v1"
        );
    }
}

/// Remove a directory that a background writer may still be touching, with a deadline.
///
/// # Why this exists rather than `remove_dir_all`
///
/// **`std::fs::remove_dir_all` is documented to fail if the directory changes while it is being removed**,
/// and macOS surfaces that race as `DirectoryNotEmpty`. This test drops the `engine`, `config` and
/// `cache` handles and then removes the directory -- but Wasmtime's managed cache is a directory of
/// `.cwasm` files written by cache machinery whose shutdown is not synchronised with a `Drop` of the
/// handle. **It passed on Linux and Windows and failed on macOS at the cleanup line, after every assertion
/// in the test had already run.**
///
/// # Why not `let _ =`
///
/// **This repository has paid for that shape five times.** A cleanup that cannot fail is a cleanup that
/// hides the next real failure, and the whole point of this repository's `let _ =` observations is that a
/// helper whose failure looks like success is worse than an ugly panic.
///
/// # What is asserted instead
///
/// **The removal must ultimately succeed.** The retry is bounded by a deadline, so a directory that is
/// genuinely unremovable still fails the test -- but with the last OS error attached, after giving a
/// flush that was already in flight a chance to finish. **A retry is not a weakened assertion; it is the
/// correct assertion for a path another thread may still hold.**
fn remove_dir_all_retrying(path: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match std::fs::remove_dir_all(path) {
            // **Already gone is success.** A previous attempt or a concurrent cleaner may have won.
            Ok(()) => return,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                // **The deadline is checked where the error is**, so the message it prints is the error
                // that just happened rather than a value threaded out of the match arms. `clippy` said the
                // previous shape assigned `last` without reading it, and it was right: with `assert!` the
                // initialiser was dead, because every path that reaches the check has just set it.
                assert!(
                    std::time::Instant::now() < deadline,
                    "could not remove {} within 10s, so something is still writing to it: {e}",
                    path.display()
                );
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }
}

#[test]
fn native_output_is_real_and_cache_survives_engine_recreation() {
    let root = std::env::temp_dir().join(format!("qqq-native-{}", std::process::id()));
    // **Legitimately best-effort, and said so rather than left as a bare `let _ =`.** A directory left by a
    // previous run of this same PID is not a failure of this run -- but `let _ =` is the shape this
    // repository hunts, so the tolerance is documented where a reader finds it. The removal at the END of
    // this test does not get the same tolerance: it asserts.
    let _ = std::fs::remove_dir_all(&root);
    let cache_dir = root.join("cache");
    let output =
        qqq_run::aot::emit(V1.as_bytes(), &root.join("artifacts"), Some(&cache_dir)).unwrap();
    let native = std::fs::read(&output).unwrap();
    assert_ne!(&native[..4], b"\0asm");
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.with_extension("json")).unwrap()).unwrap();
    assert_eq!(metadata["native_sha256"], qqq_host::digest_of(&native));
    let mut config = EngineConfig::default().to_wasmtime_config().unwrap();
    let cache = qqq_run::aot::configure(&mut config, Some(&cache_dir))
        .unwrap()
        .unwrap();
    let engine = wasmtime::Engine::new(&config).unwrap();
    wasmtime::component::Component::new(&engine, V1).unwrap();
    assert!(
        cache.cache_hits() > 0,
        "the second engine must reuse native code"
    );
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "cache_child", "--nocapture"])
        .env("QQQ_TEST_CACHE", &cache_dir)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(std::fs::read(cache_dir.join("child-hit")).unwrap(), b"hit");
    let misses = cache.cache_misses();
    wasmtime::component::Component::new(&engine, V1.replace("\"v1\"", "\"v2\"")).unwrap();
    assert!(
        cache.cache_misses() > misses,
        "changed bytes must compile separately"
    );
    assert!(
        wasmtime::component::Component::new(&engine, native).is_err(),
        "arbitrary cwasm is not accepted as portable source"
    );
    drop(engine);
    drop(config);
    drop(cache);
    // **The AOT cache directory is removed here, and macOS says `DirectoryNotEmpty` if it is not.**
    // See `remove_dir_all_retrying` for why this gives a background flush a bounded chance to finish
    // instead of trusting one `remove_dir_all` one statement after the handle was dropped.
    remove_dir_all_retrying(&root);
}

#[test]
fn cache_child() {
    let Some(directory) = std::env::var_os("QQQ_TEST_CACHE") else {
        return;
    };
    let directory = std::path::PathBuf::from(directory);
    let mut config = EngineConfig::default().to_wasmtime_config().unwrap();
    let cache = qqq_run::aot::configure(&mut config, Some(&directory))
        .unwrap()
        .unwrap();
    let engine = wasmtime::Engine::new(&config).unwrap();
    wasmtime::component::Component::new(&engine, V1).unwrap();
    assert!(cache.cache_hits() > 0);
    let guest = GuestApp::new(
        engine,
        V1.as_bytes(),
        GrantSet::empty(),
        LimitSet {
            memory_bytes: 16 * 1024 * 1024,
            fuel: 1_000_000,
            epoch_deadline_ms: 5_000,
            max_open_handles: 32,
            max_subrequests: 16,
        },
        "localhost:3000",
    )
    .unwrap();
    assert_eq!(
        guest
            .handle_request(&request(), None, "test-tenant")
            .unwrap()
            .body,
        b"v1"
    );
    std::fs::write(directory.join("child-hit"), b"hit").unwrap();
}

#[test]
fn running_guest_is_preempted_and_capacity_is_released() {
    let spin = V1.replace("i32.const 0))", "(loop br 0) i32.const 0))");
    let engine =
        wasmtime::Engine::new(&EngineConfig::default().to_wasmtime_config().unwrap()).unwrap();
    let guest = GuestApp::new(
        engine,
        spin.as_bytes(),
        GrantSet::empty(),
        LimitSet {
            memory_bytes: 16 * 1024 * 1024,
            fuel: u64::MAX,
            epoch_deadline_ms: 20,
            max_open_handles: 32,
            max_subrequests: 16,
        },
        "localhost:3000",
    )
    .unwrap();
    let start = std::time::Instant::now();
    assert!(
        guest
            .handle_request(&request(), None, "test-tenant")
            .is_err()
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(guest.in_flight(), 0);
    let live = LiveApp::new(guest).unwrap();
    live.replace(V1.as_bytes()).unwrap();
    assert_eq!(
        live.acquire()
            .unwrap()
            .value()
            .handle_request(&request(), None, "test-tenant")
            .unwrap()
            .body,
        b"v1"
    );
}

#[test]
fn overlapping_generations_share_one_capacity_limit() {
    let spin = V1.replace("i32.const 0))", "(loop br 0) i32.const 0))");
    let engine =
        wasmtime::Engine::new(&EngineConfig::default().to_wasmtime_config().unwrap()).unwrap();
    let guest = GuestApp::new(
        engine,
        spin.as_bytes(),
        GrantSet::empty(),
        LimitSet {
            memory_bytes: 16 * 1024 * 1024,
            fuel: u64::MAX,
            epoch_deadline_ms: 2_000,
            max_open_handles: 32,
            max_subrequests: 16,
        },
        "localhost:3000",
    )
    .unwrap();
    let live = LiveApp::new(guest).unwrap();
    let old = live.acquire().unwrap();
    let invocation = Arc::clone(&old);
    let call = std::thread::spawn(move || {
        invocation
            .value()
            .handle_request(&request(), None, "test-tenant")
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while old.value().in_flight() == 0 {
        assert!(std::time::Instant::now() < deadline && !call.is_finished());
        std::thread::yield_now();
    }
    live.replace(V1.as_bytes()).unwrap();
    let next = live.acquire().unwrap();
    assert_eq!(
        next.value().in_flight(),
        1,
        "replacement must share the old quota"
    );
    assert!(
        next.value()
            .handle_request(&request(), None, "test-tenant")
            .is_err()
    );
    assert!(call.join().unwrap().is_err(), "old CPU work must terminate");
    assert_eq!(next.value().in_flight(), 0);
    assert_eq!(
        next.value()
            .handle_request(&request(), None, "test-tenant")
            .unwrap()
            .body,
        b"v1"
    );
}

#[test]
fn cache_configuration_fails_closed() {
    let mut config = EngineConfig::default().to_wasmtime_config().unwrap();
    assert!(qqq_run::aot::configure(&mut config, Some(std::path::Path::new("relative"))).is_err());
    let manifest = qqq_cap::Manifest::parse(
        r#"
[package]
name = "cache-guest"
version = "0.1.0"
[[capabilities.fs]]
path = "."
mode = "read-write"
"#,
    )
    .unwrap();
    let grants = GrantSet::from_manifest(&manifest);
    assert!(grants.grants(qqq_cap::Capability::FsWrite));
    assert!(
        qqq_run::aot::check_grants(Some(std::path::Path::new("/host-cache")), &grants).is_err()
    );
    assert!(qqq_run::aot::check_grants(None, &grants).is_ok());
}

#[tokio::test]
async fn the_same_listener_serves_the_replacement() {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let live = LiveApp::new(app(V1)).unwrap();
    let mut routes = qqq_serve::route::RouteTable::new();
    routes
        .insert(qqq_serve::route::Route::new(qqq_serve::route::Method::Get, "/", "app").unwrap())
        .unwrap();
    let config = qqq_serve::server::ServerConfig::for_addr(
        qqq_io::ListenAddr::parse(&address.to_string()).unwrap(),
    );
    let shutdown = qqq_io::Shutdown::new();
    let task = tokio::spawn(qqq_serve::serve(
        config,
        routes,
        qqq_serve::Dispatch::flat(live.dispatch()),
        shutdown.clone(),
        qqq_serve::access_log::Logger::new(
            qqq_serve::access_log::Format::Json,
            qqq_serve::access_log::Level::Info,
        ),
    ));
    let stream = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match tokio::net::TcpStream::connect(address).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .unwrap();
    let mut stream = tokio::io::BufReader::new(stream);
    for version in ["v1", "v2"] {
        if version == "v2" {
            let controller = live.clone();
            tokio::task::spawn_blocking(move || {
                controller.replace(V1.replace("\"v1\"", "\"v2\"").as_bytes())
            })
            .await
            .unwrap()
            .unwrap();
        }
        let connection = if version == "v2" {
            "close"
        } else {
            "keep-alive"
        };
        let request =
            format!("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: {connection}\r\n\r\n");
        stream
            .get_mut()
            .write_all(request.as_bytes())
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), async {
            use tokio::io::AsyncBufReadExt as _;
            let mut length = None;
            loop {
                let mut header = String::new();
                assert!(stream.read_line(&mut header).await.unwrap() > 0);
                if header == "\r\n" {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
            }
            let mut body = vec![0; length.expect("buffered response length")];
            stream.read_exact(&mut body).await.unwrap();
            body
        })
        .await
        .unwrap();
        assert_eq!(response, version.as_bytes());
    }
    shutdown.signal();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
