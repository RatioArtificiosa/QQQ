// SPDX-License-Identifier: Apache-2.0

// Test-setup idiom (`F-18`): fixtures unwrap, assertions index vectors
// built inline above. One file-level reason, not per-site noise;
// shipping code carries no such allowance.
#![allow(
    clippy::expect_used,
    reason = "test setup unwraps fixtures and indexes inline vectors"
)]

//! `qqq:sql` end to end — `HOST-036` — against the real probe guest.
//!
//! The probe (`examples/iface-probe/guests/sql`) is compiled by the real
//! toolchain through `wit-bindgen`, so its calls use the true canonical ABI.
//! The databases behind the instance are file-backed SQLite files in a fresh
//! temporary directory per test, so no test touches a shared database: the
//! boundary under test is guest → host → grant check → config → SQLite.

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
                "probe sql guest build failed with the toolchain present: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let artifact = workspace.join("target/wasm32-wasip2/release/probe_sql.wasm");
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

/// A fresh directory per test: the two database files live here, and
/// nothing outside the test knows them. Named per test so parallel tests
/// never share a file.
fn db_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("qqq-iface-sql-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sql probe dir creates");
    dir
}

fn manifest(dir: &std::path::Path) -> Manifest {
    Manifest::parse(&format!(
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\
         [[capabilities.sql]]\nname = \"orders\"\ndriver = \"sqlite\"\n\
         host = \"{}\"\nexecute = true\n\
         [[capabilities.sql]]\nname = \"ledger\"\ndriver = \"sqlite\"\n\
         host = \"{}\"\n\
         [capabilities.http]\nserver = true\n",
        dir.join("orders.db")
            .display()
            .to_string()
            .replace('\\', "/"),
        dir.join("ledger.db")
            .display()
            .to_string()
            .replace('\\', "/"),
    ))
    .expect("probe manifest parses")
}

fn sql_view(dir: &std::path::Path) -> qqq_host::host_sql::SqlView {
    use qqq_host::host_sql::{SqlConfig, SqlDatabase, SqlView};
    // Read-only databases open read-only and never materialize: both files
    // exist before the guest runs, so the probe's read-only case exercises
    // the enforcement rather than a missing file.
    for name in ["orders.db", "ledger.db"] {
        std::fs::File::create(dir.join(name)).expect("probe database file creates");
    }
    SqlView::new(Arc::new(SqlConfig::new(vec![
        SqlDatabase::new("orders".to_owned(), dir.join("orders.db"), true),
        SqlDatabase::new("ledger".to_owned(), dir.join("ledger.db"), false),
    ])))
}

/// Run the probe and return its summary.
fn call_probe(grants: &GrantSet, dir: &std::path::Path) -> Option<String> {
    let bytes = probe_component()?;
    let engine = engine();
    let prepared = PreparedComponent::compile(&engine, &bytes).expect("probe component compiles");
    let opts = qqq_host::instance::InstanceOptions {
        sql: sql_view(dir),
        ..Default::default()
    };
    let instance = Instance::create_with(&engine, &prepared, grants, limits(), &opts)
        .expect("probe must instantiate");
    let mut out: Option<String> = None;
    instance
        .run(|mut store, wasm| {
            let (_, interface) = wasm
                .get_export(&mut store, None, "qqq:iface-probe-sql/probe-api@1.0.0")
                .expect("the probe export instance exists");
            let index = wasm
                .get_export_index(&mut store, Some(&interface), "probe-sql")
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

/// A granted guest round-trips rows, tells unlisted from read-only by name,
/// bounds oversize statements, and commits while rolling back — through the
/// real canonical ABI into real SQLite files.
#[test]
fn granted_guest_drives_sqlite() {
    let dir = db_dir("granted");
    let manifest = manifest(&dir);
    let grants = GrantSet::from_manifest(&manifest);
    let Some(summary) = call_probe(&grants, &dir) else {
        return;
    };
    for expected in [
        "create=ok",
        "reset=ok",
        "insert=ok:1",
        "select=ok:1",
        "unlisted=err:database-not-configured",
        "readonly=err:read-only-connection",
        "oversize=err:prepare-failed",
        "txn-commit=ok",
        "txn-rollback=ok",
        "databases=ok",
    ] {
        assert!(
            summary.contains(expected),
            "the guest must report {expected}: {summary}"
        );
    }
    for unexpected in ["unexpected", "err:not-granted", "err:pool-exhausted"] {
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
        text.contains("qqq:sql/database") || text.contains("qqq:sql/transaction"),
        "the refusal must name the interface: {text}"
    );
}

/// The rows the run committed survive it: cross-request state lives in the
/// files, so opening the same file from outside the host sees them — one
/// plain insert plus one committed transaction, with the rolled-back row
/// absent.
#[test]
fn committed_rows_persist_across_instances() {
    let dir = db_dir("persist");
    let manifest = manifest(&dir);
    let grants = GrantSet::from_manifest(&manifest);
    let Some(first) = call_probe(&grants, &dir) else {
        return;
    };
    assert!(
        first.contains("txn-commit=ok"),
        "first run commits: {first}"
    );
    let connection =
        rusqlite::Connection::open(dir.join("orders.db")).expect("the database file opens");
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM t", [], |row| row.get(0))
        .expect("the count reads");
    assert_eq!(count, 2, "insert plus committed transaction persist");
    let rolled_back: i64 = connection
        .query_row("SELECT COUNT(*) FROM t WHERE id = 9", [], |row| row.get(0))
        .expect("the rolled-back row reads as absent");
    assert_eq!(rolled_back, 0, "rollback discards");
}
