// SPDX-License-Identifier: Apache-2.0

//! SQL probe guest: exercises `qqq:sql/database` and `qqq:sql/transaction`
//! and encodes every outcome in a summary string the host asserts on.

wit_bindgen::generate!({
    world: "probe",
    path: "wit",
    generate_all,
});

use exports::qqq::http::incoming_handler::{Guest as HttpGuest, HttpError, Request, Response};
use exports::qqq::iface_probe_sql::probe_api::Guest as ProbeGuest;
use qqq::sql::database::{databases, prepare, query_once, SqlError, Value};
use qqq::sql::transaction::begin;

struct Probe;

export!(Probe);

impl HttpGuest for Probe {
    fn handle(_req: Request) -> Result<Response, HttpError> {
        Ok(Response {
            status: 200,
            headers: Vec::new(),
            body: run_scenario().into_bytes(),
        })
    }
}

impl ProbeGuest for Probe {
    fn probe_sql() -> String {
        run_scenario()
    }
}

fn run_scenario() -> String {
    let mut parts: Vec<String> = Vec::new();

    // A fresh table every run: the file persists across requests, so the
    // scenario resets its own state rather than assuming a fresh database.
    match query_once(
        "orders",
        "CREATE TABLE IF NOT EXISTS t (id INTEGER, name TEXT)",
        &[],
    ) {
        Ok(_) => parts.push("create=ok".to_string()),
        Err(e) => parts.push(format!("create=err:{}", err_name(&e))),
    }
    match query_once("orders", "DELETE FROM t", &[]) {
        Ok(_) => parts.push("reset=ok".to_string()),
        Err(e) => parts.push(format!("reset=err:{}", err_name(&e))),
    }

    match prepare("orders", "INSERT INTO t VALUES (?1, ?2)") {
        Ok(stmt) => match stmt.execute(&[Value::Integer(7), Value::Text("seven".to_string())]) {
            Ok(n) => parts.push(format!("insert=ok:{n}")),
            Err(e) => parts.push(format!("insert=err:{}", err_name(&e))),
        },
        Err(e) => parts.push(format!("insert=err:{}", err_name(&e))),
    }
    match query_once("orders", "SELECT * FROM t", &[]) {
        Ok(rows) => parts.push(format!("select=ok:{}", rows.len())),
        Err(e) => parts.push(format!("select=err:{}", err_name(&e))),
    }
    match prepare("ledger-missing", "SELECT 1") {
        Ok(_) => parts.push("unlisted=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("unlisted=err:{}", err_name(&e))),
    }
    // `ledger` grants query only: the write fails read-only.
    match query_once("ledger", "CREATE TABLE t (id INTEGER)", &[]) {
        Ok(_) => parts.push("readonly=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("readonly=err:{}", err_name(&e))),
    }
    // An over-long statement fails before it parses.
    let big = "SELECT ".to_string() + &"1".repeat(64 * 1024);
    match prepare("orders", &big) {
        Ok(_) => parts.push("oversize=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("oversize=err:{}", err_name(&e))),
    }
    // Commit persists; rollback discards.
    match begin("orders") {
        Ok(txn) => {
            let inserted = txn
                .prepare("INSERT INTO t VALUES (8, 'eight')")
                .and_then(|stmt| stmt.execute(&[]));
            match inserted {
                Ok(_) => match txn.commit() {
                    Ok(()) => parts.push("txn-commit=ok".to_string()),
                    Err(e) => parts.push(format!("txn-commit=err:{}", err_name(&e))),
                },
                Err(e) => parts.push(format!("txn-commit=err:{}", err_name(&e))),
            }
        }
        Err(e) => parts.push(format!("txn-commit=err:{}", err_name(&e))),
    }
    match begin("orders") {
        Ok(txn) => {
            let inserted = txn
                .prepare("INSERT INTO t VALUES (9, 'nine')")
                .and_then(|stmt| stmt.execute(&[]));
            match inserted {
                Ok(_) => match txn.rollback() {
                    Ok(()) => match query_once("orders", "SELECT * FROM t WHERE id = 9", &[]) {
                        Ok(rows) if rows.is_empty() => {
                            parts.push("txn-rollback=ok".to_string());
                        }
                        Ok(rows) => {
                            parts.push(format!("txn-rollback=unexpected-rows:{}", rows.len()));
                        }
                        Err(e) => parts.push(format!("txn-rollback=err:{}", err_name(&e))),
                    },
                    Err(e) => parts.push(format!("txn-rollback=err:{}", err_name(&e))),
                },
                Err(e) => parts.push(format!("txn-rollback=err:{}", err_name(&e))),
            }
        }
        Err(e) => parts.push(format!("txn-rollback=err:{}", err_name(&e))),
    }
    let names = databases();
    if names.contains(&"orders".to_string()) && names.contains(&"ledger".to_string()) {
        parts.push(format!("databases=ok:{}", names.join(",")));
    } else {
        parts.push(format!("databases=unexpected:{names:?}"));
    }

    parts.join(" ")
}

fn err_name(e: &SqlError) -> &str {
    match e {
        SqlError::NotGranted => "not-granted",
        SqlError::DatabaseNotConfigured => "database-not-configured",
        SqlError::ReadOnlyConnection => "read-only-connection",
        SqlError::PrepareFailed(_) => "prepare-failed",
        SqlError::ExecutionFailed(_) => "execution-failed",
        SqlError::PoolExhausted => "pool-exhausted",
        SqlError::ResultTooLarge => "result-too-large",
        SqlError::ArgumentMismatch(_) => "argument-mismatch",
    }
}
