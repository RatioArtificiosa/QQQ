// SPDX-License-Identifier: Apache-2.0

//! Kv probe guest: exercises `qqq:kv/store` and encodes every outcome in a
//! summary string the host asserts on.

wit_bindgen::generate!({
    world: "probe",
    path: "wit",
    generate_all,
});

use exports::qqq::http::incoming_handler::{Guest as HttpGuest, HttpError, Request, Response};
use exports::qqq::iface_probe_kv::probe_api::Guest as ProbeGuest;
use qqq::kv::store::{delete, exists, get, get_many, keys, set, stores, KvError};

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
    fn probe_kv() -> String {
        run_scenario()
    }
}

fn run_scenario() -> String {
    // Writes land before reads on purpose: every `get` below proves the
    // value crossed into the shared backend and back, not just that the
    // call did not fail.
    let mut parts: Vec<String> = Vec::new();

    match set("s", "a", b"1", None) {
        Ok(()) => parts.push("set-a=ok".to_string()),
        Err(e) => parts.push(format!("set-a=err:{}", err_name(&e))),
    }
    match set("s", "b", b"2", None) {
        Ok(()) => parts.push("set-b=ok".to_string()),
        Err(e) => parts.push(format!("set-b=err:{}", err_name(&e))),
    }
    match keys("s", "", 100) {
        Ok(list) => parts.push(format!("keys=ok:{}", list.join(","))),
        Err(e) => parts.push(format!("keys=err:{}", err_name(&e))),
    }
    match set("s", "k", b"hello", None) {
        Ok(()) => parts.push("set=ok".to_string()),
        Err(e) => parts.push(format!("set=err:{}", err_name(&e))),
    }
    match get("s", "k") {
        Ok(Some(value)) => parts.push(format!("get=ok:{}", String::from_utf8_lossy(&value))),
        Ok(None) => parts.push("get=ok:none-unexpected".to_string()),
        Err(e) => parts.push(format!("get=err:{}", err_name(&e))),
    }
    match get("s", "missing") {
        Ok(None) => parts.push("get-missing=ok:none".to_string()),
        Ok(Some(_)) => parts.push("get-missing=unexpected-some".to_string()),
        Err(e) => parts.push(format!("get-missing=err:{}", err_name(&e))),
    }
    match exists("s", "k") {
        Ok(found) => parts.push(format!("exists={found}")),
        Err(e) => parts.push(format!("exists=err:{}", err_name(&e))),
    }
    match exists("s", "missing") {
        Ok(found) => parts.push(format!("exists-missing={found}")),
        Err(e) => parts.push(format!("exists-missing=err:{}", err_name(&e))),
    }
    match set("s", "temp", b"v", Some(3600)) {
        Ok(()) => match get("s", "temp") {
            Ok(Some(_)) => parts.push("ttl=ok:v".to_string()),
            other => parts.push(format!("ttl=unexpected:{other:?}")),
        },
        Err(e) => parts.push(format!("ttl=err:{}", err_name(&e))),
    }
    match get_many("s", &["k".to_string(), "missing".to_string()]) {
        Ok(values) => parts.push(format!("get-many=ok:{}", values.len())),
        Err(e) => parts.push(format!("get-many=err:{}", err_name(&e))),
    }
    match delete("s", "k") {
        Ok(()) => parts.push("delete=ok".to_string()),
        Err(e) => parts.push(format!("delete=err:{}", err_name(&e))),
    }
    match get("s", "k") {
        Ok(None) => parts.push("get-after-delete=ok:none".to_string()),
        Ok(Some(_)) => parts.push("get-after-delete=unexpected-some".to_string()),
        Err(e) => parts.push(format!("get-after-delete=err:{}", err_name(&e))),
    }
    parts.push(format!("stores={}", stores().join(",")));
    match get("nope", "k") {
        Ok(_) => parts.push("unlisted=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("unlisted=err:{}", err_name(&e))),
    }
    match set("s", "big", &vec![0u8; 70 * 1024], None) {
        Ok(()) => parts.push("big-value=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("big-value=err:{}", err_name(&e))),
    }
    match set("s", &"k".repeat(2048), b"v", None) {
        Ok(()) => parts.push("big-key=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("big-key=err:{}", err_name(&e))),
    }

    parts.join(" ")
}

fn err_name(e: &KvError) -> &str {
    match e {
        KvError::NotGranted => "not-granted",
        KvError::StoreNotConfigured => "store-not-configured",
        KvError::ReadOnly => "read-only",
        KvError::EntryTooLarge => "entry-too-large",
        KvError::QuotaExceeded => "quota-exceeded",
        KvError::BackendFailed(_) => "backend-failed",
    }
}
