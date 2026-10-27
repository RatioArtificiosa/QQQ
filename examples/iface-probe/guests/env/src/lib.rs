// SPDX-License-Identifier: Apache-2.0

//! Env probe guest: exercises `qqq:env/environment` and encodes every outcome
//! — values, WIT error names, and the allowlist — into one summary string
//! the host asserts on.

wit_bindgen::generate!({
    world: "probe",
    path: "wit",
    generate_all,
});

use exports::qqq::http::incoming_handler::{HttpError, Request, Response};
use exports::qqq::iface_probe_env::probe_api::Guest as ProbeGuest;
use qqq::env::environment::{allowed_names, get, get_or, EnvError};

struct Probe;

export!(Probe);

use exports::qqq::http::incoming_handler::Guest as HttpGuest;

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
    fn probe_env() -> String {
        run_scenario()
    }
}

fn run_scenario() -> String {
    // Raw outcomes; the host asserts what its grants imply.
    let mut parts: Vec<String> = Vec::new();
    match get("REGION") {
        Ok(v) => parts.push(format!("get-region=ok:{v}")),
        Err(e) => parts.push(format!("get-region=err:{}", err_name(&e))),
    }
    match get("MISSING") {
        Ok(v) => parts.push(format!("get-missing=unexpected-ok:{v}")),
        Err(e) => parts.push(format!("get-missing=err:{}", err_name(&e))),
    }
    match get("UNLISTED") {
        Ok(v) => parts.push(format!("get-unlisted=unexpected-ok:{v}")),
        Err(e) => parts.push(format!("get-unlisted=err:{}", err_name(&e))),
    }
    match get_or("MISSING", "fallback") {
        Ok(v) => parts.push(format!("get-or-missing=ok:{v}")),
        Err(e) => parts.push(format!("get-or-missing=err:{}", err_name(&e))),
    }
    match get_or("UNLISTED", "fallback") {
        Ok(v) => parts.push(format!("get-or-unlisted=unexpected-ok:{v}")),
        Err(e) => parts.push(format!("get-or-unlisted=err:{}", err_name(&e))),
    }
    match get("BINARY") {
        Ok(_) => parts.push("get-binary=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("get-binary=err:{}", err_name(&e))),
    }
    let names = allowed_names();
    parts.push(format!("allowed={}", names.join(",")));
    parts.join(" ")
}

fn err_name(e: &EnvError) -> &'static str {
    match e {
        EnvError::NotAllowed => "not-allowed",
        EnvError::Unset => "unset",
        EnvError::InvalidUtf8 => "invalid-utf8",
    }
}
