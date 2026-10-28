// SPDX-License-Identifier: Apache-2.0

//! DNS probe guest: exercises `qqq:dns/resolver` and encodes every outcome
//! in a summary string the host asserts on.

wit_bindgen::generate!({
    world: "probe",
    path: "wit",
    generate_all,
});

use exports::qqq::http::incoming_handler::{Guest as HttpGuest, HttpError, Request, Response};
use exports::qqq::iface_probe_dns::probe_api::Guest as ProbeGuest;
use qqq::dns::resolver::{allowed_names, resolve, resolve_many, Address, DnsError};

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
    fn probe_dns() -> String {
        run_scenario()
    }
}

fn run_scenario() -> String {
    let mut parts: Vec<String> = Vec::new();

    match resolve("api.example.com") {
        Ok(addrs) => {
            parts.push(format!("resolve=ok:{}", addrs.len()));
            let first_v4 = matches!(addrs.first(), Some(Address::Ipv4(_)));
            parts.push(format!(
                "resolve-v4-first={}",
                if first_v4 { "ok" } else { "no" }
            ));
        }
        Err(e) => parts.push(format!("resolve=err:{}", err_name(&e))),
    }
    match resolve("missing.example.com") {
        Ok(_) => parts.push("resolve-missing=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("resolve-missing=err:{}", err_name(&e))),
    }
    match resolve("unlisted.example.com") {
        Ok(_) => parts.push("resolve-unlisted=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("resolve-unlisted=err:{}", err_name(&e))),
    }
    match resolve_many(&[
        "missing.example.com".to_string(),
        "api.example.com".to_string(),
    ]) {
        Ok(results) => {
            parts.push(format!("resolve-many=ok:{}", results.len()));
            let order_ok = matches!(&results[..], [Err(_), Ok(_)])
                && results[1].as_ref().is_ok_and(|addrs| addrs.len() == 2);
            parts.push(format!(
                "resolve-many-order={}",
                if order_ok { "ok" } else { "bad" }
            ));
        }
        Err(e) => parts.push(format!("resolve-many=err:{}", err_name(&e))),
    }
    let names = allowed_names();
    if names.contains(&"api.example.com".to_string()) {
        parts.push(format!("allowed-names=ok:{}", names.join(",")));
    } else {
        parts.push(format!("allowed-names=unexpected:{:?}", names));
    }
    // 129 names exceeds the host batch cap: the whole call fails before any
    // per-name lookup runs.
    let big: Vec<String> = (0..129).map(|i| format!("n{i}.example.com")).collect();
    match resolve_many(&big) {
        Ok(_) => parts.push("batch-too-big=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("batch-too-big=err:{}", err_name(&e))),
    }
    match resolve(&"a".repeat(300)) {
        Ok(_) => parts.push("big-name=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("big-name=err:{}", err_name(&e))),
    }

    parts.join(" ")
}

fn err_name(e: &DnsError) -> &str {
    match e {
        DnsError::NotGranted => "not-granted",
        DnsError::NameNotAllowed => "name-not-allowed",
        DnsError::NotFound => "not-found",
        DnsError::Timeout => "timeout",
        DnsError::ResolverFailed(_) => "resolver-failed",
    }
}
