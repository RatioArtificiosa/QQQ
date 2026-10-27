// SPDX-License-Identifier: Apache-2.0

//! Trace probe guest: exercises `qqq:trace/tracing` and reports trace ids,
//! parentage, and error propagation in a summary the host asserts on.

wit_bindgen::generate!({
    world: "probe",
    path: "wit",
    generate_all,
});

use exports::qqq::http::incoming_handler::{HttpError, Request, Response};
use exports::qqq::iface_probe_trace::probe_api::Guest as ProbeGuest;
use qqq::trace::tracing::{current_traceparent, start_span, Attribute, AttributeValue};

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
    fn probe_trace() -> String {
        run_scenario()
    }
}

fn attr(name: &str, value: AttributeValue) -> Attribute {
    Attribute {
        name: name.to_string(),
        value,
    }
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn run_scenario() -> String {
    let mut parts: Vec<String> = Vec::new();

    match current_traceparent() {
        None => parts.push("tp-start=none".to_string()),
        Some(tp) => parts.push(format!("tp-start=unexpected:{tp}")),
    }

    let root = match start_span("root") {
        Ok(r) => {
            parts.push("root=ok".to_string());
            Some(r)
        }
        Err(e) => {
            parts.push(format!("root=err:{e:?}"));
            None
        }
    };
    let Some(root) = root else {
        parts.push("trace-id=none".to_string());
        return parts.join(" ");
    };

    match current_traceparent() {
        None => parts.push("tp-root=none-unexpected".to_string()),
        Some(tp) => {
            let ok = tp.starts_with("00-") && tp.len() == 55 && tp.ends_with("-01");
            parts.push(format!("tp-root={}", if ok { "ok" } else { "malformed" }));
        }
    }

    let kid = match root.child("kid") {
        Ok(k) => {
            parts.push("child=ok".to_string());
            Some(k)
        }
        Err(e) => {
            parts.push(format!("child=err:{e:?}"));
            None
        }
    };
    if let Some(kid) = kid {
        match kid.event("ev", &[attr("k", AttributeValue::Text("v".to_string()))]) {
            Ok(()) => parts.push("event=ok".to_string()),
            Err(e) => parts.push(format!("event=err:{e:?}")),
        }
        match kid.set_attributes(&[attr("n", AttributeValue::Integer(1))]) {
            Ok(()) => parts.push("attrs=ok".to_string()),
            Err(e) => parts.push(format!("attrs=err:{e:?}")),
        }
    }

    match root.set_error("boom") {
        Ok(()) => parts.push("set-error=ok".to_string()),
        Err(e) => parts.push(format!("set-error=err:{e:?}")),
    }

    parts.join(" ")
}
