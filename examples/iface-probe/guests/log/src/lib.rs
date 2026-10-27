// SPDX-License-Identifier: Apache-2.0

//! Log probe guest: exercises `qqq:log/logging` and encodes every outcome in
//! a summary string. Redaction itself is host-observable only; the host test
//! reads the recorded entries.

wit_bindgen::generate!({
    world: "probe",
    path: "wit",
    generate_all,
});

use exports::qqq::http::incoming_handler::{HttpError, Request, Response};
use exports::qqq::iface_probe_log::probe_api::Guest as ProbeGuest;
use qqq::log::logging::{emit, emit_many, enabled, Attribute, AttributeValue, Level, LogError};

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
    fn probe_log() -> String {
        run_scenario()
    }
}

/// A value the host test registers as a secret: emitting it must store
/// `[redacted:secret]`, never the bytes.
const LEAK: &str = "test-only-leak-value-4f6d";

fn run_scenario() -> String {
    let mut parts: Vec<String> = Vec::new();

    match emit(
        Level::Info,
        "hello",
        &[
            Attribute {
                name: "t".to_string(),
                value: AttributeValue::Text("v".to_string()),
            },
            Attribute {
                name: "n".to_string(),
                value: AttributeValue::Integer(7),
            },
            Attribute {
                name: "f".to_string(),
                value: AttributeValue::Float(0.5),
            },
            Attribute {
                name: "b".to_string(),
                value: AttributeValue::Boolean(true),
            },
        ],
    ) {
        Ok(()) => parts.push("emit=ok".to_string()),
        Err(e) => parts.push(format!("emit=err:{}", err_name(&e))),
    }
    match emit(Level::Error, LEAK, &[]) {
        Ok(()) => parts.push("emit-secret=ok".to_string()),
        Err(e) => parts.push(format!("emit-secret=err:{}", err_name(&e))),
    }
    let mut many = Vec::new();
    for i in 0..70u32 {
        many.push((
            Level::Debug,
            format!("m{i}"),
            vec![Attribute {
                name: "i".to_string(),
                value: AttributeValue::Integer(i as i64),
            }],
        ));
    }
    match emit_many(&many) {
        Ok(()) => parts.push("emit-many=ok".to_string()),
        Err(e) => parts.push(format!("emit-many=err:{}", err_name(&e))),
    }
    let big = "x".repeat(70 * 1024);
    match emit(Level::Info, &big, &[]) {
        Ok(()) => parts.push("emit-big=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("emit-big=err:{}", err_name(&e))),
    }
    let mut attrs = Vec::new();
    for i in 0..70u32 {
        attrs.push(Attribute {
            name: format!("k{i}"),
            value: AttributeValue::Boolean(false),
        });
    }
    match emit(Level::Info, "many-attrs", &attrs) {
        Ok(()) => parts.push("emit-attrs=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("emit-attrs=err:{}", err_name(&e))),
    }

    parts.push(format!("enabled-trace={}", enabled(Level::Trace)));
    parts.push(format!("enabled-error={}", enabled(Level::Error)));
    parts.join(" ")
}

fn err_name(e: &LogError) -> &str {
    match e {
        LogError::NotGranted => "not-granted",
        LogError::RecordTooLarge => "record-too-large",
    }
}
