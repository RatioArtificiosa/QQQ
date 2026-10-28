// SPDX-License-Identifier: Apache-2.0

//! Queue probe guest: exercises `qqq:queue/messaging` and encodes every
//! outcome in a summary string the host asserts on.

wit_bindgen::generate!({
    world: "probe",
    path: "wit",
    generate_all,
});

use exports::qqq::http::incoming_handler::{Guest as HttpGuest, HttpError, Request, Response};
use exports::qqq::iface_probe_queue::probe_api::Guest as ProbeGuest;
use qqq::queue::messaging::{
    acknowledge, publish, publish_many, queues, receive, reject, QueueError,
};

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
    fn probe_queue() -> String {
        run_scenario()
    }
}

fn run_scenario() -> String {
    // Receives follow publishes on purpose: every delivery below proves a
    // message crossed into the shared backend and back out, not just that
    // the call did not fail.
    let mut parts: Vec<String> = Vec::new();

    match publish("q", b"m1") {
        Ok(()) => parts.push("publish=ok".to_string()),
        Err(e) => parts.push(format!("publish=err:{}", err_name(&e))),
    }
    match publish_many("q", &[b"a".to_vec(), b"b".to_vec()]) {
        Ok(()) => parts.push("publish-many=ok".to_string()),
        Err(e) => parts.push(format!("publish-many=err:{}", err_name(&e))),
    }
    let first = match receive("q", 0) {
        Ok(Some(delivery)) => {
            parts.push(format!("receive=ok:{}", delivery.delivery_count));
            Some(delivery)
        }
        Ok(None) => {
            parts.push("receive=ok:none-unexpected".to_string());
            None
        }
        Err(e) => {
            parts.push(format!("receive=err:{}", err_name(&e)));
            None
        }
    };
    if let Some(delivery) = first {
        match acknowledge("q", &delivery.id) {
            Ok(()) => parts.push("ack=ok".to_string()),
            Err(e) => parts.push(format!("ack=err:{}", err_name(&e))),
        }
    }
    let second = match receive("q", 0) {
        Ok(Some(delivery)) => Some(delivery),
        Ok(None) => {
            parts.push("receive2=ok:none-unexpected".to_string());
            None
        }
        Err(e) => {
            parts.push(format!("receive2=err:{}", err_name(&e)));
            None
        }
    };
    if let Some(delivery) = second {
        match reject("q", &delivery.id) {
            Ok(()) => parts.push("reject=ok".to_string()),
            Err(e) => parts.push(format!("reject=err:{}", err_name(&e))),
        }
    }
    match receive("q", 0) {
        Ok(Some(delivery)) => {
            parts.push(format!("redeliver=ok:{}", delivery.delivery_count));
            match acknowledge("q", &delivery.id) {
                Ok(()) => parts.push("redeliver-ack=ok".to_string()),
                Err(e) => parts.push(format!("redeliver-ack=err:{}", err_name(&e))),
            }
        }
        Ok(None) => parts.push("redeliver=ok:none-unexpected".to_string()),
        Err(e) => parts.push(format!("redeliver=err:{}", err_name(&e))),
    }
    // Drain the rest so the scenario ends empty: ack everything remaining.
    loop {
        match receive("q", 0) {
            Ok(Some(delivery)) => {
                if acknowledge("q", &delivery.id).is_err() {
                    parts.push("drain-ack=err".to_string());
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                parts.push(format!("drain=err:{}", err_name(&e)));
                break;
            }
        }
    }
    match receive("q", 0) {
        Ok(None) => parts.push("receive-empty=ok:none".to_string()),
        Ok(Some(_)) => parts.push("receive-empty=unexpected-some".to_string()),
        Err(e) => parts.push(format!("receive-empty=err:{}", err_name(&e))),
    }
    let names: Vec<String> = queues().iter().map(|(name, _)| name.clone()).collect();
    parts.push(format!("queues={}", names.join(",")));
    match publish("nope", b"v") {
        Ok(()) => parts.push("unlisted=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("unlisted=err:{}", err_name(&e))),
    }
    match publish("q", &vec![0u8; 70 * 1024]) {
        Ok(()) => parts.push("big-message=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("big-message=err:{}", err_name(&e))),
    }

    parts.join(" ")
}

fn err_name(e: &QueueError) -> &str {
    match e {
        QueueError::NotGranted => "not-granted",
        QueueError::QueueNotConfigured => "queue-not-configured",
        QueueError::MessageTooLarge => "message-too-large",
        QueueError::QuotaExceeded => "quota-exceeded",
        QueueError::BackendFailed(_) => "backend-failed",
        QueueError::LeaseExpired => "lease-expired",
    }
}
