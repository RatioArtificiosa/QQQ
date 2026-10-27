// SPDX-License-Identifier: Apache-2.0

//! Secrets probe guest: exercises `qqq:secrets/secret-use` and encodes every
//! outcome — success values and WIT error names alike — into one summary
//! string the host test asserts on.

wit_bindgen::generate!({
    world: "probe",
    path: "wit",
    generate_all,
});

use exports::qqq::http::incoming_handler::{Guest as HttpGuest, HttpError, Request, Response};
use exports::qqq::iface_probe_secrets::probe_api::Guest as ProbeGuest;
use qqq::secrets::secret_use::{
    apply, exists, permitted_operations, SecretError, SecretOp, VerifyRequest,
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
    fn probe_secrets() -> String {
        run_scenario()
    }
}

fn run_scenario() -> String {
    // Every outcome is encoded raw (`ok:<detail>` or `err:<wit-name>`): the
    // guest must not assume the host's grants, so the host asserts what its
    // grants imply. A `verify` answer is one byte, `1` valid or `0` invalid.
    let mut parts: Vec<String> = Vec::new();

    parts.push(format!("exists-k={}", exists("K")));
    parts.push(format!("exists-unknown={}", exists("NO-SUCH-SECRET")));
    parts.push(format!("exists-unresolved={}", exists("UNRESOLVED")));
    match apply("UNRESOLVED", &SecretOp::Sign(b"hello".to_vec()), &[]) {
        Ok(_) => parts.push("unresolved=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("unresolved=err:{}", err_name(&e))),
    }

    parts.push(format!("ops-k={}", permitted_operations("K").len()));
    parts.push(format!(
        "ops-unknown={}",
        permitted_operations("NO-SUCH-SECRET").len()
    ));

    match apply("K", &SecretOp::Sign(b"hello".to_vec()), &[]) {
        Ok(sig) => {
            parts.push(format!("sign=ok:{}", sig.len()));
            match apply(
                "K",
                &SecretOp::Verify(VerifyRequest {
                    input: b"hello".to_vec(),
                    signature: sig,
                }),
                &[],
            ) {
                Ok(v) => parts.push(format!("verify=ok:{}", hex(&v))),
                Err(e) => parts.push(format!("verify=err:{}", err_name(&e))),
            }
        }
        Err(e) => parts.push(format!("sign=err:{}", err_name(&e))),
    }

    match apply("K", &SecretOp::Hmac(b"hello".to_vec()), &[]) {
        Ok(mac) => parts.push(format!("hmac=ok:{}", mac.len())),
        Err(e) => parts.push(format!("hmac=err:{}", err_name(&e))),
    }
    let enc = match apply("K", &SecretOp::Encrypt(b"hello".to_vec()), &[]) {
        Ok(ct) => {
            parts.push(format!("encrypt=ok:{}", ct.len()));
            Some(ct)
        }
        Err(e) => {
            parts.push(format!("encrypt=err:{}", err_name(&e)));
            None
        }
    };
    if let Some(ct) = enc {
        match apply("K", &SecretOp::Decrypt(ct), &[]) {
            Ok(pt) => parts.push(format!("decrypt=ok:{}", String::from_utf8_lossy(&pt))),
            Err(e) => parts.push(format!("decrypt=err:{}", err_name(&e))),
        }
    }
    match apply("K", &SecretOp::Encrypt(b"hello".to_vec()), &[]) {
        Ok(mut ct) => {
            if let Some(last) = ct.last_mut() {
                *last ^= 0x01;
            }
            match apply("K", &SecretOp::Decrypt(ct), &[]) {
                Ok(_) => parts.push("tamper=unexpected-ok".to_string()),
                Err(e) => parts.push(format!("tamper=err:{}", err_name(&e))),
            }
        }
        Err(e) => parts.push(format!("tamper-setup=err:{}", err_name(&e))),
    }
    match apply("K", &SecretOp::PublicKey, &[]) {
        Ok(pk) => parts.push(format!("public-key=ok:{}", pk.len())),
        Err(e) => parts.push(format!("public-key=err:{}", err_name(&e))),
    }

    match apply("NO-SUCH-SECRET", &SecretOp::Sign(b"hello".to_vec()), &[]) {
        Ok(_) => parts.push("unknown=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("unknown=err:{}", err_name(&e))),
    }

    parts.join(" ")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn err_name(e: &SecretError) -> &'static str {
    match e {
        SecretError::NotGranted => "not-granted",
        SecretError::Unavailable => "unavailable",
        SecretError::OperationNotPermitted => "operation-not-permitted",
        SecretError::InputTooLong => "input-too-long",
    }
}
