// SPDX-License-Identifier: Apache-2.0

//! Crypto probe guest: exercises `qqq:crypto/hmac`, `qqq:crypto/aead` and
//! `qqq:crypto/signing` and encodes every outcome in a summary string the
//! host asserts on.

wit_bindgen::generate!({
    world: "probe",
    path: "wit",
    generate_all,
});

use exports::qqq::http::incoming_handler::{Guest as HttpGuest, HttpError, Request, Response};
use exports::qqq::iface_probe_crypto::probe_api::Guest as ProbeGuest;
use qqq::crypto::aead::{decrypt, encrypt, key_length, nonce_length, AeadError, Construction};
use qqq::crypto::hmac::{compute, verify, Algorithm as HmacAlgorithm, HmacError};
use qqq::crypto::signing::{
    self as signing, public_key, Algorithm as SignAlgorithm, SignatureError,
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
    fn probe_crypto() -> String {
        run_scenario()
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn run_scenario() -> String {
    let mut parts: Vec<String> = Vec::new();

    match compute(HmacAlgorithm::Sha256, &[0x0b; 20], b"Hi There") {
        Ok(tag)
            if hex(&tag) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" =>
        {
            parts.push("hmac-sha256=ok".to_string());
        }
        Ok(tag) => parts.push(format!("hmac-sha256=unexpected-tag:{}", hex(&tag))),
        Err(e) => parts.push(format!("hmac-sha256=err:{}", hmac_err_name(&e))),
    }
    match compute(HmacAlgorithm::Sha512, &[0x0b; 20], b"Hi There") {
        Ok(tag)
            if hex(&tag)
                == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cded\
                    aa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854" =>
        {
            parts.push("hmac-sha512=ok".to_string());
        }
        Ok(tag) => parts.push(format!("hmac-sha512=unexpected-tag:{}", hex(&tag))),
        Err(e) => parts.push(format!("hmac-sha512=err:{}", hmac_err_name(&e))),
    }
    // Blake3 is deliberately ungranted in this probe's manifest: the call
    // must fail closed naming the allowlist, not compute.
    match compute(HmacAlgorithm::Blake3, &[0u8; 32], b"abc") {
        Ok(_) => parts.push("hmac-blake3-unlisted=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("hmac-blake3-unlisted=err:{}", hmac_err_name(&e))),
    }
    let tag = compute(HmacAlgorithm::Sha256, &[0x0bu8; 20], b"Hi There").expect("sha256 computes");
    let ok = verify(HmacAlgorithm::Sha256, &[0x0bu8; 20], b"Hi There", &tag).expect("verify runs");
    let mut bad = tag.clone();
    bad[0] ^= 1;
    let bad_ok =
        verify(HmacAlgorithm::Sha256, &[0x0bu8; 20], b"Hi There", &bad).expect("verify runs");
    if ok && !bad_ok {
        parts.push("hmac-verify=ok".to_string());
    } else {
        parts.push(format!("hmac-verify=unexpected:ok={ok} bad={bad_ok}"));
    }

    let key: Vec<u8> = vec![7u8; 32];
    let nonce: Vec<u8> = vec![9u8; 12];
    match encrypt(Construction::Aes256Gcm, &key, &nonce, b"ad", b"secret") {
        Ok(ct) => match decrypt(Construction::Aes256Gcm, &key, &nonce, b"ad", &ct) {
            Ok(pt) if pt == b"secret" => parts.push("aes-roundtrip=ok".to_string()),
            Ok(_) => parts.push("aes-roundtrip=unexpected-plaintext".to_string()),
            Err(e) => parts.push(format!("aes-roundtrip=err:{}", aead_err_name(&e))),
        },
        Err(e) => parts.push(format!("aes-roundtrip=err:{}", aead_err_name(&e))),
    }
    match encrypt(
        Construction::Aes256Gcm,
        &vec![0u8; 32],
        &vec![0u8; 12],
        &[],
        &[],
    ) {
        Ok(ct) if ct.len() == 16 => match decrypt(
            Construction::Aes256Gcm,
            &vec![0u8; 32],
            &vec![0u8; 12],
            &[],
            &ct,
        ) {
            Ok(pt) if pt.is_empty() => parts.push("aes-zero=ok".to_string()),
            Ok(_) => parts.push("aes-zero=unexpected-plaintext".to_string()),
            Err(e) => parts.push(format!("aes-zero=err:{}", aead_err_name(&e))),
        },
        Ok(ct) => parts.push(format!("aes-zero=unexpected-len:{}", ct.len())),
        Err(e) => parts.push(format!("aes-zero=err:{}", aead_err_name(&e))),
    }
    if let Ok(mut ct) = encrypt(Construction::Aes256Gcm, &key, &nonce, b"ad", b"secret") {
        ct[0] ^= 1;
        match decrypt(Construction::Aes256Gcm, &key, &nonce, b"ad", &ct) {
            Err(AeadError::AuthenticationFailed) => {
                parts.push("aes-tamper=err:authentication-failed".to_string());
            }
            other => parts.push(format!("aes-tamper=unexpected:{other:?}")),
        }
    } else {
        parts.push("aes-tamper=unexpected-encrypt-failed".to_string());
    }
    // ChaCha20-Poly1305 is deliberately ungranted: the call must fail
    // closed naming the allowlist.
    match encrypt(Construction::Chacha20Poly1305, &key, &nonce, b"ad", b"x") {
        Ok(_) => parts.push("chacha-unlisted=unexpected-ok".to_string()),
        Err(e) => parts.push(format!("chacha-unlisted=err:{}", aead_err_name(&e))),
    }

    let seed = hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let expected_pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    match public_key(SignAlgorithm::Ed25519, &seed) {
        Ok(pk) if hex(&pk) == expected_pub => parts.push("ed25519-pubkey=ok".to_string()),
        Ok(pk) => parts.push(format!("ed25519-pubkey=unexpected:{}", hex(&pk))),
        Err(e) => parts.push(format!("ed25519-pubkey=err:{}", sign_err_name(&e))),
    }
    let expected_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    match signing::sign(SignAlgorithm::Ed25519, &seed, &[]) {
        Ok(sig) if hex(&sig) == expected_sig => parts.push("ed25519-sign=ok".to_string()),
        Ok(sig) => parts.push(format!("ed25519-sign=unexpected:{}", hex(&sig))),
        Err(e) => parts.push(format!("ed25519-sign=err:{}", sign_err_name(&e))),
    }
    let zeros = vec![0u8; 64];
    let sig_bytes = hex_decode(expected_sig);
    let pub_bytes = hex_decode(expected_pub);
    match signing::verify(SignAlgorithm::Ed25519, &pub_bytes, &[], &sig_bytes) {
        Ok(true) => {
            match signing::verify(SignAlgorithm::Ed25519, &pub_bytes, b"tampered", &zeros) {
                Ok(false) => parts.push("ed25519-verify=ok".to_string()),
                other => parts.push(format!("ed25519-verify=unexpected-wrong:{other:?}")),
            }
        }
        other => parts.push(format!("ed25519-verify=unexpected:{other:?}")),
    }
    match signing::verify(SignAlgorithm::Ed25519, &pub_bytes, b"tampered", &zeros) {
        Ok(false) => parts.push("ed25519-wrong-msg=ok:false".to_string()),
        other => parts.push(format!("ed25519-wrong-msg=unexpected:{other:?}")),
    }

    if nonce_length(Construction::Aes256Gcm) == 12
        && key_length(Construction::Aes256Gcm) == 32
        && nonce_length(Construction::Chacha20Poly1305) == 12
        && key_length(Construction::Chacha20Poly1305) == 32
    {
        parts.push("lengths=ok".to_string());
    } else {
        parts.push("lengths=unexpected".to_string());
    }

    parts.join(" ")
}

fn hex_decode(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "test vectors are whole bytes");
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ascii hex"), 16)
                .expect("hex digits")
        })
        .collect()
}

fn hmac_err_name(e: &HmacError) -> &'static str {
    match e {
        HmacError::AlgorithmNotAllowed => "algorithm-not-allowed",
        HmacError::InvalidKey => "invalid-key",
    }
}

fn aead_err_name(e: &AeadError) -> &'static str {
    match e {
        AeadError::ConstructionNotAllowed => "construction-not-allowed",
        AeadError::AuthenticationFailed => "authentication-failed",
        AeadError::InvalidNonce => "invalid-nonce",
        AeadError::InvalidKey => "invalid-key",
    }
}

fn sign_err_name(e: &SignatureError) -> &'static str {
    match e {
        SignatureError::AlgorithmNotAllowed => "algorithm-not-allowed",
        SignatureError::InvalidKey => "invalid-key",
        SignatureError::InvalidSignature => "invalid-signature",
    }
}
