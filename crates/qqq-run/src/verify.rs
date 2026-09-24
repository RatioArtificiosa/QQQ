// SPDX-License-Identifier: Apache-2.0
//! `qqqai verify <artifact>` — signature and attestation checking (`§5.2`, `SUP-002`).
//!
//! # The two halves, and which one is real
//!
//! §5.2 describes the command as *"Verify signature + attestation"*.
//!
//! * **Signature.** Implemented end to end over [`qqq_pkg::signature`]: a real Ed25519
//!   verification, against a trust policy built from `--key` and `--policy`, with the
//!   failure naming the signing key and every key the policy would have accepted.
//! * **Attestation.** Not implemented, and the report says so with `attestation:
//!   not_checked` plus the checklist item that owns it. §7.4 fixes the algorithm for artifact
//!   signing; provenance attestation is `SUP-004` and `SUP-009`, and there is no attestation
//!   format in this repository to verify against. Reporting "attestation: ok" in that state
//!   would be a green check over nothing, which is worse than an absent one — the same
//!   reasoning `qqqai audit` gives for never claiming a check it did not perform.
//!
//! # Why the exit status carries the answer
//!
//! This is the command a CI job runs before deploying an artifact. A verification result that
//! a script must parse out of prose is not usable as a gate, so:
//!
//! | Situation | Status |
//! |---|---|
//! | signature present and valid | `0`, `verified` |
//! | no signature, policy does not require one | `0`, `unsigned` |
//! | no signature, policy requires one | non-zero |
//! | signature invalid | non-zero |
//!
//! The third row is the one worth stating: an *optional* signature that is absent is a policy
//! choice, not a failure, and conflating the two would make the opportunistic policy
//! indistinguishable from a requirement.

use std::path::{Path, PathBuf};

use qqq_core::{Error, ErrorCode, Result};
use qqq_pkg::signature::{TrustPolicy, Verification, VerifyingKey};

/// What `qqqai verify` was asked to check.
///
/// # Why `Default` is deliberately not derived
///
/// `VerifyOptions::default()` would produce an empty `artifact` path, and every caller needs a
/// real one — the type has no valid all-defaults state. Deriving `Default` therefore offers a
/// way to build an invalid request that the compiler would otherwise prevent, and it was
/// removed after external review pointed out the hazard. Nothing called it; it existed only as
/// something a future caller could reach for and get wrong.
///
/// A `#[cfg(test)]` fixture is what the tests use instead, which keeps the convenience where it
/// is wanted and out of the public surface.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// The artifact to verify.
    pub artifact: PathBuf,
    /// Public keys accepted as signers, from `--key`.
    pub keys: Vec<[u8; 32]>,
    /// Whether a signature is **required**, from `--policy`.
    pub require_signature: bool,
}

/// The result of a verification, in the shape the envelope publishes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyOutput {
    /// The artifact that was checked.
    pub artifact: String,
    /// Its SHA-256, because a verification is about *these* bytes.
    pub digest: String,
    /// `verified`, `unsigned` or `missing`.
    pub state: &'static str,
    /// The signing key's hex id, when there was a signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Whether the signing key was one the policy *required*.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_key: Option<bool>,
    /// How many keys the policy accepted.
    pub keys_in_policy: usize,
    /// Whether the policy required a signature.
    pub signature_required: bool,
    /// The attestation state. Always `not_checked` today, with `attestation_owner` naming
    /// the item that will change that.
    pub attestation: &'static str,
    /// The checklist item that owns the attestation half.
    pub attestation_owner: &'static str,
    /// Whether the command's answer is a pass.
    ///
    /// Present because the exit code and this field must agree, and a script reading JSON
    /// should not have to reimplement the table in the module doc comment.
    pub ok: bool,
}

impl VerifyOutput {
    /// The digest this verification is about, as hex.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        &self.digest
    }
}

impl crate::output::CommandOutput for VerifyOutput {
    fn command(&self) -> crate::output::CommandName {
        crate::output::CommandName::Verify
    }

    /// The one-line conclusion, naming what was actually checked.
    ///
    /// # Why the sentence names the attestation gap
    ///
    /// Because "verified" alone would be read as covering the whole of §5.2's *"signature +
    /// attestation"*, and this command checks one of the two. A reader who stops at the first
    /// line must not come away believing more was proven than was.
    fn summary(&self) -> String {
        use std::fmt::Write as _;
        let mut out = match (&self.key_id, self.state) {
            (Some(id), "verified") => {
                format!("{}: signature verified against key {id}", self.artifact)
            }
            (_, "unsigned") => format!(
                "{}: unsigned, and the policy does not require a signature",
                self.artifact
            ),
            _ => format!("{}: no acceptable signature", self.artifact),
        };

        let _ = write!(
            out,
            "\n  digest sha256:{}\n  {} key(s) in the policy{}",
            self.digest,
            self.keys_in_policy,
            if self.signature_required {
                ", a signature was required"
            } else {
                ""
            }
        );

        if self.keys_in_policy == 0 {
            let _ = write!(
                out,
                "\n\nNo keys were configured, so no signature could be attributed to a \
                 publisher.\nPass --key <hex> for each publisher key you trust."
            );
        }

        // The gap, stated rather than implied.
        let _ = write!(
            out,
            "\n\nattestation: {} (owned by `{}`)",
            self.attestation, self.attestation_owner
        );
        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Decode a hex-encoded 32-byte public key.
///
/// # Errors
///
/// `QQQ-7001`, naming the length found. `--key` is typed by a human, and the two mistakes
/// that actually happen are a truncated copy-paste and a base64 key pasted into a hex flag;
/// both are answered by saying how long the input was and how long a key is.
pub fn parse_key(hex: &str) -> Result<[u8; 32]> {
    let cleaned: String = hex
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();

    // # Why the length is counted in *characters* and validated before any slicing
    //
    // This used to compare `cleaned.len()` — **bytes** — against 64 while the message said
    // "characters", and then slice `&cleaned[i * 2..i * 2 + 2]` by byte index. A two-byte
    // character landing on an odd boundary makes that slice fall mid-character, and Rust
    // panics: measured, `--key` set to 31 ASCII bytes + `é` + 31 more ASCII bytes (64 bytes,
    // 63 characters) exited **101** with `end byte index 32 is not a char boundary`.
    //
    // A panic in an argument parser is worse than a wrong answer: the caller sees a Rust
    // backtrace for what is a typo, and the process died rather than reporting. So the
    // character count is checked first, and **non-hex input is rejected before the slicing
    // loop** — which is what makes the byte slices provably ASCII, and therefore provably on
    // boundaries.
    let char_count = cleaned.chars().count();
    if char_count != 64 {
        return Err(Error::new(
            ErrorCode::McpArgumentInvalid,
            format!("`--key` must be 64 hex characters (32 bytes), found {char_count} characters"),
        )
        .with_remediation(
            "pass the key in hex, e.g. --key 3b6a27bcceb6a42d62a3a8d02a6f0d73\
             65f1a3b5c8e9d0f1a2b3c4d5e6f70819; a base64 key looks similar and is not this",
        ));
    }

    // The non-hex check runs over the whole string, before any byte indexing. `+` is included
    // in the rejection for the reason base64 is: a base64 key can begin with `+`, and
    // `u8::from_str_radix("+f", 16)` would otherwise accept it as 15.
    if let Some(bad) = cleaned.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(Error::new(
            ErrorCode::McpArgumentInvalid,
            format!("`--key` contains a non-hex character `{bad}`"),
        )
        .with_remediation("a hex key uses only 0-9 and a-f (or A-F)"));
    }

    // Every character is now an ASCII hex digit, so the string is 64 bytes and indexing it in
    // pairs is safe by construction rather than by hope.
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = &cleaned[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).map_err(|_| {
            Error::new(
                ErrorCode::McpArgumentInvalid,
                format!("`--key` contains a non-hex character in `{pair}`"),
            )
            .with_remediation("a hex key uses only 0-9 and a-f")
        })?;
    }
    Ok(out)
}

/// Build the trust policy the options describe.
///
/// # Why `--policy` is a requirement flag rather than a named policy file
///
/// §5.2 lists `--policy` without specifying a format, and inventing a policy-file schema
/// would be designing something the Proposal has not settled — and `SUP-002` is where a
/// *configurable* policy belongs. What exists is the distinction that has teeth today: with
/// keys and no `--policy`, a signature is verified **when present**; with `--policy require`,
/// a missing signature is a failure. Both are real readings of "configurable trust policy"
/// and neither invents a format.
#[must_use]
pub fn policy_for(options: &VerifyOptions) -> TrustPolicy {
    let keys: Vec<VerifyingKey> = options
        .keys
        .iter()
        .map(|k| {
            if options.require_signature {
                VerifyingKey::required(*k)
            } else {
                VerifyingKey::optional(*k)
            }
        })
        .collect();
    if options.require_signature {
        TrustPolicy::requiring(keys)
    } else {
        TrustPolicy::opportunistic(keys)
    }
}

/// Verify an artifact against the options.
///
/// # Errors
///
/// Propagates `QQQ-5002` from [`qqq_pkg::signature::verify_files`], which covers an
/// unreadable artifact, a malformed `.sig`, an unacceptable key, a mismatched signature, and
/// a required signature that is absent.
pub fn verify(options: &VerifyOptions) -> Result<VerifyOutput> {
    let policy = policy_for(options);

    // The digest is computed and reported even on the failure path, because the first
    // question about a rejected artifact is "which bytes were rejected?" — and a report that
    // answered only "signature failed" would leave the reader unable to tell a corrupted
    // download from a substituted file.
    let digest = sha256_file(&options.artifact)?;

    // The digest is part of the failure report, so a rejection carries it rather than being
    // thrown away for the caller to recompute: the first question about a rejected artifact
    // is "which bytes were rejected?", and a report answering only "signature failed" leaves
    // the reader unable to tell a corrupted download from a substituted file.
    //
    // `outcome` is consumed rather than matched by reference, because `with_context` takes
    // `self` -- the error has to be owned for the chain to be extended.
    let signature_state = match qqq_pkg::signature::verify_files(&options.artifact, &policy) {
        Ok(v) => v,
        Err(e) => return Err(e.with_context("digest", format!("sha256:{digest}"))),
    };

    Ok(interpret(options, &signature_state, digest))
}

/// Turn a verification and a digest into the published report.
///
/// `verification` is taken by reference because it is read twice — once for the key id and
/// once for `state()` — and nothing here needs to own it.
#[must_use]
pub fn interpret(
    options: &VerifyOptions,
    verification: &Verification,
    digest: String,
) -> VerifyOutput {
    let (key_id, required_key) = match verification {
        Verification::Verified { key_id, required } => (Some(key_id.to_hex()), Some(*required)),
        _ => (None, None),
    };
    VerifyOutput {
        artifact: options.artifact.display().to_string(),
        digest,
        state: verification.state(),
        key_id,
        required_key,
        keys_in_policy: options.keys.len(),
        signature_required: options.require_signature,
        attestation: "not_checked",
        attestation_owner: "SUP-004",
        ok: verification.is_ok(),
    }
}

/// SHA-256 of a file, as lowercase hex.
///
/// # Errors
///
/// `QQQ-5002` when the file cannot be read: a verification that could not read its subject
/// did not happen, and reporting it any other way would be a check over nothing.
pub fn sha256_file(path: &Path) -> Result<String> {
    // Both imports are at the top of the body rather than beside their first use: an item
    // declared after a statement reads as though it came into scope mid-function, which it
    // does not.
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;

    let bytes = std::fs::read(path).map_err(|e| {
        Error::new(
            ErrorCode::SignatureVerificationFailed,
            format!("cannot read `{}`: {e}", path.display()),
        )
        .with_remediation("check the path; `qqqai verify` needs the artifact's bytes")
    })?;
    let digest = Sha256::digest(&bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hex_key_parses() {
        let key = parse_key(&"ab".repeat(32)).expect("parse");
        assert_eq!(key, [0xab; 32]);
    }

    #[test]
    fn a_short_key_names_both_lengths() {
        let err = parse_key("abcd").expect_err("4 characters is not a key");
        // Both numbers, asserted as the phrases they appear in. `contains("64")` alone is not
        // enough: the remediation text also contains "64", so the assertion would pass even if
        // the *found* length were reported wrongly. What must be true is the pair — what the
        // key is, and what it was.
        assert!(
            err.message.contains("64 hex characters"),
            "the required length must be stated: {}",
            err.message
        );
        assert!(
            err.message.contains("found 4 characters"),
            "the actual length must be stated: {}",
            err.message
        );
    }

    #[test]
    fn a_base64_key_is_refused_with_the_reason() {
        // A **genuine** base64 key: `base64(bytes(range(32)))` is exactly 44 characters and ends
        // in `=`. The fixture matters here. The previous version used a 60-character hex-looking
        // string while its comment claimed 44 base64 characters, so the test's name and its
        // input disagreed and a reader could not tell which mistake the test was pinning.
        //
        // The base64 alphabet shares `a-f` with hex, so this input also proves the refusal is
        // reached by *length* for the common `a-f`-only case rather than only by its `=` pad.
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        assert_eq!(
            key.chars().count(),
            44,
            "the fixture's length must be pinned"
        );
        let err = parse_key(key).expect_err("a 44-character key is not 64 characters");
        assert!(
            err.message.contains("found 44 characters"),
            "the message must report the length actually found: {}",
            err.message
        );
        assert!(err.message.contains("64 hex characters"), "{}", err.message);
    }

    /// A base64 key that is **64 characters** is refused for its alphabet, not its length.
    ///
    /// The companion to the test above: there, the length check fires first. Here the length
    /// passes and the character check must catch it, so both refusal paths are pinned and
    /// neither test can be satisfied by the other's path.
    #[test]
    fn a_64_character_base64_key_is_refused_for_its_alphabet() {
        // Exactly 64 characters, 62 of them valid hex, then the two base64-only characters that
        // hex has no room for. The length check passes, so the alphabet check is what must fire.
        let key = format!("{}/+", "ab".repeat(31));
        assert_eq!(key.chars().count(), 64, "the fixture must be 64 characters");
        let err = parse_key(&key).expect_err("`/` and `+` are not hex digits");
        assert!(
            err.message.contains("non-hex"),
            "the refusal must be about the alphabet, not the length: {}",
            err.message
        );
    }

    #[test]
    fn a_non_hex_character_is_named() {
        let mut k = "ab".repeat(31);
        k.push_str("zz");
        let err = parse_key(&k).expect_err("zz is not hex");
        // The character is named, and this asserts on the character itself rather than on the
        // surrounding punctuation, so tightening the message's quoting does not break it.
        assert!(err.message.contains('z'), "{}", err.message);
        assert!(err.message.contains("non-hex"), "{}", err.message);
    }

    /// A non-ASCII key must produce a diagnostic, not a panic.
    ///
    /// # Why this test exists, and why the fixture is shaped this way
    ///
    /// This is the regression test for a **real panic**: `parse_key` compared `String::len`
    /// (bytes) against 64 while slicing by byte index, so a two-byte character straddling an
    /// odd boundary made `&cleaned[i * 2..i * 2 + 2]` fall mid-character and Rust aborted with
    /// `end byte index 32 is not a char boundary` — measured, exit code 101.
    ///
    /// The fixture is exactly that shape: 31 ASCII characters, one two-byte character, then 31
    /// more. It is 64 **bytes** and 63 **characters**, which is the smallest input that reaches
    /// the slicing loop under the old byte-length check. A test using `"é".repeat(32)` would NOT
    /// catch it — that is 64 bytes and 32 characters, and it happens to slice cleanly — which is
    /// the "fixture that cannot exhibit the defect" trap the handbook names.
    #[test]
    fn a_non_ascii_key_is_diagnosed_rather_than_panicking() {
        let straddling = format!("{}é{}", "a".repeat(31), "a".repeat(31));
        assert_eq!(straddling.len(), 64, "the fixture must be 64 bytes");
        assert_eq!(
            straddling.chars().count(),
            63,
            "and 63 characters, which is the whole point"
        );

        let err = parse_key(&straddling).expect_err("63 characters is not a 64-character key");
        // The count in the message is the *character* count. The old message said 64 here, or
        // panicked before it could say anything.
        assert!(
            err.message.contains("63 characters"),
            "the message must report the character count: {}",
            err.message
        );
    }

    /// The `+` case, which is why the hex check rejects rather than relying on `from_str_radix`.
    ///
    /// `u8::from_str_radix("+f", 16)` returns `Ok(15)` — Rust accepts a leading sign — so a
    /// base64 key containing `+` could have been read as a valid hex key. Rejecting non-hex
    /// characters up front is what closes it.
    #[test]
    fn a_plus_sign_is_not_read_as_a_hex_digit() {
        let mut k = "ab".repeat(31);
        k.push_str("+f");
        let err = parse_key(&k).expect_err("`+f` is not a hex pair");
        assert!(err.message.contains("non-hex"), "{}", err.message);
        assert!(err.message.contains('+'), "{}", err.message);
    }

    #[test]
    fn separators_and_whitespace_are_tolerated() {
        let spaced = "ab:".repeat(32);
        assert_eq!(
            parse_key(&spaced).expect("colons are separators"),
            [0xab; 32]
        );
    }

    #[test]
    fn an_opportunistic_policy_does_not_require_a_signature() {
        let o = VerifyOptions {
            artifact: PathBuf::from("x"),
            keys: vec![[1u8; 32]],
            require_signature: false,
        };
        let p = policy_for(&o);
        assert!(!p.requires_signature());
        assert_eq!(p.keys().len(), 1);
        assert!(
            !p.keys()[0].required,
            "an opportunistic policy marks keys optional"
        );
    }

    #[test]
    fn a_required_policy_marks_every_key_required() {
        let o = VerifyOptions {
            artifact: PathBuf::from("x"),
            keys: vec![[1u8; 32], [2u8; 32]],
            require_signature: true,
        };
        let p = policy_for(&o);
        assert!(p.requires_signature());
        assert!(p.keys().iter().all(|k| k.required));
    }

    #[test]
    fn an_unsigned_artifact_under_an_opportunistic_policy_is_ok_and_says_unsigned() {
        let o = VerifyOptions {
            artifact: PathBuf::from("app.wasm"),
            keys: vec![[1u8; 32]],
            require_signature: false,
        };
        let out = interpret(&o, &Verification::Unsigned, "deadbeef".to_owned());
        assert!(
            out.ok,
            "an optional signature that is absent is not a failure"
        );
        assert_eq!(out.state, "unsigned");
        assert!(out.key_id.is_none());
        assert_eq!(out.attestation, "not_checked");
    }

    #[test]
    fn a_missing_required_signature_is_not_ok() {
        let o = VerifyOptions {
            artifact: PathBuf::from("app.wasm"),
            keys: vec![[1u8; 32]],
            require_signature: true,
        };
        let out = interpret(&o, &Verification::MissingButRequired, "deadbeef".to_owned());
        assert!(!out.ok, "a required signature that is absent must fail");
        assert_eq!(out.state, "missing");
    }

    #[test]
    fn a_summary_of_an_unsigned_artifact_does_not_claim_verification() {
        let o = VerifyOptions {
            artifact: PathBuf::from("app.wasm"),
            keys: vec![[1u8; 32]],
            require_signature: false,
        };
        let out = interpret(&o, &Verification::Unsigned, "deadbeef".to_owned());
        let text = crate::output::CommandOutput::summary(&out);
        assert!(text.contains("unsigned"), "{text}");
        assert!(!text.contains("signature verified"), "{text}");
        // The attestation gap is stated, not implied.
        assert!(text.contains("not_checked"), "{text}");
        assert!(text.contains("SUP-004"), "{text}");
    }

    #[test]
    fn a_verified_summary_names_the_key() {
        let o = VerifyOptions {
            artifact: PathBuf::from("app.wasm"),
            keys: vec![[1u8; 32]],
            require_signature: true,
        };
        let key_id = qqq_pkg::signature::KeyId::of(&[1u8; 32]);
        let out = interpret(
            &o,
            &Verification::Verified {
                key_id,
                required: true,
            },
            "deadbeef".to_owned(),
        );
        let text = crate::output::CommandOutput::summary(&out);
        assert!(text.contains(&key_id.to_hex()), "{text}");
    }

    #[test]
    fn a_zero_key_policy_says_so_rather_than_implying_a_check() {
        let o = VerifyOptions {
            artifact: PathBuf::from("app.wasm"),
            keys: Vec::new(),
            require_signature: false,
        };
        let out = interpret(&o, &Verification::Unsigned, "deadbeef".to_owned());
        let text = crate::output::CommandOutput::summary(&out);
        assert!(text.contains("No keys were configured"), "{text}");
    }
}
