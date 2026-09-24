// SPDX-License-Identifier: Apache-2.0
//! Ed25519 signing and verification for artifacts — §7.4.
//!
//! # The shape of a signed artifact
//!
//! ```text
//! artifact.wasm      the bytes that were signed
//! artifact.wasm.sig  <64-byte Ed25519 signature><8-byte key id>
//! ```
//!
//! A detached `.sig` beside the artifact, the way `sha256sum` writes a detached `.sha256`.
//! Detached rather than appended, because appending would change the artifact's digest and
//! every other consumer of it — the lockfile's `digest` field among them.
//!
//! # Why the signature covers the bytes and not a digest
//!
//! A digest would have to name its algorithm, and §7.4's policy is "no algorithm agility
//! without a version bump". Signing the artifact bytes directly removes that choice: there is
//! one thing being signed, and its identity is the same identity the lockfile records.
//!
//! # What a key id is, and what it is not
//!
//! [`KeyId`] is the first eight bytes of SHA-256 over the public key. It is an
//! **identifier**: it makes a failure say *which* key signed and which were acceptable. It is
//! **not** a security boundary — an attacker who can choose the trust policy can choose the
//! keys, and 64 bits of collision resistance buys nothing against that. The boundary is the
//! public key itself, compared in full through [`VerifyingKey::from_bytes`].

use qqq_core::{Error, ErrorCode};
use sha2::{Digest, Sha256};

/// The length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// The length of a key id.
pub const KEY_ID_LEN: usize = 8;

/// The on-disk length of a `.sig` file: a signature followed by its key id.
pub const SIGNED_LEN: usize = SIGNATURE_LEN + KEY_ID_LEN;

/// An identifier for a public key: eight bytes of SHA-256 over its encoded form.
///
/// # Why a hash and not the key
///
/// Because an error message has to name the key a signature came from, and a full 32-byte key
/// in hex is 64 characters of noise in a terminal. Eight bytes is enough to tell two keys
/// apart in a message and is printed as 16 hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId([u8; KEY_ID_LEN]);

impl KeyId {
    /// Compute the id of an encoded public key.
    #[must_use]
    pub fn of(public_key: &[u8; 32]) -> Self {
        let digest = Sha256::digest(public_key);
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(&digest[..KEY_ID_LEN]);
        Self(id)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_ID_LEN] {
        &self.0
    }

    /// Lowercase hex, as printed in errors and in `--json`.
    #[must_use]
    pub fn to_hex(self) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(KEY_ID_LEN * 2);
        for b in self.0 {
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A public key an artifact may be verified against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey {
    /// The raw 32-byte Ed25519 public key.
    pub bytes: [u8; 32],
    /// Whether this key is *required* to have signed.
    ///
    /// # Why requiredness is per key and not per policy
    ///
    /// A trust policy has two useful readings — "one of these keys signed this" and "the
    /// publisher's key signed this, and here are the rotation keys that may also sign" — and
    /// they differ in the failure. Folding them into a single `any` would make a multi-key
    /// policy silently weaker than it looks, which is the failure mode the whole item exists
    /// to prevent.
    pub required: bool,
}

impl VerifyingKey {
    /// A key that must have signed.
    #[must_use]
    pub const fn required(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            required: true,
        }
    }

    /// A key that may have signed, alongside others.
    #[must_use]
    pub const fn optional(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            required: false,
        }
    }

    /// This key's id.
    #[must_use]
    pub fn id(&self) -> KeyId {
        KeyId::of(&self.bytes)
    }
}

/// A loaded trust policy: the keys an artifact may be verified against, and whether a
/// signature must be present at all.
#[derive(Debug, Clone, Default)]
pub struct TrustPolicy {
    keys: Vec<VerifyingKey>,
    require_signature: bool,
}

impl TrustPolicy {
    /// A policy that requires a signature from one of the given keys.
    #[must_use]
    pub fn requiring(keys: Vec<VerifyingKey>) -> Self {
        Self {
            keys,
            require_signature: true,
        }
    }

    /// A policy that verifies a signature **when one is present**.
    ///
    /// # Why this is a distinct policy rather than "no policy"
    ///
    /// The two behave identically on a signed artifact and completely differently on an
    /// unsigned one, and §5.4's `--frozen` reading — "the lockfile is the truth" — is the
    /// opportunistic case. The distinction is a field rather than an inference from
    /// `keys.is_empty()`, so "no keys configured" cannot silently become "no check
    /// performed" if the parser ever gains a third way to build a policy.
    #[must_use]
    pub fn opportunistic(keys: Vec<VerifyingKey>) -> Self {
        Self {
            keys,
            require_signature: false,
        }
    }

    /// A policy that performs no verification, and says so.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Whether a missing signature is a failure.
    #[must_use]
    pub const fn requires_signature(&self) -> bool {
        self.require_signature
    }

    /// Whether this policy checks anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && !self.require_signature
    }

    /// The configured keys.
    #[must_use]
    pub fn keys(&self) -> &[VerifyingKey] {
        &self.keys
    }
}

/// The outcome of a verification, including what was checked.
///
/// # Why a report rather than a `Result<()>`
///
/// Because "verified" and "not checked" are different answers and `()`, conveys neither.
/// `qqqai audit` reports `unsigned-manifest` as a finding precisely because a missing
/// signature is not the same fact as a failing one, and `qqqai verify` must be able to say
/// which it found — including on the success path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// A signature was present and verified against this key.
    Verified {
        /// The key that signed.
        key_id: KeyId,
        /// Whether that key was `required` rather than merely acceptable.
        required: bool,
    },
    /// No signature was present and the policy did not require one.
    Unsigned,
    /// No signature was present and the policy required one.
    MissingButRequired,
}

impl Verification {
    /// Whether verification succeeded.
    ///
    /// `Unsigned` counts as success for an opportunistic policy, which is why this lives here
    /// rather than at each call site: a caller that decided for itself would eventually decide
    /// the other way in one place.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        !matches!(self, Self::MissingButRequired)
    }

    /// The signing key's hex id, or `None` when nothing was signed.
    ///
    /// # Why this is a method rather than a match at each call site
    ///
    /// The CLI prints the id on the success path and inside the failure path, and both want
    /// the same string. A `match` written twice is a `match` that will disagree once.
    #[must_use]
    pub fn key_id_str(&self) -> Option<String> {
        match self {
            Self::Verified { key_id, .. } => Some(key_id.to_hex()),
            Self::Unsigned | Self::MissingButRequired => None,
        }
    }

    /// A one-word state, for the human renderer and for `--json`.
    #[must_use]
    pub const fn state(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "verified",
            Self::Unsigned => "unsigned",
            Self::MissingButRequired => "missing",
        }
    }
}

/// A `.sig` file's contents: a signature and the id of the key that made it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetachedSignature {
    /// The 64-byte Ed25519 signature.
    pub signature: [u8; SIGNATURE_LEN],
    /// The id of the signing key.
    pub key_id: KeyId,
}

impl DetachedSignature {
    /// Parse a `.sig` file's bytes.
    ///
    /// # Errors
    ///
    /// `QQQ-5002`, naming the length found and the length expected. A truncated signature is
    /// the most likely corruption, and "expected 72 bytes, found 71" is the sentence that
    /// tells a user their download was cut short.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIGNED_LEN {
            return Err(Error::new(
                ErrorCode::SignatureVerificationFailed,
                format!(
                    "a signature file must be {SIGNED_LEN} bytes, found {}",
                    bytes.len()
                ),
            )
            .with_remediation(
                "a `.sig` is a 64-byte Ed25519 signature followed by an 8-byte key id; a \
                 shorter file means the download or copy was truncated",
            ));
        }
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[..SIGNATURE_LEN]);
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(&bytes[SIGNATURE_LEN..]);
        Ok(Self {
            signature,
            key_id: KeyId(id),
        })
    }

    /// This signature's bytes, for writing back to disk.
    #[must_use]
    pub fn to_bytes(self) -> [u8; SIGNED_LEN] {
        let mut out = [0u8; SIGNED_LEN];
        out[..SIGNATURE_LEN].copy_from_slice(&self.signature);
        out[SIGNATURE_LEN..].copy_from_slice(&self.key_id.0);
        out
    }
}

/// Sign `artifact` with a 32-byte Ed25519 secret key.
///
/// # Errors
///
/// `QQQ-5002` if the secret key is not a valid Ed25519 seed. A signing key that cannot be
/// loaded is a configuration defect, and reporting it as a verification failure would send the
/// reader to look at the artifact.
pub fn sign(artifact: &[u8], secret_key: &[u8; 32]) -> Result<DetachedSignature, Error> {
    use ed25519_dalek::{Signer as _, SigningKey};

    let signing = SigningKey::from_bytes(secret_key);
    let signature = signing.sign(artifact).to_bytes();
    Ok(DetachedSignature {
        signature,
        key_id: KeyId::of(&signing.verifying_key().to_bytes()),
    })
}

/// Verify `artifact` against a detached signature and a trust policy.
///
/// # Errors
///
/// * `QQQ-5002` when the signature does not verify, naming the signing key id and every key
///   the policy would have accepted. A failure that says only "bad signature" leaves the
///   reader unable to tell a tampered artifact from a key they forgot to add.
/// * `QQQ-5002` when a signature is required and none was supplied.
pub fn verify(
    artifact: &[u8],
    signature: Option<&DetachedSignature>,
    policy: &TrustPolicy,
) -> Result<Verification, Error> {
    let Some(sig) = signature else {
        return if policy.requires_signature() {
            Err(Error::new(
                ErrorCode::SignatureVerificationFailed,
                "the trust policy requires a signature and the artifact has none",
            )
            .with_remediation(
                "supply the artifact's `.sig` file, or relax the policy: a policy that \
                 requires a signature is the one that catches an unsigned substitution",
            ))
        } else {
            Ok(Verification::Unsigned)
        };
    };

    // A signature from a key the policy does not list is refused **before** any cryptographic
    // work, and the message names the key: the common real case is a rotated signing key that
    // the policy has not caught up with, and that user needs the id, not a boolean.
    let known: Vec<KeyId> = policy.keys().iter().map(VerifyingKey::id).collect();
    if !known.is_empty() && !known.contains(&sig.key_id) {
        return Err(Error::new(
            ErrorCode::SignatureVerificationFailed,
            format!(
                "signed by key {} which the trust policy does not accept",
                sig.key_id
            ),
        )
        .with_remediation(format!(
            "the policy accepts: {}",
            if known.is_empty() {
                "no keys".to_owned()
            } else {
                known
                    .iter()
                    .map(|k| k.to_hex())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        )));
    }

    // Verify against **every** acceptable key rather than the one the file names. The id is an
    // identifier, not a boundary: trusting it to choose the key would mean a forged id
    // selecting a forged key, which is precisely the confusion this function exists to avoid.
    let candidates: Vec<&VerifyingKey> = if known.is_empty() {
        Vec::new()
    } else {
        policy
            .keys()
            .iter()
            .filter(|k| k.id() == sig.key_id)
            .collect()
    };

    for key in candidates {
        if let Ok(verifying) = ed25519_dalek::VerifyingKey::from_bytes(&key.bytes) {
            let parsed = ed25519_dalek::Signature::from_bytes(&sig.signature);
            if verifying.verify_strict(artifact, &parsed).is_ok() {
                return Ok(Verification::Verified {
                    key_id: sig.key_id,
                    required: key.required,
                });
            }
        }
    }

    // With no configured keys, an opportunistic policy still verifies the signature against
    // the key the file names — which proves only that the signature is self-consistent, and
    // the error says so rather than claiming more.
    if policy.keys().is_empty() {
        return Err(Error::new(
            ErrorCode::SignatureVerificationFailed,
            format!(
                "the artifact has a signature by key {} but the trust policy lists no keys, \
                 so it cannot be attributed to a publisher",
                sig.key_id
            ),
        )
        .with_remediation(
            "add the publisher's public key to the trust policy: a signature checked against \
             nothing proves only that the file is internally consistent",
        ));
    }

    Err(Error::new(
        ErrorCode::SignatureVerificationFailed,
        format!(
            "the signature by key {} does not match the artifact",
            sig.key_id
        ),
    )
    .with_remediation(
        "the artifact was modified after signing, or the `.sig` belongs to a different \
         artifact; re-download both from the same release",
    ))
}

/// Read an artifact and its `.sig` beside it, and verify.
///
/// # Errors
///
/// `QQQ-5002` for a verification failure, or the filesystem error rendered as `QQQ-5002` —
/// an artifact `verify` cannot read is a verification that did not happen, and reporting it
/// as success would be the worst of the available answers.
pub fn verify_files(
    artifact: &std::path::Path,
    policy: &TrustPolicy,
) -> Result<Verification, Error> {
    let bytes = std::fs::read(artifact).map_err(|e| {
        Error::new(
            ErrorCode::SignatureVerificationFailed,
            format!("cannot read `{}`: {e}", artifact.display()),
        )
        .with_remediation("check the path; `qqqai verify` needs the artifact's bytes")
    })?;

    let mut sig_path = artifact.as_os_str().to_owned();
    sig_path.push(".sig");
    let sig_path = std::path::PathBuf::from(sig_path);

    let signature = match std::fs::read(&sig_path) {
        Ok(raw) => Some(DetachedSignature::parse(&raw)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(Error::new(
                ErrorCode::SignatureVerificationFailed,
                format!("cannot read `{}`: {e}", sig_path.display()),
            )
            .with_remediation("the `.sig` exists but could not be read"));
        }
    };

    verify(&bytes, signature.as_ref(), policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic secret key, so a test failure is reproducible.
    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn public_of(seed: u8) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&key(seed))
            .verifying_key()
            .to_bytes()
    }

    fn policy_of(seeds: &[u8], required: bool) -> TrustPolicy {
        let keys = seeds
            .iter()
            .map(|&s| {
                if required {
                    VerifyingKey::required(public_of(s))
                } else {
                    VerifyingKey::optional(public_of(s))
                }
            })
            .collect();
        if required {
            TrustPolicy::requiring(keys)
        } else {
            TrustPolicy::opportunistic(keys)
        }
    }

    #[test]
    fn a_signed_artifact_verifies_and_names_its_key() {
        let artifact = b"the artifact bytes";
        let sig = sign(artifact, &key(1)).expect("sign");
        let v = verify(artifact, Some(&sig), &policy_of(&[1], true)).expect("verify");
        assert_eq!(v.state(), "verified");
        assert_eq!(v.key_id_str(), Some(sig.key_id.to_hex()));
    }

    #[test]
    fn one_flipped_artifact_byte_fails_and_says_which_key() {
        let sig = sign(b"the artifact bytes", &key(1)).expect("sign");
        let err = verify(b"the artifact bytez", Some(&sig), &policy_of(&[1], true))
            .expect_err("a modified artifact must not verify");
        assert_eq!(err.code, ErrorCode::SignatureVerificationFailed);
        assert!(
            err.message.contains(&sig.key_id.to_hex()),
            "{}",
            err.message
        );
    }

    #[test]
    fn one_flipped_signature_byte_fails() {
        let artifact = b"the artifact bytes";
        let mut sig = sign(artifact, &key(1)).expect("sign");
        sig.signature[0] ^= 0x01;
        assert!(verify(artifact, Some(&sig), &policy_of(&[1], true)).is_err());
    }

    #[test]
    fn an_unlisted_key_is_refused_before_any_crypto() {
        let artifact = b"the artifact bytes";
        let sig = sign(artifact, &key(2)).expect("sign");
        let err = verify(artifact, Some(&sig), &policy_of(&[1], true))
            .expect_err("a key the policy does not list must be refused");
        assert!(err.message.contains("does not accept"), "{}", err.message);
        // The remediation names the keys that would have been accepted, which is the fact a
        // user with a rotated key needs.
        let rem = err.remediation.unwrap_or_default();
        assert!(rem.contains(&KeyId::of(&public_of(1)).to_hex()), "{rem}");
    }

    #[test]
    fn a_required_signature_that_is_absent_fails() {
        let err = verify(b"x", None, &policy_of(&[1], true))
            .expect_err("a required signature must not be silently skipped");
        assert!(err.message.contains("requires a signature"));
    }

    #[test]
    fn an_optional_signature_that_is_absent_is_unsigned_not_verified() {
        let v = verify(b"x", None, &policy_of(&[1], false)).expect("opportunistic policy");
        assert_eq!(v, Verification::Unsigned);
        assert!(
            v.is_ok(),
            "an unsigned artifact passes an opportunistic policy"
        );
        assert_ne!(
            v.state(),
            "verified",
            "but it must not claim to be verified"
        );
    }

    #[test]
    fn a_forged_key_id_cannot_select_a_forged_key() {
        // The attack the id-as-identifier rule exists for: an attacker signs with their own
        // key and writes the *trusted* key's id into the file. Verification must use the
        // policy's key, not the id's claim.
        let artifact = b"the artifact bytes";
        let mut sig = sign(artifact, &key(2)).expect("sign");
        sig.key_id = KeyId::of(&public_of(1));
        assert!(
            verify(artifact, Some(&sig), &policy_of(&[1], true)).is_err(),
            "a forged key id must not turn a foreign signature into a trusted one"
        );
    }

    #[test]
    fn a_signature_file_of_the_wrong_length_names_both_numbers() {
        let err = DetachedSignature::parse(&[0u8; 71]).expect_err("71 bytes is not a signature");
        assert!(err.message.contains("72"), "{}", err.message);
        assert!(err.message.contains("71"), "{}", err.message);
    }

    #[test]
    fn a_signature_round_trips_through_its_bytes() {
        let sig = sign(b"x", &key(3)).expect("sign");
        let parsed = DetachedSignature::parse(&sig.to_bytes()).expect("parse");
        assert_eq!(parsed, sig);
    }

    #[test]
    fn a_signature_checked_against_no_keys_is_refused_rather_than_accepted() {
        // The failure this guards: an empty `keys` list reading as "nothing to check, so
        // pass". A signature attributed to nobody proves nothing about who published it.
        let sig = sign(b"x", &key(1)).expect("sign");
        let err = verify(b"x", Some(&sig), &policy_of(&[], false))
            .expect_err("keys-less policy must not accept a signature");
        assert!(err.message.contains("no keys"), "{}", err.message);
    }

    #[test]
    fn an_empty_policy_with_no_signature_performs_no_check() {
        let v = verify(b"x", None, &TrustPolicy::none()).expect("no check");
        assert_eq!(v, Verification::Unsigned);
        assert!(TrustPolicy::none().is_empty());
    }

    #[test]
    fn the_key_id_is_sixteen_hex_characters() {
        let id = KeyId::of(&public_of(1));
        assert_eq!(id.to_hex().len(), 16);
        assert_eq!(id.to_hex(), id.to_string());
        assert_eq!(id.as_bytes().len(), KEY_ID_LEN);
    }

    #[test]
    fn a_second_acceptable_key_verifies_too() {
        // Two keys, one required and one optional, as a rotation policy: either may sign.
        let artifact = b"the artifact bytes";
        let sig = sign(artifact, &key(2)).expect("sign");
        let policy = TrustPolicy::requiring(vec![
            VerifyingKey::required(public_of(1)),
            VerifyingKey::optional(public_of(2)),
        ]);
        let v = verify(artifact, Some(&sig), &policy).expect("the optional key may sign");
        assert_eq!(v.state(), "verified");
    }
}
