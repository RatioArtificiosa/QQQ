// SPDX-License-Identifier: Apache-2.0

//! Signed audit checkpoints, core primitives (`I-02`).
//!
//! A SHA-256 chain proves order and detects accidental damage, but
//! anyone who can write the file can recompute it. Evidence-grade
//! logs need a signature made with a key the log writer cannot
//! forge after the fact, verifiable with a public key alone —
//! which is what this module provides: a domain-separated message
//! constructor plus sign/verify over ed25519-dalek 2.x.
//!
//! # What lives here and what does not
//!
//! The pure cryptography only: message layout, signing,
//! verification. Key generation, key storage (0600 files, env
//! secrets, hardware tokens), checkpoint scheduling in the sink
//! (every N records or T seconds), the `qqq audit verify` command,
//! and external anchoring are the scheduled product wiring —
//! tracked as the `I-02` follow-up, not smuggled in here. A
//! checkpoint primitive that also managed keys would fuse two
//! trust decisions; keeping them apart is what lets verification
//! need only a public key.
//!
//! # Message layout
//!
//! `b"qqq-audit-checkpoint-v1\0" || seq.to_le_bytes() ||
//! head_bytes(32) || ts.to_le_bytes()`. The domain prefix keeps a
//! checkpoint signature from verifying as anything else; the fixed
//! field order and little-endian integers keep every implementation
//! byte-identical. `head` is the chain head's raw 32 bytes, not its
//! hex rendering — the sink decodes hex before calling.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

/// Domain separator for checkpoint messages.
///
/// The trailing NUL terminates the C-string-shaped prefix so
/// `...-v1` can never be a prefix of a `...-v10` format — version
/// confusion would let a signature migrate across formats.
///
/// ```
/// use qqq_host::audit_checkpoint::CHECKPOINT_DOMAIN;
///
/// assert!(CHECKPOINT_DOMAIN.starts_with(b"qqq-audit-checkpoint-v1"));
/// assert_eq!(CHECKPOINT_DOMAIN.last(), Some(&0));
/// ```
pub const CHECKPOINT_DOMAIN: &[u8] = b"qqq-audit-checkpoint-v1\0";

/// Build the exact bytes a checkpoint signature covers.
///
/// Pure concatenation in the documented layout — no hashing here,
/// because ed25519 hashes internally and a pre-hash would be a
/// second, unaudited commitment layer.
///
/// ```
/// use qqq_host::audit_checkpoint::checkpoint_message;
///
/// let msg = checkpoint_message(1000, &[3u8; 32], 1_700_000_000_000);
/// assert_eq!(msg.len(), 24 + 8 + 32 + 8);
/// assert!(msg.starts_with(b"qqq-audit-checkpoint-v1\0"));
/// assert_eq!(&msg[24..32], &1000u64.to_le_bytes());
/// assert_eq!(&msg[32..64], &[3u8; 32]);
/// ```
#[must_use]
pub fn checkpoint_message(seq: u64, head: &[u8; 32], ts_ms: u64) -> Vec<u8> {
    let mut message = Vec::with_capacity(CHECKPOINT_DOMAIN.len() + 8 + 32 + 8);
    message.extend_from_slice(CHECKPOINT_DOMAIN);
    message.extend_from_slice(&seq.to_le_bytes());
    message.extend_from_slice(head);
    message.extend_from_slice(&ts_ms.to_le_bytes());
    message
}

/// Sign a checkpoint with the operator's key.
///
/// Deterministic: the same inputs always yield the same signature
/// (ed25519 has no per-signature randomness), so two signers over
/// the same log agree byte-for-byte — pinned by
/// `signing_is_deterministic` below.
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use qqq_host::audit_checkpoint::{sign_checkpoint, verify_checkpoint};
///
/// let key = SigningKey::from_bytes(&[9u8; 32]);
/// let head = [3u8; 32];
/// let sig = sign_checkpoint(&key, 1000, &head, 1_700_000_000_000);
/// assert!(verify_checkpoint(
///     &key.verifying_key(),
///     1000,
///     &head,
///     1_700_000_000_000,
///     &sig
/// ));
/// ```
#[must_use]
pub fn sign_checkpoint(key: &SigningKey, seq: u64, head: &[u8; 32], ts_ms: u64) -> Signature {
    key.sign(&checkpoint_message(seq, head, ts_ms))
}

/// Verify a checkpoint signature against the public key.
///
/// Returns `false` on any mismatch — wrong key, moved sequence,
/// edited head, shifted timestamp, forged bytes — never an error,
/// because a checkpoint that does not verify is simply untrusted,
/// not malformed.
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use qqq_host::audit_checkpoint::{sign_checkpoint, verify_checkpoint};
///
/// let key = SigningKey::from_bytes(&[9u8; 32]);
/// let head = [3u8; 32];
/// let sig = sign_checkpoint(&key, 1000, &head, 1_700_000_000_000);
/// assert!(!verify_checkpoint(
///     &key.verifying_key(),
///     1001,
///     &head,
///     1_700_000_000_000,
///     &sig
/// ));
/// ```
#[must_use]
pub fn verify_checkpoint(
    key: &VerifyingKey,
    seq: u64,
    head: &[u8; 32],
    ts_ms: u64,
    sig: &Signature,
) -> bool {
    key.verify(&checkpoint_message(seq, head, ts_ms), sig)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        // Fixed key for tests only: determinism is the point, and a
        // generated key would make failure output unreproducible.
        SigningKey::from_bytes(&[9u8; 32])
    }

    /// The audit document's acceptance shape: a signature verifies,
    /// and changing any single covered field breaks it.
    #[test]
    fn signature_round_trips_and_detects_any_field_change() {
        let signing = key();
        let head = [3u8; 32];
        let sig = sign_checkpoint(&signing, 1000, &head, 1_700_000_000_000);
        let vk = signing.verifying_key();
        assert!(verify_checkpoint(&vk, 1000, &head, 1_700_000_000_000, &sig));
        assert!(!verify_checkpoint(
            &vk,
            1001,
            &head,
            1_700_000_000_000,
            &sig
        ));
        assert!(!verify_checkpoint(
            &vk,
            1000,
            &[4u8; 32],
            1_700_000_000_000,
            &sig
        ));
        assert!(!verify_checkpoint(
            &vk,
            1000,
            &head,
            1_700_000_000_001,
            &sig
        ));
    }

    /// A signature from another key never verifies: key confusion is
    /// the forgery the unkeyed chain cannot detect.
    #[test]
    fn a_signature_from_another_key_never_verifies() {
        let head = [7u8; 32];
        let sig = sign_checkpoint(&key(), 500, &head, 1_700_000_000_000);
        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        assert!(!verify_checkpoint(
            &other,
            500,
            &head,
            1_700_000_000_000,
            &sig
        ));
    }

    /// Signing is deterministic: same inputs, same bytes. Checkpoint
    /// comparability across signers depends on it.
    #[test]
    fn signing_is_deterministic() {
        let signing = key();
        let head = [3u8; 32];
        let first = sign_checkpoint(&signing, 1000, &head, 1_700_000_000_000);
        let second = sign_checkpoint(&signing, 1000, &head, 1_700_000_000_000);
        assert_eq!(first.to_bytes(), second.to_bytes());
    }
}
