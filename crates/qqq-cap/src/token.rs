// SPDX-License-Identifier: Apache-2.0

//! Attenuable capability tokens, core primitives (`I-06`).
//!
//! Authority today is a resolved `GrantSet`: all-or-nothing per
//! interface. Delegation needs narrowing — hand a child the same
//! host with a shorter lifetime or fewer calls, with no way to
//! widen it back. These primitives are the macaroon-style chain
//! that makes narrowing one-directional: root signature
//! `HMAC(root_key, capability_id)`, each caveat
//! `sig' = HMAC(sig, caveat_bytes)`. Appending needs only the
//! current signature; removing one needs the previous signature,
//! which the holder never had — widening is impossible by
//! construction, not by checking.
//!
//! # What lives here and what does not
//!
//! Chain math, caveat codec, and evaluation only. The root key
//! lives with the host (never in this crate's API surface as
//! anything but a byte slice at the call instant), and wiring
//! caveats to live policy (host allowlist subsets, path prefixes,
//! call counters) is the scheduled product work — tracked as the
//! `I-06` follow-up. A token constructor anywhere but `mint` and
//! `attenuate` would be a second mint; there is none.
//!
//! # Caveat wire form
//!
//! `kind ":" payload`, kinds `exp` (8-byte little-endian unix-ms
//! expiry) and `calls` (8-byte little-endian maximum call count).
//! Anything else — unknown kind, wrong length, trailing bytes —
//! fails closed at parse: an unevaluated caveat is a granted
//! caveat, so parsing refuses what it cannot understand.

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

type HmacSha256 = Hmac<Sha256>;

/// A parsed caveat: the only conditions a token can carry.
///
/// Closed on purpose: adding a kind is a policy decision with a
/// parser, an evaluator, and tests — never a stringly-typed
/// free-for-all, because an evaluator that ignores what it does
/// not know grants what it does not understand.
///
/// ```
/// use qqq_cap::token::{Caveat, evaluate_caveat};
///
/// assert!(evaluate_caveat(&Caveat::Expiry { unix_ms: 2_000 }, 1_000, 0));
/// assert!(!evaluate_caveat(&Caveat::Expiry { unix_ms: 500 }, 1_000, 0));
/// assert!(evaluate_caveat(&Caveat::MaxCalls { max: 3 }, 0, 3));
/// assert!(!evaluate_caveat(&Caveat::MaxCalls { max: 3 }, 0, 4));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caveat {
    /// Refuse at or after this unix-millisecond timestamp.
    ///
    /// ```
    /// use qqq_cap::token::{Caveat, evaluate_caveat};
    ///
    /// let exp = Caveat::Expiry { unix_ms: 2_000 };
    /// assert!(evaluate_caveat(&exp, 1_999, 0));
    /// assert!(!evaluate_caveat(&exp, 2_000, 0));
    /// ```
    Expiry {
        /// Exclusive upper bound: valid while `now_ms < unix_ms`.
        unix_ms: u64,
    },
    /// Refuse after this many calls (1-based count supplied by the host).
    ///
    /// ```
    /// use qqq_cap::token::{Caveat, evaluate_caveat};
    ///
    /// let budget = Caveat::MaxCalls { max: 2 };
    /// assert!(evaluate_caveat(&budget, 0, 2));
    /// assert!(!evaluate_caveat(&budget, 0, 3));
    /// ```
    MaxCalls {
        /// Inclusive bound: valid while `calls_used <= max`.
        max: u64,
    },
}

/// Evaluate one parsed caveat against the host's clock and counter.
///
/// Pure: time and usage arrive as arguments, so tests pin them and
/// production cannot smuggle a clock read past review.
///
/// ```
/// use qqq_cap::token::{Caveat, evaluate_caveat};
///
/// // Boundary behaviour is the contract: expiry is exclusive, calls inclusive.
/// assert!(!evaluate_caveat(&Caveat::Expiry { unix_ms: 1_000 }, 1_000, 0));
/// assert!(evaluate_caveat(&Caveat::MaxCalls { max: 1 }, 0, 1));
/// ```
#[must_use]
pub fn evaluate_caveat(caveat: &Caveat, now_ms: u64, calls_used: u64) -> bool {
    match *caveat {
        Caveat::Expiry { unix_ms } => now_ms < unix_ms,
        Caveat::MaxCalls { max } => calls_used <= max,
    }
}

/// Encode a caveat to its wire bytes for the HMAC chain.
///
/// ```
/// use qqq_cap::token::{Caveat, encode_caveat, parse_caveat};
///
/// let bytes = encode_caveat(&Caveat::Expiry { unix_ms: 1_000 });
/// assert_eq!(parse_caveat(&bytes), Some(Caveat::Expiry { unix_ms: 1_000 }));
/// ```
#[must_use]
pub fn encode_caveat(caveat: &Caveat) -> Vec<u8> {
    // Fixed layouts, no delimiters to misparse: kind tag, colon,
    // exactly 8 little-endian bytes. `parse_caveat` enforces the
    // same shape, so encode-then-parse round-trips by construction.
    let (tag, value) = match *caveat {
        Caveat::Expiry { unix_ms } => (&b"exp"[..], unix_ms),
        Caveat::MaxCalls { max } => (&b"calls"[..], max),
    };
    let mut bytes = Vec::with_capacity(tag.len() + 1 + 8);
    bytes.extend_from_slice(tag);
    bytes.push(b':');
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes
}

/// Parse wire bytes to a caveat, or `None` for anything unknown.
///
/// `None` means refuse: lengths, kinds, and trailing bytes are all
/// checked, because a partially-understood caveat is a hole shaped
/// exactly like the misunderstood part.
///
/// ```
/// use qqq_cap::token::parse_caveat;
///
/// assert_eq!(parse_caveat(b"exp:short"), None);
/// assert_eq!(parse_caveat(b"priority:high!"), None);
/// ```
#[must_use]
pub fn parse_caveat(bytes: &[u8]) -> Option<Caveat> {
    let (tag, payload) = bytes.split_at_checked(4)?;
    if tag == b"exp:" && payload.len() == 8 {
        let unix_ms = u64::from_le_bytes(payload.try_into().ok()?);
        return Some(Caveat::Expiry { unix_ms });
    }
    let (tag, payload) = bytes.split_at_checked(6)?;
    if tag == b"calls:" && payload.len() == 8 {
        let max = u64::from_le_bytes(payload.try_into().ok()?);
        return Some(Caveat::MaxCalls { max });
    }
    None
}

/// Mint a root token signature for a capability id.
///
/// The root key never leaves the host; what travels is the
/// signature, which attenuation can only narrow.
///
/// ```
/// use qqq_cap::token::mint;
///
/// let root = mint(b"operator-root-key", b"http egress to api.example.com");
/// let again = mint(b"operator-root-key", b"http egress to api.example.com");
/// assert_eq!(root, again, "minting is deterministic");
/// ```
/// HMAC accepts any key length (short keys are hashed, long keys
/// are hashed too), so no length check here — a short root key is
/// an operator decision, and refusing it would be policy, not math.
///
/// # Panics
///
/// Never at runtime: `new_from_slice` fails only for key lengths
/// the HMAC construction rejects, and it rejects none — every
/// length is hashed. The `expect` names the invariant so a future
/// primitive change fails loudly instead of widening minting.
#[must_use]
pub fn mint(root_key: &[u8], capability_id: &[u8]) -> [u8; 32] {
    #[expect(
        clippy::expect_used,
        reason = "HMAC accepts every key length by hashing; the error arm is unreachable by construction"
    )]
    let mut mac = HmacSha256::new_from_slice(root_key).expect("hmac accepts any key length");
    mac.update(capability_id);
    mac.finalize().into_bytes().into()
}

/// Append one caveat, narrowing the token.
///
/// Returns the new signature; the old one stays valid for the
/// un-narrowed token, which is why parents are kept server-side
/// and only narrowed tokens travel.
///
/// ```
/// use qqq_cap::token::{attenuate, encode_caveat, mint, verify_chain, Caveat};
///
/// let root_key = b"operator-root-key";
/// let capability = b"http egress to api.example.com";
/// let root = mint(root_key, capability);
/// let caveat = encode_caveat(&Caveat::Expiry { unix_ms: 2_000 });
/// let narrowed = attenuate(root, &caveat);
/// assert!(verify_chain(root_key, capability, &[caveat], &narrowed));
/// ```
///
/// # Panics
///
/// Never at runtime — same construction invariant as [`mint`].
#[must_use]
pub fn attenuate(sig: [u8; 32], caveat: &[u8]) -> [u8; 32] {
    #[expect(
        clippy::expect_used,
        reason = "HMAC accepts every key length by hashing; the error arm is unreachable by construction"
    )]
    let mut mac = HmacSha256::new_from_slice(&sig).expect("hmac accepts any key length");
    mac.update(caveat);
    mac.finalize().into_bytes().into()
}

/// Verify a token by replaying the chain from the root key.
///
/// Recomputes every HMAC step and compares the final signature in
/// constant time (`Mac::verify`); a `false` is untrusted, never
/// malformed — same shape as checkpoint verification.
///
/// ```
/// use qqq_cap::token::{attenuate, encode_caveat, mint, verify_chain, Caveat};
///
/// let root_key = b"operator-root-key";
/// let capability = b"http egress to api.example.com";
/// let root = mint(root_key, capability);
/// assert!(verify_chain(root_key, capability, &[], &root));
/// assert!(!verify_chain(b"wrong-key", capability, &[], &root));
/// ```
#[must_use]
pub fn verify_chain(
    root_key: &[u8],
    capability_id: &[u8],
    caveats: &[Vec<u8>],
    sig: &[u8; 32],
) -> bool {
    // Replay, not decode: the signature commits to exact bytes, so
    // verification re-runs the chain over the presented bytes rather
    // than re-encoded caveats — a canonicalization gap between
    // encode and verify would be a forgery seam.
    let mut current = mint(root_key, capability_id);
    for caveat in caveats {
        current = attenuate(current, caveat);
    }
    // Constant-time by construction: `ct_eq` compares without
    // early exit, so no caller can measure how close a forgery got
    // by timing the rejection.
    current.ct_eq(sig).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_key() -> &'static [u8] {
        b"test-root-key, never a production secret"
    }

    /// Dropping or reordering any caveat breaks the chain: the
    /// signature commits to the exact sequence, so narrowing is
    /// append-only and widening needs a signature nobody holds.
    #[test]
    fn dropping_or_reordering_a_caveat_breaks_the_chain() {
        let capability = b"egress to api.example.com";
        let first = encode_caveat(&Caveat::Expiry { unix_ms: 9_999 });
        let second = encode_caveat(&Caveat::MaxCalls { max: 5 });
        let root = mint(root_key(), capability);
        let narrowed = attenuate(attenuate(root, &first), &second);
        let full = [first.clone(), second.clone()];
        assert!(verify_chain(root_key(), capability, &full, &narrowed));
        // Drop the first caveat.
        assert!(!verify_chain(
            root_key(),
            capability,
            std::slice::from_ref(&second),
            &narrowed
        ));
        // Drop the second.
        assert!(!verify_chain(
            root_key(),
            capability,
            std::slice::from_ref(&first),
            &narrowed
        ));
        // Reorder.
        assert!(!verify_chain(
            root_key(),
            capability,
            &[second, first],
            &narrowed
        ));
        // Drop all.
        assert!(!verify_chain(root_key(), capability, &[], &narrowed));
    }

    /// Attenuation is monotone: a narrowed token verifies only with
    /// its full caveat list, and the parent still verifies alone —
    /// narrowing never invents authority the parent lacked.
    #[test]
    fn attenuation_never_widens() {
        let capability = b"egress to api.example.com";
        let root = mint(root_key(), capability);
        let caveat = encode_caveat(&Caveat::MaxCalls { max: 1 });
        let narrowed = attenuate(root, &caveat);
        assert_ne!(root, narrowed, "attenuation must move the signature");
        assert!(verify_chain(root_key(), capability, &[], &root));
        assert!(verify_chain(root_key(), capability, &[caveat], &narrowed));
        assert!(!verify_chain(root_key(), capability, &[], &narrowed));
    }

    /// Expired tokens refuse, evaluated against a pinned clock.
    #[test]
    fn expired_tokens_refuse() {
        assert!(!evaluate_caveat(
            &Caveat::Expiry { unix_ms: 1_000 },
            1_000,
            0
        ));
        assert!(!evaluate_caveat(&Caveat::Expiry { unix_ms: 999 }, 1_000, 0));
        assert!(evaluate_caveat(
            &Caveat::Expiry { unix_ms: 1_001 },
            1_000,
            0
        ));
    }

    /// Unknown caveat kinds refuse at parse: fail closed, never skip.
    #[test]
    fn unknown_caveat_kinds_refuse() {
        assert_eq!(parse_caveat(b"priority:high!"), None);
        assert_eq!(parse_caveat(b"exp:short"), None);
        assert_eq!(parse_caveat(b"calls:\x00\x01"), None);
        assert_eq!(parse_caveat(b""), None);
        // Trailing bytes are not ignored.
        let mut trailing = encode_caveat(&Caveat::MaxCalls { max: 1 });
        trailing.push(b'!');
        assert_eq!(parse_caveat(&trailing), None);
    }
}
