//! The `qqq:secrets` host implementation: use a secret without disclosing it --
//! `CAP-016`.
//!
//! # The inversion this implements
//!
//! Proposal §6.3:
//!
//! > Today, a service reads `DATABASE_URL` from the environment, which means the
//! > secret is *in the guest's memory* and can be exfiltrated by a compromised or
//! > malicious dependency. QQQ inverts this: the secret is named; the guest can
//! > never read it.
//!
//! Concretely: the guest sends a **name** and an **operation**; the host looks up
//! the material in its own memory and returns only the operation's *result*. A
//! fully compromised guest can ask for signatures — which the manifest granted —
//! but it cannot steal the key. The blast radius of a compromise drops from "the
//! attacker has your signing key forever" to "the attacker can sign while the
//! process is running".
//!
//! # The three properties, and where each is enforced
//!
//! | Property | Enforced by |
//! |---|---|
//! | The value never crosses the boundary | [`SecretMaterial`] holds it with no accessor at all |
//! | Only allowlisted names are reachable | [`SecretStore::apply`] checks the grant list *before* the lookup |
//! | A grant cannot be pivoted to another primitive | the per-secret `permitted` set, checked per call |
//!
//! # Why the operation set is closed
//!
//! The WIT declares `secret-op` as a **variant** rather than an open
//! "call-algorithm-with-key" interface, and the WIT doc gives the reason: an open
//! interface lets a guest extract the key through a chosen-input attack on a weak
//! algorithm — sign a crafted message, observe the output, recover the key. A
//! closed set of well-understood operations removes that class entirely.
//!
//! The same reasoning drives the per-secret permission set: a secret declared for
//! signing must not be usable for HMAC, so a leaked grant cannot be pivoted.
//!
//! # What this module does NOT do
//!
//! It does not **resolve** secrets from the environment or a file. Resolution is
//! `qqq-cap`'s job (`SecretRef` names a source like `env:ORDERS_DB_URL`) and it
//! belongs to the deploy layer, not the request path: resolving on every call
//! would read the environment on every call, which §2.5 forbids and
//! `tools/check_no_ambient.py` enforces. A store is **constructed** with material
//! already resolved, and this module touches no ambient state.

use std::collections::BTreeMap;

use qqq_core::{Error, ErrorCode, Result};

/// An operation a secret may be used for.
///
/// A closed enum rather than a string, for the reason the WIT gives: an open
/// interface invites chosen-input key recovery. This is the host-side mirror of
/// the WIT `secret-op` variant, and the discriminant order below **must** match
/// the WIT declaration — `the_discriminants_match_the_wit_declaration_order`
/// pins that, because a mismatch would make a guest's `sign` invoke `verify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PermittedOp {
    /// Sign an input with the secret's key. WIT discriminant 0.
    Sign,
    /// Verify a signature using the secret's **public** key. Discriminant 1.
    Verify,
    /// Compute an HMAC over the input, using the secret as the key. Discriminant 2.
    Hmac,
    /// Decrypt using the secret as the key. Discriminant 3.
    Decrypt,
    /// Encrypt using the secret as the key. Discriminant 4.
    Encrypt,
    /// Return the public half of a key pair. Safe by construction. Discriminant 5.
    PublicKey,
}

impl PermittedOp {
    /// The name the WIT interface uses, for `permitted-operations`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::Hmac => "hmac",
            Self::Decrypt => "decrypt",
            Self::Encrypt => "encrypt",
            Self::PublicKey => "public-key",
        }
    }

    /// Parse the name a manifest writes in its secret grants.
    ///
    /// Returns `None` for an unknown name, which the caller reports rather than
    /// guessing: a typo in a manifest should fail at load, not silently grant
    /// nothing.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "sign" => Self::Sign,
            "verify" => Self::Verify,
            "hmac" => Self::Hmac,
            "decrypt" => Self::Decrypt,
            "encrypt" => Self::Encrypt,
            "public-key" => Self::PublicKey,
            _ => return None,
        })
    }

    /// Every operation, in WIT declaration order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Sign,
            Self::Verify,
            Self::Hmac,
            Self::Decrypt,
            Self::Encrypt,
            Self::PublicKey,
        ]
    }
}

/// The operation a guest asked for, in a form that can only hold a valid one.
///
/// # Why this is a separate type from [`PermittedOp`]
///
/// The WIT variant lowers to a `u32` discriminant, so the guest can send **any
/// number**. Converting that is where an out-of-range value has to be rejected,
/// and keeping the two types apart makes the conversion a place a reviewer looks
/// rather than an implicit `as` cast buried in a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestedOp(PermittedOp);

impl RequestedOp {
    /// Interpret a discriminant from the guest.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-4004` for an out-of-range discriminant — a *capability*
    /// fault rather than a guest trap, because the guest is asking for an
    /// operation outside the declared set, which is what `secret-op` being closed
    /// means.
    pub fn from_discriminant(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self(PermittedOp::Sign)),
            1 => Ok(Self(PermittedOp::Verify)),
            2 => Ok(Self(PermittedOp::Hmac)),
            3 => Ok(Self(PermittedOp::Decrypt)),
            4 => Ok(Self(PermittedOp::Encrypt)),
            5 => Ok(Self(PermittedOp::PublicKey)),
            other => Err(Error::new(
                ErrorCode::SecretUseFailed,
                "the operation discriminant is outside the declared set",
            )
            .with_context("discriminant", other.to_string())
            .with_context(
                "valid_range",
                format!("0..={}", PermittedOp::all().len() - 1),
            )
            .with_remediation(
                "`secret-op` is a closed WIT variant; a guest sending an \
                 out-of-range discriminant is either built against a newer \
                 interface or is probing",
            )),
        }
    }

    /// The operation.
    #[must_use]
    pub const fn op(self) -> PermittedOp {
        self.0
    }
}

/// The host-side material for one secret.
///
/// # Why the value is private and there is no accessor
///
/// The whole point of the interface is that the value never crosses to the guest.
/// A `pub` field or a `value()` method would make that a convention rather than a
/// property, and the first caller to want it "just for logging" would break the
/// guarantee everywhere. The field is private and **no accessor exists**.
///
/// # Why `Debug` is manual
///
/// A derived `Debug` prints the bytes, and a secret in a log line is exactly the
/// leak this interface exists to prevent. The manual implementation prints the
/// *name* and the permitted operations — useful for diagnosis, harmless if
/// logged. `debug_never_prints_the_material` pins it.
pub struct SecretMaterial {
    name: String,
    /// The bytes. Never leaves this module.
    value: Vec<u8>,
    permitted: Vec<PermittedOp>,
}

impl std::fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately no `value` field. The length is not printed either: length
        // is a fact about the secret, and the WIT's own design keeps even that
        // from the guest.
        f.debug_struct("SecretMaterial")
            .field("name", &self.name)
            .field("permitted", &self.permitted)
            .finish_non_exhaustive()
    }
}

impl SecretMaterial {
    /// Construct material from **already resolved** bytes.
    ///
    /// Resolution (environment, file, key manager) happens once in the deploy
    /// layer and the result is passed here. Resolving per call would read ambient
    /// state on the request path.
    #[must_use]
    pub fn new(name: impl Into<String>, value: Vec<u8>, permitted: Vec<PermittedOp>) -> Self {
        Self {
            name: name.into(),
            value,
            permitted,
        }
    }

    /// The name, which is not secret.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether this secret permits an operation.
    #[must_use]
    pub fn permits(&self, op: PermittedOp) -> bool {
        self.permitted.contains(&op)
    }
}

/// The cryptographic primitives a secret operation is performed with.
///
/// # Why the store delegates rather than implementing them
///
/// Signing, HMAC and AEAD already live in `qqq:crypto` (`host_crypto.rs`).
/// Re-implementing them here would create a second source of truth for the
/// algorithm choices, and the two would drift — the reason §4.3 keeps the
/// interface registry in one place.
///
/// Delegation also makes this module testable **without real cryptography**,
/// which is what lets the tests below assert the access-control behaviour rather
/// than a cipher's.
pub trait SecretCrypto {
    /// Sign `input` with `key`.
    ///
    /// # Errors
    ///
    /// Returns a message on failure, which the store keeps for the host log.
    fn sign(&self, key: &[u8], input: &[u8]) -> std::result::Result<Vec<u8>, String>;

    /// Verify `signature` over `input` with `key`.
    ///
    /// # Errors
    ///
    /// As [`SecretCrypto::sign`].
    fn verify(
        &self,
        key: &[u8],
        input: &[u8],
        signature: &[u8],
    ) -> std::result::Result<bool, String>;

    /// HMAC `input` with `key`.
    ///
    /// # Errors
    ///
    /// As [`SecretCrypto::sign`].
    fn hmac(&self, key: &[u8], input: &[u8]) -> std::result::Result<Vec<u8>, String>;

    /// Encrypt `plaintext` with `key`.
    ///
    /// # Errors
    ///
    /// As [`SecretCrypto::sign`].
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> std::result::Result<Vec<u8>, String>;

    /// Decrypt `ciphertext` with `key`.
    ///
    /// # Errors
    ///
    /// As [`SecretCrypto::sign`].
    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> std::result::Result<Vec<u8>, String>;

    /// The public half of `key`, when the algorithm has one.
    ///
    /// # Errors
    ///
    /// As [`SecretCrypto::sign`]. A symmetric secret returns `Err`, which the
    /// store reports as `unavailable`.
    fn public_key(&self, key: &[u8]) -> std::result::Result<Vec<u8>, String>;
}

/// The per-call input ceiling.
///
/// A secret operation on a gigabyte of input is not a use of a secret, it is a
/// denial-of-service against the host's own memory. The WIT declares
/// `input-too-long` for exactly this, so the bound is part of the interface
/// rather than an implementation detail.
pub const MAX_SECRET_INPUT: usize = 8 * 1024 * 1024;

/// The host's secret store for one instance.
///
/// # Why the grant list and the material are separate fields
///
/// `granted` is what the manifest allowed; `material` is what the host managed to
/// resolve. Keeping them apart is what lets the store distinguish *"not granted"*
/// from *"granted but unavailable"* — two conditions with different fixes, which
/// the WIT declares as separate error variants for the same reason.
#[derive(Debug)]
pub struct SecretStore {
    granted: Vec<String>,
    material: BTreeMap<String, SecretMaterial>,
}

impl SecretStore {
    /// A store with no grants, reaching nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            granted: Vec::new(),
            material: BTreeMap::new(),
        }
    }

    /// A store granting `granted`, with `material` resolved for those the host
    /// could load.
    ///
    /// A name in `granted` with no material is **legal** and produces
    /// `unavailable` at use: the manifest asked for a secret the host could not
    /// load, which is a deployment problem the guest should be able to observe.
    #[must_use]
    pub fn with_grants(granted: Vec<String>, material: Vec<SecretMaterial>) -> Self {
        Self {
            granted,
            material: material.into_iter().map(|m| (m.name.clone(), m)).collect(),
        }
    }

    /// Whether a name is in the manifest's allowlist.
    #[must_use]
    pub fn is_granted(&self, name: &str) -> bool {
        self.granted.iter().any(|n| n == name)
    }

    /// `exists(name)`: whether a granted secret is resolved and usable.
    ///
    /// Returns `false` for an ungranted name *and* for a granted-but-unresolved
    /// one, deliberately: the WIT documents this as disclosing nothing beyond a
    /// boolean, so the two collapse. The distinction remains available to the
    /// *operator* through `unavailable` on `apply`.
    #[must_use]
    pub fn exists(&self, name: &str) -> bool {
        self.is_granted(name) && self.material.contains_key(name)
    }

    /// `permitted-operations(name)`: what the guest may do with a secret.
    ///
    /// Returns an empty list for an ungranted name rather than an error, matching
    /// the WIT signature. An empty list is the honest answer to "what may I do
    /// with something I cannot reach?".
    #[must_use]
    pub fn permitted_operations(&self, name: &str) -> Vec<&'static str> {
        if !self.is_granted(name) {
            return Vec::new();
        }
        match self.material.get(name) {
            Some(m) => PermittedOp::all()
                .iter()
                .filter(|op| m.permits(**op))
                .map(|op| op.as_str())
                .collect(),
            None => Vec::new(),
        }
    }

    /// Perform an operation with a secret, returning only its result.
    ///
    /// # The access-control order, and why each step is where it is
    ///
    /// 1. **Grant check first** — before the material lookup, so an ungranted name
    ///    produces `not-granted` regardless of whether the host holds it. Reversed,
    ///    an ungranted guest could probe which secret names are populated.
    /// 2. **Availability second** — a granted name with no material is
    ///    `unavailable`, a deployment fault distinct from a refusal.
    /// 3. **Permission third** — a grant for `sign` must not become a grant for
    ///    `hmac`.
    /// 4. **Input size fourth** — cheap, and it protects the host's memory.
    /// 5. **The primitive last**, with the material in hand.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-4004` carrying the `secret-error` variant name in context, so
    /// the ABI layer maps it without re-deciding.
    pub fn apply(
        &self,
        name: &str,
        op: PermittedOp,
        input: &[u8],
        crypto: &impl SecretCrypto,
    ) -> Result<Vec<u8>> {
        if !self.is_granted(name) {
            return Err(Self::secret_failure(name, "not-granted"));
        }
        let Some(material) = self.material.get(name) else {
            return Err(Self::secret_failure(name, "unavailable"));
        };
        if !material.permits(op) {
            return Err(Self::secret_failure(name, "operation-not-permitted"));
        }
        if input.len() > MAX_SECRET_INPUT {
            return Err(Self::secret_failure(name, "input-too-long")
                .with_context("input_bytes", input.len().to_string()));
        }

        if op == PermittedOp::Verify {
            // The WIT carries a record for verify, and the ABI layer splits it. A
            // `verify` arriving here as a bare input means the caller did not, so
            // it is reported rather than guessed.
            return Err(
                Self::secret_failure(name, "operation-not-permitted").with_remediation(
                    "`verify` takes a `verify-request` record; the ABI layer must \
                     split it into input and signature before calling `apply`",
                ),
            );
        }

        let outcome = match op {
            PermittedOp::Sign => crypto.sign(&material.value, input),
            PermittedOp::Hmac => crypto.hmac(&material.value, input),
            PermittedOp::Encrypt => crypto.encrypt(&material.value, input),
            PermittedOp::Decrypt => crypto.decrypt(&material.value, input),
            PermittedOp::PublicKey => crypto.public_key(&material.value),
            PermittedOp::Verify => unreachable!("handled above"),
        };

        outcome.map_err(|reason| {
            // The primitive failed. Its reason is **not** forwarded to the guest
            // through the WIT error -- it lands in the context for the host log --
            // because a primitive's error text can carry key material or internal
            // structure.
            Self::secret_failure(name, "unavailable")
                .with_cause(reason)
                .with_context("operation", op.as_str())
        })
    }

    /// Perform a `verify`, which takes a separate signature.
    ///
    /// # Why this is not part of `apply`
    ///
    /// `verify` is the one operation whose payload is a **record** rather than a
    /// bare `list<u8>`. Splitting it here keeps the common path simple and puts
    /// the record's two fields in a signature the compiler can check.
    ///
    /// # Errors
    ///
    /// As [`SecretStore::apply`].
    pub fn verify(
        &self,
        name: &str,
        input: &[u8],
        signature: &[u8],
        crypto: &impl SecretCrypto,
    ) -> Result<bool> {
        if !self.is_granted(name) {
            return Err(Self::secret_failure(name, "not-granted"));
        }
        let Some(material) = self.material.get(name) else {
            return Err(Self::secret_failure(name, "unavailable"));
        };
        if !material.permits(PermittedOp::Verify) {
            return Err(Self::secret_failure(name, "operation-not-permitted"));
        }
        if input.len() > MAX_SECRET_INPUT || signature.len() > MAX_SECRET_INPUT {
            return Err(Self::secret_failure(name, "input-too-long"));
        }

        crypto
            .verify(&material.value, input, signature)
            .map_err(|reason| {
                Self::secret_failure(name, "unavailable")
                    .with_cause(reason)
                    .with_context("operation", "verify")
            })
    }

    /// Build the error for a `secret-error` variant.
    ///
    /// The variant name travels in `context` so the ABI layer maps it without
    /// re-deciding, and so the host log says which condition fired.
    ///
    /// # Why this takes no receiver
    ///
    /// It has no state to consult, and clippy's `unused_self` said so. The same
    /// shape appeared in `handles.rs` (`§O-064d`) — a helper left with a receiver
    /// from a design that later moved its work elsewhere. A free function is the
    /// honest signature, and `#[must_use]` states that the caller always uses the
    /// result.
    #[must_use]
    pub fn secret_failure(name: &str, variant: &str) -> Error {
        Error::new(
            ErrorCode::SecretUseFailed,
            format!("the secret operation failed: {variant}"),
        )
        .with_context("secret", name.to_owned())
        .with_context("variant", variant.to_owned())
        .with_remediation(match variant {
            "not-granted" => {
                "add the secret to `[capabilities.secrets]` in `qqq.toml`; the \
                 manifest's allowlist is the only way a guest reaches a secret"
            }
            "unavailable" => {
                "the manifest grants this secret but the host could not resolve \
                 it; check that its source is set in the deployment environment"
            }
            "operation-not-permitted" => {
                "the secret's `operations` list does not include this one; add it \
                 in `qqq.toml` if the use is intended"
            }
            "input-too-long" => {
                "the input exceeded the host's per-secret-call maximum; send less \
                 data per call"
            }
            _ => "this is a QQQ bug; please report it",
        })
    }
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for the real primitives, so these tests exercise the
    /// **access-control** behaviour rather than a cipher's.
    ///
    /// Each operation is reversible and obviously distinguishable, which is what
    /// lets a test assert *which* primitive ran — important, because `apply`
    /// dispatching to the wrong one would otherwise pass every permission test.
    struct FakeCrypto {
        /// Every `(operation, key)` the primitive was called with.
        calls: std::cell::RefCell<Vec<(&'static str, Vec<u8>)>>,
        /// When true, every operation fails.
        failing: bool,
    }

    impl FakeCrypto {
        fn new() -> Self {
            Self {
                calls: std::cell::RefCell::new(Vec::new()),
                failing: false,
            }
        }

        fn failing() -> Self {
            Self {
                calls: std::cell::RefCell::new(Vec::new()),
                failing: true,
            }
        }

        fn record(&self, name: &'static str, key: &[u8]) {
            self.calls.borrow_mut().push((name, key.to_vec()));
        }
    }

    impl SecretCrypto for FakeCrypto {
        fn sign(&self, key: &[u8], input: &[u8]) -> std::result::Result<Vec<u8>, String> {
            self.record("sign", key);
            if self.failing {
                return Err("primitive failed".to_owned());
            }
            Ok([b"SIG".as_slice(), input].concat())
        }

        fn verify(
            &self,
            key: &[u8],
            input: &[u8],
            signature: &[u8],
        ) -> std::result::Result<bool, String> {
            self.record("verify", key);
            if self.failing {
                return Err("primitive failed".to_owned());
            }
            Ok(signature == [b"SIG".as_slice(), input].concat())
        }

        fn hmac(&self, key: &[u8], input: &[u8]) -> std::result::Result<Vec<u8>, String> {
            self.record("hmac", key);
            if self.failing {
                return Err("primitive failed".to_owned());
            }
            Ok([b"MAC".as_slice(), input].concat())
        }

        fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> std::result::Result<Vec<u8>, String> {
            self.record("encrypt", key);
            if self.failing {
                return Err("primitive failed".to_owned());
            }
            Ok([b"ENC".as_slice(), plaintext].concat())
        }

        fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> std::result::Result<Vec<u8>, String> {
            self.record("decrypt", key);
            if self.failing {
                return Err("primitive failed".to_owned());
            }
            Ok(ciphertext
                .strip_prefix(b"ENC".as_slice())
                .unwrap_or(ciphertext)
                .to_vec())
        }

        fn public_key(&self, key: &[u8]) -> std::result::Result<Vec<u8>, String> {
            self.record("public-key", key);
            if self.failing {
                return Err("primitive failed".to_owned());
            }
            // A DERIVED value, not the key with a prefix. The first version
            // returned PUB ++ key, which made the fake model a BUGGY primitive
            // -- one that leaks the private half through its public key -- and
            // 	he_secret_material_never_appears_in_a_result correctly failed.
            // A fake has to model a correct implementation, or every test that
            // uses it is testing the fake's defect.
            let digest = <sha2::Sha256 as sha2::Digest>::digest(key);
            Ok([b"PUB".as_slice(), &digest[..8]].concat())
        }
    }

    const MATERIAL: &[u8] = b"super-secret-key-material";

    fn store() -> SecretStore {
        SecretStore::with_grants(
            vec!["signing-key".to_owned(), "unresolved".to_owned()],
            vec![SecretMaterial::new(
                "signing-key",
                MATERIAL.to_vec(),
                vec![
                    PermittedOp::Sign,
                    PermittedOp::Verify,
                    PermittedOp::PublicKey,
                ],
            )],
        )
    }

    #[test]
    fn a_granted_operation_returns_its_result() {
        let crypto = FakeCrypto::new();
        let out = store()
            .apply("signing-key", PermittedOp::Sign, b"payload", &crypto)
            .expect("permitted");
        assert_eq!(out, b"SIGpayload");
    }

    /// **The core property.** The material must not appear in any result.
    ///
    /// A test checking only the result *shape* would pass even if `apply` returned
    /// the key, so this asserts the key bytes are absent.
    #[test]
    fn the_secret_material_never_appears_in_a_result() {
        let crypto = FakeCrypto::new();
        let out = store()
            .apply("signing-key", PermittedOp::Sign, b"payload", &crypto)
            .expect("permitted");
        assert!(
            !out.windows(MATERIAL.len()).any(|w| w == MATERIAL),
            "the key material must never cross to the guest"
        );

        // Even `public-key`, the one operation returning key-derived bytes, must
        // not return the private material.
        let pubkey = store()
            .apply("signing-key", PermittedOp::PublicKey, b"", &crypto)
            .expect("permitted");
        assert!(
            !pubkey.windows(MATERIAL.len()).any(|w| w == MATERIAL),
            "a public key must not contain the private material"
        );
    }

    /// The value must reach the primitive, or the operation is meaningless.
    ///
    /// The control for the test above: proving the key does NOT leak is vacuous if
    /// it never reached the crypto at all.
    #[test]
    fn the_material_does_reach_the_primitive() {
        let crypto = FakeCrypto::new();
        store()
            .apply("signing-key", PermittedOp::Sign, b"payload", &crypto)
            .expect("permitted");

        let calls = crypto.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "sign", "the sign primitive must run");
        assert_eq!(calls[0].1, MATERIAL, "and it must receive the material");
    }

    /// An ungranted name is refused, and the material lookup never happens.
    #[test]
    fn an_ungranted_secret_is_refused() {
        let crypto = FakeCrypto::new();
        let err = store()
            .apply("other-key", PermittedOp::Sign, b"x", &crypto)
            .expect_err("not granted");
        assert_eq!(err.code, ErrorCode::SecretUseFailed);
        assert!(err
            .context
            .iter()
            .any(|(k, v)| k == "variant" && v == "not-granted"));
        assert!(
            crypto.calls.borrow().is_empty(),
            "the primitive must not run for an ungranted secret"
        );
    }

    /// A grant for one operation must not be pivotable to another.
    ///
    /// The property the WIT calls out: *"a secret declared for signing cannot be
    /// used for HMAC, so a leaked grant cannot be pivoted into a different
    /// primitive."*
    #[test]
    fn a_grant_cannot_be_pivoted_to_another_operation() {
        let crypto = FakeCrypto::new();
        let err = store()
            .apply("signing-key", PermittedOp::Hmac, b"x", &crypto)
            .expect_err("hmac was not permitted");
        assert!(err
            .context
            .iter()
            .any(|(k, v)| k == "variant" && v == "operation-not-permitted"));
        assert!(
            crypto.calls.borrow().is_empty(),
            "the primitive must not run for a non-permitted operation"
        );
    }

    /// A granted but unresolved secret is `unavailable`, NOT `not-granted` — a
    /// deployment fault and a refusal need different fixes.
    #[test]
    fn a_granted_but_unresolved_secret_is_unavailable() {
        let crypto = FakeCrypto::new();
        let err = store()
            .apply("unresolved", PermittedOp::Sign, b"x", &crypto)
            .expect_err("no material");
        assert!(
            err.context
                .iter()
                .any(|(k, v)| k == "variant" && v == "unavailable"),
            "a granted-but-unresolved secret is a deployment fault: {err}"
        );
    }

    /// The grant check runs **before** the material lookup, so an ungranted guest
    /// learns nothing about which secrets the host holds.
    #[test]
    fn the_grant_check_precedes_the_material_lookup() {
        // A secret resolved but NOT granted. Reversed order would report
        // `unavailable` and leak that the host holds material for a name the guest
        // may not use.
        let s = SecretStore::with_grants(
            vec![],
            vec![SecretMaterial::new(
                "hidden",
                MATERIAL.to_vec(),
                vec![PermittedOp::Sign],
            )],
        );
        let crypto = FakeCrypto::new();
        let err = s
            .apply("hidden", PermittedOp::Sign, b"x", &crypto)
            .expect_err("not granted");
        assert!(
            err.context
                .iter()
                .any(|(k, v)| k == "variant" && v == "not-granted"),
            "an ungranted name must report not-granted even when material exists: {err}"
        );
        assert!(!s.exists("hidden"), "and `exists` must not disclose it");
    }

    #[test]
    fn exists_is_false_for_ungranted_and_for_unresolved() {
        let s = store();
        assert!(s.exists("signing-key"));
        assert!(!s.exists("unresolved"), "granted but not resolved");
        assert!(!s.exists("never-heard-of-it"));
    }

    #[test]
    fn permitted_operations_lists_the_permitted_set() {
        let s = store();
        let ops = s.permitted_operations("signing-key");
        assert_eq!(ops, vec!["sign", "verify", "public-key"]);
    }

    #[test]
    fn permitted_operations_is_empty_for_an_ungranted_secret() {
        let s = store();
        assert!(
            s.permitted_operations("other-key").is_empty(),
            "an empty list is the honest answer to `what may I do with something \
             I cannot reach`"
        );
    }

    /// An oversized input is refused before the primitive runs.
    #[test]
    fn an_oversized_input_is_refused_before_the_primitive() {
        let crypto = FakeCrypto::new();
        let big = vec![0_u8; MAX_SECRET_INPUT + 1];
        let err = store()
            .apply("signing-key", PermittedOp::Sign, &big, &crypto)
            .expect_err("too long");
        assert!(err
            .context
            .iter()
            .any(|(k, v)| k == "variant" && v == "input-too-long"));
        assert!(
            crypto.calls.borrow().is_empty(),
            "the primitive must not be handed an oversized input"
        );

        // And exactly at the limit is accepted, so the bound is not off by one.
        let at_limit = vec![0_u8; MAX_SECRET_INPUT];
        store()
            .apply("signing-key", PermittedOp::Sign, &at_limit, &crypto)
            .expect("the limit itself must be allowed");
    }

    /// A primitive failure is reported as `unavailable` and its message is kept
    /// for the log rather than forwarded.
    #[test]
    fn a_primitive_failure_is_reported_without_forwarding_its_message() {
        let crypto = FakeCrypto::failing();
        let err = store()
            .apply("signing-key", PermittedOp::Sign, b"x", &crypto)
            .expect_err("the primitive failed");
        assert!(err
            .context
            .iter()
            .any(|(k, v)| k == "variant" && v == "unavailable"));
        assert!(
            !err.cause.is_empty(),
            "the primitive's reason must be kept for the host log"
        );
    }

    #[test]
    fn verify_round_trips_and_rejects_a_wrong_signature() {
        let crypto = FakeCrypto::new();
        let s = store();
        let sig = s
            .apply("signing-key", PermittedOp::Sign, b"msg", &crypto)
            .expect("sign");
        assert!(s
            .verify("signing-key", b"msg", &sig, &crypto)
            .expect("verify"));
        assert!(!s
            .verify("signing-key", b"msg", b"wrong", &crypto)
            .expect("verify"));
    }

    /// `verify` goes through the same grant and permission checks as `apply`.
    #[test]
    fn verify_enforces_the_same_access_control() {
        let crypto = FakeCrypto::new();
        let s = store();
        assert!(s.verify("other-key", b"m", b"s", &crypto).is_err());

        let hmac_only = SecretStore::with_grants(
            vec!["mac".to_owned()],
            vec![SecretMaterial::new(
                "mac",
                MATERIAL.to_vec(),
                vec![PermittedOp::Hmac],
            )],
        );
        let err = hmac_only
            .verify("mac", b"m", b"s", &crypto)
            .expect_err("mac does not permit verify");
        assert!(err
            .context
            .iter()
            .any(|(k, v)| k == "variant" && v == "operation-not-permitted"));
    }

    /// An out-of-range discriminant from the guest is rejected.
    #[test]
    fn an_out_of_range_operation_discriminant_is_rejected() {
        for d in 0..=5 {
            assert!(
                RequestedOp::from_discriminant(d).is_ok(),
                "discriminant {d} is in the declared set"
            );
        }
        for d in [6, 7, 100, u32::MAX] {
            let err = RequestedOp::from_discriminant(d).expect_err("out of range");
            assert_eq!(err.code, ErrorCode::SecretUseFailed);
            assert!(err.context.iter().any(|(k, _)| k == "discriminant"));
        }
    }

    /// The discriminants must match the WIT declaration order, or a guest calling
    /// `sign` would invoke `verify`.
    #[test]
    fn the_discriminants_match_the_wit_declaration_order() {
        let expected = [
            (0, "sign"),
            (1, "verify"),
            (2, "hmac"),
            (3, "decrypt"),
            (4, "encrypt"),
            (5, "public-key"),
        ];
        for (d, name) in expected {
            let op = RequestedOp::from_discriminant(d).expect("valid").op();
            assert_eq!(op.as_str(), name, "discriminant {d} must be `{name}`");
        }
        assert_eq!(PermittedOp::all().len(), 6);
    }

    #[test]
    fn operation_names_round_trip_through_parse() {
        for op in PermittedOp::all() {
            assert_eq!(PermittedOp::parse(op.as_str()), Some(*op));
        }
        assert_eq!(PermittedOp::parse("not-an-op"), None);
    }

    /// **A secret must not appear in a debug rendering.** A `Debug` printing the
    /// bytes would put the key in every log line that touched the store.
    #[test]
    fn debug_never_prints_the_material() {
        let m = SecretMaterial::new("k", MATERIAL.to_vec(), vec![PermittedOp::Sign]);
        let text = format!("{m:?}");
        assert!(text.contains('k'), "the name is not secret: {text}");
        assert!(
            text.contains("Sign"),
            "the permitted set is diagnostic: {text}"
        );
        assert!(
            !text.contains("super-secret"),
            "the material must never be printed: {text}"
        );

        let store_text = format!("{:?}", store());
        assert!(
            !store_text.contains("super-secret"),
            "the store must not print material: {store_text}"
        );
    }

    /// Dispatching must reach the RIGHT primitive, not merely a permitted one.
    #[test]
    fn each_operation_dispatches_to_its_own_primitive() {
        let crypto = FakeCrypto::new();
        let s = SecretStore::with_grants(
            vec!["k".to_owned()],
            vec![SecretMaterial::new(
                "k",
                MATERIAL.to_vec(),
                PermittedOp::all().to_vec(),
            )],
        );

        for (op, expected) in [
            (PermittedOp::Sign, "sign"),
            (PermittedOp::Hmac, "hmac"),
            (PermittedOp::Encrypt, "encrypt"),
            (PermittedOp::Decrypt, "decrypt"),
            (PermittedOp::PublicKey, "public-key"),
        ] {
            crypto.calls.borrow_mut().clear();
            let _ = s.apply("k", op, b"body", &crypto);
            let calls = crypto.calls.borrow();
            assert_eq!(
                calls.first().map(|(n, _)| *n),
                Some(expected),
                "`{}` must dispatch to `{expected}`",
                op.as_str()
            );
        }
    }

    /// A bare `verify` through `apply` is refused rather than guessed at.
    #[test]
    fn verify_through_apply_is_refused_with_an_explanation() {
        let crypto = FakeCrypto::new();
        let s = store();
        let err = s
            .apply("signing-key", PermittedOp::Verify, b"m", &crypto)
            .expect_err("verify needs a record");
        assert!(
            err.remediation
                .as_deref()
                .is_some_and(|r| r.contains("verify-request")),
            "the remediation must name the record: {err}"
        );
    }

    #[test]
    fn a_store_with_no_grants_reaches_nothing() {
        let s = SecretStore::new();
        let crypto = FakeCrypto::new();
        assert!(!s.exists("anything"));
        assert!(s.permitted_operations("anything").is_empty());
        assert!(s
            .apply("anything", PermittedOp::Sign, b"x", &crypto)
            .is_err());
    }

    /// Every `secret-error` variant must carry a remediation.
    #[test]
    fn every_error_variant_has_a_remediation() {
        for variant in [
            "not-granted",
            "unavailable",
            "operation-not-permitted",
            "input-too-long",
        ] {
            let e = SecretStore::secret_failure("k", variant);
            assert_eq!(e.code, ErrorCode::SecretUseFailed);
            assert!(
                e.remediation.is_some(),
                "`{variant}` must have a remediation"
            );
            assert!(e
                .context
                .iter()
                .any(|(k, v)| k == "variant" && v == variant));
        }
    }
}
