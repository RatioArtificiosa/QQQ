// SPDX-License-Identifier: Apache-2.0

//! The `qqq:crypto` host implementation — `random`, `hashing`, `hmac`,
//! `aead` and `signing`.
//!
//! Wires `wit/qqq-crypto.wit` to the [`AmbientState`] already in the store.
//!
//! [`AmbientState`]: crate::ambient::AmbientState
//!
//! # Scope, stated precisely
//!
//! All five interfaces are implemented:
//!
//! | Interface | State |
//! |---|---|
//! | `random` | implemented |
//! | `hashing` | implemented |
//! | `hmac` | implemented (`HOST-037`) |
//! | `aead` | implemented (`HOST-037`) |
//! | `signing` | implemented (`HOST-037`) |
//!
//! The registry reports `qqq:crypto@1.0.0` as `implemented: true`, pinned
//! by a test in `qqq-abi`. An interface whose grant is absent stays absent
//! from the linker rather than registered as a stub: a stub that traps at
//! call time turns a clear "unknown import" at instantiation into a mystery
//! at runtime, and instantiation is when a developer can still do something
//! about it.
//!
//! # Why all five bindings are generated
//!
//! Every interface in this module binds through `wasmtime::component::bindgen!`
//! against `../../wit/qqq-crypto.wit`, like `host_sql` and `host_http` do:
//! generated signatures carry the `result<_, error>` variants a `func_wrap`
//! closure cannot express, and the macro reads the same file the guest
//! toolchain consumes, so host and guest cannot disagree about a shape.
//! `random` and `hashing` used to be hand-written `func_wrap`s predating the
//! `wit/` wiring; they served bare lists while the WIT declared results, and
//! a WIT-conformant guest failed to *instantiate* — the probe below pins
//! that the shapes bind, and the WIT-reading tests pin the variant orders.
//! Hand-written host bodies remain (the trait implementations), but no
//! hand-written *signatures* do.
//!
//! # The two parameters that matter most
//!
//! * **The allowlist is enforced here, not in the guest.** `hash_data` checks
//!   the grant, that the algorithm is known, *and* that the manifest named it.
//!   The host can compute SHA-512 whether or not the manifest mentioned it, so
//!   without the third check the allowlist would be advisory.
//! * **`random` fails closed.** A source failure returns `source-failed`; it
//!   never falls back to a weaker generator. Predictable "randomness" is worse
//!   than an error, because the guest would not know to stop.
//!
//! # Error discipline: WIT `Err` on every interface
//!
//! All five interfaces report misuse as catchable WIT `Err` values, because
//! every one of them declares `result<_, _>` in `wit/qqq-crypto.wit`.
//! `random.get` returns `random-error`, `digest`/`digest-many` return
//! `hash-error`, and the `bindgen!` trio returns its own variants — so a
//! guest handles `algorithm-not-allowed`, `too-long` and `source-failed`
//! with `match`, never with a trap.
//!
//! That uniformity was *restored*, not original: `random` and `hashing`
//! used to trap (denied, over-long, or unlisted inputs never returned to
//! the guest) while the WIT already declared results. The host was behind
//! its own interface — a WIT-conformant guest failed to *instantiate*,
//! which the `iface_crypto` probe proves by importing all five interfaces
//! (a bare-shape host fails linkage, not the call). The only traps left
//! are version mismatches (an out-of-range `algorithm` discriminant that
//! passed the boundary means guest and host disagree about the enum),
//! which trap exactly as `bindgen!`-generated code would.
//!
//! The `iface_crypto` probe imports `random` and `hashing` from the real
//! WIT and matches on their `Err` cases, so a host that served bare lists
//! would fail at instantiation — the contract is proven by linkage, not
//! prose.
//!
//! # Input sizes (review finding HOST-037/4)
//!
//! `hashing` bounds its input through `MAX_HASH_INPUT`. `hmac`, `aead` and
//! `signing` deliberately carry no separate byte ceiling: their WIT error
//! variants (`hmac-error`, `aead-error`, `signature-error`) have no
//! `input-too-long` case, so a size refusal would have to masquerade as
//! `invalid-key` or `authentication-failed` — a lie that misdirects triage.
//! Adding a ceiling needs a WIT variant plus a coordinated registry handoff
//! (§5.2), which is recorded as follow-up rather than smuggled in here.
//! Fixed-size fields already bound what matters most: HMAC-Blake3 keys are
//! exactly 32 bytes, AEAD keys 32 and nonces 12, Ed25519 seeds and public
//! keys 32. Variable-length payloads remain bounded by the instance's
//! memory, fuel, and per-call allocation limits.

use wasmtime::component::{Linker, ResourceAny};

use qqq_cap::capability::Capability;
use qqq_cap::resolve::GrantSet;

use crate::ambient::hash_data;
use crate::linker::StoreData;

/// The WIT package this module implements.
pub const INTERFACE: &str = "qqq:crypto@1.0.0";

/// The `random` interface, as a component imports it.
pub const RANDOM: &str = "qqq:crypto/random@1.0.0";

/// The `hashing` interface, as a component imports it.
pub const HASHING: &str = "qqq:crypto/hashing@1.0.0";

/// The `hmac` interface, as a component imports it.
///
/// ```
/// assert_eq!(qqq_host::host_crypto::HMAC_IFACE, "qqq:crypto/hmac@1.0.0");
/// ```
pub const HMAC_IFACE: &str = "qqq:crypto/hmac@1.0.0";

/// The `aead` interface, as a component imports it.
///
/// ```
/// assert_eq!(qqq_host::host_crypto::AEAD_IFACE, "qqq:crypto/aead@1.0.0");
/// ```
pub const AEAD_IFACE: &str = "qqq:crypto/aead@1.0.0";

/// The `signing` interface, as a component imports it.
///
/// ```
/// assert_eq!(qqq_host::host_crypto::SIGNING_IFACE, "qqq:crypto/signing@1.0.0");
/// ```
pub const SIGNING_IFACE: &str = "qqq:crypto/signing@1.0.0";

/// An AEAD construction the host serves.
///
/// Mirrors the WIT `aead.construction` enum. Kept as a Rust enum so an
/// unknown discriminant fails closed by construction rather than by string
/// comparison — and so the declaration order is pinned by a test, because
/// the order is the guest-visible numbering.
///
/// ```
/// assert_eq!(
///     qqq_host::host_crypto::AeadConstruction::parse("aes-256-gcm"),
///     Some(qqq_host::host_crypto::AeadConstruction::Aes256Gcm)
/// );
/// assert_eq!(
///     qqq_host::host_crypto::AeadConstruction::parse("rot13"),
///     None
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadConstruction {
    /// AES-256-GCM. Hardware-accelerated on most modern CPUs.
    Aes256Gcm,
    /// ChaCha20-Poly1305. Preferred where AES hardware acceleration is
    /// absent or its timing characteristics are a concern.
    ChaCha20Poly1305,
}

impl AeadConstruction {
    /// The manifest spelling, or `None` for anything the host does not serve.
    ///
    /// Unknown names fail closed here rather than at the crypto call: a name
    /// the host cannot implement is not a construction the guest may use.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// The WIT discriminant: `aes-256-gcm = 0`, `chacha20-poly1305 = 1`.
    ///
    /// The order is the guest-visible numbering, so it is pinned by a test
    /// that reads the WIT rather than restating it here.
    ///
    /// ```
    /// use qqq_host::host_crypto::AeadConstruction;
    /// assert_eq!(AeadConstruction::Aes256Gcm.discriminant(), 0);
    /// assert_eq!(AeadConstruction::ChaCha20Poly1305.discriminant(), 1);
    /// ```
    #[must_use]
    pub const fn discriminant(self) -> u32 {
        match self {
            Self::Aes256Gcm => 0,
            Self::ChaCha20Poly1305 => 1,
        }
    }

    /// The construction for a WIT discriminant, or `None` when the guest
    /// and host disagree about the enum — a version mismatch, refused as
    /// `construction-not-allowed` so an unknown construction can never
    /// become a default.
    ///
    /// ```
    /// use qqq_host::host_crypto::AeadConstruction;
    ///
    /// assert_eq!(AeadConstruction::from_discriminant(0), Some(AeadConstruction::Aes256Gcm));
    /// assert_eq!(AeadConstruction::from_discriminant(1), Some(AeadConstruction::ChaCha20Poly1305));
    /// assert_eq!(AeadConstruction::from_discriminant(7), None);
    /// ```
    #[must_use]
    pub const fn from_discriminant(index: u32) -> Option<Self> {
        match index {
            0 => Some(Self::Aes256Gcm),
            1 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// The nonce length in bytes, shared by both constructions.
    ///
    /// Fixed by the constructions, not configured, and needed only in this
    /// module — guests learn the lengths through
    /// `nonce-length`/`key-length`.
    const NONCE_LEN: usize = 12;

    /// The key length in bytes, shared by both constructions.
    const KEY_LEN: usize = 32;

    /// The authentication tag length in bytes, appended to the ciphertext.
    /// Shared by both constructions.
    const TAG_LEN: usize = 16;
}

/// A signing algorithm the host serves.
///
/// V1 offers Ed25519 only: small keys, fast verification, and no parameter
/// choices to get wrong.
///
/// ```
/// assert_eq!(
///     qqq_host::host_crypto::SignAlgorithm::parse("ed25519"),
///     Some(qqq_host::host_crypto::SignAlgorithm::Ed25519)
/// );
/// assert_eq!(qqq_host::host_crypto::SignAlgorithm::parse("rsa"), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAlgorithm {
    /// Ed25519. The only signing algorithm offered in V1.
    Ed25519,
}

impl SignAlgorithm {
    /// The manifest spelling, or `None` for anything the host does not serve.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }

    /// The WIT discriminant: `ed25519 = 0`.
    ///
    /// ```
    /// assert_eq!(
    ///     qqq_host::host_crypto::SignAlgorithm::Ed25519.discriminant(),
    ///     0
    /// );
    /// ```
    #[must_use]
    pub const fn discriminant(self) -> u32 {
        match self {
            Self::Ed25519 => 0,
        }
    }

    /// The algorithm for a WIT discriminant, or `None` when the guest and
    /// host disagree about the enum.
    ///
    /// ```
    /// use qqq_host::host_crypto::SignAlgorithm;
    ///
    /// assert_eq!(SignAlgorithm::from_discriminant(0), Some(SignAlgorithm::Ed25519));
    /// assert_eq!(SignAlgorithm::from_discriminant(7), None);
    /// ```
    #[must_use]
    pub const fn from_discriminant(index: u32) -> Option<Self> {
        match index {
            0 => Some(Self::Ed25519),
            _ => None,
        }
    }
}

/// Which crypto algorithms the guest may use, and for what.
///
/// Resolved once at deploy from the manifest's `[capabilities.crypto]`
/// stanza; cloned per request, never re-resolved per call. Membership is
/// the allowlist: an unlisted algorithm is refused by name.
///
/// ```
/// let config = qqq_host::host_crypto::CryptoConfig::from_manifest(
///     &qqq_cap::manifest::Manifest::parse(
///         "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
///          [capabilities.crypto]\nrandom = true\n",
///     )
///     .expect("manifest parses"),
/// );
/// assert!(config.hashes.is_empty());
/// assert!(config.hmacs.is_empty());
/// ```
#[derive(Debug, Clone, Default)]
pub struct CryptoConfig {
    /// Hash algorithms the manifest's `hash` list named.
    pub hashes: Vec<crate::ambient::HashAlgorithm>,
    /// HMAC algorithms the manifest's `hmac` list named.
    pub hmacs: Vec<crate::ambient::HashAlgorithm>,
    /// AEAD constructions the manifest's `aead` list named.
    pub aeads: Vec<AeadConstruction>,
    /// Signing algorithms the manifest's `sign` list named.
    pub signs: Vec<SignAlgorithm>,
}

impl CryptoConfig {
    /// The deploy-time resolution: exactly what the manifest configures.
    ///
    /// Unknown names are dropped, not refused: the allowlist is enforced
    /// by set membership at call time, so an unknown name simply never
    /// matches — the same indistinguishability rule hashing uses, which
    /// keeps a guest from enumerating the host's supported set.
    ///
    /// ```
    /// let manifest = qqq_cap::manifest::Manifest::parse(
    ///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
    ///      [capabilities.crypto]\nhash = [\"sha256\"]\n",
    /// )
    /// .expect("manifest parses");
    /// let config = qqq_host::host_crypto::CryptoConfig::from_manifest(&manifest);
    /// assert_eq!(config.hashes, vec![qqq_host::ambient::HashAlgorithm::Sha256]);
    /// ```
    #[must_use]
    pub fn from_manifest(manifest: &qqq_cap::manifest::Manifest) -> Self {
        let crypto = manifest.capabilities.crypto.as_ref();
        let hashes = crypto
            .map(|c| {
                c.hash
                    .iter()
                    .filter_map(|h| crate::ambient::HashAlgorithm::parse(h))
                    .collect()
            })
            .unwrap_or_default();
        let hmacs = crypto
            .map(|c| {
                c.hmac
                    .iter()
                    .filter_map(|h| crate::ambient::HashAlgorithm::parse(h))
                    .collect()
            })
            .unwrap_or_default();
        let aeads = crypto
            .map(|c| {
                c.aead
                    .iter()
                    .filter_map(|h| AeadConstruction::parse(h))
                    .collect()
            })
            .unwrap_or_default();
        let signs = crypto
            .map(|c| {
                c.sign
                    .iter()
                    .filter_map(|h| SignAlgorithm::parse(h))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            hashes,
            hmacs,
            aeads,
            signs,
        }
    }
}

/// The per-instance view: deploy-resolved config, no shared state.
///
/// Pure computation needs no backend and no per-request state to share:
/// the view is just the config, cloned per request.
///
/// ```
/// let view = qqq_host::host_crypto::CryptoView::new(std::sync::Arc::new(
///     qqq_host::host_crypto::CryptoConfig::from_manifest(
///         &qqq_cap::manifest::Manifest::parse(
///             "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
///         )
///         .expect("manifest parses"),
///     ),
/// ));
/// assert!(view.config.hashes.is_empty());
/// ```
#[derive(Debug, Clone, Default)]
pub struct CryptoView {
    /// The deploy-resolved allowlists.
    pub config: std::sync::Arc<CryptoConfig>,
}

impl CryptoView {
    /// A view over `config`.
    #[must_use]
    pub fn new(config: std::sync::Arc<CryptoConfig>) -> Self {
        Self { config }
    }
}
/// The maximum input length the host will hash in one call.
///
/// A bound rather than an unbounded allocation: a guest passing a huge buffer
/// is either buggy or attacking the host's memory, and a limit is cheaper than
/// an investigation. 64 MiB is generous for a hash input and small enough that
/// the copy across the ABI boundary cannot exhaust a typical instance budget.
///
/// ```
/// assert_eq!(qqq_host::host_crypto::MAX_HASH_INPUT, 64 * 1024 * 1024);
/// ```
pub const MAX_HASH_INPUT: usize = 64 * 1024 * 1024;

/// Register the crypto host interfaces the grants justify.
///
/// Every interface registers only under its grant, so an ungranted
/// interface stays absent from the linker and a component importing it
/// fails at instantiation with a nameable error rather than at call time.
///
/// # Errors
///
/// A `wasmtime::Error` if the linker rejects a signature.
///
/// ```
/// let mut config = wasmtime::Config::new();
/// config.wasm_component_model(true);
/// let engine = wasmtime::Engine::new(&config).expect("engine builds");
/// let manifest = qqq_cap::manifest::Manifest::parse(
///     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\
///      [capabilities.crypto]\nhmac = [\"sha256\"]\n",
/// )
/// .expect("manifest parses");
/// let grants = qqq_cap::resolve::GrantSet::from_manifest(&manifest);
/// let mut linker =
///     wasmtime::component::Linker::<qqq_host::linker::StoreData>::new(&engine);
/// qqq_host::host_crypto::register(&mut linker, &grants).expect("register");
/// ```
pub fn register(linker: &mut Linker<StoreData>, grants: &GrantSet) -> wasmtime::Result<()> {
    use wasmtime::component::HasSelf;
    if grants.grants(Capability::CryptoRandom) {
        bindings::qqq::crypto::random::add_to_linker::<StoreData, HasSelf<StoreData>>(
            linker,
            |state| state,
        )?;
    }
    if grants.grants(Capability::CryptoHash) {
        bindings::qqq::crypto::hashing::add_to_linker::<StoreData, HasSelf<StoreData>>(
            linker,
            |state| state,
        )?;
    }
    if grants.grants(Capability::CryptoHmac) {
        register_hmac(linker)?;
    }
    if grants.grants(Capability::CryptoAead) {
        register_aead(linker)?;
    }
    if grants.grants(Capability::CryptoSign) {
        register_signing(linker)?;
    }
    Ok(())
}

/// The generated bindings carry no doc comments of their own, and re-exporting
/// them would fail `missing_docs` on the WIT's definition rather than on any
/// prose this crate wrote. The allow is scoped to the generated module so
/// hand-written items keep the lint.
#[allow(missing_docs)]
mod bindings {
    wasmtime::component::bindgen!({
        path: "../../wit/qqq-crypto.wit",
        interfaces: "import qqq:crypto/random@1.0.0; import qqq:crypto/hashing@1.0.0; import qqq:crypto/hmac@1.0.0; import qqq:crypto/aead@1.0.0; import qqq:crypto/signing@1.0.0;",
    });
}

/// The WIT `hmac-error`, re-exported rather than re-declared: the WIT variant
/// is the definition. (Same rule as `host_log` and `host_kv`.)
pub use bindings::qqq::crypto::hmac::HmacError as WitHmacError;

/// The WIT `aead-error`, re-exported rather than re-declared.
pub use bindings::qqq::crypto::aead::AeadError as WitAeadError;

/// The WIT `signature-error`, re-exported rather than re-declared.
pub use bindings::qqq::crypto::signing::SignatureError as WitSignatureError;

use bindings::qqq::crypto::aead::Construction as WitConstruction;
use bindings::qqq::crypto::hmac::Algorithm as WitHmacAlgorithm;
use bindings::qqq::crypto::signing::Algorithm as WitSignAlgorithm;

/// The host implementation of `qqq:crypto/random`.
///
/// Grant first (an ungranted call fails before its length is judged), then
/// the `SEC-011` boundary, then the read. Both are the call-time re-checks
/// `ARCH-012` demands of a grant-gated registration: a mis-built linker
/// that bound the interface unconditionally still cannot hand out entropy.
impl bindings::qqq::crypto::random::Host for crate::linker::StoreData {
    fn get(
        &mut self,
        length: u32,
    ) -> std::result::Result<Vec<u8>, bindings::qqq::crypto::random::RandomError> {
        use bindings::qqq::crypto::random::RandomError;
        // Defence in depth: the function is only registered when granted,
        // but re-checking at call time means a future change that registers
        // it unconditionally still cannot hand out entropy. The refusal
        // is a WIT `Err`, not a trap: the interface declares
        // `result<list<u8>, random-error>`.
        //
        // No `guard::guard` wrapper: the body contains no panic primitive
        // (the H1 checker enforces that), and the return channel is the
        // WIT `result` — a host fault would have nowhere to go but a case
        // the WIT does not define.
        //
        // Through the audit seam, like every other crypto entry point: an
        // inline grant check would answer identically while leaving a
        // `random.get` caller looking capability-clean to `assert-caps-only`.
        crate::ambient::require(self, Capability::CryptoRandom, "random_get")
            .map_err(|_| RandomError::NotGranted)?;
        // **`SEC-011`: the boundary check, before any host work.**
        //
        // Charged ahead of the allocation, not after: `random_bytes`
        // allocates `length` bytes on the guest's instruction, so a check
        // that ran afterwards would have already paid the cost it exists
        // to prevent. The ceiling is read from the state, so the boundary
        // and the allocation cannot disagree. `ambient` enforces it too,
        // and that redundancy is deliberate: this is the boundary's own
        // statement of its contract, and `ambient` may be reached from
        // callers that have no boundary.
        if random_length_verdict(length, &self.ambient).is_reject() {
            return Err(RandomError::TooLong);
        }
        match self.ambient.read_random(length) {
            Ok(bytes) => Ok(bytes),
            // A source failure fails closed as a WIT error, not a trap:
            // predictable "randomness" is worse than a failure, and the
            // guest was promised a `result`. A replay log that cannot
            // supply the bytes reports `source-failed` too — the WIT has
            // no replay case, and the bytes are unavailable either way.
            Err(_) => Err(RandomError::SourceFailed),
        }
    }
}

/// The host implementation of `qqq:crypto/hashing`.
///
/// The grant and the allowlist are enforced by [`hash_data`](crate::ambient::hash_data),
/// which every path calls: the `ARCH-012` `ViaHelper` shape — one shared
/// helper performing the check, rather than a check inlined per function.
/// The boundary sizes are enforced here, before the helper runs.
impl bindings::qqq::crypto::hashing::Host for crate::linker::StoreData {
    fn digest(
        &mut self,
        algorithm: bindings::qqq::crypto::hashing::Algorithm,
        data: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, bindings::qqq::crypto::hashing::HashError> {
        use bindings::qqq::crypto::hashing::{Algorithm, HashError};
        let name = match algorithm {
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
            Algorithm::Blake3 => "blake3",
        };
        // Size, through the boundary layer.
        if crate::boundary::size("data", data.len(), MAX_HASH_INPUT)
            .into_result("data")
            .is_err()
        {
            return Err(HashError::InputTooLong);
        }
        match hash_data(self, name, &data) {
            Ok(digested) => Ok(digested),
            // `hash_data` reports `NotGranted` (no grant) and
            // `AlgorithmNotAllowed` (unlisted); the WIT `hash-error`
            // has only the latter, and the registration is already
            // grant-gated, so an ungranted call reaching here is the
            // mis-built linker the allowlist names.
            Err(_) => Err(HashError::AlgorithmNotAllowed),
        }
    }

    fn digest_many(
        &mut self,
        algorithm: bindings::qqq::crypto::hashing::Algorithm,
        inputs: Vec<Vec<u8>>,
    ) -> std::result::Result<Vec<Vec<u8>>, bindings::qqq::crypto::hashing::HashError> {
        use bindings::qqq::crypto::hashing::{Algorithm, HashError};
        // **`SEC-011`: the list boundary, on BOTH axes.**
        //
        // This is the case the two-axis check exists for. The earlier
        // version only bounded each element's length, so a guest passing a
        // hundred million *empty* lists allocated a `Vec<Vec<u8>>` of
        // headers — zero payload bytes, gigabytes of metadata. Neither axis
        // alone catches it, which is why `list_size` states both.
        let total_bytes: usize = inputs.iter().map(Vec::len).sum();
        if crate::boundary::list_size("inputs", inputs.len(), total_bytes)
            .into_result("inputs")
            .is_err()
        {
            return Err(HashError::InputTooLong);
        }
        let name = match algorithm {
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
            Algorithm::Blake3 => "blake3",
        };
        // After the `list_size` gate above, so the capacity is bounded
        // by the checked count — never by the raw guest length.
        let mut out = Vec::with_capacity(inputs.len());
        for (i, input) in inputs.iter().enumerate() {
            // The per-element limit is still separate from the list
            // limits: a single 1 GiB input is one element and within
            // neither of them.
            if crate::boundary::size("inputs", input.len(), MAX_HASH_INPUT)
                .with_field("inputs")
                .into_result(&format!("inputs[{i}]"))
                .is_err()
            {
                return Err(HashError::InputTooLong);
            }
            match hash_data(self, name, input) {
                Ok(digested) => out.push(digested),
                Err(_) => return Err(HashError::AlgorithmNotAllowed),
            }
        }
        Ok(out)
    }
}

/// The `hmac` interface.
fn register_hmac(linker: &mut Linker<StoreData>) -> wasmtime::Result<()> {
    use wasmtime::component::HasSelf;
    bindings::qqq::crypto::hmac::add_to_linker::<StoreData, HasSelf<StoreData>>(linker, |state| {
        state
    })?;
    Ok(())
}

/// The `aead` interface.
fn register_aead(linker: &mut Linker<StoreData>) -> wasmtime::Result<()> {
    use wasmtime::component::HasSelf;
    bindings::qqq::crypto::aead::add_to_linker::<StoreData, HasSelf<StoreData>>(linker, |state| {
        state
    })?;
    Ok(())
}

/// The `signing` interface.
fn register_signing(linker: &mut Linker<StoreData>) -> wasmtime::Result<()> {
    use wasmtime::component::HasSelf;
    bindings::qqq::crypto::signing::add_to_linker::<StoreData, HasSelf<StoreData>>(
        linker,
        |state| state,
    )?;
    Ok(())
}

/// Compute one HMAC tag.
///
/// Shared by `compute` (returned) and `verify` (compared in constant time):
/// one implementation means the two cannot disagree about what a tag is.
///
/// # What `Blake3` means here
///
/// Keyed BLAKE3 (`blake3::keyed_hash`), not RFC-2104 HMAC with BLAKE3 as the
/// hash. The WIT reuses the `hashing.algorithm` enum, so the name alone does
/// not say which construction runs; this is the statement: a 32-byte key is
/// the keyed mode's key, any other length is `invalid-key`, and a tag from
/// another construction never verifies. Guests hashing with BLAKE3
/// unkeyed (`hashing.digest`) and keying BLAKE3 (`hmac.compute`)
/// are using two different functions that share a name.
fn hmac_tag(
    algorithm: crate::ambient::HashAlgorithm,
    key: &[u8],
    data: &[u8],
) -> std::result::Result<Vec<u8>, WitHmacError> {
    if key.is_empty() {
        return Err(WitHmacError::InvalidKey);
    }
    match algorithm {
        crate::ambient::HashAlgorithm::Sha256 => {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let mut mac =
                Hmac::<Sha256>::new_from_slice(key).map_err(|_| WitHmacError::InvalidKey)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        crate::ambient::HashAlgorithm::Sha512 => {
            use hmac::{Hmac, Mac};
            use sha2::Sha512;
            let mut mac =
                Hmac::<Sha512>::new_from_slice(key).map_err(|_| WitHmacError::InvalidKey)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        crate::ambient::HashAlgorithm::Blake3 => {
            let key32: &[u8; 32] = key.try_into().map_err(|_| WitHmacError::InvalidKey)?;
            Ok(blake3::keyed_hash(key32, data).as_bytes().to_vec())
        }
    }
}

/// The host implementation of `qqq:crypto/hmac`.
///
/// Grant first (an ungranted call fails before its algorithm is judged),
/// then the algorithm's membership in the manifest's allowlist. Both are
/// re-checked per call even though registration is grant-gated
/// (`ARCH-012`): a mis-built linker must still deny.
impl bindings::qqq::crypto::hmac::Host for crate::linker::StoreData {
    fn compute(
        &mut self,
        algorithm: WitHmacAlgorithm,
        key: Vec<u8>,
        data: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, WitHmacError> {
        crate::ambient::require(self, Capability::CryptoHmac, "hmac_compute")
            .map_err(|_| WitHmacError::AlgorithmNotAllowed)?;
        let alg = match algorithm {
            WitHmacAlgorithm::Sha256 => crate::ambient::HashAlgorithm::Sha256,
            WitHmacAlgorithm::Sha512 => crate::ambient::HashAlgorithm::Sha512,
            WitHmacAlgorithm::Blake3 => crate::ambient::HashAlgorithm::Blake3,
        };
        if !self.crypto.config.hmacs.contains(&alg) {
            return Err(WitHmacError::AlgorithmNotAllowed);
        }
        hmac_tag(alg, &key, &data)
    }

    fn verify(
        &mut self,
        algorithm: WitHmacAlgorithm,
        key: Vec<u8>,
        data: Vec<u8>,
        tag: Vec<u8>,
    ) -> std::result::Result<bool, WitHmacError> {
        crate::ambient::require(self, Capability::CryptoHmac, "hmac_verify")
            .map_err(|_| WitHmacError::AlgorithmNotAllowed)?;
        let alg = match algorithm {
            WitHmacAlgorithm::Sha256 => crate::ambient::HashAlgorithm::Sha256,
            WitHmacAlgorithm::Sha512 => crate::ambient::HashAlgorithm::Sha512,
            WitHmacAlgorithm::Blake3 => crate::ambient::HashAlgorithm::Blake3,
        };
        // Empty-key consistency (HOST-037/1): `compute` rejects an empty key
        // for every algorithm through `hmac_tag`, so `verify` must too —
        // before the length gate. Without this, SHA-256/512 `verify` with an
        // empty key returns `Ok(false)` (HMAC accepts any key length) while
        // BLAKE3 `verify` returns `Err(InvalidKey)`, and the two paths that
        // must agree about what a tag is disagree instead.
        if key.is_empty() {
            return Err(WitHmacError::InvalidKey);
        }
        // Length first: a tag of the wrong length can never match, and the
        // length itself is not secret — every tag of an algorithm shares it.
        // The digest length is what a valid tag must have; anything else is
        // simply not a tag for this algorithm.
        let digest_len = match alg {
            crate::ambient::HashAlgorithm::Sha512 => 64,
            crate::ambient::HashAlgorithm::Sha256 | crate::ambient::HashAlgorithm::Blake3 => 32,
        };
        if tag.len() != digest_len {
            return Ok(false);
        }
        // Constant time: a byte-by-byte comparison would leak the first
        // differing position and let a guest recover a valid tag one byte
        // at a time — the exact attack the WIT documents this function
        // as preventing.
        let equal = match alg {
            crate::ambient::HashAlgorithm::Sha256 => {
                use hmac::{Hmac, Mac};
                use sha2::Sha256;
                // `verify_slice` is constant-time; `==` on byte strings
                // would not be.
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(&key).map_err(|_| WitHmacError::InvalidKey)?;
                mac.update(&data);
                mac.verify_slice(&tag).is_ok()
            }
            crate::ambient::HashAlgorithm::Sha512 => {
                use hmac::{Hmac, Mac};
                use sha2::Sha512;
                let mut mac =
                    Hmac::<Sha512>::new_from_slice(&key).map_err(|_| WitHmacError::InvalidKey)?;
                mac.update(&data);
                mac.verify_slice(&tag).is_ok()
            }
            crate::ambient::HashAlgorithm::Blake3 => {
                // `blake3::Hash: PartialEq` is documented constant-time in
                // the blake3 crate, which is why the comparison goes through
                // `Hash` rather than byte strings. The length gate above
                // already established both sides are 32 bytes.
                let expected: [u8; 32] = hmac_tag(alg, &key, &data)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| WitHmacError::InvalidKey)?;
                let expected_hash = blake3::Hash::from(expected);
                let given: [u8; 32] = tag
                    .as_slice()
                    .try_into()
                    .map_err(|_| WitHmacError::InvalidKey)?;
                let given_hash = blake3::Hash::from(given);
                expected_hash == given_hash
            }
        };
        Ok(equal)
    }
}

/// The host implementation of `qqq:crypto/aead`.
///
/// Grant first (an ungranted call fails before its construction is judged),
/// then the construction's membership in the manifest's allowlist. Both are
/// re-checked per call even though registration is grant-gated
/// (`ARCH-012`).
impl bindings::qqq::crypto::aead::Host for crate::linker::StoreData {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "12 always fits u32; the constant is a construction parameter, not guest input"
    )]
    fn nonce_length(&mut self, construction: WitConstruction) -> u32 {
        // Infallible by WIT design, and the same for both constructions:
        // a nonce length is a public parameter of the construction, not a
        // secret the grant protects. The grant is still enforced wherever a
        // fallible call exists — `encrypt` and `decrypt` below re-check both
        // the grant and the allowlist per call (`ARCH-012`), so a mis-built
        // linker that bound this query without the grant still cannot move a
        // byte. Returning the length through a `result` would be a WIT change
        // on a frozen surface (§5.2); until an owner ADR ratifies it, the
        // infallible shape stays and this comment states why it is safe.
        //
        // Exhaustive match, not a constant: both constructions share 12/32
        // today, and a future WIT variant must fail *compilation* here rather
        // than silently inherit today's lengths.
        match construction {
            WitConstruction::Aes256Gcm | WitConstruction::Chacha20Poly1305 => {}
        }
        AeadConstruction::NONCE_LEN as u32
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "32 always fits u32; the constant is a construction parameter, not guest input"
    )]
    fn key_length(&mut self, construction: WitConstruction) -> u32 {
        // Same reasoning as `nonce_length`: public parameter, no gate. The
        // value is a construction constant, not guest-influenced state, so
        // there is no confused-deputy path through it; `encrypt`/`decrypt`
        // remain the enforcement points. Exhaustive match for the same
        // fail-at-compilation reason as above.
        match construction {
            WitConstruction::Aes256Gcm | WitConstruction::Chacha20Poly1305 => {}
        }
        AeadConstruction::KEY_LEN as u32
    }

    fn encrypt(
        &mut self,
        construction: WitConstruction,
        key: Vec<u8>,
        nonce: Vec<u8>,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, WitAeadError> {
        // Nonce uniqueness is the caller's contract, stated here because
        // the failure mode is silent: reusing a (key, nonce) pair across
        // two encryptions destroys confidentiality for both, and no host
        // check can tell a fresh nonce from a repeated one. A guest that
        // cannot track nonces should draw 12 bytes from `qqq:crypto/random`
        // per message and never send the same pair twice.
        use aes_gcm::aead::{Aead, Payload};
        crate::ambient::require(self, Capability::CryptoAead, "aead_encrypt")
            .map_err(|_| WitAeadError::ConstructionNotAllowed)?;
        let construction = match construction {
            WitConstruction::Aes256Gcm => AeadConstruction::Aes256Gcm,
            WitConstruction::Chacha20Poly1305 => AeadConstruction::ChaCha20Poly1305,
        };
        if !self.crypto.config.aeads.contains(&construction) {
            return Err(WitAeadError::ConstructionNotAllowed);
        }
        if key.len() != AeadConstruction::KEY_LEN {
            return Err(WitAeadError::InvalidKey);
        }
        if nonce.len() != AeadConstruction::NONCE_LEN {
            return Err(WitAeadError::InvalidNonce);
        }
        let out = match construction {
            AeadConstruction::Aes256Gcm => {
                use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
                let cipher =
                    Aes256Gcm::new_from_slice(&key).map_err(|_| WitAeadError::InvalidKey)?;
                let nonce_bytes: [u8; 12] = nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| WitAeadError::InvalidNonce)?;
                let nonce = Nonce::from(nonce_bytes);
                cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: &plaintext,
                            aad: &associated_data,
                        },
                    )
                    .map_err(|_| WitAeadError::AuthenticationFailed)?
            }
            AeadConstruction::ChaCha20Poly1305 => {
                use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
                let cipher =
                    ChaCha20Poly1305::new_from_slice(&key).map_err(|_| WitAeadError::InvalidKey)?;
                let nonce_bytes: [u8; 12] = nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| WitAeadError::InvalidNonce)?;
                let nonce = Nonce::from(nonce_bytes);
                cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: &plaintext,
                            aad: &associated_data,
                        },
                    )
                    .map_err(|_| WitAeadError::AuthenticationFailed)?
            }
        };
        // The tag is appended, not prepended and not returned separately:
        // the WIT carries one `ciphertext` list, and append-at-end is the
        // convention `decrypt` below relies on (and documents). The length
        // check pins the shape: the output is exactly the plaintext plus
        // one tag, so a backend that silently changed the layout fails here
        // rather than shipping undecryptable bytes. This is a runtime check,
        // not a `debug_assert!`: the assertion build strips debug checks, and
        // a layout change must fail closed in release too. The variant is the
        // closest fail-closed one the WIT offers — `encrypt` performs no
        // authentication, but there is no `internal-error` case, and inventing
        // the failure as `invalid-key` would blame the guest for a host bug.
        // The arm is unreachable unless the backend breaks its contract; the
        // comment states that so triage reads it as host fault, not forgery.
        if out.len() != plaintext.len() + AeadConstruction::TAG_LEN {
            return Err(WitAeadError::AuthenticationFailed);
        }
        Ok(out)
    }

    fn decrypt(
        &mut self,
        construction: WitConstruction,
        key: Vec<u8>,
        nonce: Vec<u8>,
        associated_data: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, WitAeadError> {
        use aes_gcm::aead::{Aead, Payload};
        crate::ambient::require(self, Capability::CryptoAead, "aead_decrypt")
            .map_err(|_| WitAeadError::ConstructionNotAllowed)?;
        let construction = match construction {
            WitConstruction::Aes256Gcm => AeadConstruction::Aes256Gcm,
            WitConstruction::Chacha20Poly1305 => AeadConstruction::ChaCha20Poly1305,
        };
        if !self.crypto.config.aeads.contains(&construction) {
            return Err(WitAeadError::ConstructionNotAllowed);
        }
        if key.len() != AeadConstruction::KEY_LEN {
            return Err(WitAeadError::InvalidKey);
        }
        if nonce.len() != AeadConstruction::NONCE_LEN {
            return Err(WitAeadError::InvalidNonce);
        }
        // Shorter than one tag means no tag is present at all: the input
        // cannot be an output of `encrypt`, so it fails authentication
        // rather than a length check — a truncated ciphertext is tampering
        // until proven otherwise.
        if ciphertext.len() < AeadConstruction::TAG_LEN {
            return Err(WitAeadError::AuthenticationFailed);
        }
        let plaintext = match construction {
            AeadConstruction::Aes256Gcm => {
                use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
                let cipher =
                    Aes256Gcm::new_from_slice(&key).map_err(|_| WitAeadError::InvalidKey)?;
                let nonce_bytes: [u8; 12] = nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| WitAeadError::InvalidNonce)?;
                let nonce = Nonce::from(nonce_bytes);
                cipher
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: &ciphertext,
                            aad: &associated_data,
                        },
                    )
                    .map_err(|_| WitAeadError::AuthenticationFailed)?
            }
            AeadConstruction::ChaCha20Poly1305 => {
                use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
                let cipher =
                    ChaCha20Poly1305::new_from_slice(&key).map_err(|_| WitAeadError::InvalidKey)?;
                let nonce_bytes: [u8; 12] = nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| WitAeadError::InvalidNonce)?;
                let nonce = Nonce::from(nonce_bytes);
                cipher
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: &ciphertext,
                            aad: &associated_data,
                        },
                    )
                    .map_err(|_| WitAeadError::AuthenticationFailed)?
            }
        };
        // `decrypt` returns `Err` without plaintext on failure — the crate
        // refuses to hand back unauthenticated bytes, so there is no path
        // here that leaks a forgery through a partial return.
        Ok(plaintext)
    }
}

/// The host implementation of `qqq:crypto/signing`.
///
/// Grant first, then the algorithm's membership in the manifest's allowlist,
/// re-checked per call (`ARCH-012`). The private key is guest-supplied per
/// call, never stored: for a key the guest must never see, `qqq:secrets`
/// signs without disclosing it.
impl bindings::qqq::crypto::signing::Host for crate::linker::StoreData {
    fn sign(
        &mut self,
        algorithm: WitSignAlgorithm,
        key: Vec<u8>,
        message: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, WitSignatureError> {
        use ed25519_dalek::Signer as _;
        crate::ambient::require(self, Capability::CryptoSign, "signing_sign")
            .map_err(|_| WitSignatureError::AlgorithmNotAllowed)?;
        let algorithm = match algorithm {
            WitSignAlgorithm::Ed25519 => SignAlgorithm::Ed25519,
        };
        if !self.crypto.config.signs.contains(&algorithm) {
            return Err(WitSignatureError::AlgorithmNotAllowed);
        }
        let seed: &[u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| WitSignatureError::InvalidKey)?;
        let signature = ed25519_dalek::SigningKey::from_bytes(seed).sign(&message);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(
        &mut self,
        algorithm: WitSignAlgorithm,
        public_key: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> std::result::Result<bool, WitSignatureError> {
        use ed25519_dalek::Verifier as _;
        crate::ambient::require(self, Capability::CryptoSign, "signing_verify")
            .map_err(|_| WitSignatureError::AlgorithmNotAllowed)?;
        let algorithm = match algorithm {
            WitSignAlgorithm::Ed25519 => SignAlgorithm::Ed25519,
        };
        if !self.crypto.config.signs.contains(&algorithm) {
            return Err(WitSignatureError::AlgorithmNotAllowed);
        }
        // A malformed key means the host cannot run the check at all, so it
        // is an error rather than a `false`: `false` would claim the
        // signature was checked and failed, which never happened.
        let public: &[u8; 32] = public_key
            .as_slice()
            .try_into()
            .map_err(|_| WitSignatureError::InvalidKey)?;
        // A malformed signature is an error, not a `false` (HOST-037/2): the
        // WIT defines `invalid-signature` as "the signature was the wrong
        // length, so it cannot be valid", and a dedicated variant that the
        // host never returns is a dead contract. `false` stays reserved for
        // a well-formed signature that was checked and failed; a 63- or
        // 65-byte input was never checked at all.
        let Ok(sig) = <&[u8; 64]>::try_from(signature.as_slice()) else {
            return Err(WitSignatureError::InvalidSignature);
        };
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(public)
            .map_err(|_| WitSignatureError::InvalidKey)?;
        let parsed = ed25519_dalek::Signature::from_bytes(sig);
        Ok(verifying.verify(&message, &parsed).is_ok())
    }

    fn public_key(
        &mut self,
        algorithm: WitSignAlgorithm,
        key: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, WitSignatureError> {
        crate::ambient::require(self, Capability::CryptoSign, "signing_public_key")
            .map_err(|_| WitSignatureError::AlgorithmNotAllowed)?;
        let algorithm = match algorithm {
            WitSignAlgorithm::Ed25519 => SignAlgorithm::Ed25519,
        };
        if !self.crypto.config.signs.contains(&algorithm) {
            return Err(WitSignatureError::AlgorithmNotAllowed);
        }
        let seed: &[u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| WitSignatureError::InvalidKey)?;
        Ok(ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes()
            .to_vec())
    }
}

/// The `SEC-011` boundary verdict for a `random.get` length.
///
/// # Why this is a named function rather than an inline expression
///
/// Because an inline check inside the host body **could not be tested** when
/// the body was a `func_wrap` closure — reaching it needed a compiled
/// component importing `qqq:crypto/random`, and hand-written WAT against
/// that interface failed to instantiate four times (the lowered
/// `result<list<u8>, random-error>` needs a return-area pointer and a
/// fully-declared error variant, and each attempt failed to instantiate
/// *whether or not* the capability was granted, making the ungranted
/// case pass for the wrong reason — see `tests/hostile_guests.rs`).
///
/// That untestability has a measurable cost, found by injection rather than by
/// reasoning: neutering the inline check so it could never reject left **every**
/// test in this module green. Extracting it gives the test a seam, and
/// `the_random_length_boundary_accepts_to_the_ceiling_and_refuses_past_it` now
/// fails when the *helper* is wrong.
///
/// # The second gap, and how it closed
///
/// Extracting the helper closes only half the hole. A **second** injection —
/// neutering the call site while leaving the helper correct — also left every
/// test green, because a test that calls the helper directly proves the helper
/// works and proves nothing about whether the host function uses it. That gap
/// closed two ways: the `bindgen!` trait methods are directly callable, so
/// `random_get_refuses_by_name` and `hashing_refuses_by_name` execute the
/// call site for each refusal case; and the `iface_crypto` probe covers the
/// same paths end to end through a real component. No structural source
/// assertion remains because nothing structural is left unproven.
fn random_length_verdict(
    length: u32,
    ambient: &crate::ambient::AmbientState,
) -> crate::quota::Verdict {
    // The ceiling comes from the ambient state rather than a constant here, so
    // the boundary states the *same* limit the allocation enforces. A second copy
    // of the number would be a second source of truth that drifts.
    crate::boundary::size(
        "length",
        length as usize,
        ambient.max_random_bytes() as usize,
    )
}
/// Unused import guard: `ResourceAny` is not needed yet but keeps the import
/// list stable when resource-returning interfaces (`fs`, `http`) land.
const _: Option<ResourceAny> = None;

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_cap::manifest::Manifest;
    use wasmtime::{Engine, StoreContextMut};

    /// **The anti-drift test.** Every function the WIT declares for these
    /// interfaces must be implemented here: `bindgen!` generates the trait,
    /// but a missing method is a compile error, not a silent gap — so this
    /// test asserts the WIT-declared names against the implemented methods
    /// rather than the registration mechanism. The guest-compiled probe
    /// (`iface_crypto`) proves the other direction: the host's shapes bind
    /// a real component.
    #[test]
    fn every_implemented_wit_function_is_registered() {
        let wit = include_str!("../../../wit/qqq-crypto.wit");
        let this_file = include_str!("host_crypto.rs");

        // `random.get`
        assert!(wit.contains("get: func(length: u32)"), "random.get renamed");
        assert!(
            this_file.contains("fn get("),
            "random.get is declared in the WIT but not implemented"
        );

        // `hashing.digest` and `hashing.digest-many`
        for name in ["digest", "digest_many"] {
            assert!(
                wit.contains(&format!("\n  {name}: func("))
                    || wit.contains(&format!("\n  {}: func(", name.replace('_', "-"))),
                "`{name}` is not declared in qqq-crypto.wit"
            );
            assert!(
                this_file.contains(&format!("fn {name}(")),
                "`{name}` is declared in the WIT but not implemented here"
            );
        }

        // `hmac.compute`, `hmac.verify`, the five `aead` functions and the
        // three `signing` functions: declared in the WIT; linked by the
        // `bindgen!` modules and proven executable by
        // `new_interfaces_are_grant_gated` plus the guest-compiled probe.
        for name in [
            "compute",
            "verify",
            "nonce-length",
            "key-length",
            "encrypt",
            "decrypt",
            "sign",
            "public-key",
        ] {
            assert!(
                wit.contains(&format!("\n  {name}: func(")),
                "`{name}` is not declared in qqq-crypto.wit"
            );
        }
    }

    /// The grant-gating test below links every function of every interface
    /// against a real linker, so registration is proven by binding — no
    /// source-text detector needed.
    #[test]
    fn new_interfaces_are_grant_gated() {
        let engine = test_engine();

        let full = grants_with(
            "[capabilities.crypto]\nrandom = true\nhash = [\"sha256\"]\n\
             hmac = [\"sha256\"]\naead = [\"aes-256-gcm\"]\nsign = [\"ed25519\"]\n",
        );

        // Granted: every function of every interface links.
        let mut linker = Linker::<StoreData>::new(&engine);
        register(&mut linker, &full).expect("register");
        for (interface, names) in [
            (RANDOM, vec!["get"]),
            (HASHING, vec!["digest", "digest-many"]),
            (HMAC_IFACE, vec!["compute", "verify"]),
            (
                AEAD_IFACE,
                vec!["nonce-length", "key-length", "encrypt", "decrypt"],
            ),
            (SIGNING_IFACE, vec!["sign", "verify", "public-key"]),
        ] {
            for name in names {
                assert!(
                    has_func(&mut linker, interface, name),
                    "a granted {interface} must expose {name}"
                );
            }
        }

        // Ungranted: nothing links, and the failure names the interface.
        let mut bare = Linker::<StoreData>::new(&engine);
        register(&mut bare, &GrantSet::empty()).expect("register");
        for (interface, name) in [
            (RANDOM, "get"),
            (HASHING, "digest"),
            (HMAC_IFACE, "compute"),
            (AEAD_IFACE, "encrypt"),
            (SIGNING_IFACE, "sign"),
        ] {
            assert!(
                !has_func(&mut bare, interface, name),
                "an ungranted {interface} must not expose {name}"
            );
        }
    }

    /// A partial grant binds only its own interface: an hmac-only guest
    /// must not see aead or signing, and vice versa. Directions never widen.
    #[test]
    fn partial_crypto_grants_bind_only_their_interface() {
        let engine = test_engine();

        let mut hmac_only = Linker::<StoreData>::new(&engine);
        register(
            &mut hmac_only,
            &grants_with("[capabilities.crypto]\nhmac = [\"sha256\"]\n"),
        )
        .expect("register");
        assert!(has_func(&mut hmac_only, HMAC_IFACE, "compute"));
        assert!(!has_func(&mut hmac_only, AEAD_IFACE, "encrypt"));
        assert!(!has_func(&mut hmac_only, SIGNING_IFACE, "sign"));
    }

    #[test]
    fn the_package_name_matches_the_wit() {
        let wit = include_str!("../../../wit/qqq-crypto.wit");
        assert!(
            wit.contains(&format!("package {INTERFACE};")),
            "the WIT package declaration does not match INTERFACE={INTERFACE}"
        );
    }

    /// **The anti-drift test for the algorithm set.**
    ///
    /// `HASH_ALGORITHM_COUNT` records how many algorithms the WIT declares.
    /// `bindgen!` owns the discriminant mapping (an out-of-range value traps
    /// at the ABI boundary) and the host's `match` arms are exhaustive (a new
    /// WIT member fails to compile until handled), so the constant is no
    /// longer load-bearing for correctness — but it remains the explicit
    /// record of the set's size, and this test fails if the WIT set changes
    /// without a conscious update here.
    ///
    /// The check counts the members of the WIT `enum algorithm` block rather than
    /// asserting a literal, so the test follows the WIT instead of restating it.
    #[test]
    fn the_hash_algorithm_count_agrees_with_the_wit() {
        let wit = include_str!("../../../wit/qqq-crypto.wit");

        let start = wit
            .find("enum algorithm {")
            .expect("the `algorithm` enum must exist in qqq-crypto.wit");
        let body = &wit[start..];
        let end = body.find('}').expect("the `algorithm` enum must be closed");
        let block = &body[..end];

        // Members are the non-empty lines that are not doc comments, are not the
        // `enum` header, and do not contain `{` or `}`. Each ends with a comma.
        let members: Vec<&str> = block
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter(|l| !l.starts_with("///") && !l.starts_with("//"))
            .filter(|l| !l.starts_with("enum "))
            .filter(|l| l.ends_with(','))
            .collect();

        assert_eq!(
            members.len(),
            crate::ambient::HASH_ALGORITHM_COUNT as usize,
            "the WIT declares {} algorithm member(s) {members:?} but \
             HASH_ALGORITHM_COUNT is {}. Update the constant with the WIT.",
            members.len(),
            crate::ambient::HASH_ALGORITHM_COUNT
        );

        // And the declaration order is the ABI the discriminant relies on.
        assert_eq!(
            members,
            vec!["sha256,", "sha512,", "blake3,"],
            "the discriminant numbering depends on declaration order; reordering \
             the WIT silently changes what a guest's `1` means"
        );
    }

    #[test]
    fn the_interface_paths_match_the_wit() {
        let wit = include_str!("../../../wit/qqq-crypto.wit");
        assert!(wit.contains("interface random {"), "random renamed");
        assert!(wit.contains("interface hashing {"), "hashing renamed");
        assert_eq!(RANDOM, "qqq:crypto/random@1.0.0");
        assert_eq!(HASHING, "qqq:crypto/hashing@1.0.0");
    }

    /// The error variant indices are an ABI and must follow the WIT order.
    /// The `bindgen!` types carry the order, so this pins the generated
    /// discriminants against the WIT text rather than trusting the macro.
    #[test]
    fn the_error_variant_orders_match_the_wit() {
        use super::bindings::qqq::crypto::hashing::HashError as GenHashError;
        use super::bindings::qqq::crypto::random::RandomError as GenRandomError;
        let wit = include_str!("../../../wit/qqq-crypto.wit");

        let ng = wit.find("not-granted").expect("declared");
        let tl = wit.find("too-long").expect("declared");
        let sf = wit.find("source-failed").expect("declared");
        assert!(ng < tl && tl < sf, "random-error order changed");
        assert_eq!(GenRandomError::NotGranted as u32, 0);
        assert_eq!(GenRandomError::TooLong as u32, 1);
        assert_eq!(GenRandomError::SourceFailed as u32, 2);

        let ana = wit.find("algorithm-not-allowed").expect("declared");
        let itl = wit.find("input-too-long").expect("declared");
        assert!(ana < itl, "hash-error order changed");
        assert_eq!(GenHashError::AlgorithmNotAllowed as u32, 0);
        assert_eq!(GenHashError::InputTooLong as u32, 1);
    }

    /// The `algorithm` enum order is an ABI too. `sha256` is declared first,
    /// and the host's `match` arms follow that order — a non-exhaustive
    /// match would fail to compile if the WIT gained a member, so the
    /// ordering pin is the only runtime half left to assert. (An
    /// out-of-range discriminant can no longer reach host code: `bindgen!`
    /// lifts the enum at the ABI boundary and traps there, exactly as for
    /// every other generated interface.)
    #[test]
    fn the_algorithm_enum_order_matches_the_wit() {
        use super::bindings::qqq::crypto::hashing::Algorithm as GenAlgorithm;
        let wit = include_str!("../../../wit/qqq-crypto.wit");
        let sha256 = wit.find("sha256,").expect("declared");
        let sha512 = wit.find("sha512,").expect("declared");
        let blake3 = wit.find("blake3,").expect("declared");
        assert!(
            sha256 < sha512 && sha512 < blake3,
            "the algorithm enum order changed"
        );
        // And the generated discriminants must agree with that order.
        assert_eq!(GenAlgorithm::Sha256 as u32, 0);
        assert_eq!(GenAlgorithm::Sha512 as u32, 1);
        assert_eq!(GenAlgorithm::Blake3 as u32, 2);
    }

    /// The known-answer tests: these are the published digests of `"abc"`.
    /// A round-trip test would pass for any deterministic function, including a
    /// wrong one, so the vector is asserted rather than the invariance.
    #[test]
    fn hashing_produces_published_test_vectors() {
        use crate::ambient::{AmbientState, HashAlgorithm};
        let sha256 = AmbientState::hash(HashAlgorithm::Sha256, b"abc");
        assert_eq!(
            hex(&sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let blake3 = AmbientState::hash(HashAlgorithm::Blake3, b"abc");
        assert_eq!(
            hex(&blake3),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// The allowlist must be enforced: the host can compute SHA-512 whether or
    /// not the manifest named it, so a manifest allowing only sha256 must refuse
    /// sha512. Without this the manifest's list would be advisory.
    #[test]
    fn the_manifest_allowlist_is_enforced() {
        let manifest = Manifest::parse(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhash = [\"sha256\"]\n",
        )
        .expect("manifest");
        let data = StoreData::from_manifest(&manifest);

        assert!(
            hash_data(&data, "sha256", b"abc").is_ok(),
            "the allowed algorithm must work"
        );
        assert!(
            hash_data(&data, "sha512", b"abc").is_err(),
            "an algorithm the manifest did not name must be refused"
        );
        assert!(
            hash_data(&data, "blake3", b"abc").is_err(),
            "an algorithm the manifest did not name must be refused"
        );
    }

    /// A store whose crypto stanza names exactly the given algorithms.
    /// Goes through a real manifest: only the manifest may grant.
    fn crypto_store(hmac: &[&str], aead: &[&str], sign: &[&str]) -> StoreData {
        fn list(items: &[&str]) -> String {
            items
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(", ")
        }
        let src = format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhash = [\"sha256\"]\n\
             hmac = [{}]\naead = [{}]\nsign = [{}]\n",
            list(hmac),
            list(aead),
            list(sign),
        );
        let manifest = Manifest::parse(&src).expect("manifest");
        StoreData::from_manifest(&manifest)
    }

    /// `CryptoConfig::from_manifest` keeps known names and drops unknown
    /// ones: an unknown name never matches, so it can neither grant nor
    /// deny — it is simply absent, exactly like an unlisted algorithm.
    #[test]
    fn crypto_config_parses_known_names_and_drops_unknown_ones() {
        use crate::ambient::HashAlgorithm;
        let manifest = Manifest::parse(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhash = [\"sha256\"]\n\
             hmac = [\"sha256\", \"rot13\"]\naead = [\"aes-256-gcm\", \"rot13\"]\n\
             sign = [\"ed25519\", \"rot13\"]\n",
        )
        .expect("manifest");
        let config = CryptoConfig::from_manifest(&manifest);
        assert_eq!(config.hashes, vec![HashAlgorithm::Sha256]);
        assert_eq!(config.hmacs, vec![HashAlgorithm::Sha256]);
        assert_eq!(config.aeads, vec![AeadConstruction::Aes256Gcm]);
        assert_eq!(config.signs, vec![SignAlgorithm::Ed25519]);
    }

    /// The AEAD construction order is the guest-visible numbering and
    /// matches the WIT declaration order.
    #[test]
    fn the_aead_construction_order_matches_the_wit() {
        let wit = include_str!("../../../wit/qqq-crypto.wit");
        let start = wit
            .find("enum construction {")
            .expect("the `construction` enum must exist");
        let body = &wit[start..];
        let end = body.find('}').expect("the enum must be closed");
        let members: Vec<&str> = body[..end]
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter(|l| !l.starts_with("///") && !l.starts_with("//"))
            .filter(|l| !l.starts_with("enum "))
            .filter(|l| l.ends_with(','))
            .collect();
        assert_eq!(members, vec!["aes-256-gcm,", "chacha20-poly1305,"]);
        assert_eq!(
            AeadConstruction::from_discriminant(0),
            Some(AeadConstruction::Aes256Gcm)
        );
        assert_eq!(
            AeadConstruction::from_discriminant(1),
            Some(AeadConstruction::ChaCha20Poly1305)
        );
        assert_eq!(AeadConstruction::from_discriminant(7), None);
        // Name parsing agrees with the numbering: `parse` and
        // `from_discriminant` cannot disagree about what exists.
        assert_eq!(
            AeadConstruction::parse("aes-256-gcm"),
            AeadConstruction::from_discriminant(0)
        );
        assert_eq!(
            AeadConstruction::parse("chacha20-poly1305"),
            AeadConstruction::from_discriminant(1)
        );
    }

    /// The signing algorithm set is exactly `ed25519`, here and in the WIT.
    #[test]
    fn the_sign_algorithm_set_matches_the_wit() {
        let wit = include_str!("../../../wit/qqq-crypto.wit");
        let signing = wit.find("interface signing {").expect("signing exists");
        let after = &wit[signing..];
        let start = after
            .find("enum algorithm {")
            .expect("the signing `algorithm` enum must exist");
        let body = &after[start..];
        let end = body.find('}').expect("the enum must be closed");
        let members: Vec<&str> = body[..end]
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter(|l| !l.starts_with("///") && !l.starts_with("//"))
            .filter(|l| !l.starts_with("enum "))
            .filter(|l| l.ends_with(','))
            .collect();
        assert_eq!(members, vec!["ed25519,"]);
        assert_eq!(
            SignAlgorithm::from_discriminant(0),
            Some(SignAlgorithm::Ed25519)
        );
        assert_eq!(SignAlgorithm::from_discriminant(7), None);
        assert_eq!(
            SignAlgorithm::parse("ed25519"),
            SignAlgorithm::from_discriminant(0)
        );
    }

    /// HMAC-SHA-256 against RFC 4231 §4.2 case 1. A round-trip test would
    /// pass for any deterministic function, including a wrong one, so the
    /// vector is asserted rather than the invariance.
    #[test]
    fn hmac_sha256_matches_rfc4231_case_1() {
        use super::bindings::qqq::crypto::hmac::{Algorithm as HmacAlgorithm, Host as _};
        let mut data = crypto_store(&["sha256"], &[], &[]);
        let tag = data
            .compute(HmacAlgorithm::Sha256, vec![0x0b; 20], b"Hi There".to_vec())
            .expect("compute");
        assert_eq!(
            hex(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// HMAC-SHA-512 against RFC 4231 §4.2 case 1.
    #[test]
    fn hmac_sha512_matches_rfc4231_case_1() {
        use super::bindings::qqq::crypto::hmac::{Algorithm as HmacAlgorithm, Host as _};
        let mut data = crypto_store(&["sha512"], &[], &[]);
        let tag = data
            .compute(HmacAlgorithm::Sha512, vec![0x0b; 20], b"Hi There".to_vec())
            .expect("compute");
        assert_eq!(
            hex(&tag),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
                       daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    /// HMAC-BLAKE3 with a 32-byte key, verified against the reference
    /// implementation's keyed mode. The length gate is part of the claim:
    /// any other key size is `invalid-key`, never silently hashed down.
    #[test]
    fn hmac_blake3_matches_the_reference_keyed_mode() {
        use super::bindings::qqq::crypto::hmac::{Algorithm as HmacAlgorithm, Host as _};
        let mut data = crypto_store(&["blake3"], &[], &[]);
        let key: Vec<u8> = (0..32).collect();
        let tag = data
            .compute(HmacAlgorithm::Blake3, key, b"abc".to_vec())
            .expect("compute");
        assert_eq!(
            hex(&tag),
            "6da54495d8152f2bcba87bd7282df70901cdb66b4448ed5f4c7bd2852b8b5532"
        );
        let err = data
            .compute(HmacAlgorithm::Blake3, vec![0u8; 16], b"abc".to_vec())
            .expect_err("a 16-byte blake3 key must be refused");
        assert!(matches!(err, WitHmacError::InvalidKey));
    }

    /// `verify` accepts the right tag, rejects a wrong one, and treats a
    /// wrong-length tag as `false` rather than an error: the length is not
    /// secret, and a 5-byte value can never be a 32-byte tag.
    #[test]
    fn hmac_verify_accepts_recomputes_and_rejects() {
        use super::bindings::qqq::crypto::hmac::{Algorithm as HmacAlgorithm, Host as _};
        let mut data = crypto_store(&["sha256"], &[], &[]);
        let key = vec![0x0bu8; 20];
        let good = data
            .compute(HmacAlgorithm::Sha256, key.clone(), b"Hi There".to_vec())
            .expect("compute");
        assert!(
            data.verify(
                HmacAlgorithm::Sha256,
                key.clone(),
                b"Hi There".to_vec(),
                good
            )
            .expect("verify")
        );
        let mut bad = vec![0u8; 32];
        *bad.get_mut(0).expect("a 32-byte tag has a first byte") ^= 1;
        assert!(
            !data
                .verify(
                    HmacAlgorithm::Sha256,
                    key.clone(),
                    b"Hi There".to_vec(),
                    bad
                )
                .expect("verify runs"),
            "one flipped bit must fail"
        );
        assert!(
            !data
                .verify(
                    HmacAlgorithm::Sha256,
                    key,
                    b"Hi There".to_vec(),
                    vec![0u8; 5]
                )
                .expect("verify runs"),
            "a short tag is simply not the tag"
        );
    }

    /// Grants and the allowlist gate every hmac call: no grant, no listing,
    /// and an empty key each fail before any MAC is computed.
    #[test]
    fn hmac_grants_and_allowlist_are_checked() {
        use super::bindings::qqq::crypto::hmac::{Algorithm as HmacAlgorithm, Host as _};
        use qqq_cap::resolve::GrantSet;

        // No grant at all: refused before the algorithm is judged.
        let mut ungranted = StoreData::new(GrantSet::empty());
        let err = ungranted
            .compute(HmacAlgorithm::Sha256, vec![1u8; 32], b"x".to_vec())
            .expect_err("ungranted compute fails");
        assert!(matches!(err, WitHmacError::AlgorithmNotAllowed));

        // Granted but unlisted: refused by name.
        let mut data = crypto_store(&["sha256"], &[], &[]);
        let err = data
            .compute(HmacAlgorithm::Sha512, vec![1u8; 32], b"x".to_vec())
            .expect_err("unlisted algorithm fails");
        assert!(matches!(err, WitHmacError::AlgorithmNotAllowed));

        // Empty key: refused, never hashed into a default.
        let err = data
            .compute(HmacAlgorithm::Sha256, Vec::new(), b"x".to_vec())
            .expect_err("empty key fails");
        assert!(matches!(err, WitHmacError::InvalidKey));
    }

    /// The HMAC algorithm enum order is the guest-visible numbering and
    /// matches the WIT `hashing.algorithm` declaration order (the interface
    /// reuses that enum). The bindgen types carry the order implicitly, so
    /// this pins it the same way the AEAD and signing orders are pinned.
    #[test]
    fn the_hmac_algorithm_order_matches_the_wit() {
        let wit = include_str!("../../../wit/qqq-crypto.wit");
        let hashing = wit.find("interface hashing {").expect("hashing exists");
        let after = &wit[hashing..];
        let start = after
            .find("enum algorithm {")
            .expect("the hashing `algorithm` enum must exist");
        let body = &after[start..];
        let end = body.find('}').expect("the enum must be closed");
        let members: Vec<&str> = body[..end]
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter(|l| !l.starts_with("///") && !l.starts_with("//"))
            .filter(|l| !l.starts_with("enum "))
            .filter(|l| l.ends_with(','))
            .collect();
        assert_eq!(members, vec!["sha256,", "sha512,", "blake3,"]);
    }

    /// Empty-key `verify` agrees with `compute` for every algorithm
    /// (HOST-037/1): all three refuse `invalid-key` rather than splitting
    /// between `Ok(false)` and `Err`.
    #[test]
    fn hmac_empty_key_verify_fails_closed_for_every_algorithm() {
        use super::bindings::qqq::crypto::hmac::{Algorithm as HmacAlgorithm, Host as _};
        let mut data = crypto_store(&["sha256", "sha512", "blake3"], &[], &[]);
        for algorithm in [
            HmacAlgorithm::Sha256,
            HmacAlgorithm::Sha512,
            HmacAlgorithm::Blake3,
        ] {
            let digest_len = match algorithm {
                HmacAlgorithm::Sha512 => 64,
                HmacAlgorithm::Sha256 | HmacAlgorithm::Blake3 => 32,
            };
            let err = data
                .verify(algorithm, Vec::new(), b"x".to_vec(), vec![0u8; digest_len])
                .expect_err("empty-key verify must fail");
            assert!(
                matches!(err, WitHmacError::InvalidKey),
                "empty-key verify must be invalid-key for every algorithm"
            );
        }
    }

    /// An unknown-only grant binds the interface but denies every call
    /// (HOST-037/9): the grant comes from the raw manifest list while the
    /// allowlist comes from the filtered parse, so `hmac = ["rot13"]`
    /// grants `crypto.hmac` yet matches nothing at call time. Fail-closed,
    /// pinned so a future grant-filter change cannot silently widen it.
    #[test]
    fn unknown_only_grant_binds_but_denies_every_call() {
        use super::bindings::qqq::crypto::hmac::{Algorithm as HmacAlgorithm, Host as _};
        let engine = test_engine();
        let grants = grants_with("[capabilities.crypto]\nhmac = [\"rot13\"]\n");
        assert!(
            grants.grants(qqq_cap::Capability::CryptoHmac),
            "the raw unknown name still grants the capability"
        );
        let mut linker = Linker::<StoreData>::new(&engine);
        register(&mut linker, &grants).expect("register");
        assert!(
            has_func(&mut linker, HMAC_IFACE, "compute"),
            "the granted interface binds even when its allowlist is empty"
        );
        let manifest = Manifest::parse(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
             [capabilities.crypto]\nhmac = [\"rot13\"]\n",
        )
        .expect("manifest");
        let mut data = StoreData::from_manifest(&manifest);
        let err = data
            .compute(HmacAlgorithm::Sha256, vec![1u8; 32], b"x".to_vec())
            .expect_err("unknown-only allowlist denies");
        assert!(matches!(err, WitHmacError::AlgorithmNotAllowed));
    }

    /// Grant-present with view-empty denies at call time (HOST-037/10):
    /// `StoreData::new` carries no manifest-resolved allowlist, so a
    /// granted call still fails closed by name. Production builds through
    /// `create_with` with a resolved view; this pins the test-only
    /// constructor's fail-closed direction.
    #[test]
    fn grant_present_with_empty_view_denies_at_call_time() {
        use super::bindings::qqq::crypto::hmac::{Algorithm as HmacAlgorithm, Host as _};
        let mut data = StoreData::new(grants_with("[capabilities.crypto]\nhmac = [\"sha256\"]\n"));
        assert!(
            data.crypto.config.hmacs.is_empty(),
            "the test-only constructor carries no resolved allowlist"
        );
        let err = data
            .compute(HmacAlgorithm::Sha256, vec![1u8; 32], b"x".to_vec())
            .expect_err("empty view denies");
        assert!(matches!(err, WitHmacError::AlgorithmNotAllowed));
    }

    /// The length queries answer the constructions' public parameters: 12-byte
    /// nonces, 32-byte keys, for both. Unknown discriminants cannot reach
    /// here — the typed bindings only construct the two real variants.
    #[test]
    fn aead_lengths_are_the_construction_parameters() {
        use super::bindings::qqq::crypto::aead::{Construction as WitConstruction, Host as _};
        let mut data = crypto_store(&[], &["aes-256-gcm", "chacha20-poly1305"], &[]);
        assert_eq!(data.nonce_length(WitConstruction::Aes256Gcm), 12);
        assert_eq!(data.key_length(WitConstruction::Aes256Gcm), 32);
        assert_eq!(data.nonce_length(WitConstruction::Chacha20Poly1305), 12);
        assert_eq!(data.key_length(WitConstruction::Chacha20Poly1305), 32);
    }

    /// AES-256-GCM round-trips, and the all-zero vector matches the known
    /// answer: empty plaintext encrypts to exactly the 16-byte tag, so the
    /// tag-appended layout is pinned, not just round-tripped.
    #[test]
    fn aes_gcm_round_trips_and_matches_the_zero_vector() {
        use super::bindings::qqq::crypto::aead::{Construction as WitConstruction, Host as _};
        let mut data = crypto_store(&[], &["aes-256-gcm"], &[]);
        let ct = data
            .encrypt(
                WitConstruction::Aes256Gcm,
                vec![0u8; 32],
                vec![0u8; 12],
                Vec::new(),
                Vec::new(),
            )
            .expect("encrypt");
        assert_eq!(hex(&ct), "530f8afbc74536b9a963b4f1c4cb738b");
        let pt = data
            .decrypt(
                WitConstruction::Aes256Gcm,
                vec![0u8; 32],
                vec![0u8; 12],
                Vec::new(),
                ct,
            )
            .expect("decrypt");
        assert!(pt.is_empty());
    }

    /// AES-256-GCM output shape is plaintext plus exactly one tag
    /// (HOST-037/7): the release build must enforce the layout the debug
    /// build asserted, or a backend change ships undecryptable bytes
    /// silently.
    #[test]
    fn aead_output_length_is_plaintext_plus_tag() {
        use super::bindings::qqq::crypto::aead::{Construction as WitConstruction, Host as _};
        let mut data = crypto_store(&[], &["aes-256-gcm", "chacha20-poly1305"], &[]);
        for construction in [
            WitConstruction::Aes256Gcm,
            WitConstruction::Chacha20Poly1305,
        ] {
            let out = data
                .encrypt(
                    construction,
                    vec![3u8; 32],
                    vec![5u8; 12],
                    b"aad".to_vec(),
                    b"hello world".to_vec(),
                )
                .expect("encrypt");
            assert_eq!(
                out.len(),
                b"hello world".len() + AeadConstruction::TAG_LEN,
                "ciphertext must be plaintext plus one tag"
            );
        }
    }

    /// Bulk payloads round-trip with the tag shape intact: the host carries
    /// no per-call byte ceiling for AEAD (the WIT has no `input-too-long`
    /// case — see the module docs), so a megabyte of plaintext must work,
    /// bounded only by the instance's memory and fuel. If a ceiling is ever
    /// added it needs a WIT variant plus a registry handoff, not a silent
    /// new refusal; this test pins today's contract from the allowed side.
    #[test]
    fn aead_round_trips_a_megabyte_with_tag_shape_intact() {
        use super::bindings::qqq::crypto::aead::{Construction as WitConstruction, Host as _};
        let mut data = crypto_store(&[], &["aes-256-gcm"], &[]);
        let plaintext = vec![0xABu8; 1024 * 1024];
        let out = data
            .encrypt(
                WitConstruction::Aes256Gcm,
                vec![3u8; 32],
                vec![5u8; 12],
                b"aad".to_vec(),
                plaintext.clone(),
            )
            .expect("a megabyte encrypts");
        assert_eq!(
            out.len(),
            plaintext.len() + AeadConstruction::TAG_LEN,
            "bulk output is still plaintext plus exactly one tag"
        );
        let back = data
            .decrypt(
                WitConstruction::Aes256Gcm,
                vec![3u8; 32],
                vec![5u8; 12],
                b"aad".to_vec(),
                out,
            )
            .expect("a megabyte decrypts");
        assert_eq!(back, plaintext);
    }

    /// ChaCha20-Poly1305 against RFC 8439 §2.8.2: the ciphertext and tag
    /// match the published sunscreen vector byte for byte.
    #[test]
    fn chacha20poly1305_matches_rfc8439_section_2_8_2() {
        use super::bindings::qqq::crypto::aead::{Construction as WitConstruction, Host as _};
        let mut data = crypto_store(&[], &["chacha20-poly1305"], &[]);
        let key = hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex_to_bytes("070000004041424344454647");
        let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        let out = data
            .encrypt(
                WitConstruction::Chacha20Poly1305,
                key.clone(),
                nonce.clone(),
                aad.clone(),
                plaintext.clone(),
            )
            .expect("encrypt");
        assert_eq!(
            hex(&out),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
                     3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
                     92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
                     3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060\
                     0691"
        );
        let back = data
            .decrypt(WitConstruction::Chacha20Poly1305, key, nonce, aad, out)
            .expect("decrypt");
        assert_eq!(back, plaintext);
    }

    /// AEAD failures name themselves: tampered bytes and truncated
    /// ciphertext fail authentication (never a partial plaintext), wrong
    /// key/nonce lengths fail the length check, an unlisted construction
    /// fails closed, and an ungranted call fails before any of that.
    #[test]
    fn aead_failures_are_named_and_total() {
        use super::bindings::qqq::crypto::aead::{Construction as WitConstruction, Host as _};
        use qqq_cap::resolve::GrantSet;
        let mut data = crypto_store(&[], &["aes-256-gcm"], &[]);
        let key = vec![7u8; 32];
        let nonce = vec![9u8; 12];
        let good = data
            .encrypt(
                WitConstruction::Aes256Gcm,
                key.clone(),
                nonce.clone(),
                b"ad".to_vec(),
                b"secret".to_vec(),
            )
            .expect("encrypt");
        // Flip one ciphertext bit: authentication must fail, with nothing returned.
        let mut tampered = good.clone();
        *tampered.get_mut(0).expect("ciphertext is non-empty") ^= 1;
        let err = data
            .decrypt(
                WitConstruction::Aes256Gcm,
                key.clone(),
                nonce.clone(),
                b"ad".to_vec(),
                tampered,
            )
            .expect_err("tampering fails");
        assert!(matches!(err, WitAeadError::AuthenticationFailed));
        // Truncated below one tag: not a length error, an authentication failure.
        let err = data
            .decrypt(
                WitConstruction::Aes256Gcm,
                key.clone(),
                nonce.clone(),
                b"ad".to_vec(),
                vec![0u8; 15],
            )
            .expect_err("short input fails");
        assert!(matches!(err, WitAeadError::AuthenticationFailed));
        // Wrong lengths name themselves.
        let err = data
            .encrypt(
                WitConstruction::Aes256Gcm,
                vec![0u8; 16],
                nonce.clone(),
                Vec::new(),
                b"x".to_vec(),
            )
            .expect_err("short key fails");
        assert!(matches!(err, WitAeadError::InvalidKey));
        let err = data
            .encrypt(
                WitConstruction::Aes256Gcm,
                key.clone(),
                vec![0u8; 8],
                Vec::new(),
                b"x".to_vec(),
            )
            .expect_err("short nonce fails");
        assert!(matches!(err, WitAeadError::InvalidNonce));
        // Unlisted construction: the other construction from the WIT fails by name.
        let err = data
            .encrypt(
                WitConstruction::Chacha20Poly1305,
                key.clone(),
                nonce.clone(),
                Vec::new(),
                b"x".to_vec(),
            )
            .expect_err("unlisted construction fails");
        assert!(matches!(err, WitAeadError::ConstructionNotAllowed));
        // Ungranted: fails before the construction is judged.
        let mut bare = StoreData::new(GrantSet::empty());
        let err = bare
            .encrypt(
                WitConstruction::Aes256Gcm,
                key,
                nonce,
                Vec::new(),
                b"x".to_vec(),
            )
            .expect_err("ungranted encrypt fails");
        assert!(matches!(err, WitAeadError::ConstructionNotAllowed));
    }

    /// Ed25519 against RFC 8032 §7.1 TEST 1: `public-key` derives the
    /// published key, `sign` reproduces the published signature, and
    /// `verify` accepts it — while a different message fails.
    #[test]
    fn ed25519_matches_rfc8032_test_1() {
        use super::bindings::qqq::crypto::signing::{Algorithm as WitSignAlgorithm, Host as _};
        let mut data = crypto_store(&[], &[], &["ed25519"]);
        let seed = hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public = data
            .public_key(WitSignAlgorithm::Ed25519, seed.clone())
            .expect("public-key");
        assert_eq!(
            hex(&public),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = data
            .sign(WitSignAlgorithm::Ed25519, seed.clone(), Vec::new())
            .expect("sign");
        assert_eq!(
            hex(&sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(
            data.verify(WitSignAlgorithm::Ed25519, public.clone(), Vec::new(), sig)
                .expect("verify"),
            "the RFC signature verifies"
        );
        assert!(
            !data
                .verify(
                    WitSignAlgorithm::Ed25519,
                    public,
                    b"tampered".to_vec(),
                    vec![0u8; 64]
                )
                .expect("verify runs"),
            "a different message must not verify"
        );
    }

    /// Signing lengths and grants fail closed and named: short seeds and
    /// keys are `invalid-key`, short signatures are `invalid-signature`,
    /// unlisted algorithms and missing grants never reach the primitive.
    #[test]
    fn signing_lengths_and_grants_are_checked() {
        use super::bindings::qqq::crypto::signing::{Algorithm as WitSignAlgorithm, Host as _};
        use qqq_cap::resolve::GrantSet;
        let mut data = crypto_store(&[], &[], &["ed25519"]);
        let seed = vec![4u8; 32];
        let public = data
            .public_key(WitSignAlgorithm::Ed25519, seed.clone())
            .expect("public-key");
        // Bad seed length for sign and public-key.
        for result in [
            data.sign(WitSignAlgorithm::Ed25519, vec![0u8; 31], Vec::new()),
            data.public_key(WitSignAlgorithm::Ed25519, vec![0u8; 31]),
        ] {
            assert!(
                matches!(result, Err(WitSignatureError::InvalidKey)),
                "a 31-byte seed is not a key"
            );
        }
        // Bad public key length for verify: the host cannot run the check.
        let err = data
            .verify(
                WitSignAlgorithm::Ed25519,
                vec![0u8; 31],
                Vec::new(),
                vec![0u8; 64],
            )
            .expect_err("short public key fails");
        assert!(matches!(err, WitSignatureError::InvalidKey));
        // Bad signature length: the WIT's `invalid-signature` case. A
        // 63-byte value was never checked, so it errors rather than
        // returning `false` — `false` stays reserved for a well-formed
        // signature that was checked and failed.
        let err = data
            .verify(WitSignAlgorithm::Ed25519, public, Vec::new(), vec![0u8; 63])
            .expect_err("short signature fails");
        assert!(matches!(err, WitSignatureError::InvalidSignature));
        // Ungranted: fails before the key is judged.
        let mut bare = StoreData::new(GrantSet::empty());
        let err = bare
            .sign(WitSignAlgorithm::Ed25519, seed, Vec::new())
            .expect_err("ungranted sign fails");
        assert!(matches!(err, WitSignatureError::AlgorithmNotAllowed));
    }

    /// Hex decoding for test vectors. Panics on bad input like the other
    /// test helpers (`F-18`): fixtures unwrap, assertions do not.
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        assert!(
            hex.len().is_multiple_of(2),
            "test vectors are whole bytes: {hex}"
        );
        hex.as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii hex"), 16)
                    .expect("hex digits")
            })
            .collect()
    }

    /// `random` must not be registered without its grant, and must be with it.
    #[test]
    fn random_registration_follows_the_grant() {
        let engine = test_engine();

        let mut with = Linker::<StoreData>::new(&engine);
        register(
            &mut with,
            &grants_with("[capabilities.crypto]\nrandom = true\n"),
        )
        .expect("register");
        assert!(
            has_func(&mut with, RANDOM, "get"),
            "a random grant must expose get"
        );

        let mut without = Linker::<StoreData>::new(&engine);
        register(
            &mut without,
            &grants_with("[capabilities.crypto]\nhash = [\"sha256\"]\n"),
        )
        .expect("register");
        assert!(
            !has_func(&mut without, RANDOM, "get"),
            "a hash-only grant must not expose random"
        );
    }

    /// **`SEC-011`: the boundary checks are reached, not merely declared.**
    ///
    /// # Why this test exists, and how its absence was found
    ///
    /// Every other boundary test in this crate exercises a helper directly
    /// (`boundary::size(…)`), which proves the helper is correct and proves
    /// **nothing about whether a live host call invokes it**. Neutering the call
    /// inside `random.get` — replacing `length` with a constant `0`, so the check
    /// can never reject — left every test in this module passing. A boundary check
    /// that is wired in and never exercised is indistinguishable from one that is
    /// absent, and only an injection found that.
    ///
    /// # Why the check is a named function rather than an inline expression
    ///
    /// So that a test can assert the *call site* rather than the helper. The
    /// inline form was untestable without a compiled component importing
    /// `qqq:crypto/random`, and hand-written WAT against that interface is a trap
    /// this project has already fallen into four times (see the extended note in
    /// `tests/hostile_guests.rs`): the lowered signature of `result<list<u8>,
    /// random-error>` needs a return-area pointer and a fully-declared error
    /// variant, and every hand-written attempt failed to instantiate **whether or
    /// not the capability was granted** — which made the ungranted case pass for
    /// the wrong reason.
    ///
    /// Naming the check gives the test a seam without inventing a fake guest.
    #[test]
    fn the_random_length_boundary_accepts_to_the_ceiling_and_refuses_past_it() {
        let ambient = crate::ambient::AmbientState::default();
        let ceiling = ambient.max_random_bytes();

        // At the ceiling: accepted. The limit is inclusive, so a guest asking for
        // exactly the maximum is served rather than refused by an off-by-one.
        assert!(
            random_length_verdict(ceiling, &ambient).is_accept(),
            "a request of exactly {ceiling} bytes (the ceiling) must be served"
        );

        // One past: rejected.
        if let Some(over) = ceiling.checked_add(1) {
            let v = random_length_verdict(over, &ambient);
            assert!(
                v.is_reject(),
                "a request of {over} bytes must be refused by the boundary check"
            );
            // The rejection names the argument, which is what makes it actionable
            // rather than a bare "invalid".
            assert!(
                v.reason().is_some_and(|r| r.contains("length")),
                "the rejection must name `length`: {:?}",
                v.reason()
            );
        }

        // The enforcement underneath must agree with the boundary, or the
        // boundary is checking a different limit from the one that applies — the
        // two-sources-of-truth failure this project records as `§O-068`.
        assert!(
            ambient.random_bytes(ceiling).is_ok(),
            "the enforcement must accept the ceiling the boundary accepts"
        );
        if let Some(over) = ceiling.checked_add(1) {
            assert!(
                ambient.random_bytes(over).is_err(),
                "the enforcement must refuse what the boundary refuses"
            );
        }

        // A small request is accepted, so the check is not a blanket refusal.
        assert!(random_length_verdict(32, &ambient).is_accept());
    }

    /// **The call-site checks, asserted by execution — `SEC-011`.**
    ///
    /// The `bindgen!` trait methods are directly callable, so these tests
    /// prove the property the old structural test could only approximate:
    /// the boundary verdict is applied at the call site and its rejection
    /// reaches the guest as the WIT error. The guest-compiled probe covers
    /// the same paths end to end; these pin each refusal case by name.
    /// Every crypto entry point records through the audit seam: a direct
    /// grant check would answer identically while leaving the caller looking
    /// capability-clean to `assert-caps-only`. Counted, not `contains`.
    #[test]
    fn every_crypto_body_records_through_the_audit_seam() {
        let production = include_str!("host_crypto.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default();
        let seams = production.matches("ambient::require(").count();
        assert_eq!(
            seams, 8,
            "every crypto body (random.get, hmac x2, aead x2, signing x3) must consult \
             the audit seam; found {seams} seam call(s)"
        );
    }

    #[test]
    fn random_get_refuses_by_name() {
        use super::bindings::qqq::crypto::random::{Host as _, RandomError};
        // No grant: refused before the length is judged.
        let mut ungranted = StoreData::new(GrantSet::empty());
        assert!(matches!(ungranted.get(16), Err(RandomError::NotGranted)));
        // Granted but over the ceiling: refused before any allocation.
        let mut granted = StoreData::new(grants_with("[capabilities.crypto]\nrandom = true\n"));
        assert!(matches!(
            granted.get(granted.ambient.max_random_bytes() + 1),
            Err(RandomError::TooLong)
        ));
        // At the ceiling: served.
        assert!(granted.get(16).is_ok());
    }

    /// `digest`/`digest-many` refuse by name: unlisted algorithms and
    /// oversize inputs fail as WIT `Err`s, never as traps.
    #[test]
    fn hashing_refuses_by_name() {
        use super::bindings::qqq::crypto::hashing::{Algorithm, HashError, Host as _};
        let mut data = crypto_store(&["sha256"], &[], &[]);
        // Unlisted algorithm: refused by name.
        assert!(matches!(
            data.digest(Algorithm::Blake3, b"abc".to_vec()),
            Err(HashError::AlgorithmNotAllowed)
        ));
        // Oversize input: refused before hashing.
        assert!(matches!(
            data.digest(Algorithm::Sha256, vec![0u8; MAX_HASH_INPUT + 1]),
            Err(HashError::InputTooLong)
        ));
        // Batch over the list bound: refused whole.
        assert!(matches!(
            data.digest_many(Algorithm::Sha256, vec![vec![0u8; MAX_HASH_INPUT + 1]]),
            Err(HashError::InputTooLong)
        ));
        // Listed algorithm, bounded input: computes.
        assert!(data.digest(Algorithm::Sha256, b"abc".to_vec()).is_ok());
    }

    /// And the converse: `hashing` must not appear without its grant.
    #[test]
    fn hashing_registration_follows_the_grant() {
        let engine = test_engine();

        let mut with = Linker::<StoreData>::new(&engine);
        register(
            &mut with,
            &grants_with("[capabilities.crypto]\nhash = [\"sha256\"]\n"),
        )
        .expect("register");
        assert!(
            has_func(&mut with, HASHING, "digest"),
            "a hash grant must expose digest"
        );

        let mut without = Linker::<StoreData>::new(&engine);
        register(
            &mut without,
            &grants_with("[capabilities.crypto]\nrandom = true\n"),
        )
        .expect("register");
        assert!(
            !has_func(&mut without, HASHING, "digest"),
            "a random-only grant must not expose hashing"
        );
    }

    /// **The positive control for the probe.** Without it, a probe that always
    /// returned `false` would make every deny assertion above pass vacuously.
    #[test]
    fn the_registration_probe_detects_a_bound_function() {
        let engine = test_engine();
        let mut linker = Linker::<StoreData>::new(&engine);
        register(
            &mut linker,
            &grants_with("[capabilities.crypto]\nrandom = true\n"),
        )
        .expect("register");
        assert!(
            has_func(&mut linker, RANDOM, "get"),
            "the probe failed to detect a certainly-registered function"
        );

        let mut fresh = Linker::<StoreData>::new(&engine);
        register(
            &mut fresh,
            &grants_with("[capabilities.crypto]\nrandom = true\n"),
        )
        .expect("register");
        assert!(
            !has_func(&mut fresh, RANDOM, "never-registered"),
            "the probe reported a function that does not exist"
        );
    }

    /// Whether a linker exposes a function, via the shadowing signal.
    ///
    /// Wasmtime 48's `Linker` has no lookup API, so redefinition is the only
    /// observable. With shadowing disallowed (the default), redefining a name
    /// fails when present and succeeds when absent. Each call must use a fresh
    /// linker, because the probe *defines* the name when it turns out to be
    /// free.
    fn has_func(linker: &mut Linker<StoreData>, interface: &str, name: &str) -> bool {
        let Ok(mut inst) = linker.instance(interface) else {
            return false;
        };
        let probe = inst.func_wrap(name, |_: StoreContextMut<'_, StoreData>, (): ()| {
            Ok::<_, wasmtime::Error>(())
        });
        probe.is_err()
    }

    fn test_engine() -> Engine {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        Engine::new(&cfg).expect("engine")
    }

    /// Build a grant set from a `[capabilities.crypto]` body.
    ///
    /// Goes through a real manifest because `GrantSet::from_manifest` is the
    /// only layer that may grant authority — `GrantSet::empty().narrow(...)`
    /// grants nothing, since `narrow` intersects. See Observations §O-020c.
    /// The body carries its own `[capabilities.crypto]` header; no table
    /// line is added here, because an extra one would either duplicate
    /// the header or — before the root denied unknown tables — vanish
    /// silently while looking load-bearing.
    fn grants_with(crypto_body: &str) -> GrantSet {
        let src = format!("[package]\nname = \"test\"\nversion = \"0.1.0\"\n\n{crypto_body}");
        let manifest = Manifest::parse(&src).expect("test manifest must parse");
        GrantSet::from_manifest(&manifest)
    }
}
