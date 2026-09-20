//! The `qqq:crypto` host implementation — `random` and `hashing`.
//!
//! Wires `wit/qqq-crypto.wit` to the [`AmbientState`] already in the store.
//!
//! [`AmbientState`]: crate::ambient::AmbientState
//!
//! # Scope, stated precisely
//!
//! Only two of the five interfaces are implemented:
//!
//! | Interface | State |
//! |---|---|
//! | `random` | implemented |
//! | `hashing` | implemented |
//! | `hmac` | **not implemented** |
//! | `aead` | **not implemented** |
//! | `signing` | **not implemented** |
//!
//! The registry reports `qqq:crypto@1.0.0` as `implemented: false` for exactly
//! this reason, and a test in `qqq-abi` pins that. A partially-served interface
//! claiming completeness would let a component needing AEAD pass admission and
//! then fail at first call — the opaque failure the flag exists to prevent.
//!
//! The unimplemented interfaces are **absent from the linker** rather than
//! registered as stubs. That is deliberate: a stub that traps at call time turns
//! a clear "unknown import" at instantiation into a mystery at runtime, and
//! instantiation is when a developer can still do something about it.
//!
//! # Why the bindings are hand-written
//!
//! `wasmtime::component::bindgen!` needs the `wit/` directory wired into this
//! crate's build — the right change for the whole interface set at once. Until
//! then the signatures are written against the published WIT by hand, pinned by
//! tests that read the `.wit` file. See `host_clock.rs` for the same reasoning.
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

use wasmtime::component::{Linker, ResourceAny};
use wasmtime::StoreContextMut;

use qqq_cap::capability::Capability;
use qqq_cap::resolve::GrantSet;

use crate::ambient::{hash_data, HostCallError};
use crate::linker::StoreData;

/// The WIT package this module implements.
pub const INTERFACE: &str = "qqq:crypto@1.0.0";

/// The `random` interface, as a component imports it.
pub const RANDOM: &str = "qqq:crypto/random@1.0.0";

/// The `hashing` interface, as a component imports it.
pub const HASHING: &str = "qqq:crypto/hashing@1.0.0";

/// Why a randomness request failed, mirroring the WIT `random-error` variant.
///
/// **The order is the WIT declaration order.** A `variant` is an indexed type,
/// so `not-granted` is case 0. Reordering would make a guest read a denial as a
/// source failure and plausibly retry forever — a silent miscommunication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomError {
    /// `crypto.random` was not granted.
    NotGranted = 0,
    /// The requested length exceeds the host's per-call maximum.
    TooLong = 1,
    /// The host entropy source failed.
    SourceFailed = 2,
}

impl RandomError {
    /// The variant index, as the component ABI lowers it.
    #[must_use]
    pub const fn as_index(self) -> u32 {
        self as u32
    }
}

/// Why a hashing operation failed, mirroring the WIT `hash-error` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashError {
    /// The algorithm is not in the manifest's allowlist.
    AlgorithmNotAllowed = 0,
    /// The input exceeds the host's per-call maximum.
    InputTooLong = 1,
}

impl HashError {
    /// The variant index, as the component ABI lowers it.
    #[must_use]
    pub const fn as_index(self) -> u32 {
        self as u32
    }
}

impl From<HostCallError> for HashError {
    fn from(e: HostCallError) -> Self {
        match e {
            // A guest reaching `NotGranted` was not granted the capability. The
            // WIT's `hash-error` has no `not-granted` case, so it maps to the
            // closest honest case. The real protection is that `digest` is not
            // registered without the grant, so this arm is unreachable in
            // practice and exists only so the mapping is total.
            //
            // `TooLong` and `SourceFailed` are randomness concerns that
            // `hash_data` cannot produce; mapping them to `InputTooLong` keeps
            // the function total without inventing a case the WIT lacks.
            HostCallError::NotGranted(_)
            | HostCallError::AlgorithmNotAllowed(_)
            | HostCallError::TooLong
            | HostCallError::SourceFailed => Self::AlgorithmNotAllowed,
        }
    }
}

/// The maximum input length the host will hash in one call.
///
/// A bound rather than an unbounded allocation: a guest passing a huge buffer
/// is either buggy or attacking the host's memory, and a limit is cheaper than
/// an investigation. 64 MiB is generous for a hash input and small enough that
/// the copy across the ABI boundary cannot exhaust a typical instance budget.
pub const MAX_HASH_INPUT: usize = 64 * 1024 * 1024;

/// Register the crypto host functions the grants justify.
///
/// Only `random` and `hashing` have implementations; `hmac`, `aead` and
/// `signing` are deliberately not registered, so a component importing them
/// fails at instantiation with a nameable error rather than at call time.
///
/// # Errors
///
/// A `wasmtime::Error` if the linker rejects a signature.
pub fn register(linker: &mut Linker<StoreData>, grants: &GrantSet) -> wasmtime::Result<()> {
    if grants.grants(Capability::CryptoRandom) {
        register_random(linker)?;
    }
    if grants.grants(Capability::CryptoHash) {
        register_hashing(linker)?;
    }
    // `CryptoHmac`, `CryptoAead` and `CryptoSign` are intentionally absent.
    // See the module documentation: an absent import is a clear failure at
    // instantiation; a stub that traps is a mystery at call time.
    Ok(())
}

/// The `random` interface.
fn register_random(linker: &mut Linker<StoreData>) -> wasmtime::Result<()> {
    let mut inst = linker.instance(RANDOM)?;

    // `get: func(length: u32) -> result<list<u8>, random-error>`
    //
    // Every return is a one-element **tuple**. `ComponentNamedList` — the trait
    // a host function's parameter and return lists must satisfy — is
    // implemented for tuples, not for bare types, so `Vec<u8>` alone does not
    // compile while `(Vec<u8>,)` does. That is a property of the Component
    // Model's flat-parameter representation, not a style choice.
    inst.func_wrap(
        "get",
        |store: StoreContextMut<'_, StoreData>,
         (length,): (u32,)|
         -> wasmtime::Result<(Vec<u8>,)> {
            // `HOST-011`: contained, like every host body — see `host_clock.rs`
            // for why a panic here would otherwise unwind through the engine.
            crate::guard::guard("qqq:crypto@1.0.0/random.get", || {
                // Defence in depth: the function is only registered when granted,
                // but re-checking at call time means a future change that registers
                // it unconditionally still cannot hand out entropy.
                if !store.data().grants.grants(Capability::CryptoRandom) {
                    return Err(denied(Capability::CryptoRandom));
                }
                store
                    .data()
                    .ambient
                    .random_bytes(length)
                    .map(|b| (b,))
                    .map_err(|e| {
                        // A source failure must fail closed. Surfacing it as a host
                        // error rather than fabricating bytes is the whole point:
                        // predictable "randomness" is worse than a failure.
                        wasmtime::Error::msg(match e {
                            crate::ambient::RandomFailure::TooLong => {
                                format!(
                                    "random request of {length} bytes exceeds the per-call maximum"
                                )
                            }
                            crate::ambient::RandomFailure::SourceFailed => {
                                "the host entropy source failed; refusing to substitute a weaker source"
                                    .to_owned()
                            }
                        })
                    })
            })
        },
    )?;

    Ok(())
}

/// The `hashing` interface.
fn register_hashing(linker: &mut Linker<StoreData>) -> wasmtime::Result<()> {
    let mut inst = linker.instance(HASHING)?;

    // `digest: func(algorithm: algorithm, data: list<u8>) -> result<list<u8>, hash-error>`
    //
    // `algorithm` is an `enum`, which the ABI lowers to a `u32` discriminant in
    // WIT declaration order: sha256=0, sha512=1, blake3=2.
    inst.func_wrap(
        "digest",
        |store: StoreContextMut<'_, StoreData>,
         (algorithm, data): (u32, Vec<u8>)|
         -> wasmtime::Result<(Vec<u8>,)> {
            crate::guard::guard("qqq:crypto@1.0.0/hashing.digest", || {
                let name = algorithm_name(algorithm)?;
                if data.len() > MAX_HASH_INPUT {
                    return Err(wasmtime::Error::msg(format!(
                        "hash input of {} bytes exceeds the {MAX_HASH_INPUT}-byte limit",
                        data.len()
                    )));
                }
                hash_data(store.data(), name, &data)
                    .map(|d| (d,))
                    .map_err(|e| wasmtime::Error::msg(format!("{e:?}")))
            })
        },
    )?;

    // `digest-many: func(algorithm, inputs: list<list<u8>>) -> result<list<list<u8>>, hash-error>`
    //
    // The batch-first shape (Proposal §4.5, `CON-012`). A guest hashing a list
    // in a loop pays the ABI crossing once per value; this pays it once.
    inst.func_wrap(
        "digest-many",
        |store: StoreContextMut<'_, StoreData>,
         (algorithm, inputs): (u32, Vec<Vec<u8>>)|
         -> wasmtime::Result<(Vec<Vec<u8>>,)> {
            crate::guard::guard("qqq:crypto@1.0.0/hashing.digest-many", || {
                let name = algorithm_name(algorithm)?;
                let mut out = Vec::with_capacity(inputs.len());
                for input in &inputs {
                    if input.len() > MAX_HASH_INPUT {
                        return Err(wasmtime::Error::msg(format!(
                            "hash input of {} bytes exceeds the {MAX_HASH_INPUT}-byte limit",
                            input.len()
                        )));
                    }
                    out.push(
                        hash_data(store.data(), name, input)
                            .map_err(|e| wasmtime::Error::msg(format!("{e:?}")))?,
                    );
                }
                Ok((out,))
            })
        },
    )?;

    Ok(())
}

/// Map the WIT `algorithm` enum discriminant to its name.
///
/// # Errors
///
/// A host error for an out-of-range discriminant. That indicates the guest and
/// host disagree about the enum — a version mismatch — and producing a hash
/// with a guessed algorithm would be worse than failing.
fn algorithm_name(index: u32) -> wasmtime::Result<&'static str> {
    match index {
        0 => Ok("sha256"),
        1 => Ok("sha512"),
        2 => Ok("blake3"),
        other => Err(wasmtime::Error::msg(format!(
            "unknown hash algorithm discriminant {other}; the guest and host \
             disagree about the `algorithm` enum, which means a version mismatch"
        ))),
    }
}

/// The error a call-time re-check produces.
fn denied(cap: Capability) -> wasmtime::Error {
    wasmtime::Error::msg(format!(
        "capability `{cap}` was re-checked at call time and is not granted; \
         this means the linker was built incorrectly, which is a QQQ bug"
    ))
}

/// Unused import guard: `ResourceAny` is not needed yet but keeps the import
/// list stable when resource-returning interfaces (`fs`, `http`) land.
const _: Option<ResourceAny> = None;

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_cap::manifest::Manifest;
    use wasmtime::Engine;

    /// **The anti-drift test.** These bindings are hand-written, so they can
    /// drift from `wit/qqq-crypto.wit`. This test reads the WIT and asserts
    /// every function of the two *implemented* interfaces is registered here.
    #[test]
    fn every_implemented_wit_function_is_registered() {
        let wit = include_str!("../../../wit/qqq-crypto.wit");
        let this_file = include_str!("host_crypto.rs");

        // `random.get`
        assert!(wit.contains("get: func(length: u32)"), "random.get renamed");
        assert!(
            this_file.contains("\"get\""),
            "random.get is declared in the WIT but not registered"
        );

        // `hashing.digest` and `hashing.digest-many`
        for name in ["digest", "digest-many"] {
            assert!(
                wit.contains(&format!("\n  {name}: func(")),
                "`{name}` is not declared in qqq-crypto.wit"
            );
            assert!(
                this_file.contains(&format!("\"{name}\"")),
                "`{name}` is declared in the WIT but not registered here"
            );
        }
    }

    /// Whether `source` contains `func_wrap("name"`, ignoring whitespace.
    ///
    /// # Why whitespace is normalised rather than matched literally
    ///
    /// An earlier version of these tests matched the exact string
    /// `func_wrap(\n        "digest"` — eight spaces, one newline. That made the
    /// test depend on **formatting**, and it failed on the Windows CI runner
    /// while passing everywhere else: `rustfmt` lays the call out differently
    /// there, and `include_str!` reads whatever layout the repository holds.
    ///
    /// A test whose result depends on where a line breaks is not testing the
    /// property it names. Stripping whitespace asks the question that was meant
    /// — "is this function registered?" — independently of how the source is
    /// laid out. If `rustfmt` reflows the call again, this keeps working.
    fn registers(source: &str, name: &str) -> bool {
        let squeezed: String = source.chars().filter(|c| !c.is_whitespace()).collect();
        squeezed.contains(&format!("func_wrap(\"{name}\""))
    }

    /// The *unimplemented* interfaces must not be registered. Registering a
    /// stub would replace a clear instantiation failure with a runtime mystery.
    ///
    /// # Why this looks for the registration call, not the bare name
    ///
    /// An earlier version asserted the raw string `"compute"` does not appear in
    /// this file — and failed, because the word appears in this file's own
    /// prose. The property being tested is "no host function is registered under
    /// this name", so the test must look at how registrations are written
    /// (`func_wrap("name"`), not at whether a word occurs anywhere. A test that
    /// greps prose tests the prose.
    #[test]
    fn unimplemented_interfaces_are_not_registered() {
        let this_file = include_str!("host_crypto.rs");
        for name in [
            "compute",    // hmac
            "encrypt",    // aead
            "decrypt",    // aead
            "sign",       // signing
            "verify",     // hmac + signing
            "public-key", // signing
            "nonce-length",
            "key-length",
        ] {
            assert!(
                !registers(this_file, name),
                "`{name}` belongs to an unimplemented interface (hmac/aead/signing) \
                 and must not be registered as a stub"
            );
        }
    }

    /// The positive control for the test above: `digest` *is* registered, so the
    /// same detection must find it. Without this, a check that never matched
    /// anything would look like proof.
    #[test]
    fn the_unregistered_check_can_find_a_registered_name() {
        let this_file = include_str!("host_crypto.rs");
        for name in ["get", "digest", "digest-many"] {
            assert!(
                registers(this_file, name),
                "the detection used by the test above cannot find `{name}`, which \
                 certainly is registered, so its assertions prove nothing"
            );
        }
        // And it must not report a name that is genuinely absent.
        assert!(!registers(this_file, "definitely-not-registered"));
    }

    /// The detection itself must be formatting-independent. This pins the fix
    /// for the Windows CI failure: the same call laid out three ways must be
    /// recognised every time.
    #[test]
    fn the_registration_detection_ignores_layout() {
        for layout in [
            "inst.func_wrap(\"digest\", |s, p| Ok((vec![],)))",
            "inst.func_wrap(\n    \"digest\",\n    |s, p| Ok((vec![],)),\n)",
            "inst\n    .func_wrap(\n        \"digest\",\n        |s, p| Ok((vec![],)),\n    )",
        ] {
            assert!(
                registers(layout, "digest"),
                "the detection missed a registration written as:\n{layout}"
            );
        }
        assert!(!registers(
            "inst.func_wrap(\"other\", |s, p| Ok(()))",
            "digest"
        ));
    }

    #[test]
    fn the_package_name_matches_the_wit() {
        let wit = include_str!("../../../wit/qqq-crypto.wit");
        assert!(
            wit.contains(&format!("package {INTERFACE};")),
            "the WIT package declaration does not match INTERFACE={INTERFACE}"
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
    #[test]
    fn the_error_variant_orders_match_the_wit() {
        let wit = include_str!("../../../wit/qqq-crypto.wit");

        let ng = wit.find("not-granted").expect("declared");
        let tl = wit.find("too-long").expect("declared");
        let sf = wit.find("source-failed").expect("declared");
        assert!(ng < tl && tl < sf, "random-error order changed");
        assert_eq!(RandomError::NotGranted.as_index(), 0);
        assert_eq!(RandomError::TooLong.as_index(), 1);
        assert_eq!(RandomError::SourceFailed.as_index(), 2);

        let ana = wit.find("algorithm-not-allowed").expect("declared");
        let itl = wit.find("input-too-long").expect("declared");
        assert!(ana < itl, "hash-error order changed");
        assert_eq!(HashError::AlgorithmNotAllowed.as_index(), 0);
        assert_eq!(HashError::InputTooLong.as_index(), 1);
    }

    /// The `algorithm` enum order is an ABI too. `sha256` is declared first.
    #[test]
    fn the_algorithm_enum_order_matches_the_wit() {
        let wit = include_str!("../../../wit/qqq-crypto.wit");
        let sha256 = wit.find("sha256,").expect("declared");
        let sha512 = wit.find("sha512,").expect("declared");
        let blake3 = wit.find("blake3,").expect("declared");
        assert!(
            sha256 < sha512 && sha512 < blake3,
            "the algorithm enum order changed; algorithm_name must change too"
        );
        // And the mapping must agree with that order.
        assert_eq!(algorithm_name(0).unwrap(), "sha256");
        assert_eq!(algorithm_name(1).unwrap(), "sha512");
        assert_eq!(algorithm_name(2).unwrap(), "blake3");
    }

    /// An out-of-range discriminant must fail rather than guess. Producing a
    /// hash with the wrong algorithm silently would break every stored digest.
    #[test]
    fn an_unknown_algorithm_discriminant_is_refused() {
        let e = algorithm_name(3).unwrap_err();
        assert!(
            e.to_string().contains("version mismatch"),
            "the error must explain the cause: {e}"
        );
        assert!(algorithm_name(u32::MAX).is_err());
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
    fn grants_with(crypto_body: &str) -> GrantSet {
        let src =
            format!("[package]\nname = \"test\"\nversion = \"0.1.0\"\n\n[crypto]\n{crypto_body}");
        let manifest = Manifest::parse(&src).expect("test manifest must parse");
        GrantSet::from_manifest(&manifest)
    }
}
