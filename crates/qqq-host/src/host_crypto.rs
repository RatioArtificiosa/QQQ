// SPDX-License-Identifier: Apache-2.0

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
                random_length_verdict(length, &store.data().ambient)
                    .into_result("length")
                    .map_err(|e| wasmtime::Error::msg(e.render()))?;
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
                // **`SEC-011`: the discriminant is validated through the shared
                // boundary layer**, so the check is the same one the registry
                // declares and the same one `digest-many` applies. `algorithm_name`
                // still performs its own match — the two are not redundant in the
                // way a duplicated check normally is: `algorithm_name` maps a
                // validated index to a name, and the boundary states the contract
                // "this index is a member of the set the host defined" *before*
                // any work happens.
                crate::boundary::discriminant(
                    "algorithm",
                    algorithm,
                    crate::ambient::HASH_ALGORITHM_COUNT,
                )
                .into_result("algorithm")
                .map_err(|e| wasmtime::Error::msg(e.render()))?;
                let name = algorithm_name(algorithm)?;
                // Size, through the boundary layer.
                crate::boundary::size("data", data.len(), MAX_HASH_INPUT)
                    .into_result("data")
                    .map_err(|e| wasmtime::Error::msg(e.render()))?;
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
                // **`SEC-011`: the list boundary, on BOTH axes.**
                //
                // This is the case the two-axis check exists for. The earlier
                // version only bounded each element's length, so a guest passing a
                // hundred million *empty* lists allocated a `Vec<Vec<u8>>` of
                // headers — zero payload bytes, gigabytes of metadata. Neither axis
                // alone catches it, which is why `list_size` states both.
                let total_bytes: usize = inputs.iter().map(Vec::len).sum();
                crate::boundary::discriminant(
                    "algorithm",
                    algorithm,
                    crate::ambient::HASH_ALGORITHM_COUNT,
                )
                .into_result("algorithm")
                .map_err(|e| wasmtime::Error::msg(e.render()))?;
                crate::boundary::list_size("inputs", inputs.len(), total_bytes)
                    .into_result("inputs")
                    .map_err(|e| wasmtime::Error::msg(e.render()))?;

                let name = algorithm_name(algorithm)?;
                let mut out = Vec::with_capacity(inputs.len());
                for (i, input) in inputs.iter().enumerate() {
                    // The per-element limit is still separate from the list
                    // limits: a single 1 GiB input is one element and within
                    // neither of them.
                    crate::boundary::size("inputs", input.len(), MAX_HASH_INPUT)
                        .with_field("inputs")
                        .into_result(&format!("inputs[{i}]"))
                        .map_err(|e| wasmtime::Error::msg(e.render()))?;
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

/// The `SEC-011` boundary verdict for a `random.get` length.
///
/// # Why this is a named function rather than an inline expression
///
/// Because an inline check inside a `func_wrap` closure **cannot be tested** —
/// reaching it needs a compiled component importing `qqq:crypto/random`, and
/// hand-written WAT against that interface is a trap this project has fallen into
/// four times (the lowered `result<list<u8>, random-error>` needs a return-area
/// pointer and a fully-declared error variant, and each attempt failed to
/// instantiate *whether or not* the capability was granted, making the ungranted
/// case pass for the wrong reason — see `tests/hostile_guests.rs`).
///
/// That untestability has a measurable cost, found by injection rather than by
/// reasoning: neutering the inline check so it could never reject left **every**
/// test in this module green. Extracting it gives the test a seam, and
/// `the_random_length_boundary_accepts_to_the_ceiling_and_refuses_past_it` now
/// fails when the *helper* is wrong.
///
/// # The second gap, and why `the_call_site_applies_the_boundary_check` exists
///
/// Extracting the helper closes only half the hole. A **second** injection —
/// neutering the call site while leaving the helper correct — also left every
/// test green, because a test that calls the helper directly proves the helper
/// works and proves nothing about whether the host function uses it. Probing the
/// function's *result* is what remains untestable without a real component, so
/// the call site is asserted **structurally** instead: the registration body must
/// reference `random_length_verdict` and must propagate its rejection with `?`.
/// That is weaker than an execution test and strictly stronger than nothing, and
/// the test says so rather than implying otherwise.
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

    /// **The anti-drift test for `SEC-011`'s range boundary.**
    ///
    /// `HASH_ALGORITHM_COUNT` is the number the boundary check validates a raw
    /// guest-supplied discriminant against. It is a property of the WIT
    /// declaration order — an ABI — so a member added to the WIT without updating
    /// the constant would make the host **refuse a valid algorithm**, and a member
    /// removed without updating it would let the host accept one that no longer
    /// exists. Both are silent in every other test, because `algorithm_name`
    /// matches the same three names and would agree with a stale constant.
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
             HASH_ALGORITHM_COUNT is {}. The boundary check would refuse a valid \
             algorithm (if the constant is low) or accept a non-existent one (if \
             high), and `algorithm_name` would agree with the stale constant, so \
             nothing else would catch this.",
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

    /// **The call-site check, asserted structurally — `SEC-011`.**
    ///
    /// # Why this is structural rather than behavioural, stated plainly
    ///
    /// The property is "the registered `random.get` host function applies
    /// `random_length_verdict` and propagates its rejection." Proving that by
    /// execution needs a guest that imports `qqq:crypto/random` and calls `get`
    /// with an oversized length — and hand-written WAT against that interface has
    /// failed to instantiate four times in this project (see the note in
    /// `tests/hostile_guests.rs`), each failure making the case pass for the wrong
    /// reason.
    ///
    /// So this asserts the call site in source. It is **weaker** than an
    /// execution test: it cannot prove the check runs before the allocation, and
    /// a sufficiently determined refactor could satisfy it while breaking the
    /// property. It is **stronger than nothing**, which is what the previous
    /// state was — demonstrated, not assumed: neutering the call site left all 16
    /// tests in this module green.
    ///
    /// The honest description of the coverage is therefore: the helper is proven
    /// by execution, the wiring is proven by source inspection, and the
    /// end-to-end path is unproven until a generated fixture exists. That
    /// limitation is recorded here rather than left for a reader to discover.
    #[test]
    fn the_call_site_applies_the_boundary_check() {
        let source = include_str!("host_crypto.rs");

        // Locate the `random.get` registration body. The registration is
        // `func_wrap("get", …)`, and the body runs until the closing `)?;`.
        let squeezed: String = source.chars().filter(|c| !c.is_whitespace()).collect();
        let at = squeezed
            .find("func_wrap(\"get\"")
            .expect("`random.get` must be registered");
        let body_end = squeezed[at..]
            .find(")?;")
            .map(|o| at + o)
            .expect("the registration must be closed");
        let body = &squeezed[at..body_end];

        assert!(
            body.contains("random_length_verdict("),
            "the `random.get` registration body does not call `random_length_verdict`; \
             the boundary check is defined but NOT APPLIED, so an oversized length \
             reaches the allocation unchecked. SEC-011 requires validation at the \
             crossing, not merely a function that could perform it."
        );

        // And the rejection must be PROPAGATED. A body that computed the verdict
        // and ignored it would satisfy the assertion above while doing nothing —
        // which is exactly the injection (`let _check = …;`) that went undetected
        // before this test existed.
        //
        // The propagation is `?` on the `into_result(...).map_err(...)` chain. The
        // slice above ends at the `)` of `)?;`, so the `?` itself is the next
        // character after the slice — which is why this asserts on the *chain*
        // rather than reaching for a `?` that the delimiter already consumed. The
        // first version of this test asserted `?;` inside the slice and failed
        // against a body that was, in fact, correct.
        assert!(
            body.contains("into_result(\"length\")") && body.contains("map_err("),
            "the `random.get` body computes the boundary verdict but does not \
             convert and propagate the rejection; a check whose result is discarded \
             is not a check. Body tail: …{}",
            &body[body.len().saturating_sub(80)..]
        );

        // The `?` is the character immediately following the slice, because the
        // slice stops at the `)` of `)?;`. Asserting that placement — rather than
        // merely that a `?` exists somewhere later in the file — is what ties the
        // propagation to THIS chain.
        assert!(
            squeezed[body_end..].starts_with(")?;"),
            "the boundary check's rejection must be propagated with `?` immediately \
             after the chain, so the host function returns before performing the \
             allocation the check exists to prevent. Found: {:?}",
            &squeezed[body_end..(body_end + 8).min(squeezed.len())]
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
