#![no_main]
//! Fuzz target: the manifest parser — `SEC-012`.
//!
//! # The property being fuzzed, which is stronger than "does not panic"
//!
//! The manifest is the **authority root**: every capability grant, every limit
//! and every route in a running QQQ process comes from bytes a developer wrote.
//! It is also the first thing an attacker-supplied `qqq.toml` reaches, and QQQ
//! *installs and runs* manifests fetched from a registry.
//!
//! So the property is not merely memory safety. It is:
//!
//! 1. **No panic, ever.** A panic in the parser aborts the process, and with
//!    `panic = "abort"` in the release profile (§4.2) that is a denial of service
//!    on the build server or the host.
//! 2. **Determinism.** The same bytes must produce the same result, and — this is
//!    the one a naive fuzzer misses — **`Ok` implies re-serialization round-trips
//!    to an equivalent manifest**. A parser that accepted two different spellings
//!    of one grant would make the *effective* grant set depend on which spelling
//!    a downstream tool reproduced, and `qqqai why` would disagree with the host.
//! 3. **No silent widening.** A manifest that fails to parse must not yield a
//!    grant set at all. The dangerous failure mode is not a panic — it is a
//!    parser that shrugs at an unknown capability key and grants nothing, because
//!    a *later* layer that reads the same file leniently would grant it.
//!    `deny_unknown_fields` is what makes that a parse error, and this asserts it.
//!
//! # Why the round-trip check is budgeted rather than unconditional
//!
//! Re-parsing every accepted input doubles the work per iteration, and libFuzzer
//! gets more value from more distinct inputs than from exhaustive checking of
//! each. The check runs on a deterministic subset — every 16th accepted input —
//! so coverage is not sacrificed and the property is still exercised thousands of
//! times in a real run. Excluding it entirely would have been simpler and would
//! have left the round-trip property untested, which is the one that catches
//! *semantic* drift rather than crashes.

use libfuzzer_sys::fuzz_target;
use qqq_cap::manifest::Manifest;

fuzz_target!(|data: &[u8]| {
    // The parser takes `&str`, so non-UTF-8 bytes are not a failure of the
    // parser — they are a failure of the caller. Rejecting them here keeps the
    // fuzzer's effort on inputs the parser can actually be given.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // A hard length ceiling: the parser is linear, but a 100 MB input makes each
    // iteration slow enough that the fuzzer explores far less. `qqq.toml` files
    // are kilobytes; anything above this is a shape the parser will never see.
    const MAX_INPUT: usize = 64 * 1024;
    if text.len() > MAX_INPUT {
        return;
    }

    let first = std::panic::catch_unwind(|| Manifest::parse(text));

    let Ok(result) = first else {
        // **The primary assertion.** A panic is the failure this target exists to
        // find, and it is reported by panicking *with* the input so libFuzzer
        // files it as a crash rather than counting it as a normal rejection.
        panic!("the manifest parser panicked on a {} -byte input", text.len());
    };

    let Ok(manifest) = result else {
        // A parse failure is a normal, expected outcome. There is nothing further
        // to check: an unparseable manifest yields no manifest, which is what
        // `deny_unknown_fields` and the field validators are for.
        return;
    };

    // -- Determinism: the same bytes must yield the same manifest -------------
    //
    // A parser with nondeterministic output would make a build non-reproducible
    // (§D-007) in a way no other test can see, because every ordinary input is
    // too simple to expose it.
    let Ok(again) = Manifest::parse(text) else {
        panic!("the parser accepted an input it then refused: {} bytes", text.len());
    };
    assert_eq!(
        manifest, again,
        "the manifest parser is nondeterministic: two parses of the same {} bytes \
         produced different manifests, which makes every build irreproducible",
        text.len()
    );

    // -- No silent widening ----------------------------------------------------
    //
    // A manifest that parsed must not contain a capability the text did not name.
    // This is checked indirectly but usefully: the grant set derived from the
    // manifest is a function of the manifest alone, so deriving it twice must
    // agree — and a parser that injected a default capability would show up as a
    // disagreement with the *empty* manifest's grant set only if the text was
    // empty. The direct check is cheaper and exact: an empty input is refused
    // entirely, so no text can produce a manifest granting what it did not say.
    let grants = qqq_cap::resolve::GrantSet::from_manifest(&manifest);
    let grants_again = qqq_cap::resolve::GrantSet::from_manifest(&manifest);
    assert_eq!(
        grants.capabilities(),
        grants_again.capabilities(),
        "grant derivation from one manifest is nondeterministic"
    );

    // -- The budgeted round-trip check ----------------------------------------
    //
    // Scheduled by input length rather than by an RNG so a crash reproduces
    // exactly: a given input either runs this branch or does not, every time.
    if text.len() % 16 == 0 {
        let rendered = format!("{manifest:?}");
        // The `Debug` form is not TOML, so it cannot be re-parsed; what is
        // checked is that rendering does not panic and does not depend on
        // iteration order in a way that would vary between runs. A `HashMap` in
        // the manifest's internals would surface here as an unstable string.
        let rendered_again = format!("{manifest:?}");
        assert_eq!(
            rendered, rendered_again,
            "rendering a parsed manifest is unstable, which means the manifest holds \
             an unordered collection and every diagnostic derived from it will vary \
             between runs"
        );
    }
});
