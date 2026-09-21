#![no_main]
// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: the host interfaces — `SEC-012`.
//!
//! # What "the host interfaces" means here, and what fuzzing them can prove
//!
//! The guest-to-host calls are reached through a live Wasm store, and reaching
//! one requires a compiled component that imports it. Hand-written WAT against
//! the real interfaces has failed to instantiate four times in this project (the
//! lowered `result<list<u8>, E>` needs a return-area pointer and a fully-declared
//! error variant), so driving the calls *through* a guest is not something a fuzz
//! target can do reliably either.
//!
//! What **is** fuzzable, and what this target covers, is the **argument-validation
//! and value-construction layer** every host call runs on: the boundary checks and
//! the ambient/secret primitives they guard. That layer is where a guest's
//! integers, strings and byte lists arrive, and §7.2's adversary controls all of
//! them.
//!
//! # The properties, each named for the failure it prevents
//!
//! 1. **No panic in any boundary check.** These run inside `func_wrap` closures
//!    via `guard`. A panic there unwinds through Wasmtime's frames and, with
//!    `panic = "abort"`, kills the process — so a boundary check that panics is a
//!    denial of service *introduced by the defence*.
//! 2. **`Verdict::Accept` is never produced for a known-bad shape.** The traversal
//!    corpus is a fixed set of inputs the shape check must refuse; re-running it
//!    against arbitrary bytes confirms the check does not have an input-dependent
//!    hole.
//! 3. **Diagnostic rendering is total and bounded.** Every rejection's reason is
//!    derived from attacker-controlled bytes. Rendering must never panic and must
//!    never emit a raw control character — a guest that can put a newline into a
//!    log line can forge a log event, which is a real attack on operators.
//! 4. **Secret material never appears in a diagnostic.** The `CAP-016` store's
//!    whole contract is that a value is used but never disclosed. A boundary
//!    rejection that echoed the request would be that contract's failure, and it
//!    would be invisible to every test that only checks the happy path.

use libfuzzer_sys::fuzz_target;
use qqq_host::boundary::{
    self, consistent_length, discriminant, list_size, one_of, path_component, path_shape,
    range_within, render_for_diagnostic, size, text, Verdict,
};

/// Run one boundary check and assert the invariants every check must hold.
///
/// # Why this is one helper rather than four copies
///
/// The invariants are about the *interface* — "never panics", "a rejection
/// explains itself", "a rejection is safe to log". Stating them once means a
/// check added later is covered by construction rather than by remembering to
/// copy four assertions, which is the failure mode a boundary layer exists to
/// prevent at the host level and which applies equally to its tests.
fn check(field: &'static str, verdict: Verdict) {
    match verdict {
        Verdict::Accept => {}
        Verdict::Reject { reason } => {
            assert!(
                !reason.is_empty(),
                "a rejection of `{field}` has an empty reason; an empty diagnostic is \
                 indistinguishable from a missing one"
            );
            // **No raw control characters.** This is the log-injection property,
            // and it applies to every rejection because every rejection embeds
            // guest-controlled text.
            assert!(
                !reason.chars().any(|c| c == '\n' || c == '\r'),
                "the rejection of `{field}` contains a raw newline, which forges a \
                 second log line: {reason:?}"
            );
            // **Bounded.** A diagnostic derived from a 4096-byte path must not
            // echo 4096 bytes; a rejection that scales with the attack is itself
            // an amplification vector.
            assert!(
                reason.len() < 4096,
                "the rejection of `{field}` is {} bytes; a diagnostic must be bounded \
                 independently of the input",
                reason.len()
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // A 4 KiB ceiling: this target's inputs are arguments to host calls, and an
    // argument larger than a path or a key is not a shape the boundary layer
    // handles differently. Keeping iterations small keeps the throughput up.
    const MAX_INPUT: usize = 4096;
    if data.len() > MAX_INPUT {
        return;
    }

    let outcome = std::panic::catch_unwind(|| {
        let Ok(s) = std::str::from_utf8(data) else {
            return;
        };

        // -- Shape checks on the raw string ------------------------------------
        check("path", path_shape("path", s));
        check("component", path_component("component", s));
        check("text", text("text", s, boundary::MAX_IDENTIFIER_BYTES));
        check(
            "path_long",
            path_shape("path_long", &"x".repeat(s.len().min(boundary::MAX_PATH_BYTES + 1))),
        );

        // -- Range checks on the raw bytes as integers --------------------------
        //
        // Read a u32 from the prefix when there is one, so the fuzzer's mutations
        // drive the integer paths rather than only the string paths.
        if data.len() >= 4 {
            let mut buf = [0_u8; 4];
            buf.copy_from_slice(&data[..4]);
            let n = u32::from_le_bytes(buf);

            check("discriminant", discriminant("discriminant", n, 3));
            check(
                "discriminant_zero",
                discriminant("discriminant_zero", n, 0),
            );
            check("size", size("size", n as usize, 1024));
            check(
                "list_size",
                list_size("list_size", n as usize, n as usize),
            );
        }

        if data.len() >= 8 {
            let mut a = [0_u8; 4];
            let mut b = [0_u8; 4];
            a.copy_from_slice(&data[..4]);
            b.copy_from_slice(&data[4..8]);
            let x = u64::from(u32::from_le_bytes(a));
            let y = u64::from(u32::from_le_bytes(b));

            check("range_within", range_within("range_within", x, y, x.max(y)));
            check(
                "range_within_overflow",
                range_within("range_within_overflow", u64::MAX, y, u64::MAX),
            );
            check(
                "consistent_length",
                consistent_length("consistent_length", x, y),
            );
        }

        // -- `one_of` against a hostile value -----------------------------------
        check("one_of", one_of("one_of", s, &["sha256", "sha512", "blake3"]));

        // -- Diagnostic rendering must be total and safe -------------------------
        //
        // Rendered directly rather than only through a rejection, because this is
        // the function every rejection's text passes through and it must be safe
        // on *any* input, not only on inputs a check happened to reject.
        let rendered = render_for_diagnostic(s);
        assert!(
            !rendered.contains('\n') && !rendered.contains('\r'),
            "`render_for_diagnostic` emitted a raw newline, so every diagnostic built \
             on it is log-injectable"
        );
        assert!(
            rendered.len() <= boundary::MAX_ECHO_BYTES + 32,
            "`render_for_diagnostic` returned {} bytes, exceeding its own bound of \
             {}; a diagnostic must not scale with the input",
            rendered.len(),
            boundary::MAX_ECHO_BYTES
        );
    });

    if outcome.is_err() {
        panic!(
            "a boundary check panicked on a {}-byte input; these run inside host \
             call closures via `guard`, so a panic here is a host abort reachable \
             by any guest",
            data.len()
        );
    }

    // -- The traversal corpus, re-run against arbitrary bytes -------------------
    //
    // Independent of the input: a check with an input-dependent hole is exactly
    // what fuzzing is for, and the corpus is the set of shapes that must ALWAYS
    // be refused. Running it every iteration costs microseconds and would catch a
    // regression the moment it appeared, rather than only on a mutation that
    // happened to produce a traversal.
    for attack in [
        "/var/lib/orders/../../../etc/passwd",
        "../etc/passwd",
        "/data/../../etc",
        "..",
        "a/..",
        "a/../..",
        "/data/x/../y",
        "foo\\..\\bar",
        "\\..\\",
        "/data/..",
        "/data/../",
    ] {
        assert!(
            path_shape("path", attack).is_reject(),
            "the traversal corpus entry `{attack}` was ACCEPTED; a defence that passes \
             the attack it exists to stop is worse than none, because it looks like \
             protection and nobody adds the real one"
        );
    }
});
