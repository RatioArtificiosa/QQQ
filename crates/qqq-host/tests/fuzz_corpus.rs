// SPDX-License-Identifier: Apache-2.0

//! The host-side regression corpus — `SEC-012`'s always-on half for the loader
//! and the boundary checks.
//!
//! # Why these two surfaces, and not the whole host
//!
//! Because they are the two that receive **attacker-controlled bytes** on a path
//! that runs before a guest does:
//!
//! * `PreparedComponent::compile` hands bytes to Cranelift and the component-model
//!   validator — the largest attack surface QQQ owns, and the front door to §7.1's
//!   first asset (*host process integrity — compromise means total tenant
//!   compromise*).
//! * The `boundary` checks receive every guest-supplied argument at every
//!   host-call crossing, and run inside `func_wrap` closures via `guard` — so a
//!   panic in one is a host abort reachable by any guest.
//!
//! A Wasmtime *validation* bug is not something a QQQ test can find; that is
//! `SEC-014`'s advisory tracking, and it is deliberately not attempted here. What
//! is QQQ's responsibility is the layer around the engine, and that is what this
//! covers.
//!
//! # The relationship to `fuzz/`
//!
//! `fuzz/fuzz_targets/component_load.rs` and `host_interfaces.rs` assert the same
//! invariants with a nightly fuzzer's random exploration. This file asserts them
//! over a **fixed** corpus on stable Rust, in every `cargo test`. The two are
//! complements: this is the fast net that catches a regression on the commit that
//! caused it, and `libfuzzer` is the wide one that finds new shapes overnight.

use qqq_host::boundary::{
    self, consistent_length, discriminant, list_size, one_of, path_component, path_shape,
    range_within, render_for_diagnostic, size, text, Verdict,
};
use qqq_host::PreparedComponent;

/// The engine the host uses, built once.
///
/// # Why the feature set is copied rather than approximated
///
/// A fuzzer or corpus harness configured differently from production explores a
/// different code path, and the difference is never noticed — the harness stays
/// green while the production configuration goes untested.
fn engine() -> &'static wasmtime::Engine {
    use std::sync::OnceLock;
    static ENGINE: OnceLock<wasmtime::Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        cfg.consume_fuel(true);
        cfg.epoch_interruption(true);
        cfg.wasm_multi_memory(true);
        wasmtime::Engine::new(&cfg).expect("the corpus engine must build")
    })
}

/// Byte inputs for the component loader — **all of which must be rejected**.
///
/// # Why these shapes
///
/// Each is a *category of malformed input*, not random noise: the loader's job is
/// to reject, and a corpus of random bytes mostly exercises the length check.
/// These are the shapes that reach the interesting code — a valid header with a
/// corrupt body, a truncated section, an oversized declared length.
///
/// # The one that is NOT here, and why it was removed
///
/// `\x00asm\x0d\x00\x01\x00` — a component header and nothing else — **compiles**,
/// correctly: a component with zero sections is a valid, empty component. It was
/// in this table labelled "component header only" as if it were malformed, and the
/// test caught the mislabelling by reporting that the loader had accepted it. It
/// now lives in [`VALID_COMPONENTS`], where its acceptance is asserted rather than
/// its rejection, and `qqq-host`'s `preload.rs` already used the same bytes as a
/// known-good fixture named `TINY` — so the second use of it is what made the
/// mistake visible.
///
/// **A corpus entry whose expectation is wrong is worse than a missing one**: it
/// either fails for the wrong reason, or — worse — gets "fixed" by loosening the
/// check it was meant to tighten.
pub const COMPONENTS: &[(&str, &[u8])] = &[
    ("empty", b""),
    ("single byte", b"\x00"),
    ("nonsense", b"not a wasm file at all"),
    ("core module magic, no version", b"\x00asm"),
    ("core module magic, truncated version", b"\x00asm\x01"),
    ("core module header only", b"\x00asm\x01\x00\x00\x00"),
    (
        "component header, truncated body",
        b"\x00asm\x0d\x00\x01\x00\x01",
    ),
    ("wrong version", b"\x00asm\xff\xff\xff\xff"),
    (
        "elf file",
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ),
    ("zip file", b"PK\x03\x04\x14\x00\x00\x00\x08\x00"),
    ("nul fill", &[0_u8; 128]),
    ("ff fill", &[0xFF_u8; 128]),
    (
        "magic then nul fill",
        b"\x00asm\x0d\x00\x01\x00\x00\x00\x00\x00\x00\x00",
    ),
];

/// Byte inputs the loader must **accept**, as the control for [`COMPONENTS`].
///
/// # Why a positive control is mandatory here
///
/// Every entry in [`COMPONENTS`] must fail, so a loader that rejected *everything*
/// would satisfy that test completely while making the runtime useless. This is
/// the §O-067 lesson applied to a different check: a defence that passes the
/// attack is bad, and a check that refuses everything is worse, because it looks
/// like it is working.
pub const VALID_COMPONENTS: &[(&str, &[u8])] = &[
    (
        "component header only (a component with zero sections)",
        b"\x00asm\x0d\x00\x01\x00",
    ),
    // A real component, compiled from WAT at test time rather than embedded, so
    // this table stays `const`.
];

/// Assert a `Verdict` is safe to log, whatever it says.
///
/// # Why this is a helper rather than four inline assertions
///
/// The invariants are about the *interface*: never a raw newline, always bounded,
/// always with a reason. Stating them once means a check added later is covered by
/// construction — the same argument that justifies the boundary layer at the host
/// level, applied to its tests.
#[track_caller]
fn assert_verdict_is_loggable(field: &str, verdict: &Verdict) {
    if let Verdict::Reject { reason } = verdict {
        assert!(
            !reason.is_empty(),
            "a rejection of `{field}` has an empty reason; an empty diagnostic is \
             indistinguishable from a missing one"
        );
        assert!(
            !reason.chars().any(|c| c == '\n' || c == '\r'),
            "the rejection of `{field}` contains a raw newline, which forges a second \
             log line: {reason:?}"
        );
        assert!(
            reason.len() < 4096,
            "the rejection of `{field}` is {} bytes; a diagnostic derived from \
             attacker-controlled input must be bounded independently of it",
            reason.len()
        );
    }
}

/// **Every malformed component is a classified error, never an abort.**
#[test]
fn the_component_corpus_fails_cleanly_and_never_panics() {
    let engine = engine();

    for (name, bytes) in COMPONENTS {
        // `AssertUnwindSafe` because `wasmtime::Engine` holds `dyn` trait objects in
        // `Arc`s that are not `UnwindSafe`. That is a *type-system* limitation, not
        // a hazard here: the engine is shared and read-only across iterations, and a
        // panic in the compiler does not leave it in a torn state the way a panic
        // mid-mutation would. The fuzz targets assert the same thing and need the
        // same wrapper.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            PreparedComponent::compile(engine, bytes)
        }));
        let result = outcome.unwrap_or_else(|_| {
            panic!(
                "the component loader PANICKED on the `{name}` input ({} bytes); a \
                 malformed component must be a classified error, never a host abort",
                bytes.len()
            )
        });

        match result {
            Err(err) => {
                // Every rejection must be classified and explained: an error
                // without a code defeats the trap taxonomy, and one without
                // context leaves an operator with nothing to act on.
                assert!(
                    err.code.number() >= 1000,
                    "the `{name}` input produced error code {:?}, which is not a real \
                     QQQ-XXXX code",
                    err.code
                );
                assert!(
                    !err.render().is_empty(),
                    "the `{name}` input was rejected with an empty diagnostic"
                );
            }
            Ok(prepared) => {
                // A valid component is acceptable in this corpus only if the
                // bytes are genuinely valid — none of these are, so reaching here
                // means the loader ACCEPTED something malformed.
                let digest = prepared.digest();
                assert!(
                    !digest.is_empty(),
                    "the `{name}` input compiled but produced an empty digest"
                );
                panic!(
                    "the `{name}` input ({} bytes) COMPILED, but it is not a valid \
                     component. A loader that accepts malformed input is the front \
                     door §7.1 lists first among the assets.",
                    bytes.len()
                );
            }
        }
    }
}

/// **The loader's accepted path is usable — the control for the table above.**
///
/// # Why this is mandatory, and not a nicety
///
/// Every entry in [`COMPONENTS`] must be rejected, so a loader that rejected
/// *everything* would satisfy that test completely while making the runtime
/// useless. This is the §O-067 lesson applied to a different check: a defence that
/// passes the attack is bad, and a check that refuses everything is worse, because
/// it looks like it is working.
///
/// # What the first entry taught
///
/// `\x00asm\x0d\x00\x01\x00` compiles, and it **should** — a component with zero
/// sections is valid. It was originally in the reject table, and this test's
/// failure on it is how the mislabelling surfaced.
#[test]
fn a_valid_component_compiles_and_is_usable() {
    /// A real component that does something.
    ///
    /// Declared at the top of the body rather than beside its use, because an item
    /// declared mid-body reads as though it were scoped to that point when Rust
    /// hoists it to the whole block. It is the same benign component
    /// `hostile_guests.rs` uses, so the fixture is not invented twice — and it is
    /// WAT rather than embedded bytes because a binary component literal is
    /// unreadable and uneditable.
    const BENIGN: &str = r#"
        (component
          (core module $m (func (export "f") (result i32) (i32.const 7)))
          (core instance $i (instantiate $m))
          (func (export "f") (result u32) (canon lift (core func $i "f")))
        )
    "#;

    let engine = engine();

    // 1. The empty component, from the table.
    for (name, bytes) in VALID_COMPONENTS {
        let prepared = PreparedComponent::compile(engine, bytes).unwrap_or_else(|e| {
            panic!(
                "the `{name}` input MUST compile; a loader that refused it would be \
                 rejecting a valid component. Error: {}",
                e.render()
            )
        });
        assert!(
            !prepared.digest().is_empty(),
            "a compiled component needs a digest"
        );
    }

    // 2. A real component, so the control is not satisfied by an empty artifact.
    let prepared = PreparedComponent::compile(engine, BENIGN.as_bytes()).expect(
        "a valid component MUST compile; a loader that refused everything would satisfy \
         the malformed-input test vacuously",
    );
    assert!(!prepared.digest().is_empty());

    // The import listing must be sorted and deduplicated — `qqqai inspect` prints
    // it as a set, so an unordered result would vary between runs.
    let imports = prepared.imported_interfaces(engine);
    let mut sorted = imports.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        imports, sorted,
        "the imported-interface listing is not sorted and deduplicated"
    );
    assert!(
        imports.is_empty(),
        "this fixture imports nothing, so the listing must be empty; a non-empty \
         result means the listing reports something other than imports"
    );
}

/// **Every boundary check is total and loggable on a hostile corpus.**
///
/// # Why the corpus includes valid input
///
/// Because a check that only ever sees attacks is a check whose accept path is
/// untested, and the accept path is what makes the feature usable. Each table
/// below carries both directions for that reason — the same structure
/// `SEC-010`'s traversal corpus established.
#[test]
fn the_boundary_corpus_is_total_and_loggable() {
    /// Strings a guest can send, in every shape that has historically caused
    /// trouble: separators, traversal, control characters, unicode, encoding.
    ///
    /// # Why the oversized case is not in this table
    ///
    /// Because `"A".repeat(10_000)` is not a `const` expression, and a `const`
    /// table is what makes a corpus entry a one-line addition. The oversized input
    /// is built below and prepended, so both properties hold: the table stays
    /// `const`, and the length case is still covered.
    const HOSTILE: &[&str] = &[
        "",
        " ",
        ".",
        "..",
        "../",
        "/",
        "//",
        "\\",
        "\0",
        "\n",
        "\r\n",
        "\t",
        "\u{202e}reversed",
        "a\u{0}b",
        "%2e%2e",
        "..%2f..%2fetc%2fpasswd",
        "/var/lib/orders/../../../etc/passwd",
        "\u{1f600}\u{1f4a9}",
        "'; DROP TABLE users; --",
        "<script>alert(1)</script>",
        "${jndi:ldap://evil}",
    ];

    // The length cases, built at runtime. Both a path-sized and a
    // path-oversized input, because the boundary between them is where an
    // off-by-one would live.
    let oversized_path = "A".repeat(boundary::MAX_PATH_BYTES + 1);
    let at_path_limit = "A".repeat(boundary::MAX_PATH_BYTES);
    let oversized_name = "A".repeat(boundary::MAX_IDENTIFIER_BYTES + 1);

    let mut inputs: Vec<&str> = HOSTILE.to_vec();
    inputs.push(&oversized_path);
    inputs.push(&at_path_limit);
    inputs.push(&oversized_name);

    for input in inputs {
        // Every check, on every input. `assert_verdict_is_loggable` states the
        // interface invariants once, so a check added later is covered.
        for (field, v) in [
            ("path", path_shape("path", input)),
            ("component", path_component("component", input)),
            ("text", text("text", input, boundary::MAX_IDENTIFIER_BYTES)),
            ("path_long", path_shape("path_long", input)),
        ] {
            assert_verdict_is_loggable(field, &v);
        }

        // Rendering must be safe whatever the input, because every diagnostic is
        // built through it.
        let rendered = render_for_diagnostic(input);
        assert!(
            !rendered.contains('\n') && !rendered.contains('\r'),
            "rendering {input:?} emitted a raw newline, so every diagnostic built on \
             it is log-injectable"
        );
        assert!(
            rendered.len() <= boundary::MAX_ECHO_BYTES + 32,
            "rendering {input:?} produced {} bytes, exceeding the bound of {}",
            rendered.len(),
            boundary::MAX_ECHO_BYTES
        );
    }

    // Integer surfaces, at the extremes.
    for n in [0_u32, 1, 2, 3, 4, u32::MAX, u32::MAX - 1] {
        assert_verdict_is_loggable("discriminant", &discriminant("discriminant", n, 3));
        assert_verdict_is_loggable("size", &size("size", n as usize, 1024));
        assert_verdict_is_loggable("list_size", &list_size("list", n as usize, n as usize));
    }
    for n in [0_u64, 1, u64::MAX, u64::MAX - 1, 1 << 63] {
        assert_verdict_is_loggable("range", &range_within("range", n, n, u64::MAX));
        assert_verdict_is_loggable(
            "range_overflow",
            &range_within("range", u64::MAX, n, u64::MAX),
        );
        assert_verdict_is_loggable("consistent", &consistent_length("len", n, n));
        assert_verdict_is_loggable("one_of", &one_of("algorithm", "x", &["sha256"]));
    }
}

/// **The traversal corpus, with its control — `SEC-010`'s property, re-asserted.**
///
/// # Why it is asserted in two places
///
/// Because `SEC-010`'s own test lives in `qqq-cap` (on `path_is_within`) while
/// this boundary check is the `qqq-host`-side re-check. The two are different
/// functions guarding the same traversal class, so a regression in either must be
/// caught — and `§O-067` is the record of what happens when one of them is only
/// defended by its doc comment.
#[test]
fn the_traversal_corpus_is_refused_and_legitimate_paths_are_not() {
    /// Inputs that MUST be refused.
    const ATTACKS: &[&str] = &[
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
    ];

    /// Inputs that MUST be admitted. The control.
    const LEGITIMATE: &[&str] = &[
        "/var/lib/orders/data.csv",
        "orders/data.csv",
        "data.csv",
        "./data.csv",
        "/a/b/c",
        // Components that merely CONTAIN dots. A `contains("..")` check would
        // refuse every one of these, which is what separates a component check
        // from a substring search.
        "/data/..hidden",
        "/data/a..b",
        "/data/...",
        "/data/file.tar..gz",
    ];

    for attack in ATTACKS {
        assert!(
            path_shape("path", attack).is_reject(),
            "`{attack}` was ACCEPTED; a defence that passes the attack it exists to \
             stop is worse than none, because it looks like protection and nobody adds \
             the real one (§O-067)"
        );
    }

    for path in LEGITIMATE {
        assert!(
            path_shape("path", path).is_accept(),
            "the legitimate path `{path}` was REFUSED; a check that refuses everything \
             satisfies every attack assertion above while making every filesystem grant \
             useless"
        );
    }

    assert!(
        ATTACKS.len() >= 10,
        "the attack corpus is too small to be a corpus"
    );
    assert!(
        LEGITIMATE.len() >= 5,
        "the control corpus is too small for the attack assertions to mean anything"
    );
}

/// **`list_size` enforces both axes, on real list shapes.**
///
/// # Why this is not covered by the unit tests in `boundary.rs`
///
/// It is, in terms of the function. What this adds is the corpus *shape*: the two
/// cases that each axis alone misses, stated as inputs rather than as numbers, so
/// a reader can see what the rule is for.
#[test]
fn both_list_axes_are_enforced_on_corpus_shapes() {
    // Many tiny elements: zero payload bytes, ~2.4 GB of `String` headers. A byte
    // ceiling alone accepts this.
    assert!(
        list_size("inputs", boundary::MAX_LIST_ELEMENTS + 1, 1).is_reject(),
        "a list of {}+ empty elements was accepted; a byte ceiling alone cannot see \
         this shape, because its payload is one byte",
        boundary::MAX_LIST_ELEMENTS
    );

    // Few huge elements: three elements, 192 MiB of payload. An element-count
    // ceiling alone accepts this.
    assert!(
        list_size("inputs", 3, boundary::MAX_LIST_BYTES + 1).is_reject(),
        "a 3-element list of {} bytes was accepted; an element ceiling alone cannot \
         see this shape, because its count is three",
        boundary::MAX_LIST_BYTES + 1
    );

    // And a legitimate maximum-sized list is admitted, so the limits are inclusive
    // and a well-behaved guest at the boundary is not refused by an off-by-one.
    assert!(
        list_size(
            "inputs",
            boundary::MAX_LIST_ELEMENTS,
            boundary::MAX_LIST_BYTES
        )
        .is_accept(),
        "a list exactly at both ceilings must be admitted"
    );
}
