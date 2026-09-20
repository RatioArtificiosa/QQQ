#![no_main]
//! Fuzz target: the component loader — `SEC-012`.
//!
//! # Why this is the highest-value target in the programme
//!
//! `PreparedComponent::compile` hands attacker-supplied bytes to **Cranelift and
//! the component-model validator**, which is the largest and most complex
//! attack surface QQQ owns. §7.1 lists host process integrity first among the
//! assets because *"compromise means total tenant compromise"*, and this function
//! is the front door.
//!
//! # The property, and why it is not "does not panic"
//!
//! A Wasmtime validation bug is not something a QQQ test can find — that is
//! `SEC-014`'s advisory tracking, and it is deliberately not attempted here.
//! What **is** QQQ's responsibility, and what this target checks, is the layer
//! around the engine:
//!
//! 1. **No panic.** The engine returns `Err` for invalid input; if a QQQ wrapper
//!    unwrapped, indexed or sliced on the way out, a malformed component becomes
//!    a host abort.
//! 2. **Every failure is classified.** `compile` returns a QQQ error with an
//!    `ErrorCode`, and an unclassified failure would defeat the trap taxonomy the
//!    whole diagnostic surface is built on. A `QQQ-1002` that arrives with no
//!    context is worse than a panic for an operator, because it looks handled.
//! 3. **Accept implies usable.** Whatever `compile` accepts must yield a digest
//!    and must be reportable as its imported interfaces without panicking —
//!    because `qqqai inspect` runs that path before execution, on artifacts a
//!    user has not run yet.
//!
//! # Why the engine is built once, outside the loop
//!
//! Constructing a `wasmtime::Engine` costs milliseconds; fuzzing is measured in
//! thousands of iterations per second. An engine per input would make this target
//! roughly a thousand times less useful while testing exactly the same code.
//! `OnceLock` rather than a `static mut` keeps this sound under libFuzzer's
//! single-threaded model while remaining correct if that ever changes.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use qqq_host::PreparedComponent;

/// The shared engine, built once.
fn engine() -> &'static wasmtime::Engine {
    static ENGINE: OnceLock<wasmtime::Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut cfg = wasmtime::Config::new();
        cfg.wasm_component_model(true);
        // Deliberately the same feature set the host enables. A fuzzer
        // configured differently from production explores a different code path,
        // and the difference would never be noticed.
        cfg.consume_fuel(true);
        cfg.epoch_interruption(true);
        cfg.wasm_multi_memory(true);
        wasmtime::Engine::new(&cfg).expect("the fuzzing engine must build")
    })
}

fuzz_target!(|data: &[u8]| {
    // A 1 MiB ceiling. Compilation is the expensive step, and libFuzzer's value
    // comes from the number of distinct *module shapes* it tries; a multi-megabyte
    // input spends the whole budget on one shape. Components in practice are
    // smaller than this by a wide margin.
    const MAX_INPUT: usize = 1024 * 1024;
    if data.len() > MAX_INPUT {
        return;
    }

    let engine = engine();

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PreparedComponent::compile(engine, data)
    }));

    let Ok(compiled) = outcome else {
        panic!(
            "the component loader panicked on a {}-byte input; a malformed \
             component must be a classified error, never a host abort",
            data.len()
        );
    };

    match compiled {
        Err(err) => {
            // **Every rejection must be classified and explained.** An error with
            // no code would defeat the trap taxonomy; an error with no context
            // would leave an operator with nothing to act on.
            assert!(
                err.code.number() >= 1000,
                "a compile failure produced an out-of-range error code {:?}; every \
                 failure must carry a real QQQ-XXXX code",
                err.code
            );
            // The rendered form must exist and must not itself panic — it is what
            // the CLI prints, and a panic in rendering turns a clean rejection
            // into an abort at the worst possible moment.
            let rendered = err.render();
            assert!(
                !rendered.is_empty(),
                "a compile failure rendered an empty diagnostic; the operator gets \
                 no information about why the component was rejected"
            );
        }
        Ok(prepared) => {
            // **Accept implies usable.** These are the operations `qqqai inspect`
            // performs on an artifact before running it, so a panic here is a
            // panic on the audit surface.
            let digest = prepared.digest();
            assert!(
                !digest.is_empty(),
                "a compiled component has an empty digest; the AOT cache key and \
                 the lockfile both rely on it being a real identifier"
            );
            // The import listing must not panic. Its *content* is not asserted:
            // a component may legitimately import nothing.
            let imports = prepared.imported_interfaces(engine);
            // Sorted-and-deduplicated is the documented contract of the listing,
            // and `qqqai inspect` prints it as a set. An unordered result would
            // make the output vary between runs on the same input.
            let mut sorted = imports.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(
                imports, sorted,
                "the imported-interface listing is not sorted and deduplicated"
            );
        }
    }
});
