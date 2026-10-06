// SPDX-License-Identifier: Apache-2.0

//! F-01 probe. Built with `--release` it uses the SHIPPED panic strategy.
//!
//! Prints `SURVIVED` and exits 0 only if the HOST-011 guard converted a panic
//! into an error. Under `panic = "abort"` the process dies before printing
//! anything: the absence of output IS the failure signal.
//!
//! Run: `cargo run --release -p qqq-host --example panic_probe --features release-panic-probe`
//!
//! # Why this is an example and not only a test
//!
//! Cargo always builds test harnesses with unwinding, regardless of the
//! `[profile.release] panic` setting — so no test can observe the shipped
//! strategy. Ordinary `[[example]]` targets honour it, which is what makes
//! this probe (and not any `#[test]`) the instrument that sees the release
//! build as it ships.
//!
//! Without the `release-panic-probe` feature the probe entry point is not
//! compiled in; the fallback below says so instead of failing to compile,
//! because a default `cargo build` must keep working.

#[cfg(feature = "release-panic-probe")]
fn main() {
    // The same guard wrapper `linker.rs` uses for host functions — never a
    // re-implementation. If the probe passed on a copy, it would prove the
    // copy, which is `§O-125`'s shape exactly.
    if qqq_host::probe_panic_guard() {
        println!("SURVIVED");
    } else {
        println!("GUARD_DID_NOT_CATCH");
        std::process::exit(2);
    }
}

#[cfg(not(feature = "release-panic-probe"))]
fn main() {
    println!(
        "SKIP: rebuild with --features release-panic-probe to probe the shipped panic strategy"
    );
}
