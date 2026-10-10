// SPDX-License-Identifier: Apache-2.0

//! F-18 probe. Built with `--release` it uses the SHIPPED overflow semantics.
//!
//! Prints `PANICKED` and exits 0 only if `u64::MAX + 1` panics instead of
//! wrapping. Under a release profile without overflow checks the addition
//! wraps to zero silently: the absence of the panic line IS the failure
//! signal.
//!
//! Run: `cargo run --release -p qqq-host --example overflow_probe`
//!
//! # Why this is an example and not only a test
//!
//! A `#[test]` always runs under the dev profile (which panics on overflow
//! regardless), so no test can observe release arithmetic. Only a release
//! build of a real binary exhibits the shipped semantics.

use std::hint::black_box;

fn main() {
    // Plain `+`, not `wrapping_add`: the profile decides. With
    // overflow checks the process panics (caught below); without them the
    // addition wraps to zero and the probe reports the wrap.
    let result = std::panic::catch_unwind(|| black_box(u64::MAX) + black_box(1));
    match result {
        Err(_) => {
            println!("PANICKED");
        }
        Ok(v) => {
            println!("WRAPPED to {v}");
            std::process::exit(1);
        }
    }
}
