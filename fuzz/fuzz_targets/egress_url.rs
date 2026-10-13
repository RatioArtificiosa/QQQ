#![no_main]
// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: arbitrary URL strings through the egress vetting — `I-01`.
//!
//! A thin loop over `qqq_fuzz::egress_url::check`, which asserts the two
//! properties that must hold on every input: vetting never panics, and a
//! vetted address is never forbidden. This file owns only the libFuzzer
//! plumbing.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    qqq_fuzz::egress_url::check(data);
});
