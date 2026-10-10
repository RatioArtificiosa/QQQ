#![no_main]
// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: the HTTP/1.1 head parser, differentially against `httparse` — `I-07`.
//!
//! A thin loop over the classification in `qqq_fuzz::diff`, which documents
//! the four arms and is unit-tested there. This file owns only the
//! libFuzzer plumbing: the input ceiling and the abort-on-finding mapping.

use libfuzzer_sys::fuzz_target;
use qqq_fuzz::diff::{Verdict, classify};
use qqq_serve::http1::MAX_HEAD_BYTES;

fuzz_target!(|data: &[u8]| {
    let (verdict, head) = classify(data, MAX_HEAD_BYTES);
    match verdict {
        Verdict::Agree | Verdict::OursRejects => {}
        Verdict::Mismatch(where_) => {
            panic!(
                "differential mismatch ({where_}): {:?}",
                String::from_utf8_lossy(&head),
            );
        }
        Verdict::OursAccepts => {
            panic!(
                "QQQ accepts what httparse rejects: {:?}",
                String::from_utf8_lossy(&head),
            );
        }
    }
});
