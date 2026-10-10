// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

//! Emit the target triple this build is for, so `ReplayHeader` can name what it was recorded on.
//!
//! # Why this is a build script and not a `cfg!` or an `env!`
//!
//! Rust does not expose the target triple as a compile-time constant. `cfg!(target_arch)` and
//! `cfg!(target_os)` are available, and combining them yields **`x86_64-windows`** — which is *not* the
//! triple. The real one is **`x86_64-pc-windows-msvc`**, and the difference is the vendor and the ABI.
//!
//! **A wrong triple in a determinism header is worse than a named absence.** `ReplayHeader` exists so that
//! a reader can tell whether two recorded runs are comparable — `docs/determinism.md` states the four
//! inputs and `DET-010` names the target triple as one of them. A field that said `x86_64-windows` would
//! compare equal to a Windows GNU build and unequal to nothing, which is the *opposite* of what it is for.
//!
//! # Why the value is required rather than defaulted
//!
//! `env!("QQQ_TARGET_TRIPLE")` fails the build if this script did not run. That is the intended
//! behaviour: a defaulted triple would silently be wrong on the one platform where it matters, and a
//! compile error names the cause.

fn main() {
    // `TARGET` is set by Cargo for every build script. It is the full triple, not the components.
    // `#[expect]` with a reason: without `TARGET` the script cannot name the
    // triple, and a build script's only failure mode is failing the build —
    // which is exactly what should happen, loudly, with the reason attached.
    #[expect(
        clippy::expect_used,
        reason = "Cargo sets TARGET for every build script"
    )]
    let target = std::env::var("TARGET").expect("Cargo sets TARGET for a build script");
    println!("cargo:rustc-env=QQQ_TARGET_TRIPLE={target}");

    // Re-run only when the target changes, which is never within one build directory.
    println!("cargo:rerun-if-env-changed=TARGET");
}
