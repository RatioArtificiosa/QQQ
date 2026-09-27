// SPDX-License-Identifier: Apache-2.0

//! `LANG-001` — the `wasm32-wasip2` build path, **verified end to end**.
//!
//! # Why this test builds the repository's OWN guest
//!
//! Because `LANG-001` says *"verified end to end"*, and the honest end of that path is **a real guest
//! compiled by the real toolchain through the real command**. A scaffolded crate in a temp directory
//! would test the same code and prove less: `examples/orders-api` is the project's own reference
//! application, it carries its own `wit/`, and it is what a reader would point at.
//!
//! # The assertion that matters is the ARTIFACT'S FIRST FOUR BYTES
//!
//! A `cargo build --target wasm32-wasip2` on a crate that has **not** opted into the component model
//! emits a **core module** — and a core module has the same `\0asm` magic as a component. The two are
//! distinguished by the **layer** field that follows: `01 00 00 00` is a core module, and the component
//! model's encoding version is **`0d 00 01 00`**.
//!
//! **So a test that asserted `\0asm` would pass on exactly the failure this item exists to catch** —
//! which is why the assertion is on the whole eight-byte preamble.
//!
//! # Why the build is invoked rather than `plan`ed
//!
//! Because a plan is an **intention**. `build::plan_pure` is already tested for its arguments; what was
//! never tested is that the toolchain **turns those arguments into a component**.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the repository root")
}

/// The eight bytes a **component** starts with, and what a core module starts with instead.
const COMPONENT_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
const CORE_MODULE_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// **`qqqai build` on the reference guest produces a COMPONENT — `LANG-001`.**
///
/// # Ignored by default, and that is not a dodge
///
/// Because it **compiles a guest**, which needs the `wasm32-wasip2` target installed and takes seconds.
/// The repository's own rule is that a test which cannot run everywhere must say so rather than fail
/// everywhere — and the `rust` CI job runs it, on all three platforms. **`--ignored` is how the gate
/// asks for it**, and a skip that is *named* is a skip a reader can find.
///
/// # What `qqqai build` needs installed, and why that made CI red
///
/// **`wasm-tools`.** `build.rs` declares it as a `ToolRequirement` for a rust build, because the build
/// *validates that its own output is a component rather than a core module* — which is the same claim
/// this test makes, one layer down.
///
/// The first version of the CI step that runs this failed on **ubuntu and macos** with
/// `error[QQQ-1003]: missing a tool required for a rust build`, naming `wasm-tools`. The product
/// reported it correctly and with a remediation line; the job simply never installed the tool.
/// `wit` and `reference-app` install it, and `rust` did not.
///
/// **And it passed locally, because this machine happens to have `wasm-tools` 1.259.0.** A green that
/// depends on what is already installed is not a green — the rule is to reproduce the exact command
/// *in the environment CI runs it in*. If you run this test by hand and it fails on `QQQ-1003`, the
/// message is the answer, not the build path.
///
/// # Why `rust` and not `reference-app`
///
/// The `reference-app` job is where the *guest* is built and inspected, and it is the obvious home for
/// this. It is the wrong one: its cargo cache is keyed to `examples/orders-api -> target`, so the host
/// workspace — `wasmtime` included — would rebuild from cold on every run. `rust` has already built
/// `CARGO_BIN_EXE_qqqai` in the step above, at the same profile and feature set, so this costs one guest
/// build per platform instead of one whole workspace.
#[test]
#[ignore = "compiles a guest; runs in the rust CI job on all three platforms"]
fn the_wasm32_wasip2_build_path_produces_a_component() {
    let root = repo_root();
    let guest = root.join("examples").join("orders-api");
    assert!(
        guest.join("qqq.toml").is_file(),
        "the reference guest must exist: {}",
        guest.display()
    );

    // **A separate target directory**, so this build cannot contend with the workspace's own cargo
    // invocation for the package-cache lock.
    let out = guest.join("target").join("qqq");
    let _ = std::fs::remove_dir_all(&out);

    let status = Command::new(env!("CARGO_BIN_EXE_qqqai"))
        .arg("build")
        .current_dir(&guest)
        .output()
        .expect("`qqqai build` must be runnable");
    let stdout = String::from_utf8_lossy(&status.stdout);
    let stderr = String::from_utf8_lossy(&status.stderr);

    assert!(
        status.status.success(),
        "the build must succeed.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("wasm32-wasip2"),
        "and it must say which target it built for: {stdout}"
    );

    // **The artifact, and its preamble.**
    let artifact = out.join("orders-api.component.wasm");
    let bytes = std::fs::read(&artifact)
        .unwrap_or_else(|e| panic!("{} must exist: {e}\nstdout: {stdout}", artifact.display()));

    assert!(
        bytes.len() > 1024,
        "a component is not a stub: {} bytes",
        bytes.len()
    );
    let preamble: [u8; 8] = bytes[..8].try_into().expect("at least eight bytes");
    assert_ne!(
        preamble, CORE_MODULE_PREAMBLE,
        "a CORE MODULE is what a crate that has not opted into the component model produces -- and it \
         has the same `\\0asm` magic, so this is the assertion that distinguishes them"
    );
    assert_eq!(
        preamble, COMPONENT_PREAMBLE,
        "the artifact must be a COMPONENT, not a core module: {preamble:02x?}"
    );
}
