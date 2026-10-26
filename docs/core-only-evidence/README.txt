# RT-CORE-004 evidence index

Measured 2026-10-26 on E:\QQQ @ 4397689 plus the uncommitted core-only
change (Cargo.toml [features], store.rs + signature.rs gating).
Committed with the RT-CORE-001..004 unit; reviewed by Copilot with no blockers.

1. red-unknown-feature.log — pre-change wasm build fails: the package has no
   `core-only` feature (exit 101). The gate the feature must pass.
2. red-missing-target.log — mid-gating env red: the pinned 1.98 toolchain
   lacked the wasm32-unknown-unknown target (E0463); fixed with
   `rustup target add` (recorded for the CI step). Same run: no-default
   host tests green (107 passed), proving the pure suite stands alone.
3. core-only-build.log — wasm build GREEN after gating (exit 0);
   ed25519-dalek, sha2, toml, serde all compile for the target, no
   getrandom involvement.
4. core-only-imports.log — import-section verdict on a rooted cdylib probe:
   0 imports (no wasi_snapshot_preview1, no env imports) on a 9 MB artifact
   exporting qqq_probe; plus the deliberate std::fs::read probe proving
   fs calls link to static always-failing shims with no host surface.
   Conclusion: the import scan proves no ambient capability is reachable;
   the #[cfg(feature = "fs")] gates are what keep fs calls out of shipped
   code so misuse fails at compile time instead of becoming runtime traps.
5. core-only-tree.log — normal dependency graph for the wasm target:
   no getrandom, no tokio/hyper, no fs-pulling crates beyond std itself.
6. core-only-tests.log — default suite green (119 passed + 1 doctest);
   no-default suite green with pure tests only (107 passed + 1 doctest).
