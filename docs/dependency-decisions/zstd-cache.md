# Dependency decision: vendored `wasmtime-internal-cache` 48.0.7 (zstd 0.13 → 0.14)

- **Date:** 2026-10-27
- **Status:** implemented, `cargo deny check` green, cache path exercised
- **Scope:** `E:\QQQ\vendor\wasmtime-internal-cache` + `[patch.crates-io]` in workspace `Cargo.toml`
- **Checklist:** Phase 0 gate work (`cargo deny` red on four zstd advisories)

## The problem

`cargo deny check` failed on four advisories, all reached through
`wasmtime-internal-cache 48.0.7` → `zstd 0.13.3` → `zstd-safe 7.3.0` →
`zstd-sys 2.1.0`:

| Advisory | Fixed by |
|---|---|
| RUSTSEC-2026-0391 (abandoned stream data leaks) | `zstd >= 0.14.3` |
| RUSTSEC-2026-0398 (`Seekable::decompress` Vec length) | `zstd-safe >= 8.2.0` |
| RUSTSEC-2026-0403 (legacy-frame uninit memory) | `zstd-safe >= 8.2.0` |
| RUSTSEC-2026-0410 (wasm32 allocator shim) | `zstd-sys >= 2.1.2` |

## Why not the easy paths

1. **Compatible upgrade: impossible.** `wasmtime-internal-cache 48.0.7` requires
   `zstd "0.13.0"`, which excludes 0.14.x by semver. 48.0.7 is the last 48.x
   release (`cargo info wasmtime`), and `cargo update -p wasmtime-internal-cache`
   resolves nothing newer. A Wasmtime 49/50 bump would violate the engine pin
   the registry builds against and needs a coordinated decision, not a gate fix.
2. **Registry `[patch]` to 0.14.3: rejected by Cargo.** A `[patch.crates-io]`
   entry pointing at the same registry source errors out
   ("patches must point to different sources"); a git-source patch to
   `v0.14.3` resolves but is "not used in the crate graph" because the
   `0.13.0` requirement excludes it. Both attempts are recorded here so nobody
   retries them.
3. **Bump only `zstd-sys`: insufficient.** It would fix RUSTSEC-2026-0410 alone;
   RUSTSEC-2026-0398/0403 need `zstd-safe >= 8.2.0`, which `zstd 0.13.3`
   cannot compile against.
4. **Blanket `deny` ignore: refused.** No written reachability analysis existed,
   and the goal forbids weakening the gate to get green.

## What was done instead: vendor with a one-line requirement change

`vendor/wasmtime-internal-cache` is a byte copy of the crates.io source for
48.0.7 with exactly one functional edit. Provenance is verified, not assumed:
re-extract the upstream source (`cargo vendor --versioned-dirs` into a scratch
dir, or unpack the `.crate` file) and `diff -r` it against `vendor/` — the
only content difference must be the `zstd` requirement line below plus the
absent registry artifacts (`.cargo-ok`, root `Cargo.lock`, `.cargo-checksum.json`
are registry bookkeeping, not upstream sources, and are not vendored):

```diff
- version = "0.13.0"
+ version = "0.14"
```

The workspace `[patch.crates-io]` points `wasmtime-internal-cache` at that
path (same version, different source — the supported vendor flow). Cargo then
resolves `zstd 0.14.3` / `zstd-safe 8.2.0` / `zstd-sys 2.1.2`, i.e. exactly the
fixed versions. The vendored crate uses only `zstd::encode_all`,
`zstd::decode_all`, and `zstd::DEFAULT_COMPRESSION_LEVEL`, all stable across
the 0.13→0.14 boundary — verified by compile, not by reading changelogs.

## Reachability notes (why this is low-risk, not no-risk)

- The cache compresses artifacts the host itself compiled and decompresses
  them from an operator-owned directory (`verify_ownership` refuses foreign
  roots). An attacker needs cache-write access first, at which point the
  game is already over — but the advisories are fixed by version, not by
  this argument. The argument only explains why vendoring (rather than an
  emergency engine migration) was proportionate.
- RUSTSEC-2026-0410 targets the wasm32 allocator shim; no workspace target
  is wasm32. Fixed by version anyway.

## Verification (all committed or reproducible)

- `cargo deny check`: advisories/bans/licenses/sources all ok.
- `cargo check -p wasmtime-internal-cache`: green against zstd 0.14.3.
- Cache path exercised, not just built:
  - `live_components::native_output_is_real_and_cache_survives_engine_recreation`
    (emit → reuse/hit → miss on changed bytes → `.cwasm` refused as source).
  - **New** `live_components::corrupted_cache_falls_back_to_recompile`:
    populates the managed cache, flips bytes in every cache file, and proves
    a fresh engine still compiles instead of loading garbage.
  - `qqq-run` lib `aot::*` unit tests (9 passed).
  - Cache suite run 3× to rule out the teardown race found during development
    (a vanishing cache file between listing and read; the test now skips
    already-gone entries with the reason stated inline).

## Maintenance and exit

- **Re-vendor procedure:** copy the new upstream source over
  `vendor/wasmtime-internal-cache`, re-apply the one-line zstd requirement,
  keep `.cargo-checksum.json` from upstream, re-run `cargo deny check` and
  the cache tests above. Any other diff against upstream must be justified
  in this file.
- **Exit condition:** delete `vendor/` and the `[patch]` block when a
  Wasmtime release compatible with the engine pin requires `zstd >= 0.14`
  natively. Watch each Wasmtime 48+ release for the zstd requirement.
- **Do not** widen the vendor directory into a general patching habit: one
  crate, one line, one reason, all three recorded here.
