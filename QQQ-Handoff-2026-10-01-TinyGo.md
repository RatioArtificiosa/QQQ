# QQQ handoff — TinyGo canonical ABI and driver scaffolding

Date: 2026-10-01  
Repository: `E:\QQQ`  
Branch at handoff: `main`

## Executive state

The TinyGo failure is root-caused and has a working native-Windows mitigation.
WSL is not a user or runtime prerequisite. The first Windows failure was a
`wit-bindgen-go 0.7.0` harness defect: its embedded WASI WIT reader cannot open
an absolute Windows path through its preopen. The probe now passes the WIT path
as `wit`, relative to the temporary working directory.

After that harness defect was removed, TinyGo 0.42.0 reproduced the real 64 KiB
failure on the repository's Windows host. Precise and conservative GC modes
corrupted the request URL during canonical-ABI lowering; `-gc=leaking` passed
all five vectors. Upstream TinyGo issue `#5742` describes the collector
corruption class. Draft PR `#4897` retains `cabi_realloc` pointers until
`wasmexport` returns, which matches the observed failure mechanism. That PR is
not merged and no released TinyGo version contains it.

QQQ creates a fresh Wasmtime `Store` per request (`GuestApp::serve_one`), so the
`-gc=leaking` allocations are request-scoped and bounded by the existing Store
memory limit. This is a QQQ-specific mitigation, not a general recommendation
for a long-lived reused TinyGo process. The precise/conservative failure must
remain as a negative regression case until upstream fixes the lifetime issue.

Go is intentionally still absent from `qqq_run::build::DRIVEN`; a passing
five-vector probe is not full Go support. Production driver, template, full
bindings, conformance, reference application and standard-Go support remain
open in LANG-017..LANG-024.

## Changes made

1. `tools/run_language_probes.py`
   - Uses `Path('wit')` for native-Windows-safe `wit-bindgen-go` invocation.
   - Builds TinyGo with explicit `-gc=leaking`.
   - Records `wasm-opt --version` in Go tool evidence.
   - Retains the existing five-vector Rust-host execution and source hashing.

2. `conformance/languages/policy.json`
   - Go expectation is now `passed` for the explicit mitigation.
   - The reason preserves the upstream limitation and the fact that production
     support is still a gap.

3. `conformance/languages/install_toolchains.py` and `.github/workflows/ci.yml`
   - Pins and installs Binaryen 133 on Linux CI.
   - Adds its `wasm-opt` directory to the CI PATH.
   - The Windows native toolchain also needs Binaryen 133; WSL is not needed.

4. `crates/qqq-run/src/build.rs` and `src/lib.rs`
   - Adds `ArtifactSpec::{Cargo, File, Unspecified}`.
   - Rust plans declare the existing Cargo locator.
   - Future foreign-language multi-step plans can declare an explicit output
     file and still use one executor path for component validation, atomic
     staging, digesting, reproducibility and AOT output.
   - Go remains undriven; no unsupported language was promoted.

5. `docs/languages/phase3.md`, `QQQ-Checklist-V1.md`,
   `QQQ-Observations-and-Memories.md`
   - Document the exact root cause, upstream references, bounded mitigation,
     native Windows path behavior, Binaryen dependency and remaining support
     boundary.
   - Added observation `§O-499`.
   - LANG-022 evidence now describes the passing mitigation and preserved
     negative reproduction; LANG-023 remains explicitly blocked by upstream and
     time.

6. Generated documentation metadata
   - `llms.txt`, `llms-full.txt`, `docs/stability.md` and
     `tools/corpus_at_rest.json` were refreshed after the durable corpus edits.

## Evidence already run

The following completed successfully on native Windows:

```text
cargo test -p qqq-run --locked
  550 unit tests passed
  30 qqqai binary tests passed
  95 CLI integration tests passed
  remaining qqq-run integration tests passed
  63 doc tests passed

python tools/run_language_probes.py --self-test
python tools/check_language_parity.py --self-test
python -m py_compile tools/run_language_probes.py conformance/languages/install_toolchains.py

python tools/run_language_probes.py --language go
  passed; TinyGo 0.42.0; Go 1.27.1; wit-bindgen-go 0.7.0;
  wasm-opt 133; 5/5 vectors; 64 KiB vector passed

python tools/run_language_probes.py --language assemblyscript
  passed
python tools/run_language_probes.py --language typescript
  passed
```

The complete local parity run was intentionally not claimed: this Windows
machine did not have the native `componentize-py`, WASI SDK Clang, or
`wit-bindgen` executables on PATH, so Python/C/C++ correctly produced missing
tool failures. Missing tools are not language evidence. CI installs those
Linux toolchains and remains the cross-platform matrix authority.

`python tools/sync_docs.py --record` was started after the corpus edits. It
updated the generated metadata, but its recursive checker subprocess was
stopped for handoff after it ran long on this machine. Before the next release,
run and require:

```text
python tools/sync_docs.py --check
python tools/check_doc_claims.py --check
python tools/check_corpus_at_rest.py --check
```

The first observed sync result reported four stale `check_doc_claims` entries;
these may be phase-3 wording claims that need resolver evidence or a narrower
statement. Do not skip that gate.

## Immediate next actions

1. Run the three sync/check commands above and fix any remaining claim or
   corpus-at-rest disagreement.
2. Run the repository Rust gate:

   ```text
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo deny check
   cargo machete
   cargo test --workspace
   cargo test --manifest-path examples/orders-api/Cargo.toml --locked
   ```

3. Run `python tools/check_conformance.py --check`, the language parity
   self-test, `tools/check_gate_parity.py`, Graf refresh/read-only freshness and
   CodeRabbit on the final diff.
4. Allow the GitHub `language-probes` job to produce a fresh Linux Go pass
   artifact before treating the policy transition as cross-platform evidence.
5. Continue the real Go driver slice only after deciding how the driver obtains
   TinyGo's WASI CLI WIT dependencies on every supported host. The plan must
   use canonical `wit/`, relative paths where WASI preopens are involved,
   argument arrays, explicit `ArtifactSpec::File`, atomic validated staging,
   and no WSL dependency.
6. Do not tick LANG-017/018/019/020/021 from this probe alone and do not add Go
   to `DRIVEN` until the acceptance row in `docs/languages/phase3.md` is met.

## Git handoff

No commit or push has been performed yet at the time this handoff was written.
The user explicitly authorized commit and push in the interrupted turn; the
next agent should review the final diff, run the highest-value gates above, then
commit and push `main` to `origin` without rewriting prior history.
