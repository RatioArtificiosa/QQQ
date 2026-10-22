# WASI 0.3.2 post-migration measurement report (Phase 7B)

Runtime-side return of `§6.12 Post-migration measurement report` from
`QQQ-REGISTRY-RUNTIME-WASI-PROPOSAL.md` (registry proposal v1.6, table at
lines 526-555). The registry tree is read-only from this goal, so the table
is returned here and the registry coder copies it over (pending handoff).
Every field carries a measured value or the explicit mark **UNVERIFIED** —
never a guess.

- Date measured: 2026-10-21 (toolchain matrix, serve, run) and 2026-10-22
  (t5 re-probe, pins, conformance, claims).
- Commit measured: `2870b90` (`wasi: retire-or-keep the 0.2 linker path
  (HOST-027)`), tree clean — confirmed on both dates: the Linux bridge
  banner records `commit 2870b90 (tree clean)` on 10-21 and `git status`
  is clean at the same HEAD on 10-22.
- PR: none — direct push to `main` per repo workflow; CI verdict per pushed
  SHA (`gh run view`), never `git ls-remote`.
- Evidence: 20 transcripts cited below live in `docs/wasi-032-evidence/`
  (committed with this report), not in temp scratch. The two full-size
  Linux logs are excerpted (banner + verdict); the excerpts name their
  source and size.

## §6.12 table

| Field | Value |
|---|---|
| Date / commit / PR | 2026-10-21/22, `2870b90`, no PR (direct push, CI per SHA) |
| `wasmtime` version | `48.0.7` — `Cargo.lock:2649-2650` (`name = "wasmtime"`, `version = "48.0.7"`); `ENGINE_VERSION = "48.0.7"` (`crates/qqq-host/src/config.rs:556`); anti-drift test `engine_version_matches_the_pinned_dependency` fails the build on drift |
| `wasmtime-wasi` version | `48.0.7` — `Cargo.lock:2885-2886`; workspace enables `features = ["p2"]` only (`Cargo.toml:133`) |
| `implements` supported? | NO — blocked, measured. `wit-parser 0.254.2` keyword table (`ast/lex.rs`, vendored sources) has `map` but no `implements`; `wasmtime-wasi 48.0.7` `src/p3` tree is 0.3.0-level (no `implements`, no `map<`). Commands: `Select-String` over vendored `lex.rs` + `get-childitem -recurse` over `src/p3` (HOST-026 tick, 2026-10-22). Consequence: the 0.3 path serves sync 0.3.0 shapes only; async names (`wait-until`/`wait-for`) trap by name, never silently. Tripwire test `served_03_needs_no_031_features` fails the build if the vendored WIT ever gains either keyword. |
| `map<K,V>` supported? | NO — blocked, measured (same commands as above). Same consequence and same tripwire. |
| Rust: target / component / 0.3 imports / exec | BLOCKED — no retargeting. Per-toolchain probe 2026-10-22 (`docs/wasi-032-evidence/rustup-targets-per-toolchain.log`; active-toolchain listing in `docs/wasi-032-evidence/rustup-targets-active-toolchain.log`, active toolchain `stable`, `rustc 1.99.1`): `stable` has `wasm32-unknown-unknown` + `wasm32-wasip2`; `1.98` has `wasm32-wasip2`; `nightly`/`1.85.0`/`1.97.1` have hosts only. NO `wasm32-wasip3` target on any installed toolchain (LANG-041; the 2026-10-21 matrix in `docs/languages/phase3.md` reads the same verdict, re-probe narrative in `docs/wasi-032-evidence/toolchain-matrix-reprobe-2026-10-22.log`). No 0.3 component producible; 0.2 path unchanged. Execution conformance is the 0.2 suite, green in every gate (`conformance_exec` incl. `--ignored`, `run_language_probes`, `run_conformance`). |
| Go / TinyGo: same | BLOCKED — `tinygo`: not installed (`go 1.27.0` present); repo pins `wit-bindgen-go 0.7.0` + Binaryen 133 (wasip2-era, no 0.3 emission path evidenced). Owner upstream TinyGo (LANG-042). Nothing faked. |
| Python: same | BLOCKED — `import componentize_py`: `ModuleNotFoundError` (CPython 3.13.2 present); repo pins `componentize-py 0.25.1` (wasip2 output). Owner upstream (LANG-043). |
| C / C++: same | BLOCKED — `clang`/`wasm-ld`: not installed; repo pins WASI SDK 34 Clang (wasip2 sysroot) + `wit-bindgen 0.62.0`. Owner upstream WASI SDK sysroot with 0.3 support (LANG-044). |
| TypeScript / AssemblyScript: same | BLOCKED — `asc`: not installed (`node v22.22.0`, `tsc 5.9.3` present); repo pins `ComponentizeJS 0.23.0` (wasip2 output). Owner upstream (LANG-045). AssemblyScript stays labelled TypeScript-like, never full TypeScript. |
| `qqqai run` on `examples/orders-api` (a `std` guest) | REFUSES, pre-existing, not a migration regression (§O-782): `error[QQQ-6003]: the component imports 14 interfaces that no grant provides` — `wasi:cli/*@0.2.9` (11), `wasi:clocks/monotonic-clock@0.2.9`, `wasi:io/*@0.2.9` (3); granted: `qqq:http/http@1.0.0`; project: `orders-api`. Exact transcript: `docs/wasi-032-evidence/orders-api-run-refusal.log`. |
| `qqqai serve` on `examples/orders-api` (a `std` guest) | MEASURED working (2026-10-21, `docs/wasi-032-evidence/orders-api-serve.log`): `listening on 127.0.0.1:3000`; `GET /` → 404 (x2); `GET /orders` → 200 (x3); `GET /healthz` → 200 (`ok`). Server stopped after measurement. |
| A 0.2 component still instantiates? | YES. `guest02: ran in 28 µs` (`docs/wasi-032-evidence/wasi02-guest-runs.log`); `a_v02_guest_instantiates_and_runs_on_the_retained_path` green; full 0.2 conformance suite green in every gate on this tree (`cargo xtask ci` GATE GREEN 146). |
| `abi.host` decision | UNCHANGED (ABI-018). The migration adds a host-side 0.3 path but changes no `qqq:` interface, proven by `qqq_interface_surface_is_pinned_for_the_abi_host_decision` (exact 13-name pin). Registry examples stay `>=0.2,<0.4` (D-WASI-3, verified not edited here). Client refusal: `check_host_requirement` admits 0.2/0.3, refuses 0.1/0.4+/1.0 with `QQQ-5004`. |
| Conformance execution cases passed | 4/4 (`conformance_exec::every_execution_case_passes ... ok`, incl. `--ignored`: `docs/wasi-032-evidence/conformance-exec-rust.log`): `component-layer`, `qqq-imports-all-mapped`, `dual-abi-03-clock-required`, `dual-abi-03-unserved-reported`. Definitions 6/6 (`check_conformance.py` matrix green, self-test 12/12 injections caught). |
| Checklist items updated | HOST-025, HOST-026, HOST-027, LANG-041, LANG-042, LANG-043, LANG-044, LANG-045, ABI-017, ABI-018, CON-019, TEST-020 — all ticked with `→ Done:` / `→ Measured:` lines. |
| README / Proposal claims changed | `README.md:212-213` (Wasmtime 48.0.7, 6 modules D-WASI-4 wording); `QQQ-Proposal-V1.md` glossary WASI entry + correction A-4 + evidence B-5/B-6; `docs/languages/phase3.md` §WASI-0.3 verdicts (all BLOCKED, 2026-10-21) + t5 re-probe note; `docs/languages/rust.md`, `docs/recipes/rust.md`. |
| Any regression | None from the migration. Three observations, all dispositioned: (1) graf MCP hang under load made one gate red — same-SHA rerun GREEN, flake with mechanism recorded (§O-543 rule followed); (2) fixture CRLF scare after fault/restore scripts — `git diff` byte-identical, restored to HEAD; (3) `orders-api` run refusal is pre-existing behaviour (§O-782), the 0.3-aware pre-flight did not change the 0.2 outcome. |

## 0.3 guest probes (launch evidence, Windows)

- `qqqai inspect` on the committed 0.3 fixture: `REQUIRED:
  [{"interface": "wasi:clocks/monotonic-clock@0.3.2", "name":
  "clock.monotonic"}]`, `UNMAPPED: []`
  (`docs/wasi-032-evidence/wasi03-inspect.log`).
  The 0.3 clock resolves to a named capability the developer can grant —
  never reinterpreted onto 0.2.
- Ungranted 0.3 clock run refuses closed: `error[QQQ-6003]` naming
  `wasi:clocks/monotonic-clock@0.3.2`, capability `clock.monotonic`, with the
  `qqq.toml` snippet to grant it
  (`docs/wasi-032-evidence/wasi03-ungranted-clock-refusal.log`).
- Unserved 0.3 import refuses closed: `error[QQQ-6003]` naming
  `wasi:http/incoming-handler@0.3.2` with empty grants
  (`docs/wasi-032-evidence/wasi03-unserved-import-refusal.log`) — reported,
  never claimed, never dropped.
- `qqqai why` on an unmodelled namespace names its state
  (`sql.query DENIED (default: not granted by any layer)` + stanza;
  `docs/wasi-032-evidence/why-unmodelled-stanza.log`,
  `Manifest::parse`-shaped stanza); CLI suite pins the
  grant/denial/typo/layer stanzas
  (`why_exit_status_separates_a_grant_from_a_denial`,
  `why_prints_the_stanza_for_a_denied_capability`,
  `why_suggests_a_correction_for_a_typo`,
  `why_names_the_deciding_layer_for_a_grant`).
- Linux repeats both: `why crypto.hash` → `GRANTED by manifest` (exit 0);
  `why sql.query` → `DENIED (default: not granted by any layer)` + stanza
  (exit 1), byte-identical shape to the Windows capture
  (`docs/wasi-032-evidence/linux-why-stanzas.log`).

## Rules compliance

- No toolchain output was faked: every language verdict is BLOCKED with an
  owner and a re-measure tripwire (D-WASI-8). The 0.3 guests are committed WAT
  fixtures (`conformance/fixtures/wasi03-clock.{wat,component.wasm}`),
  preamble asserted `0d 00 01 00` by the fixture pin test — never `01 00 00 00`.
- `abi.host` was not bumped because WASI moved (D-WASI-3) — the no-bump is
  proven by the 13-name surface pin, not asserted.
- 0.2 path retained with grant parity; deleting it fails 12+ dual-ABI tests.
  Retirement needs both tripwires (determinism trials green on 0.3 +
  registry range narrowing that strands nothing); neither is met, so no date
  is named (HOST-027).
- Linux bridge `test` on the pre-report commit (`2870b90`, tree clean): `All
  Linux gates passed`
  (`docs/wasi-032-evidence/linux-bridge-test-verdict-excerpt.log`, banner +
  verdict; per-run stats in
  `docs/wasi-032-evidence/linux-bridge-stats.log`). Re-run on the final
  tree (`4c14a09`, tree clean): `All Linux gates passed`, exit 0
  (`docs/wasi-032-evidence/linux-bridge-test2-verdict-excerpt.log`;
  per-run stats in
  `docs/wasi-032-evidence/linux-bridge-test2-stats.log`).
- Bridge `checks` on the final tree: every phase green except one
  transient `test FAILED (39s)` on a cold post-reboot mount — too fast
  for the suite, with the identical phase green in the Windows gate on
  the same tree. Dispositioned environmental by two same-tree Linux
  green re-runs (direct captured `cargo test --workspace`, then the
  `test` leg above); full phase log committed as
  `docs/wasi-032-evidence/linux-bridge-checks.log`, stats (with the
  outage timestamp gap) in
  `docs/wasi-032-evidence/linux-bridge-checks-stats.log` (§O-786).
- Bridge `test-linux` on the final tree (`4c14a09`, tree clean):
  `Linux-only tests passed`, exit True
  (`docs/wasi-032-evidence/linux-bridge-testlinux-verdict-excerpt.log`;
  per-run stats in
  `docs/wasi-032-evidence/linux-bridge-testlinux-stats.log`).
- Resource normality (all legs, 8 GiB compose limit): `test` leg peaks
  ~287% CPU / 3.7 GiB (`linux-bridge-stats.log` — the `jolly_black`
  rows are an unrelated container on the shared daemon, different
  31.31 GiB limit); `checks` cold-mount phases run long (`check_xrefs`
  1320s, `sync_docs` 1330s, xrefs self-test 3051s;
  `linux-bridge-checks.log`) then settle; cached re-runs idle near 0%
  (`linux-bridge-test2-stats.log`, `linux-bridge-testlinux-stats.log`;
  the outage timestamp gap sits in `linux-bridge-checks-stats.log`).
  No leg exceeded 4 GiB, no OOM, no throttling — NORMAL against the
  prior bridges' comparison set (compile bursts, test plateaus, same
  ceiling).
- Registry handoff: PENDING — the registry tree is read-only from this goal;
  the registry coder copies §6.12 from this file.
