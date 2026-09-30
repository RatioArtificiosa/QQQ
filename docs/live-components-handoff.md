# Live components: review and operation

Read the [proposal and architecture map](rfc/live-components-and-aot.md) and
[acceptance checklist](live-components-checklist.md) first. The baseline is
`d12ad758d35e807e28ce178f4bb2df28b946d174`.

## What this patch adds

| Surface | Behavior |
|---|---|
| `Registry<T>` | Bounded named generations; reservations; stale-update rejection; removal; leases; revision/list APIs |
| `LiveApp` | Validated HTTP component replacement under the original grants, engine, audit chain and aggregate quota |
| `serve::Prepared.live` | A host-side controller; existing dispatch closures resolve a generation per request |
| `qqqai dev` | Initial build, HTTP listener, watched rebuild, candidate validation and activation; last good version survives failed reload |
| `qqqai build --aot` | Native compilation, content-addressed `.cwasm` plus JSON provenance in `target/qqq/aot/` |
| `--aot-cache PATH` | Explicit Wasmtime cache for `build`, `run` and `serve`; `build` also enables AOT emission |
| HTTP execution | Blocking guest calls leave the socket executor; generation leases own their execution; shared epoch timer bounds guest CPU work |
| Shutdown | Connection tasks are tracked, reaped and given a drain deadline |

The registry is a Rust embedding API. Independently created `GuestApp` families
need dedicated engines: each family owns its epoch clock. Replacements share
that engine and clock through explicit ownership, without a global registry. This patch does **not** expose a remote
installation endpoint, scan arbitrary package directories, implement a runnable
agent WIT world, or migrate persistent guest state. It does not add language
compilers beyond the existing Rust build driver. Compatible components from other
toolchains must implement the existing WIT contract.

## Try the implemented path

Use the repository's Rust 1.98 toolchain, `wasm32-wasip2` target and `wasm-tools`.
From a QQQ project with a valid manifest and HTTP component:

```sh
qqqai dev --host 127.0.0.1 --port 3000
# Edit guest source. Successful rebuilds activate without rebinding the listener.
```

`--once` remains build-only. The initial build must succeed. Unsupported live-dev
options are refused. A manifest edit requires restart and prevents later source
edits from activating under the old policy. It does not silently widen grants.

For native compilation and reuse, select an absolute cache directory owned by the
runtime operator, outside guest-writable paths:

```sh
qqqai build --release --aot --aot-cache /absolute/operator-owned/qqq-cache
qqqai serve --aot-cache /absolute/operator-owned/qqq-cache
```

Without `--aot-cache`, AOT emission still happens, but there is no persistent
execution cache. `run` enables debug information; `serve` does not. Their cache
entries may differ. Wasmtime controls engine/configuration/CPU compatibility;
the JSON fingerprint is diagnostic metadata, not an authorization mechanism.

On Unix, cache ownership and writable ancestors are checked; on Windows the
operator must protect directory ACLs. Cached execution with `fs.write` guests is
refused until path-aware exclusion is available. Missing cache directories are
created; unusable explicit directories cause an error. No ambient Wasmtime cache
configuration is read. Downloaded `.cwasm` is never automatically deserialized.

## Validation performed in the cloud sandbox

Environment: Amazon Linux x86_64, Rust 1.98.1 (repository channel `1.98`),
Wasmtime 48.0.3 from unchanged `Cargo.lock`, Python 3.12.14, wasm-tools 1.259.0.

| Check | Observed result |
|---|---|
| Workspace tests, all features | 2,761 passed, 1 failed, 7 ignored before stopping; workspace doctests not reached |
| Failed workspace test | Existing `qqq-sys` Landlock enforcement case: sandbox kernel reports incompatible access rights; security gate remains failed |
| `qqq-run` all features, including doctests | 780 passed, 5 ignored; subsequent narrow live-component check covers the final dispatch/cache-child test edits |
| Normally ignored `qqq-run` tests | All 5 executed and passed with guest toolchain available |
| Live component integration suite | 8 passed: real calls, wrong ABI, old leases, shared quota, epoch interruption, removal, keep-alive replacement and child-process AOT cache |
| Real CLI development/AOT check | Passed after final runtime changes |
| New fault injections | 4 defects detected by failing assertions; exact bytes restored |
| Existing fault-injection gates | All 8 scripts passed; repository restore verification passed |
| Format, all-target/all-feature Clippy | Passed |
| Dependency/security checks | `cargo deny check` and `cargo machete` passed; unchanged manifests/lockfile |
| API documentation allowance | Passed: 156 doctests; 2,105 remaining undeclared examples within existing allowance |
| Independent CodeRabbit review | Blocked: task review disabled; CLI returned no review findings or review verdict |
| Container check | Blocked: `docker info` cannot reach a daemon; no privileged daemon started |
| Remote CI and other operating systems | Not executed; must pass on the exact reviewed commit before merge |

These counts come from separate commands and must not be added as unique tests.
The later narrow checks reuse unaffected earlier workspace results. Python static,
generated-document and self-test gates are also run locally; the delivery report
records their final outcomes. The docs-index self-test now checks a hypothetical
8 GiB length without allocating 8 GiB; its real-byte and line-ending checks remain.

The patch is **not merge-ready** while the Landlock gate, independent review and
required CI/platform gates are unresolved. No performance SLO has been measured.
The local maintainer must also follow the repository's issue/RFC review process;
new contracts requiring an RFC have a minimum seven-day public review period.

## Review gates

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
python tools/check_live_dev.py
python tools/fault_inject_live_components.py
cargo test -p qqq-run --all-features --locked --test live_components
cargo deny check
cargo machete
```

Run the repository's remaining Python, guest, container and platform CI gates as
declared in `.github/workflows/ci.yml`. The fault injector temporarily changes
source files and restores their exact bytes; run it without concurrent builds.
Its success requires a failing assertion, not a compiler failure.

## Follow-up PR boundaries

1. **This foundation:** validate and merge stateless replacement, lifecycle and
   AOT preparation only after its gates pass.
2. **Package installation:** manifest/version metadata, integrity/signature policy,
   declared capabilities, staging transaction, serialized updates and status API.
   Test partial installs, unauthorized changes, update races and removal.
3. **Persistent agents:** reviewed runnable world; explicit session ownership,
   cancellation and generation pinning. Test streams and long-lived resources.
4. **State migration:** schema negotiation, bounded checkpoint/restore, quiescence,
   writer fencing and rollback before commit. Test failures at every transition.
5. **Trusted native distribution:** only after an approved safety boundary and
   compatibility/provenance policy. Preserve the safe portable-WASM fallback.

WASM isolation, background compilation and reference counting do not guarantee
zero latency, zero leaks or recovery from every host failure. Epochs interrupt
guest code; blocking host imports need separate I/O deadlines. A registry rollback
cannot undo a guest's external side effects. Performance claims need measurements.

## Local agent instruction

Audit the implementation against the proposal, checklist and supplied handbook.
Reproduce each completed check; exercise the executable failure controls. Review
the exact commit and CI results, then fix justified findings. Keep unchecked
roadmap work unchecked. Obtain the normal maintainer and RFC approvals before
merging; this draft is not a release or a claim that persistent agents are complete.
