# SPDX-License-Identifier: Apache-2.0

"""Check off checklist items that the implemented code genuinely satisfies.

Every edit is justified by evidence gathered from the source tree, not from
memory. Items that are partially done are annotated rather than checked.
"""

import sys
from pathlib import Path

# `CHECKLIST` is a TRACKED file pinned to `eol=lf` by `.gitattributes`, and `Path.write_text`
# defaults to `newline=None`, which turns every `\n` into `os.linesep` -- `\r\n` on Windows.
# Measured on this platform: `p.write_text("x\ny\n")` writes `b'x\r\ny\r\n'`, while
# `newline=""` writes `b'x\ny\n'`. The result is a file `git status` reports as modified, that
# `git diff` reports with an empty diff, and that `tools/normalize_eol.py` describes as untidy --
# and this tool's whole job is to rewrite that file. `write_text_lf` is the repository's single
# definition of the correct write (`§O-356`).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_xrefs import write_text_lf  # noqa: E402

CHECKLIST = Path("QQQ-Checklist-V1.md")

# id -> (justification comment appended under the item, or None to just tick)
COMPLETE = {
    # -- qqq-cap: 4249 lines across capability/manifest/normalize/resolve -----
    "CAP-001": "`CapabilityKind` in `qqq-cap::capability`, with the three kinds distinguished in resolution.",
    "CAP-002": "`qqq-cap::manifest` — strict parsing, field-named errors, line references.",
    "CAP-003": "`qqq-cap::normalize` — host-pattern expansion and secret-reference resolution.",
    "CAP-004": "`Layer::Developer` with `qqqai run --cap`; narrowing-only, warns when it changes anything.",
    "CAP-005": "`Layer::Organization`, narrowing-only.",
    "CAP-006": "`Layer::Platform`, narrowing-only.",
    "CAP-007": "`GrantSet` with a stable SHA-256 `digest()` over the granted capabilities.",
    "CAP-008": "`qqq-host::build_linker` constructs the linker from `grants` alone.",
    "CAP-009": "`GrantSet::digest()` — the hash that appears in the audit record.",
    "CAP-010": "`no_overlay_can_ever_widen` in `qqq-cap::resolve`: every layer x every mode x every capability.",
    "CAP-012": "`qqqai why` renders the resolution trace with the deciding layer and the fix stanza.",
    "CAP-013": "`BTreeMap`/`BTreeSet` throughout the capability and linker paths; no unordered iteration reaches a guest.",

    # -- qqq-host: 4539 lines ----------------------------------------------
    "HOST-001": "`qqq-host::config::EngineConfig`, with the component model enabled.",
    "HOST-002": "`PreparedComponent::compile` — one compiled component shared across instances.",
    "HOST-003": "`Instance::create` builds a fresh store and instance per acquisition.",
    "HOST-004": "`build_pooling` configures the pool from the manifest; instantiation measured p50 800 ns.",
    "HOST-005": "Epoch deadline set in `Instance::create`; `epoch_tick_interval` derives the tick.",
    "HOST-006": "Fuel budget set before instantiation, so a long `start` cannot escape metering.",
    "HOST-007": "`StoreLimits` built from the manifest and bound via `Store::limiter`.",
    "HOST-008": "`qqq-host::trap` — QQQ-3001/3002/3003 plus the guest-bug codes.",
    "HOST-009": "`Trap` carries the Wasmtime frames and a human message.",
    "HOST-010": "`Instance::run` consumes `self`, so a trapped instance cannot be reused; `poison()` is the second mechanism.",
    "HOST-013": "`aot_cache_key` keys by component digest, target triple and engine config.",
    "HOST-014": "`digest_of` content-addresses an artifact, so one module backs many tenants.",
    "HOST-016": "Host functions registered per interface in `host_clock` and `host_crypto`.",
    "HOST-018": "`EngineConfig::deterministic` — fixed clock, seeded RNG, canonical NaN.",
    "HOST-024": "the four probe assertions from `.scratch/witprobe` are ported to `crates/qqq-host/tests/engine.rs` with control cases: an unsatisfied import fails instantiation and names it, a component with no imports runs, fuel exhaustion traps while the host survives, and an epoch deadline interrupts a spinning guest. The scratch crate is deleted.",

    # -- qqq-run CLI -------------------------------------------------------
    "CLI-001": "`qqq-run::output` — `CommandOutput` with `--json` on every command.",
    "CLI-002": "`CommandName::all()` drives both the dispatch and the schema list; a new command cannot omit a JSON shape.",

    # -- contracts ---------------------------------------------------------
    "CON-002": "`Manifest::parse` produces field-named diagnostics with a line reference.",
    "CON-003": "`qqq-cap::normalize` — host patterns, secret references, path canonicalisation.",
    "CON-013": "`Capability::all()` — the versioned capability-name registry; `qqqai schema` publishes it.",
    "CON-014": "`qqqai inspect <artifact>` compiles the component without instantiating it and reads its import table; `interface_path_for` maps each import to the capability it requires (Observations §O-038).",

    # -- P0 Foundation -----------------------------------------------------
    #
    # Every one of these was genuinely done and showed as 0 of 101, because the
    # Checklist had drifted behind the repository. Each was verified by the probe
    # in `tools/audit_p0.py` before being ticked here, not asserted from memory.
    "FND-001": "`Cargo.toml` declares the workspace, with per-crate tier and Proposal-section comments.",
    "FND-002": "`PRINCIPLES.md` at the repository root, with the operationalization table.",
    "FND-003": "Conventional Commits used throughout; see `git log` and CONTRIBUTING.md §Commit messages.",
    "FND-004": "`.github/workflows/ci.yml` — Rust on ubuntu, macos and windows.",
    "FND-005": "`cargo-deny`, `cargo-machete` and `clippy -D warnings` are all required CI steps, with the `continue-on-error` escape hatches removed now that `deny.toml` exists.",
    "FND-006": "`docs/adr/README.md` — the ADR process and template, pointing at the canonical register in Observations §2 rather than duplicating it.",
    "FND-007": "`.github/PULL_REQUEST_TEMPLATE.md` requires naming which of the eight Non-Negotiables the change touches, with the principle names taken from Proposal §2.",
    "FND-009": "`SECURITY.md` — the reporting channel and the patch-target table by severity.",
    "FND-011": "`.scratch/witprobe` deleted; its four assertions ported to `crates/qqq-host/tests/engine.rs` with control cases (4 tests pass).",

    "DOC-001": "`README.md` at the repository root.",
    "DOC-002": "`QQQ-Proposal-V1.md`.",
    "DOC-003": "`QQQ-Checklist-V1.md`.",
    "DOC-004": "`QQQ-Observations-and-Memories.md`.",
    "DOC-006": "`tools/check_xrefs.py` — checks over the Proposal/Checklist/Observations graph.",
    "DOC-007": "`check_xrefs.py` and `self_test_xrefs.py` are both required steps in the `xrefs` CI job.",
    "DOC-009": "`QQQ-STUB(<ID>)` markers are validated against checklist items by `check_xrefs.py` checks [7] and [11], including the bidirectional case, as a required CI step.",

    "LIC-001": "`LICENSE` — Apache-2.0.",
    "LIC-004": "`LICENSING.md` §1 — the free-entity grant, stated without seat or revenue limits.",
    "LIC-007": "`deny.toml` — the licence allowlist derived from `cargo metadata` over the real tree, with the copyleft branches of OR-expressions deliberately not listed.",
    "LIC-009": "`LICENSING.md` §4 — the plain-language FAQ, including \"can my company use this for free?\".",
    "LIC-010": "CONTRIBUTING.md §Developer Certificate of Origin — DCO v1.1 with `git commit -s`, and why a DCO rather than a CLA.",

    "GOV-001": "`GOVERNANCE.md`.",
    "GOV-002": "`CONTRIBUTING.md` — setup, workflow, standards and the DCO.",
    "GOV-003": "`CODE_OF_CONDUCT.md`, which CONTRIBUTING.md already linked to before it existed.",
    "GOV-006": "`SECURITY.md` — acknowledgement, assessment and patch targets by severity.",

    # -- LANG: the Rust toolchain, and the gate in front of the other four ---------
    #
    # Only Rust. The other four languages stay open behind `TEST-010`, the cross-language
    # conformance suite, because five toolchains built against an unbuilt suite produce five
    # unverifiable claims. That is the whole point of the ordering, so it is stated here
    # rather than left to be inferred from four absences.
    "LANG-001": "`qqqai build` drives `cargo build --target wasm32-wasip2` over `examples/orders-api` and emits `target/qqq/orders-api.component.wasm`. `crates/qqq-run/tests/lang001_rust_guest.rs` asserts the artifact's eight-byte preamble is `0d 00 01 00`, the component-model encoding, and not `01 00 00 00`, a core module — the two share the `\\0asm` magic, so asserting `\\0asm` alone would pass on exactly the failure this item exists to catch. The `rust` CI job runs it on all three platforms via `--ignored`.",
    "LANG-002": "`crates/qqq-run/tests/lang002_bindings.rs` vendors **every** `wit/*.wit` into a probe and builds it with the `wit-bindgen` requirement read from `examples/orders-api/Cargo.toml`; the artifact imports `qqq:crypto/hashing@1.0.0`, which `qqqai inspect --json` maps to the `crypto.hash` capability. It found the pin at `0.44` could **not** bind the canonical tree at all — `invalid character in identifier '2'` at `wit/qqq-crypto.wit:118` (`aes-256-gcm`), a grammar `wit-parser` 0.236.1 refused and 0.259.0 accepts — while `tools/check_wit.py` stayed green because `wasm-tools` bundles the **newer** parser. Bumped to `0.62`; `examples/orders-api` builds and its 57 tests pass on the new pin.",
    "LANG-003": "`crates/qqq-run/tests/lang003_template.rs` scaffolds a project with `qqqai new --template http`, runs the scaffold's **own** CI steps on it (`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`) and asserts through `qqqai build` + `wasm-tools component wit` that the artifact **exports** `qqq:http/incoming-handler@1.0.0`. Measured before: six files, no `wit/` tree, `world root { }` — an empty component that `qqqai serve` could not dispatch to. The scaffold now writes `wit/app.wit` (byte-identical to the canonical world), the vendored `wit/deps/qqq-http/qqq-http.wit` (from `qqq-abi`'s registry), `rust-toolchain.toml` (the repository's channel, `1.98`, held equal by `the_scaffold_pins_the_repositorys_toolchain` — **written, not embedded**, because `include_str!` of the repository's file made `qqq-run` depend at compile time on a path `docker/Dockerfile.prod` does not copy, which turned the `Production image (SEC-029)` job red), `.github/workflows/ci.yml`, a `[capabilities.http] server = true` grant and a `[server] routes` table. Three injections detected: no world, no CI, and the historical defect — a source that compiles but implements no export, which fails the export assertion.",
    "LANG-004": "**The Rust row passes the whole suite, and the runner is what makes that a result rather than a claim.** `conformance/suite.json` now carries **8** cases — 6 `definition` (WIT-surface, each enforced by a checker that runs in BOTH gates) and 2 `execution` — and `crates/qqq-run/tests/conformance_exec.rs` runs the execution half against the reference guest built by `qqqai build` and read by `qqqai inspect --json`. Measured: `cargo test -p qqq-run --all-features --test conformance_exec -- --ignored` **1 passed / 0 failed**, and the same step is wired into the `rust` CI job on all three platforms. Both execution cases were fault-injected and **both** were observed to fail (`2 of the fixture's execution cases failed against the Rust guest`), so the pass is a measurement and not an empty loop. **What this does NOT claim**: the suite's execution half is thin — two cases — and the other four languages are `LANG-012`/`LANG-020`/`LANG-028`/`LANG-036`, not this item. Rust is the row this item is about, and it passes.",
    "LANG-005": "`examples/orders-api` is the **Rust** implementation of the reference application that §2.4 NN-4 requires five times: a real guest component built by `qqqai build`, with the ten §9.1 workloads as routes (`src/router.rs`, `src/orders.rs`, `src/json.rs`, `src/hash.rs`, `src/compute.rs`) and **57** tests, and it passes the conformance suite's execution half (`LANG-004`). **What this round added is the one claim in it that was false.** `qqq.toml` said *\"every stanza below is load-bearing, and a reader can check that claim by deleting one and watching a route fail\"*, and measured: `qqqai caps --json` reported **3 granted** (`clock.monotonic`, `http.server`, `crypto.hash`) while `qqqai inspect --json` reported **1 imported** (`http.server`). `crypto.hash` was declared for a SHA-256 the app implements in-tree (`src/hash.rs`, FIPS 180-4 vectors) and `clock.monotonic` for a clock no workload reads — **an inert grant is an over-grant**, the opposite of the *absent, not denied* model this app exists to demonstrate. Both stanzas are gone and the comment now says why. `crates/qqq-run/tests/lang005_reference_app.rs` asserts the two sets are **equal in both directions** through `qqqai caps --json` and `qqqai inspect --json`; fault-injected by restoring the stanzas, it fails naming `[\"clock.monotonic\", \"crypto.hash\"]`. **The other four implementations are `LANG-013`/`LANG-021`/`LANG-029`/`LANG-037`**, behind `TEST-010`.",

    # -- LANG-008: the guide, and the parenthetical in the item that is FALSE ---------------
    #
    # *"Rust language-guide page published with honest limitations (there are few)."* The page is
    # `docs/languages/rust.md`; the parenthetical is wrong, and the Done line says so rather than
    # repeating it. See the entry below for what "published" is being held to mean.
    "LANG-008": "`docs/languages/rust.md` — the Rust language guide, written to `docs/contributing/claims-policy.md`'s four kinds (Measured with its command, Derived with its mechanism, Intended with a milestone, Absent with what to do instead), indexed in `docs/README.md`, and scanned automatically because `tools/check_doc_claims.py`'s document set is `(\"*.md\", \"docs/**/*.md\", \"crates/*/*.md\")`. It adds **3** claims behind new resolvers (`conformance-cases` / `conformance-definition-cases` / `conformance-execution-cases`, read from `conformance/suite.json`), so `check_doc_claims.py` now checks **9** claims rather than 6, and its `--self-test` still passes. **THE ITEM'S OWN PARENTHETICAL — *\"(there are few)\"* — IS FALSE, and that is the finding.** The guide carries **seven** limitations, every one measured this session rather than recalled: (1) `wit-bindgen 0.44` **cannot bind the canonical `wit/` at all** (`invalid character in identifier '2'` on `aes-256-gcm`); (2) **every `qqqai new` template except `http` produces a component that exports nothing** — measured: `--template worker` builds to `world root { }`, so the build succeeds and the application cannot run; (3) `wit/` is a `wasm-tools` layout rather than a `wit-bindgen` one, so a guest must **vendor** what it binds; (4) a `wit/` edit does **not** re-run the macro, because cargo's fingerprint excludes it; (5) the build-time budget is **not met** (`LANG-007`, 25.34 s against ≤ 20 s); (6) the conformance suite's execution half is thin — the definitions outnumber the executions three to one; (7) **`docs.qqq.codes` does not exist** — no site generator, no workflow, and no `DIST-*` item that creates one. **What \"published\" is held to mean, stated rather than implied:** the page is part of the repository's checked documentation surface — indexed, claim-scanned, and generated into `llms.txt` — and `§11.3`'s `docs.qqq.codes` is a **separate artifact row** in that table, not this item's subject. A live URL is not claimed.",
    # -- LANG-006: recipes for what the host BINDS, and the ones that cannot be written -------
    #
    # `§11.3`'s recipes row names four tasks. **Three of them are recipes for capabilities the host
    # does not bind**, and the page says so instead of omitting them -- a reader who looks for
    # "connect to Postgres" should find out why there is nothing to find.
    "LANG-006": "`docs/recipes/rust.md` — task-oriented Rust recipes, written to `docs/contributing/claims-policy.md`'s four kinds and indexed in `docs/README.md`, in `llms.txt`'s `CURATED` and therefore in `llms-full.txt`. It carries **four recipes for the capabilities the host actually binds** — serve an HTTP request, hash bytes on the host, read a monotonic clock, and run untrusted code with no capabilities — each naming the test that proves it (`lang003_template.rs`, `lang002_bindings.rs`, `lang005_reference_app.rs`). **THE FINDING IS THE ABSENCES.** `§11.3` names four recipes; measured, **three cannot be written today**, because `qqq-host`'s linker registers **4** modules — the WASI baseline plus `host_clock`, `host_crypto` and `host_http` — while `wit/` declares **15** packages. So: **connect to Postgres** needs `qqq:sql`, which is declared and **not bound**, and a guest importing it fails at **instantiation**; **rate limit** has **no implementation** in `qqq-serve` (`[limits]` bounds cost per request, not rate); **stream a large file** is **not expressible**, because `wit/qqq-http.wit` declares only `http` and `incoming-handler` and `handle` returns a single `body: list<u8>`. Each is an **Absent** entry with what to do instead. Two further absences are recorded: the four non-`http` templates are libraries that build to `world root { }`, and `generate_all` makes `monotonic-clock` drag in `wall-clock`, so a monotonic-clock guest must also grant `wall` — the clock a deterministic workload must not have. The page adds **2** claims behind a **new resolver**, `host-bound-modules` (**4**, read textually from `linker.rs` with its limitation stated: it can under-report and cannot over-report), so `check_doc_claims.py` checks **11** claims rather than 9. Every generated Rust path in the recipes was **measured by compiling a probe**, not read off a convention.",
    # -- AGENT-024: the cookbook, and the ten codes nothing can produce ----------------------
    #
    # The item asks for *"a minimal reproducer for every error code"*. Measuring that is what
    # found the answer: **only 5 of the 43 can be reproduced from the command line**, and **10
    # are emitted by nothing at all**.
    "AGENT-024": "`docs/agent-cookbook.md` + `tools/check_agent_cookbook.py`, registered in both gates. The page classifies **every one of the 43 codes** in `docs/errors.md` into four kinds, and the checker **re-derives each classification from the tree** rather than trusting the page: **`cli`** (the reproducer is EXECUTED and must print the code), **`test`** (named under `crates/*/tests/`), **`src`** (raised in a non-test `.rs` and in NO test), and **`unreachable`** (named NOWHERE -- a NEGATIVE predicate, the only way to keep a claim that nothing emits a code from rotting). **THE FINDING IS THE TAXONOMY ITSELF.** Measured: **5** codes are reachable from the command line (`1001`, `2001`, `2002`, `6004`, `7001`), **10** are reproduced only by a test, **18** are raised in `src` with **no test reproducing them**, and **10 are emitted by nothing in the tree** (`2003`, `2006`, `4001`, `4002`, `4005`, `5005`, `5007`, `7002`, `7003`, `7004`). So an agent debugging from a shell will see at most **five** of the forty-three codes it can read about, and `check_error_catalogue.py`\u0027s *\"43 code(s), every one with a cause and a remediation\"* is completeness of DOCUMENTATION, not of BEHAVIOUR. Two codes are emitted for the **wrong class**: an unknown CLI flag reports `QQQ-7001` (`McpArgumentInvalid`) rather than `QQQ-7004` (`CliFlagUnknown`), and `qqqai migrate` reports `QQQ-6004` (`InternalInvariantViolated`) to mean *not implemented*. All three predicates fault-injected, each failing with exactly one problem, with the page and the tool restoring **byte-identical** (sha256 verified)."
,
    # -- TEST-015: a rule that cannot fire is worse than no rule -----------------------------
    #
    # `audit.rs` already records the lesson -- *"a rule that cannot fire is worse than no rule,
    # because it reads as coverage"* -- so this rule is built with a PURE predicate and proved to
    # fire in a unit test, in an injection, AND end to end through the CLI.
    "TEST-015": "`qqq/unused-grant` in `crates/qqq-run/src/audit.rs` -- the sixth audit rule, and the detector the item names: **a capability is granted that the artifact does not import**. It is a **warning**, not an error, and that is a decision: granting ahead of the code is legitimate, so the rule reports only the **inert grant** -- the one nothing can ever exercise -- because the linker is built from the grant set alone and an inert grant is surface the guest should not hold. The reference application takes the stronger position for itself (`LANG-005` asserts grants and imports are **equal in both directions**), which is right for the file a reader is invited to copy; this states the weaker claim that is true for every project. **The predicate and the plumbing are separate functions**, because the predicate has to be provable without a build: `unused_grants_from(granted, required)` is pure and tested directly, and `unused_grants(loaded)` reads the staged artifact `target/qqq/<name>.component.wasm` and returns **nothing** when it is absent rather than guessing from the source -- guessing would be a second opinion about what the build produces, which is the defect `§O-361`/`§O-374` records. **PROVED TO FIRE THREE WAYS.** (1) Unit: an inert grant is reported and a used one is not, with a **silent** case for a correct project, because a rule that fired on correct code would be turned off within a day. (2) Injected: the filter made inert -> the test **FAILS** with `assertion left == right failed: one finding, naming both`, and the restore is **byte-identical** (sha256 `4b8d5058…` before and after, verified against a value recorded beforehand -- `§O-373`). (3) End to end through the rebuilt CLI: a scaffolded `http` project reports **no** `qqq/unused-grant`, and the same project with `[capabilities.clock] wall = true` added reports `[warning] qqq/unused-grant  1 capability(ies) are granted and never imported: clock.wall`. Audit lib tests **31 passed / 0 failed**.",
    # -- TEST: the report formats, which are what make a run consumable ------------
    # The three formats are not three renderings of one thing: `json` is QQQ's **envelope** and the
    # other two are **foreign documents** for tools that cannot read an envelope at all.
    "TEST-003": "`crates/qqq-run/src/test.rs` — `TestFormat` (`human`/`json`/`junit`/`tap`), `to_junit`, `to_tap`, `xml_escape`, `tap_single_line` and `failure_message`; wired in `main.rs` by `--format`, which is a **local** format rather than a variant of `output::Format` because `junit` and `tap` are documents for *other tools* and are written **raw** — a CI reporter handed JUnit XML inside QQQ's JSON envelope parses neither, which is the same reason `qqqai mcp` ignores the formatter. Three decisions carry the item: `--format juint` is a **usage error** rather than a silent fallback to human text (a CI job that collects no artifact must not look like one that succeeded); a nondeterministic test is reported as a **`failure`** in both foreign formats, because neither has a `flaky` concept and reporting `ok` would show a green build for the one thing `--trials` exists to catch, with the divergent trials named in the message; and the exit code is computed by **one** closure shared with the envelope path, so a reporter cannot show green beside a non-zero exit. Measured: 12 new unit tests, lib suite **505 -> 517 passed / 0 failed**; `cargo fmt --all -- --check` and `cargo clippy -p qqq-run --all-targets --all-features -- -D warnings` both exit 0. Two fault injections, each observed to fail its named assertion and pass again after restore (`.scratch/inject_t3.py`, `VERIFIED RESTORED`): (A) `xml_escape` becomes the `.replace('<', ...).replace('&', ...)` chain — the double-escape ordering bug that renders `a<b` as `a&amp;lt;b`; (B) `tap_single_line` becomes the identity, so a name containing a newline emits a second line a harness reads as its own directive. **Both injections compiled**, so neither exit 101 measured a syntax error (`§O-280`).",
}

# Items that are genuinely partial: annotate, never tick.
PARTIAL = {
    "CAP-014": "per-tenant `TenantId` exists and grants are per-instance, but cross-tenant handle leakage is not yet proven by test.",
    "CAP-015": "fuel and duration per execution are reported; capability-use accounting into an audit stream is not built.",
    "CAP-016": "`qqq:secrets` WIT exists and the manifest parses `secrets`; the host interface is not registered.",
    "HOST-011": "the panic hook exists in the trap taxonomy; severity-1 alerting is not built.",
    "HOST-019": "fuel and duration per execution; the acquire-latency histogram and pool occupancy gauge are not built.",
    "CON-001": "the manifest parses and validates, but no JSON Schema document is published.",
    "CON-007": "WIT packages are semver'd `@1.0.0`; the `@since` policy is not enforced.",
    "FND-008": "branch protection is a repository setting, not a file; it is not verifiable from inside the tree.",
    "FND-010": "no release-engineering pipeline yet: versioning, changelog generation and artifact signing hooks are unbuilt.",
    "TEST-016": "the runner **exists and executes**: `crates/qqq-run/tests/conformance_exec.rs` reads `conformance/suite.json`, filters `kind: execution`, and runs each case against the reference guest built by `qqqai build` and read by `qqqai inspect --json` -- wired into the `rust` CI job, with a non-ignored drift guard that fails when the fixture declares an execution case nothing implements. Two cases (`component-layer`, `qqq-imports-all-mapped`), both fault-injected and observed to fail the assertion. **What is not built is the standalone surface**: it is usable through `cargo test --test conformance_exec -- --ignored`, not as `qqqai conformance`, so it is not yet an *independently usable tool* in the sense the item asks for, and it runs the Rust row only.",
    "FND-012": "`wasm-tools` is used by the test fixtures, but no bootstrap script installs it.",
    "LIC-002": "no legal review has been obtained; this is an external action, not a repository artefact.",
    # -- LANG-007: half the budget is met, and the half that is not is the one with a number -----
    #
    # This item is `[~]` rather than `[x]` because *"build-time and binary-size budget met"* is a
    # conjunction and one conjunct is false. Annotating rather than ticking is the honest state, and
    # the two numbers below are what a reader needs in order to check it.
    "LANG-007": "**The binary-size half is MET and the build-time half is NOT, and both are now measured rather than asserted.** §5.1 declared four SLOs and said they were *\"measured in CI on every commit\"* — and nothing measured any of them. Measured from the shipped image: installed footprint **20,201,728 bytes (19.3 MiB)** against ≤ 60 MB, and download size **6,420,492 bytes (6.1 MiB)** gzipped against ≤ 25 MB. Both are now **gates**: the `production-image` job extracts the binary with `docker create` + `docker cp` (the runtime stage is distroless, so there is no tool inside it) and fails when either is exceeded; the step's two failure branches and its anti-vacuity guard were each exercised and each exits 1. `qqqai --version` measures **7.75 ms p50** natively (min 6.68, max 12.72) against ≤ 15 ms, and is **reported rather than gated** because the same command through `docker run` reads 599.8 ms — the container runtime's startup, not the binary's. **The build-time budget is `§9.2`'s ≤ 20 s for 10k LOC Rust, and it is not met**: a cold release build of the reference application takes **25.34 s**, and the application is 2,513 lines rather than 10,000 — four times smaller than the subject the budget names and still 27% over (recorded in full against `PERF-013`). **`qqqai run` cold start (≤ 40 ms) is not measured anywhere**, and §5.1 now says so instead of implying otherwise.",
}


def main() -> int:
    text = CHECKLIST.read_text(encoding="utf-8")
    lines = text.split("\n")
    out: list[str] = []
    ticked = 0
    annotated = 0
    already = 0

    # # Why this iterates with an index rather than over the lines
    #
    # The `PARTIAL` branch needs to look at the line **after** the item, and the defect it
    # guards against was measured: a second run of this tool appended the annotation again, so
    # `FND-008` and `LIC-002` each ended up with two identical `→ Partial:` lines. A tool whose
    # re-run corrupts the file it owns is a tool that cannot be run twice, which is exactly
    # when it gets run (`§O-356`).
    #
    # The `COMPLETE` branch never needed the guard: a ticked item reads `- [x] ` and so cannot
    # match the `- [ ] ` prefix above, which makes it idempotent by construction.
    for index, line in enumerate(lines):
        matched = None
        for item_id in list(COMPLETE) + list(PARTIAL):
            if line.startswith("- [ ] ") and f"**{item_id}**" in line:
                matched = item_id
                break

        if matched and matched in COMPLETE:
            out.append(line.replace("- [ ] ", "- [x] ", 1))
            out.append(f"  → Done: {COMPLETE[matched]}")
            ticked += 1
        elif matched and matched in PARTIAL:
            out.append(line)
            annotation = f"  → Partial: {PARTIAL[matched]}"
            present = index + 1 < len(lines) and lines[index + 1].strip() == annotation.strip()
            if present:
                already += 1
            else:
                out.append(annotation)
                annotated += 1
        else:
            out.append(line)

    write_text_lf(CHECKLIST, "\n".join(out), encoding="utf-8")
    print(f"ticked {ticked}, annotated {annotated}, already present {already}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
