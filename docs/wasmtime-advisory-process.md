# Wasmtime advisory tracking — `SEC-014` / `R-04`

**Status:** active. **Owner:** maintainers (see `GOVERNANCE.md`).
**Patch target:** **72 hours** from a published Wasmtime security advisory to a QQQ
release containing the patched engine.

---

## 1. Why this process exists, and what makes it different from every other dependency

QQQ's security story rests on a single delegation:

> The sandbox is **Wasmtime's**, and QQQ does not reimplement it.

That is the right engineering decision — a second sandbox implementation would be
a second opportunity to get isolation wrong — and it creates a dependency that is
categorically different from the rest. §15's risk register states the consequence:

| ID | Risk | Impact | Response |
|---|---|---|---|
| **R-04** | A Wasm sandbox escape with a CVE | **High** | Track Wasmtime advisories; ship upgrades within 72 h; defence-in-depth layers |

The *impact* is High and the *trigger* is external. Every other risk in the register
is one QQQ chooses how to address; this one arrives as a CVE on somebody else's
schedule, and the only variable QQQ controls is **how fast it ships the fix**.

A slow patch here is not a defect in QQQ's code. It is the moment QQQ's central
security claim becomes false for every deployment running the old engine, and no
amount of capability-model correctness compensates — the guest is out of the
sandbox, and the grants are irrelevant.

**Risk level: Medium likelihood, High impact.** Wasmtime is heavily fuzzed and
widely deployed, so escapes are rare; but it is a large attack surface written in
Rust plus C++ (Cranelift, sanitizer runtimes) plus generated code, and "rare" is
not "never". §7.1 lists the assumption explicitly and treats it as *tracked*
rather than *assumed away*.

---

## 2. What the 72-hour clock measures, precisely

Ambiguity in a target like this is how it becomes unfalsifiable. Stated exactly:

| Event | Clock starts |
|---|---|
| **Start** | The moment a [GitHub Security Advisory](https://github.com/bytecodealliance/wasmtime/security/advisories) is published, **or** a patched release appears in the `wasmtime` crate changelog — whichever is **first** |
| **Stop** | The moment a QQQ release tag exists whose `Cargo.lock` pins a patched `wasmtime` |
| **Excluded** | Time spent waiting for a **patched upstream release to exist at all**. If the advisory is published before the fix, the clock is measured from the patched release |

That exclusion is not a loophole, it is what makes the target meaningful: QQQ
cannot ship an engine patch that upstream has not written. What QQQ **can** do —
and what the rest of this document is about — is everything between "the patched
release exists" and "QQQ users have it". The clock measures exactly that, and
nothing else.

### The escalation rule when no patch exists yet

An advisory with no upstream patch is not a reason to wait. Within **24 hours** of
the start event, one of the following must be true and recorded in the advisory
thread:

1. **A mitigation is shipped.** A configuration change, a feature disable, or a
   version bound. QQQ's defence-in-depth layers (§7.3) are relevant here: the
   capability model, the grant re-check at call time, and the per-instance linker
   already narrow what a sandbox escape buys an attacker, so a mitigation may be
   "the escape requires capability X, and X can be refused".
2. **An explicit accept-risk decision is recorded**, with the reasoning, signed
   off by a maintainer, visible to users in `SECURITY.md`'s advisory feed.

Neither is a substitute for shipping the patch. Both are how users get information
inside the window rather than after it.

---

## 3. Detection: how QQQ learns about an advisory

**A tracking process that depends on someone noticing is not a process.** All four
channels are active, and they are redundant on purpose — an advisory that reaches
one and not another is caught anyway:

| Channel | Mechanism | Latency |
|---|---|---|
| **CI, every build** | `cargo deny check advisories` against the RustSec database, which mirrors Wasmtime's advisories | ≤ 1 commit |
| **Daily, unattended** | A scheduled workflow runs `cargo deny check` on `main` and opens an issue on failure | ≤ 24 h |
| **Upstream watch** | Watching `bytecodealliance/wasmtime` releases and GitHub Security Advisories | ≤ 24 h |
| **Direct report** | Anyone reporting through `SECURITY.md`, including a reporter who saw it upstream first | immediate |

The first two are **automated and do not rely on attention**. That distinction is
the whole design: the third and fourth channels are how a human finds out, and a
human is asleep a third of the time.

### Why `cargo deny` is the primary detector

Because it is **already running on every commit and already blocking** — see
`deny.toml`'s `[advisories]` section and the `supply-chain` job in
`.github/workflows/ci.yml`, both of which are required rather than advisory. The
project learned that lesson the hard way (§O-054, §O-055): a check that only ever
runs in a job nobody reads is a check the author never sees fail.

An advisory in the RustSec database therefore **turns CI red on the next commit**,
which is the earliest possible moment for an automated system to notice.

### The gap in RustSec, stated rather than implied

RustSec is a **third party**. A Wasmtime advisory may take days to reach it, and a
CVE affecting Wasmtime's C++ components (Cranelift, the sanitizer runtimes) may not
be a Rust advisory at all. So:

* `cargo deny` is the **fast, automatic** channel for advisories RustSec knows.
* The **upstream watch** is the channel for everything else, and it is a human step.

**This gap is the reason the process has a human channel at all**, and it is
recorded here rather than left for a reader to discover. A process that claimed
`cargo deny` was sufficient would be quietly wrong for the class of advisory that
matters most.

---

## 4. Response: the steps between detection and release

Each step has an owner-by-role and a deadline **inside** the 72 hours, so the
overall target is composed of steps rather than asserted as a whole.

| # | Step | Deadline | Output |
|---|---|---|---|
| 1 | **Triage.** Determine whether QQQ is affected: which `wasmtime` versions, which features, which of QQQ's enabled feature flags (`wasm_component_model`, `consume_fuel`, `epoch_interruption`, `wasm_multi_memory`, the pooling allocator) | **+4 h** | An issue labelled `security`, stating affected range |
| 2 | **Assess exploitation under QQQ's configuration.** An advisory requiring a feature QQQ does not enable is *not* exploitable here, and saying so precisely is more useful than an alarm | **+8 h** | Exploitability statement |
| 3 | **If not affected:** publish the analysis and close. The clock stops with a *documented negative*, which is a real outcome | **+12 h** | Advisory entry |
| 4 | **If affected:** bump `wasmtime` in `[workspace.dependencies]`, run the full gate set, and confirm the specific advisory no longer reports | **+24 h** | Green CI |
| 5 | **Regenerate the AOT cache expectations.** `ENGINE_VERSION` in `qqq-host/src/config.rs` is pinned alongside the dependency and asserted by a test; a version bump breaks that test on purpose, and the constant must move with it | **+30 h** | Updated constant |
| 6 | **Run the hostile-guest suite and the fuzz corpus** against the new engine. An engine upgrade changes trap classification, and a taxonomy that silently shifted would break every operator's dashboards | **+36 h** | Green suites |
| 7 | **Release.** Version bump, changelog naming the advisory, and a `SECURITY.md` advisory-feed entry | **+72 h** | A tagged release |

### Why steps 5 and 6 exist as named steps rather than being folded into "run CI"

Because they are the two places a Wasmtime upgrade breaks QQQ **without breaking
the build**. `ENGINE_VERSION` is duplicated deliberately so its anti-drift test
fails on a version change; without step 5 the test fails and the obvious response
— relax the test — is exactly wrong. And the trap taxonomy maps Wasmtime's error
kinds to stable `QQQ-XXXX` codes; an engine that reclassifies a trap would leave
every downstream dashboard quietly mislabelled, which is the kind of change no
compiler notices.

---

## 5. What is verified, and how

A process document is worth what its checks are worth. Each of these is a real
mechanism in this repository, not an intention:

| Claim | Mechanism | Where |
|---|---|---|
| Advisories block the build | `cargo deny check` is a required CI step | `.github/workflows/ci.yml` (`supply-chain`) |
| The engine version cannot drift silently | `engine_version_matches_the_pinned_dependency` | `crates/qqq-host/src/config.rs` |
| A new engine is checked against real hostile guests | 200-case hostile-guest suite | `crates/qqq-host/tests/hostile_guests.rs` |
| A new engine is checked against the corpus | regression corpus in every build | `crates/*/tests/fuzz_corpus.rs` |
| Advisories are detected without a human | scheduled `cargo deny` on `main` | `.github/workflows/advisories.yml` |
| The pinned version is recorded | `Cargo.lock` in the repository | root |

### The current pin

`wasmtime = "48"` in `[workspace.dependencies]`, resolved to **48.0.2** by
`Cargo.lock`, and mirrored by `qqq-host::config::ENGINE_VERSION`. The anti-drift
test asserts the constant against the workspace requirement, so an upgrade that
forgets one of the two fails rather than shipping a mislabelled engine.

---

## 6. What this process does NOT cover

Stated so the boundary is visible rather than assumed:

* **Wasmtime bugs with no CVE.** A correctness or soundness bug that upstream
  fixes quietly in a patch release is not an advisory and will reach QQQ through
  ordinary dependency updates. The 72-hour clock does not apply because there is
  no start event.
* **Vulnerabilities in QQQ's *own* code.** Those go through `SECURITY.md`'s
  reporting process, with its own severity-based targets.
* **Vulnerabilities in the guest toolchains** (Rust, TinyGo, AssemblyScript, the
  C toolchain). A compiler bug that produces unsound Wasm is a toolchain
  responsibility. QQQ's validator rejects malformed output, which is a mitigation
  rather than a fix.
* **The transitive C/C++ dependencies** (`zstd-sys`, `ittapi-sys`) except insofar
  as they appear in RustSec or the upstream watch. `cargo deny` covers the Rust
  advisory database; CVE tracking for the C components is a **known gap**, and it
  is named here so it is a known gap rather than an oversight.

---

## 7. Review

This document is reviewed **quarterly** and **after every advisory response**,
whichever comes first, because a process is most usefully revised by the incident
that just exercised it. The review asks three questions:

1. Did detection happen through the channel we expected? If not, why not?
2. Did any step take longer than its deadline? What was the cause?
3. Was there a step the process did not name, that had to be invented mid-incident?

A "no" to question 1 is the most valuable answer available, because it means an
automated channel has a gap — and the last time this project assumed a check was
live without verifying it, the check was not (§O-066, §O-071).
