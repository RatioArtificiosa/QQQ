# Security Policy

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's private vulnerability reporting on this repository, or email the maintainers directly. If neither is available to you, open a minimal public issue that says only *"I have a security report, please contact me"* with no technical detail, and we will reach out.

Please include:

- A description of the issue and the impact you believe it has
- A minimal reproduction, if you can produce one
- The version, target triple, and platform
- Whether you intend to disclose publicly, and on what timeline

## What we consider a security bug

QQQ's core promise is that **a guest has no authority the manifest did not grant it**. Anything that breaks that promise is a security bug, including:

| Class | Examples |
|---|---|
| **Sandbox escape** | Guest reads or writes host memory; guest executes native code; guest reaches a syscall it was not granted |
| **Capability bypass** | A guest performs an ungranted operation; an overlay widens a declared grant; a pool slot leaks state across tenants |
| **Limit bypass** | Fuel, memory, epoch, or handle limits can be evaded; a guest can cause unbounded host resource consumption |
| **Secret disclosure** | A secret reachable by a guest that was not granted it; `qqq:secrets` disclosing a value instead of using it |
| **Supply chain** | Signature verification bypass; provenance check bypass; lockfile hash collides or is not enforced |
| **Audit integrity** | Audit records can be forged, deleted, or reordered |
| **Host memory safety** | Any unsoundness, UB, or memory-safety issue in the host |

## What is explicitly out of scope

Stated openly so nobody wastes effort (see `QQQ-Proposal-V1.md` §7.2). Each of these
is expanded, with what to do instead, in
[`docs/out-of-scope.md`](docs/out-of-scope.md) — read that before deciding QQQ fits
your threat model.

- **A malicious host administrator.** If you control the host process, you control everything. True of every runtime.
- **Side-channel attacks between tenants** (cache timing, Spectre-class). Wasmtime has mitigations and research continues; QQQ does not currently claim side-channel isolation. If you find a *practical, cross-tenant* side channel we will still want to hear about it.
- **Physical access** to the machine.
- **Volumetric denial of service** beyond what rate limiting and autoscaling can absorb.
- **Bugs in Wasmtime itself.** Report those upstream: <https://github.com/bytecodealliance/wasmtime/security/policy>. Tell us too, and we will ship the patched engine within our 72-hour target.

## Wasmtime advisories: the 72-hour target, and how it is kept

QQQ's sandbox **is** Wasmtime's, so a Wasmtime vulnerability is the one class of
issue that no amount of QQQ-side correctness can mitigate — a guest that escapes
the sandbox is out of it regardless of what its manifest granted.

`R-04` in `QQQ-Proposal-V1.md` §15 commits us to shipping the patched engine
within **72 hours** of a patched upstream release existing. The full process —
what the clock measures, the four detection channels, the per-step deadlines, and
exactly which checks verify each claim — is in
[`docs/wasmtime-advisory-process.md`](docs/wasmtime-advisory-process.md).

The short version:

| | |
|---|---|
| **Detected by** | `cargo deny check advisories` on **every commit** (required CI step) **and** a daily unattended scan that opens an issue |
| **Clock measures** | published patched release → a QQQ release pinning it. Waiting for upstream to *write* a patch is excluded |
| **No patch yet?** | Within 24 h, either a mitigation ships or an accept-risk decision is recorded publicly. An advisory with no patch is not a reason to wait quietly |
| **Verified by** | The engine version is pinned in three places that a test forbids from drifting: `[workspace.dependencies]`, `Cargo.lock`, and `qqq-host::config::ENGINE_VERSION` — including patch-level drift, because the AOT cache key depends on it |

### Known gap, stated rather than implied

`cargo deny` consults the **RustSec** database, which is a third party. An advisory
may take days to reach it, and a CVE in Wasmtime's C++ components (Cranelift, the
sanitizer runtimes) may not be a Rust advisory at all. The daily scan is therefore
the fast *automatic* channel and the upstream watch is a *human* channel, and both
are needed. A process that claimed the automated scan was sufficient would be
quietly wrong for exactly the class of advisory that matters most.

## Our commitments

| Severity | Acknowledgement | Assessment | Patch target |
|---|---|---|---|
| Critical (sandbox escape, RCE) | 24 hours | 72 hours | 7 days from confirmation |
| High (capability or limit bypass) | 48 hours | 5 days | 14 days from confirmation |
| Medium | 5 days | 14 days | Next minor release |
| Low | 10 days | 30 days | Next release |

We will credit you in the advisory unless you prefer otherwise. We will not pursue legal action against good-faith research, and we ask that you give us a reasonable window before public disclosure.

## Supported versions

Pre-1.0, only the latest release receives security fixes. After 1.0, the two most recent minor versions are supported. See the deprecation policy in `GOVERNANCE.md`.
