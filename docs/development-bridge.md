# The development bridge — verifying Linux from Windows

**Status:** active. **Entry point:** `pwsh tools/qqqdev.ps1`.
**Scope:** development infrastructure. The **runtime never knows Docker exists** —
nothing in `qqq-core`, `qqq-cap`, `qqq-host`, `qqq-abi`, `qqq-io`, `qqq-serve`,
`qqq-run`, `qqq-pkg`, `qqq-debug` or `qqq-sys` refers to this. That boundary is
deliberate and is checked by `tools/check_topology.py`.

---

## 1. Why this exists: four verification gaps, not a general wish for Docker

The idea came from a review conversation about "backing up the repo to Linux in
Docker". The useful reframing it contains is: **build a cross-platform
development and verification bridge, not a backup**. Taken to *this* repository, it
closes four gaps that are specific, measurable, and were each hit during
development:

| Gap | Evidence | What the bridge changes |
|---|---|---|
| **Linux-only code is unverifiable locally** | `SEC-019`'s seccomp filter, uid-0 refusal and `no_new_privs` call are `#[cfg(target_os = "linux")]`. Injecting a defect into each produced `NOT CAUGHT` on Windows — and the injection harness had to report `PLATFORM: not exercised here`. | Those three guards execute on every `qqqdev inject` run |
| **The fuzzer cannot run on Windows** | `cargo-fuzz` builds the targets but the binary dies at startup with `0xC0000135 STATUS_DLL_NOT_FOUND` — a missing libFuzzer runtime DLL, a `libfuzzer-sys` limitation, confirmed by running the built executable directly | `qqqdev fuzz` runs them with AddressSanitizer |
| **Fault injections are platform-gated** | `tools/inject_harden2.py` reported `PLATFORM` for 3 of 4 cases | All injections run where they can fire |
| **A stale build can look like a real defect** | Three recorded occurrences (`§O-070`, `§O-072`, `§O-077`): a restored file appeared broken because the incremental cache lagged the filesystem | A clean-room container has no cache to go stale — a second opinion on any suspicious result |

**What this is not.** It is not a backup system (Git is the backup, and a filesystem
copy is a worse one), not a CI replacement (CI runs three platforms; this runs
one), and not part of the product.

---

## 2. The one-way rule, and why it is enforced in code

> **Source flows host → container. Results flow container → host. Nothing else
> crosses.**

This is the load-bearing rule, and the review conversation is right that the naive
alternative is dangerous. Two failure modes, both real for this repository:

**`Cargo.lock` ping-pong.** The repo has two lockfiles (`Cargo.lock` and
`fuzz/Cargo.lock`). If both platforms may write, a Linux run that resolves a
dependency differently rewrites the file, a Windows run rewrites it back, and the
diff churns without anyone deciding anything.

**17 GB of artifact contamination.** Measured on the development machine:

```text
target/        12,500 MB    ← Windows artifacts
fuzz/target/    4,544 MB    ← Windows artifacts
```

A bind mount exposes both. If cargo inside the container wrote to
`/workspace/target`, it would produce Linux `.rlib` files among the Windows ones,
and the next Windows build would fail with a linker error that looks nothing like
its cause.

**Therefore the enforcement is structural, in three places:**

1. **Build output goes to named volumes**, never to a bind-mounted path:
   `CARGO_TARGET_DIR=/linux-target` and `/linux-fuzz-target` (the latter in the
   entrypoint, because `fuzz/` is a separate cargo workspace and inherits nothing).
   A named volume is not visible to the host at all, so contamination is
   impossible rather than discouraged.
2. **A source guard** in `docker/entrypoint.sh` hashes every tracked file before
   and after a command. A command that changes one **fails with exit 3 and names
   the files**. It exists because a rule that lives only in documentation holds
   until someone adds a command that writes.
3. **The container is not privileged and publishes no ports.** It reaches
   crates.io and nothing else.

### Why the mount is not `:ro`

`docker/compose.yaml` mounts `/workspace` read-write, which is the obvious thing
to "fix". It is deliberate:

* `cargo` must write `Cargo.lock` when a dependency changes — refusing that makes
  the environment unable to do the work it exists for.
* `qqqdev inject` mutates source on purpose, then restores it byte-for-byte.

So the guard is the enforcement, not the mount flag. The trade is recorded in the
compose file so a future reader does not undo it without knowing why.

### Why the guard is *proven* rather than trusted

A guard that has never been observed firing is a guard assumed to work, and this
project has been burned by that exact shape five times (`§O-066`, `§O-069`,
`§O-071`, `§O-076`, `§O-085`). So the one-way rule is not trusted because the code
looks right: `qqqdev guard-prove` appends to a tracked file through the real
`source_guard_begin` / `source_guard_end` pair, asserts **exit 3**, and then
re-hashes every tracked file to prove the tree was restored.

That command also found a defect in itself (`§O-087`): the entrypoint is `COPY`ed
into the image at build time, so the first version verified the guard by running a
**stale copy** of it. The entrypoint is now bind-mounted over the image's copy —
onto `/usr/local/bin/qqq-entrypoint`, the path `ENTRYPOINT` actually names. The
first attempt at that mount targeted `/usr/local/bin/entrypoint.sh`, a path nothing
executes, and was silently inert.

**Therefore:** if `docker/Dockerfile`'s `ENTRYPOINT` path ever changes, the compose
mount target must change with it, or the bridge will quietly run baked-in logic
again. Rebuilds are needed for toolchains; they are never needed for control flow.

---

## 3. The commands

| Command | What it does | Typical use |
|---|---|---|
| `qqqdev status` | Environment contents and provenance | First run; debugging the environment |
| `qqqdev test` | `fmt --check`, `clippy -D warnings`, `cargo test --workspace`, on Linux | Before pushing, to match CI's Linux leg |
| `qqqdev test-linux` | The tests that only execute on Linux, run loudly | After touching `qqq-sys` or any `cfg(target_os)` code |
| `qqqdev checks` | The eight Python checkers, including the `unsafe` audit and its self-test | After editing the documents or tools |
| `qqqdev inject` | Injects real defects into three security guards and proves each is caught | After changing a guard — the only way to know its test still reaches it |
| `qqqdev guard-prove` | Makes the source guard fire on purpose and asserts exit 3, then verifies the tree was restored | Whenever `entrypoint.sh`'s guard changes — an unexercised guard is an assumed guard |
| `qqqdev fuzz [secs] [targets…]` | Runs the fuzz targets with ASan, corpus persisted in a volume | Overnight, or before a release |
| `qqqdev matrix` | Windows and Linux together, as one table | The "is this done?" command |
| `qqqdev build` | Rebuilds the image after a Dockerfile change | Rarely |
| `qqqdev shell` | An interactive shell | Diagnosing a failure the output does not explain |
| `qqqdev clean` | Removes the Linux volumes | Reclaiming disk; costs a re-download and the fuzz corpus |

### Why `run --rm` and not `up`

Every command is a short-lived batch job whose **exit code is the answer**. `up`
with a long-running service would need `exec` to do anything and would leave a
container alive holding a bind mount — so a developer who forgot to stop it would
have a process silently watching their source tree. `run --rm` starts, executes,
and disappears.

### Why not Compose Watch

The review suggests Compose Watch, and it would be the right tool for a
long-running dev container whose source changes must propagate continuously. Every
need here is the opposite: a **one-shot batch job** whose synchronous result is
wanted. Compose Watch would add a daemon, an ignore-file to maintain, and an
asynchronous model where "the test ran before the sync finished" is a possible
outcome. Bind mount plus one-shot container has no daemon, no ignore semantics,
and returns an exit code.

---

## 4. Provenance: every result says what produced it

A test result without provenance is an anecdote, and this project has three
recorded cases of a result being believed without checking what produced it. So
`docker/entrypoint.sh` writes `/results/provenance.env` before every command:

```text
QQQ_COMMIT=<short sha>
QQQ_TREE=clean|DIRTY
QQQ_CHANGED_FILES=<n>
QQQ_RUSTC=rustc 1.97.x
QQQ_NIGHTLY=rustc 1.9x.x-nightly
QQQ_PLATFORM=x86_64-linux
QQQ_GENERATED_AT=<utc>
```

**A dirty tree is reported, not refused.** Testing work in progress is the point —
but a green result against a dirty tree does not describe any commit, and saying so
is what keeps the result honest.

`git config --global --add safe.directory` is set inside the container because the
bind mount is owned by a Windows uid the container cannot match; without it `git`
refuses to read the tree and the provenance would be empty.

---

## 5. What is pinned, and why

| Component | Pin | Why |
|---|---|---|
| Rust | `1.97` — asserted against `rustc --version` at build time | The workspace declares `rust-version = "1.97"`. An unpinned base image makes "the tests passed" describe a different compiler every week |
| nightly | installed for `cargo-fuzz` only | A required toolchain, present because nothing else provides `-Zsanitizer` |
| `cargo-fuzz` | `cargo install --locked` | An unpinned fuzzer changes without a commit, and a failure from a new release would look like a failure in QQQ |
| Base image | `rust:1.97-slim-bookworm` | A tag is mutable; the assertion above is what makes the pin real |

---

## 6. What this environment is not, stated rather than implied

* **Not a substitute for CI.** CI runs ubuntu, macOS and Windows. This runs Linux
  only, and a green `qqqdev matrix` says nothing about macOS.
* **Not a sandbox for untrusted code.** The fuzz targets consume attacker-shaped
  bytes and run here with no published ports and no host filesystem access beyond
  the source mount — reasonable containment for a build tool, but this is a
  compiler-carrying image running as an ordinary user, not a hardened runtime.
  `SEC-019`'s hardening applies to the *host* process, not to this container.
* **Not part of the product.** No runtime crate refers to Docker or Windows. The
  bridge lives in `docker/` and `tools/`, which `tools/check_topology.py` keeps out
  of the crate graph.
* **Slow on a cold cache.** The first `qqqdev test` compiles the whole Wasmtime
  dependency graph on Linux — tens of minutes. The `cargo-registry` and
  `linux-target` volumes exist so subsequent runs are incremental. This is the one
  real cost, and it is why the volumes are named and persistent rather than
  ephemeral.

---

## 7. Adding a command

A new verification step belongs here when it needs Linux, and belongs in
`tools/` or CI when it does not. Concretely:

1. Add the case to `docker/entrypoint.sh`'s dispatch and a `cmd_*` function.
2. Add it to `tools/qqqdev.ps1`'s `ValidateSet` and `switch`.
3. Document it in §3 of this file and in the wrapper's help text.

**It must run as a one-shot that exits.** A command that needs to stay alive is a
command that should be `qqqdev shell` instead.
