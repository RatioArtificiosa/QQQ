# QQQ Linux verification environment.
#
# # What this image is for, and what it is not
#
# It exists to run the things Windows **cannot**: the Linux-only code paths, the
# fuzzer, and the sanitizers. It is a *verification* environment, not a runtime
# image, and it never ships. The distinction matters because a runtime image would
# need hardening this one deliberately does not have (it is a build tool; it runs
# as a normal user and needs a compiler).
#
# See `docs/development-bridge.md` for the design and `tools/qqqdev.ps1` for the
# entry point.
#
# # Why every toolchain is pinned to an exact version
#
# Because this environment's entire value is that its result is **trustworthy as
# evidence**. An unpinned `rust:latest` would mean "the tests passed" describes a
# different compiler every week, and a failure caused by a new Rust release would
# look like a failure in QQQ — the same reasoning `deny.toml` and the CI
# `cargo-fuzz --locked` install already apply.
#
# The base digest is pinned rather than the tag alone: a tag is mutable, and a
# rebuilt `rust:1.97-slim` could change the image underneath a commit that never
# changed. `docker build --pull` would then silently move the goalposts.

# ---------------------------------------------------------------------------
# Stage 1 — the toolchain, assembled once
# ---------------------------------------------------------------------------
FROM rust:1.97-slim-bookworm AS toolchain

# `DEBIAN_FRONTEND` for the whole build: a package that prompts would hang CI or
# the agent with no output, which is the worst kind of failure to debug.
ENV DEBIAN_FRONTEND=noninteractive

# # The packages, and why each is present
#
# This list is derived from what the repository's own gate set actually executes,
# not copied from a generic Rust image. Every entry is justified:
#
#   * `build-essential`  — `cc`/`ld` for the C components `wasmtime` links
#     (`zstd-sys`, `ittapi-sys`) and for `blake3`'s SIMD paths.
#   * `cmake`            — `zstd-sys` builds via CMake, not bare `cc`.
#   * `pkg-config`       — the `*-sys` crates probe for system libraries through it.
#   * `clang` + `libclang-dev` + `llvm` — `libfuzzer-sys` needs `clang` at link
#     time, and the ASan runtime comes from LLVM. This is the *only* reason the
#     image is not `rust:slim` alone.
#   * `git`              — the provenance stamp runs `git status`/`git rev-parse`.
#   * `ca-certificates`  — `cargo` fetches from crates.io over TLS.
#   * `python3`          — every repository tool is Python: the xref validator,
#     the topology check, and the `unsafe` audit.
#   * `sudo`             — needed by the base image's `rust` user setup; removed
#     in the final stage so the running container has no way to escalate.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        pkg-config \
        clang \
        libclang-dev \
        llvm \
        git \
        ca-certificates \
        python3 \
    && rm -rf /var/lib/apt/lists/*

# The MSRV the workspace declares (`rust-version = "1.97"` in the root manifest),
# asserted rather than assumed: if the base image ever moved off it, the build
# would fail here with a clear message instead of somewhere deep in a dependency.
RUN rustc --version | grep -q '^rustc 1\.97\.' \
    || { echo "FATAL: expected Rust 1.97.x, got: $(rustc --version)"; exit 1; }

# Nightly is required for `cargo-fuzz` (it uses `-Zsanitizer`) and nothing else.
# Installed with a minimal profile because the fuzzer needs no docs or clippy.
RUN rustup toolchain install nightly --profile minimal \
    && rustup component add rust-src --toolchain nightly || true

# # Why a SECOND stable toolchain, matching CI
#
# Found by a CI failure this environment could not have caught. CI installs
# `dtolnay/rust-toolchain@stable`, which tracks the newest release; the container
# pinned 1.97. When CI moved to 1.98, its clippy began rejecting 23
# `useless_conversion` sites in `qqq-sys` that 1.97 accepted silently --
# `i64::from(libc::SYS_clone3)` where `c_long` is already `i64` on 64-bit Linux.
#
# So the container was running a *different linter version* from the one that
# gates the merge, and "it passed locally" was not evidence about CI. A bridge
# whose whole purpose is trustworthy verification cannot have that gap.
#
# The fix is not to chase `stable` -- that would make the container
# non-reproducible, which is worse. It is to pin the version CI currently
# resolves to, and to carry BOTH: 1.97 is the MSRV floor the Dockerfile asserts
# below, and 1.98 is what CI lints with. `qqqdev checks` runs the newer one.
#
# `CI_CLIPPY_TOOLCHAIN` is the single place to bump when CI moves.
ARG CI_CLIPPY_TOOLCHAIN=1.98
RUN rustup toolchain install "${CI_CLIPPY_TOOLCHAIN}" --profile minimal -c clippy

# Record it for the entrypoint and for `qqqdev status`, so the version in use is
# never an assumption.
ENV QQQ_CI_TOOLCHAIN=${CI_CLIPPY_TOOLCHAIN}

# `cargo-fuzz` is pinned with `--locked` for the same reason CI does it: an
# unpinned fuzzer is a component of the verification that changes without a
# commit.
RUN cargo install cargo-fuzz --locked

# `SEC-028`'s SBOM generator, installed here rather than at run time.
#
# # Why it must be in the image and not installed on demand
#
# The first attempt installed it inside a `docker compose run` invocation and it
# vanished with the container — the next run reported `no such command: cyclonedx`
# while the install had *succeeded*. An ephemeral install is invisible to every
# subsequent command, so a check that depends on it would fail for a reason that
# looks like a missing tool rather than a missing step.
#
# Pinned with `--locked` for the same reason as `cargo-fuzz`: an unpinned generator
# is a supply-chain artifact whose *format* can change between two runs of the same
# commit, which is exactly what an SBOM consumer audits.
RUN cargo install cargo-cyclonedx --locked

# ---------------------------------------------------------------------------
# Stage 2 — the environment the commands actually run in
# ---------------------------------------------------------------------------
FROM toolchain AS runtime

# # Why the container runs as a non-root user
#
# Not for the runtime-hardening reason (this is a build tool), but because
# `SEC-019`'s tests **change process identity**. A container running as root would
# make `setuid` a no-op, and `dropping_to_the_current_uid_applies` — the one test
# that proves the *positive* path of the privilege-drop code — would pass for the
# wrong reason. Running unprivileged is what makes that test mean what it says.
#
# It also means a build script or a fuzz target cannot write outside its volumes,
# which bounds the blast radius of a dependency's `build.rs`.
ARG USER_ID=1000
ARG GROUP_ID=1000
RUN groupadd --gid "${GROUP_ID}" qqq || true \
    && useradd --uid "${USER_ID}" --gid "${GROUP_ID}" --create-home --shell /bin/bash qqq \
    && rm -f /etc/sudoers.d/*

# The workspace mount point. The source is bind-mounted **here**, read-mostly;
# the Linux build trees live in named volumes mounted *inside* it, so they never
# touch the Windows filesystem. That arrangement is the whole contamination
# defence — see `compose.yaml`.
WORKDIR /workspace

# # Why every volume mount point is created here, owned by the runtime user
#
# Found by running it — twice, because the first fix covered the obvious mounts
# and missed the one that is not a directory in the image's own layout.
#
# Docker creates a named volume's mount point as **root** when the directory does
# not already exist in the image. The container runs as uid 1000, so every write
# into a mounted volume failed:
#
#     /results/provenance.env: Permission denied
#     failed to create directory `/home/qqq/.cargo/registry/cache/...`
#         Caused by: Permission denied (os error 13)
#
# The second is the subtle one: `/home/qqq/.cargo` **does** exist (the base image
# creates `CARGO_HOME`), but Docker replaces a mounted path's ownership when it
# materialises the volume, so the pre-existing directory's owner does not save it.
# The volume's mount point has to be created and chowned in the same RUN, before
# `USER qqq` takes effect.
#
# This is the one place the ordering of `USER` in this file is load-bearing.
#
# # And why the paths are written out rather than interpolated
#
# The first version of this RUN used `"${CARGO_HOME}/registry"` — but this line
# sits **above** the `ENV CARGO_HOME=` declaration, so the variable expanded to the
# empty string and `mkdir` would have created a literal `/.cargo/registry` at the
# filesystem root while leaving the real `CARGO_HOME` root-owned. The paths are
# therefore spelled out in full, and the `ENV` block below repeats them with a
# comment saying the two must stay in step.
#
# This is the same class of mistake as the one the block above records — a Docker
# build reads its `ENV`s in file order, and no linter checks that a `RUN` only
# references variables declared before it.
RUN mkdir -p /linux-target /linux-fuzz-target /linux-corpus /results \
        /home/qqq/.cargo/registry /home/qqq/.cargo/git \
    && chown -R qqq:qqq /linux-target /linux-fuzz-target /linux-corpus /results \
        /home/qqq/.cargo

# # Why the runtime user owns `RUSTUP_HOME`
#
# Because rustup adds toolchain components at RUN time, not build time. The
# container installs a moving `stable` (see `CI_CLIPPY_TOOLCHAIN`), and the first
# `cargo metadata` against a workspace with a wasm target in it makes rustup fetch
# and unpack `wasm32-wasip2` for that toolchain. `RUSTUP_HOME` is root-owned, so it
# failed with:
#
#     error: could not create component directory:
#     '/usr/local/rustup/toolchains/1.98-x86_64-unknown-linux-gnu/lib/rustlib/wasm32-wasip2/lib':
#     Permission denied (os error 13)
#
# `cmd_checks` died on its second step and every checker after it never ran, so the
# bridge reported a failure that looked like a code defect and was a permission.
#
# # Why not pre-install the target instead
#
# `rustup toolchain install "${CI_CLIPPY_TOOLCHAIN}" -t wasm32-wasip2` above would fix
# the 1.98 toolchain this image happens to carry, and would NOT fix the next one.
# The toolchain is deliberately floating: when stable moves, rustup installs a new
# toolchain at run time, that toolchain has no target, and the same wall returns for
# a reason nobody would connect to this line. A toolchain added at run time has to
# be writable at run time.
#
# # What this does not weaken
#
# It widens nothing a test depends on. `SEC-019`'s positive path needs the process to
# be **unprivileged**, which it still is; `RUSTUP_HOME` ownership is a property of a
# build tool's own cache. The source guard is unaffected, and `/workspace` is not
# touched.
RUN chown -R qqq:qqq /usr/local/rustup

COPY --chown=qqq:qqq docker/entrypoint.sh /usr/local/bin/qqq-entrypoint
RUN chmod +x /usr/local/bin/qqq-entrypoint

# # Why git must be told `/workspace` is a safe directory
#
# This is not a convenience. Without it the source guard -- the ONLY control
# enforcing the bridge's one-way rule -- silently measured nothing:
#
#     fatal: detected dubious ownership in repository at '/workspace'
#
# `/workspace` is a bind mount of the host tree, so its uid does not match the
# container's uid 1000 and git refuses to operate on it. `source_guard_snapshot()`
# pipes `git ls-files` through `sha1sum`, so a refused `git` produced the hash of
# **empty input** -- `da39a3ee5e6b4b0d3255bfef95601890afd80709` -- both before and
# after every command. The two hashes were therefore ALWAYS equal and the guard
# could not trip, no matter what a command wrote to the host tree.
#
# The guard was installed, reported nothing, and was believed. That is `§O-085`'s
# failure mode (`SEC-019`'s seccomp filter) reproduced in the bridge itself, and it
# is why `cmd_guard_prove` now exists: the guard is proven to fire, not assumed.
#
# `safe.directory` is the narrowest correct fix. The alternative -- chowning the
# bind mount -- would modify the host's ownership, which is exactly the kind of
# write-back the bridge exists to prevent.
# # And why `HOME` is declared before it
#
# Found by running it. With `HOME` unset -- the base image defines `CARGO_HOME` and
# `RUSTUP_HOME` but never `HOME` -- `git config --global` wrote to `/root/.gitconfig`,
# which the image discards at `USER qqq`. The setting above was therefore inert from
# the day it was written, and the guard it protects failed with:
#
#     fatal: detected dubious ownership in repository at '/workspace'
#     fatal: unable to read config file '/home/qqq/.gitconfig': No such file or directory
#
# The block above records the identical hazard for `CARGO_HOME`: a `RUN` reads its
# `ENV`s in file order, and no linter checks that a variable is declared before use.
# This is that trap a second time, in the same file, which is why the assertion below
# exists rather than another comment.
ENV HOME=/home/qqq

# # Why the setting is asserted here rather than trusted
#
# `/workspace` is only `WORKDIR` at build time -- an empty directory. The source, and
# with it `.git`, arrives when `compose.yaml` bind-mounts the host tree at RUN time,
# so a `--file /workspace/.git/config` write here cannot work and does not:
#
#     error: could not lock config file /workspace/.git/config: No such file or directory
#
# The global file is different. It is written into the image at a real path, owned by
# `qqq`, and no mount covers it -- which is exactly why `ENV HOME` above is the fix and
# the whole fix. The assertion makes a silent regression in that ordering a failed
# build instead of a guard that measures nothing.
RUN git config --global --add safe.directory /workspace \
    && git config --global --get-all safe.directory | grep -qx /workspace

# # Why `CARGO_TARGET_DIR` is set to a volume path and not left to default
#
# Because the default would be `/workspace/target` and `/workspace/fuzz/target` —
# which on a bind mount **are the Windows directories**. Cargo would then write
# Linux artifacts into the 17 GB of Windows build output, overwriting `.rlib`
# files it cannot read, and every subsequent Windows build would fail with a
# confusing linker error. Pointing them at named volumes is what keeps the two
# platforms genuinely separate.
#
# `fuzz/` is a separate cargo workspace, so it needs its own variable; it is set
# in the entrypoint because cargo-fuzz invokes cargo in a subdirectory.
ENV CARGO_TARGET_DIR=/linux-target
ENV CARGO_HOME=/home/qqq/.cargo
ENV RUSTUP_HOME=/usr/local/rustup

# The provenance stamp is written here and read back by `qqqdev status`, so a
# result can always be tied to the commit and tree state that produced it.
ENV QQQ_RESULT_DIR=/results

USER qqq

ENTRYPOINT ["/usr/local/bin/qqq-entrypoint"]
CMD ["status"]
