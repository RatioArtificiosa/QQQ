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

# `cargo-fuzz` is pinned with `--locked` for the same reason CI does it: an
# unpinned fuzzer is a component of the verification that changes without a
# commit.
RUN cargo install cargo-fuzz --locked

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
RUN git config --global --add safe.directory /workspace

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
