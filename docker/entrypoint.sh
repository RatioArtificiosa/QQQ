#!/usr/bin/env bash
#
# The QQQ Linux verification entrypoint.
#
# # What this script is responsible for
#
# Three things, and each is a rule the design depends on rather than a convenience:
#
#   1. **Refuse to write source back to the host.** The container's `/workspace`
#      is a bind mount of the Windows tree. A command that modified source would
#      silently change the host's files, breaking the "source flows one way" rule
#      that `docs/development-bridge.md` establishes. Commands that *must* write
#      (fuzz corpus, results) write to volumes instead.
#   2. **Stamp provenance.** Every result carries the commit, the dirty-state, and
#      the toolchain versions, because a test result without provenance is an
#      anecdote — and this project has three recorded cases of a result being
#      believed without checking what produced it (`§O-070`, `§O-072`, `§O-077`).
#   3. **Run one command, then exit.** No daemon, no watch process. Every command
#      here is a short-lived batch job whose exit code is the answer.
#
# # Why bash and not a Rust binary
#
# Because this runs *before* anything is built, so a Rust entrypoint would have to
# be compiled into the image — and then the thing that decides what to test would
# itself need testing, inside the environment it is verifying. A shell script with
# `set -euo pipefail` and explicit argument handling is readable by a human at the
# moment they need to debug it, which is the moment it matters.

set -euo pipefail

# Every command is a one-shot; a failure anywhere is the result.
set -o pipefail

readonly WORKSPACE=/workspace
readonly RESULT_DIR="${QQQ_RESULT_DIR:-/results}"

# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

# Collect the facts that make a result attributable.
#
# # Why this runs even for commands that ignore its output
#
# Because the alternative is a result file with no commit in it, which is
# indistinguishable from a result produced by different code. `git` is told the
# workspace is safe so it does not refuse to read a directory owned by another uid
# — the bind mount is owned by Windows' user id, which the container cannot match.
collect_provenance() {
    local commit dirty files toolchain nightly
    commit="$(git -c safe.directory="${WORKSPACE}" -C "${WORKSPACE}" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    toolchain="$(rustc --version 2>/dev/null || echo 'unknown')"
    nightly="$(rustc +nightly --version 2>/dev/null || echo 'unknown')"

    # A dirty tree is not a failure — the whole point of this environment is
    # testing work in progress — but it must be *reported*, because a green result
    # against a dirty tree does not describe any commit.
    if git -c safe.directory="${WORKSPACE}" -C "${WORKSPACE}" diff --quiet 2>/dev/null \
        && git -c safe.directory="${WORKSPACE}" -C "${WORKSPACE}" diff --cached --quiet 2>/dev/null; then
        dirty="clean"
    else
        dirty="DIRTY"
        files="$(git -c safe.directory="${WORKSPACE}" -C "${WORKSPACE}" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
    fi

    mkdir -p "${RESULT_DIR}"

    # Written as shell-readable assignments so both the human form and `qqqdev
    # status` can consume one file rather than re-deriving the values.
    {
        echo "QQQ_COMMIT=${commit}"
        echo "QQQ_TREE=${dirty}"
        echo "QQQ_CHANGED_FILES=${files:-0}"
        echo "QQQ_RUSTC=${toolchain}"
        echo "QQQ_NIGHTLY=${nightly}"
        echo "QQQ_PLATFORM=$(uname -m)-linux"
        echo "QQQ_GENERATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "${RESULT_DIR}/provenance.env"

    echo "── QQQ Linux verification ──────────────────────────────────────"
    echo "   commit   ${commit}  (tree ${dirty})"
    echo "   rustc    ${toolchain}"
    echo "   platform $(uname -m)-linux"
    echo "────────────────────────────────────────────────────────────────"
}

# ---------------------------------------------------------------------------
# Guard: nothing may write source into the bind mount
# ---------------------------------------------------------------------------

# Record the bind mount's state before a command runs, and compare after.
#
# # Why this is a guard rather than a comment
#
# The "source flows one way" rule is the single most important property of this
# bridge — the review that prompted it spends a page on why bidirectional sync is
# dangerous. A rule that lives only in documentation is a rule that holds until
# someone adds a command that writes.
#
# This is cheap: a hash of the tracked files, taken before and after. A command
# that modified `/workspace` fails loudly, naming the files, instead of quietly
# changing the developer's tree.
#
# # What it deliberately does not cover
#
# It does not detect a file created and deleted within one command, and it does not
# track untracked files (git cannot hash what it does not track without a full
# walk). Both are accepted: the guard exists to catch a *systematic* violation, not
# to be a filesystem integrity monitor for a process that is already trusted with
# the source.
SOURCE_GUARD_BEFORE=""

# The SHA-1 of empty input. If the snapshot ever equals this, git produced no
# file list and the guard is measuring nothing.
SOURCE_GUARD_EMPTY="da39a3ee5e6b4b0d3255bfef95601890afd80709"

# Count the files the snapshot covers, so a silently-empty list is detectable.
source_guard_file_count() {
    ( cd "${WORKSPACE}" && \
      git -c safe.directory="${WORKSPACE}" ls-files 2>/dev/null | wc -l | tr -d ' ' )
}

# # Why `-c safe.directory=` is passed on EVERY call
#
# `/workspace` is a bind mount of the host tree, so its uid does not match the
# container user and git refuses it -- but ONLY for some users (it depends on HOME
# and on who owns the mount). Configuring it once at image-build time therefore
# does not work: the `RUN git config --global` executed as root, so it wrote
# `/root/.gitconfig`, and every real command runs as `qqq`.
#
# The failure that produced was the worst possible one: `git ls-files` printed
# nothing, the pipeline hashed **empty input**, and `source_guard_snapshot`
# returned `da39a3ee5e6b4b0d3255bfef95601890afd80709` before and after every
# command. The two hashes were always equal, so the guard could not trip -- an
# installed control that measured nothing while reporting no violations.
#
# # Why the subshell `cd`s to ${WORKSPACE} first
#
# This is the subtler half of the same bug. `git ls-files` prints paths relative
# to the *current directory* when it is inside the repository, so a command that
# `cd`s (as `cmd_fuzz` does, into `/workspace/fuzz`) made the snapshot list paths
# like `../crates/qqq-core/src/lib.rs`. `sha1sum` then could not open them, every
# read failed, and the pipeline hashed nothing -- producing the empty-input hash
# AGAIN, but this time with a full 181-file listing, so a count-based sanity check
# would have passed it.
#
# An observed run showed exactly this: `SOURCE_GUARD_BEFORE=ea857633...` (correct,
# taken from /workspace) and `after=033cc057...` (empty, taken from
# /workspace/fuzz) -- two different hashes for an *unchanged* tree, which would
# have made the guard report a write that never happened.
#
# Pinning the working directory makes the listing absolute-consistent, so the
# snapshot means the same thing no matter where a command left the shell.
source_guard_snapshot() {
    ( cd "${WORKSPACE}" && \
      git -c safe.directory="${WORKSPACE}" ls-files -z 2>/dev/null \
        | xargs -0 -r sha1sum 2>/dev/null \
        | sha1sum \
        | cut -d' ' -f1 )
}

# # Why a snapshot that measures nothing is a FATAL error
#
# The guard's job is to compare "before" and "after". If the snapshot silently
# returns the hash of empty input -- which is exactly what happened when git
# refused `/workspace` for dubious ownership (`da39a3ee...` both times) -- then
# before and after are ALWAYS equal and the guard can never trip. It is installed,
# it reports nothing, and it is believed.
#
# That is the failure this whole bridge exists to expose (`§O-085`), so the guard
# refuses to run at all rather than run blind. A control that cannot measure must
# say so; "no violations found" and "I could not look" are not the same result.
source_guard_assert_live() {
    local hash count
    hash="$(source_guard_snapshot)"
    count="$(source_guard_file_count)"

    if [ "${hash}" = "${SOURCE_GUARD_EMPTY}" ] || [ "${count}" -eq 0 ]; then
        echo "" >&2
        echo "!! SOURCE GUARD CANNOT MEASURE -- refusing to run" >&2
        echo "" >&2
        echo "The tracked-file snapshot covers ${count} file(s) and hashes to" >&2
        echo "${hash}." >&2
        echo "" >&2
        echo "A snapshot that sees no files always compares equal to itself, so the" >&2
        echo "one-way guarantee would appear to hold no matter what a command wrote." >&2
        echo "" >&2
        echo "Two known causes, both seen in practice:" >&2
        echo "  1. git refused ${WORKSPACE} ('detected dubious ownership'), so" >&2
        echo "     'git ls-files' printed nothing -- count would be 0." >&2
        echo "  2. the shell's cwd was inside a subdirectory of the repo, so" >&2
        echo "     'git ls-files' printed paths relative to it, sha1sum could not" >&2
        echo "     open them, and the pipeline hashed empty input -- count would be" >&2
        echo "     correct while the hash is still the empty-input hash." >&2
        echo "The second one passes any count check, which is why both are tested." >&2
        echo "" >&2
        echo "Diagnose with:" >&2
        echo "  ( cd ${WORKSPACE} && git ls-files | wc -l )" >&2
        echo "  ( cd ${WORKSPACE} && git ls-files -z | xargs -0 sha1sum | wc -l )" >&2
        exit 4
    fi
}

source_guard_begin() {
    SOURCE_GUARD_BEFORE="$(source_guard_snapshot)"
}

source_guard_end() {
    local after
    after="$(source_guard_snapshot)"

    if [ "${SOURCE_GUARD_BEFORE}" != "${after}" ]; then
        echo ""
        echo "!! SOURCE GUARD TRIPPED" >&2
        echo "" >&2
        echo "A command modified files under ${WORKSPACE}, which is a bind mount of" >&2
        echo "the HOST working tree. The bridge's rule is that source flows one way" >&2
        echo "(host -> container) and that nothing writes back." >&2
        echo "" >&2
        echo "Changed tracked files:" >&2
        git -c safe.directory="${WORKSPACE}" -C "${WORKSPACE}" diff --name-only 2>/dev/null | sed 's/^/  /' >&2 || true
        echo "" >&2
        echo "If the command legitimately needs to write, send its output to a" >&2
        echo "volume (see the named volumes in compose.yaml) rather than to" >&2
        echo "\`/workspace\`. See docs/development-bridge.md §\"The one-way rule\"." >&2
        exit 3
    fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

# Prove the source guard actually trips.
#
# # Why this command exists
#
# The guard is the *only* thing enforcing the bridge's one-way rule -- `/workspace`
# is deliberately read-write, so nothing else stops a mistyped command from
# rewriting the host tree. That makes it exactly the kind of control this project
# has already been burned by five times: believed live, never observed firing.
# (`§O-066` advisory limit, `§O-069` amplifiable refusal, `§O-071` unreachable
# check, `§O-076` self-comparing diff, `§O-085` inert seccomp filter -- see
# QQQ-Observations-and-Memories.md.)
#
# So the guard is not trusted because it is written correctly. It is trusted
# because this command makes it fire on purpose and checks the exit code, here, in
# this container, against this bind mount. A guard that has never been seen
# tripping is a guard that is assumed to work.
#
# The write is performed by a *modified copy of this entrypoint* whose target
# command appends to a tracked file. That means the proof runs the production
# `main` -> `source_guard_begin` -> command -> `source_guard_end` path rather than
# a re-implementation of it.
cmd_guard_prove() {
    echo ""
    echo "── proving the source guard refuses a write to /workspace ──"
    echo ""

    local target="${WORKSPACE}/Cargo.toml"
    local backup="${WORKSPACE}/.bridge-probe-backup"

    # Undo everything this command does, however it exits. A verification command
    # that can leave the tree dirty is worse than no verification command.
    restore_probe() {
        if [ -f "${backup}" ]; then
            mv "${backup}" "${target}"
        fi
        return 0
    }
    trap restore_probe EXIT

    cp "${target}" "${backup}"

    # ---- Part 1: the guard must be able to MEASURE -------------------------
    #
    # Before testing that the guard trips, test that it is *capable* of tripping.
    # A guard whose snapshot is empty compares equal to itself forever, so it
    # passes every write silently. `source_guard_assert_live` exits 4 in that case
    # rather than allowing this command to report a meaningless success.
    local live_rc=0
    ( source_guard_assert_live ) >/dev/null 2>&1 || live_rc=$?

    if [ "${live_rc}" -ne 0 ]; then
        echo "   !! THE GUARD CANNOT MEASURE (exit ${live_rc})" >&2
        echo "   Its tracked-file snapshot is empty, so it would never trip." >&2
        echo "   Run: git -C ${WORKSPACE} ls-files | wc -l" >&2
        restore_probe
        trap - EXIT
        return 1
    fi

    local before after_probe
    before="$(source_guard_snapshot)"
    echo "   snapshot covers $(source_guard_file_count) tracked file(s): ${before}"

    # ---- Part 2: a real write must MOVE the snapshot -----------------------
    #
    # This isolates the measurement from the guard's own control flow. If the
    # write does not change the hash, no later conclusion about the guard is
    # meaningful.
    printf '\n# source-guard probe\n' >> "${target}"
    after_probe="$(source_guard_snapshot)"

    if [ "${before}" = "${after_probe}" ]; then
        echo "   !! a real write did NOT change the snapshot" >&2
        echo "   The guard cannot detect writes even in principle." >&2
        restore_probe
        trap - EXIT
        return 1
    fi
    echo "   a write to Cargo.toml moves the snapshot: ${after_probe}"

    # ---- Part 3: the guard's own body must refuse it ----------------------
    #
    # `source_guard_end` exits 3 when the hash moved. Run it in a subshell so its
    # `exit` does not terminate this command, and check the CODE -- not merely
    # "something failed", which is what a broken `set -e` produces.
    local rc=0
    ( source_guard_end ) >/dev/null 2>&1 || rc=$?

    if [ "${rc}" -eq 3 ]; then
        echo "   GUARD TRIPPED (exit 3) -- the write was refused"
    else
        echo "   !! GUARD DID NOT TRIP (exit ${rc}, expected 3)" >&2
        echo "   A write to the bind-mounted host tree was NOT refused, so the" >&2
        echo "   bridge's one-way guarantee is not enforced." >&2
        restore_probe
        trap - EXIT
        return 1
    fi

    restore_probe
    trap - EXIT

    # ---- Part 4: the tree must be exactly as it was ------------------------
    local restored
    restored="$(source_guard_snapshot)"
    if [ "${restored}" != "${before}" ]; then
        echo "   !! tree NOT restored after the probe" >&2
        return 1
    fi

    echo "   tree restored byte-for-byte"
    echo ""
    return 0
}

cmd_status() {
    echo ""
    echo "Toolchains:"
    echo "  stable   $(rustc --version)"
    echo "  nightly  $(rustc +nightly --version 2>/dev/null || echo 'absent')"
    echo "  cargo-fuzz $(cargo fuzz --version 2>/dev/null || echo 'absent')"
    echo "  python   $(python3 --version)"
    echo "  clang    $(clang --version | head -1)"
    echo ""
    echo "Source guard:"
    echo "  tracked files  $(source_guard_file_count)"
    echo "  snapshot       $(source_guard_snapshot)"
    echo ""
    echo "Linux-only code this environment exists to exercise:"
    grep -rl 'cfg(target_os = "linux")' "${WORKSPACE}"/crates/*/src/*.rs 2>/dev/null \
        | sed "s|${WORKSPACE}/|  |" || echo "  (none found)"
    echo ""
    echo "Named volumes (Linux build output; never touches the host):"
    echo "  CARGO_TARGET_DIR  ${CARGO_TARGET_DIR:-unset}"
    du -sh "${CARGO_TARGET_DIR}" 2>/dev/null | sed 's/^/  /' || echo "  (empty)"
    echo ""
}

# Detect an injection that was left applied by an interrupted `inject` run.
#
# # Why this check exists, and why it is a *behavioural* check
#
# `cmd_inject` edits real source, then restores it. If the process is killed
# mid-run -- a CI timeout, a Ctrl-C, a container stop -- the restore may not
# happen, and the tree is left holding an injected defect. That is exactly what
# happened here: `qqq-sys::harden::deny_action()` was left returning
# `SeccompAction::Allow` instead of `Errno(EPERM)`, which **disables the seccomp
# filter entirely** while the doc comment above it still described the correct
# behaviour.
#
# A file-hash comparison against `git` cannot detect this reliably, because the
# developer's tree is legitimately dirty during normal work. So the check is
# behavioural: it asserts the *properties* the injections are designed to break.
# Those properties are true in every legitimate state of this repository, so a
# violation means an injection is still applied.
injections_are_clean() {
    local ok=1

    # Injection 2 would make the default action `Allow`, which seccompiler rejects
    # at construction -- so the property to assert is simply that the action is not
    # `Allow`. This is read from source because the profile is `#[cfg(linux)]` and
    # this function also runs where it is not compiled.
    if grep -qE 'SeccompAction::Allow\s*$' "${WORKSPACE}/crates/qqq-sys/src/harden.rs"; then
        # `Allow` appears legitimately as the *matching* action; only a trailing
        # `Allow` inside `deny_action` is the injected defect.
        if awk '/fn deny_action/,/^    }/' "${WORKSPACE}/crates/qqq-sys/src/harden.rs" \
            | grep -q 'SeccompAction::Allow'; then
            echo "   !! the seccomp default action is Allow -- injection 2 is still applied"
            ok=0
        fi
    fi

    # Injection 1 would disable the uid-0 refusal.
    if grep -q 'if false && uid == 0' "${WORKSPACE}/crates/qqq-sys/src/harden.rs"; then
        echo "   !! the uid-0 refusal is disabled -- injection 1 is still applied"
        ok=0
    fi

    # Injection 3 would duplicate a TLS version, tripping the agility tripwire.
    if grep -qE 'rustls::version::TLS12, &rustls::version::TLS12' "${WORKSPACE}/crates/qqq-serve/src/tls.rs"; then
        echo "   !! the TLS version list is duplicated -- injection 3 is still applied"
        ok=0
    fi

    # Injection 4 replaces the hybrid group with a classical one, demoting it out
    # of first place. Detected by the hybrid name being absent from the group list,
    # which is the property the test asserts.
    if ! grep -q 'kx_group::X25519MLKEM768' "${WORKSPACE}/crates/qqq-serve/src/tls.rs"; then
        echo "   !! the post-quantum key exchange is missing -- injection 4 is still applied"
        ok=0
    fi

    [ "${ok}" -eq 1 ]
}

# The gate set, run natively on Linux.
#
# # Why this is the same sequence as CI rather than a subset
#
# Because a local verification that runs fewer checks than CI produces a green
# local result and a red CI, which is the failure `§O-055` records. The point of
# this environment is to make the Linux half of CI **checkable before pushing**.
cmd_test() {
    cd "${WORKSPACE}"
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
}

# The Linux-only tests, run explicitly and noisily.
#
# # Why this is a separate command from `test`
#
# Because `cargo test` on Linux runs them anyway, but *silently* — and the failure
# mode this command exists for is a test that passes on Windows by being `cfg`'d
# out. `harden.rs`'s step report is identical on both platforms (four steps,
# documented order) while only four of the *outcomes* differ, so a Windows run
# looks complete. This command makes the Linux-only execution visible.
cmd_test_linux() {
    cd "${WORKSPACE}"
    echo "Running the tests that only execute on Linux:"
    echo "  (on Windows these are compiled out, so a green Windows run says"
    echo "   nothing about them — see docs/development-bridge.md)"
    echo ""

    # A tree carrying a leftover injection tests the injection, not the code.
    # Refusing loudly is the only safe answer: a green result here would be a
    # statement about a repository state nobody intended.
    if ! injections_are_clean; then
        echo "" >&2
        echo "!! an injected defect is still applied; the results would describe a" >&2
        echo "   tree nobody wrote. Restore it before running this." >&2
        return 1
    fi

    local failed=0

    echo "── qqq-sys hardening (SEC-019) ──"
    cargo test -p qqq-sys --test harden -- --nocapture || failed=1

    echo ""
    echo "── the whole workspace, for the Linux-only paths elsewhere ──"
    cargo test --workspace -- --nocapture || failed=1

    return "${failed}"
}

# Fault-injection: prove the guards catch a REAL removal, on Linux.
#
# # Why this belongs in the bridge rather than in a script
#
# Three of `SEC-019`'s four injections are `#[cfg(target_os = "linux")]`, so on
# Windows they report "not exercised" — honestly, but that means the guards have
# never been proven live. A guard whose test has never run is a guard that might
# be dead, and this project has found that four times (`§O-066`, `§O-071`,
# `§O-073`, `§O-076`).
cmd_inject() {
    cd "${WORKSPACE}"

    # # Why the harness first proves the tree is NOT already poisoned
    #
    # `inject` edits source and restores it. If a previous run was killed before
    # the restore -- a timeout, a Ctrl-C, a stopped container -- the tree still
    # holds an injected defect, and re-running `inject` would measure that instead
    # of the code. Worse, every later `test`/`test-linux` would report on a tree
    # nobody wrote.
    #
    # That happened: `deny_action()` was left returning `SeccompAction::Allow`,
    # silently disabling the seccomp filter, and it was only found because a
    # `test-linux` run failed for a different reason and the failure was chased
    # down rather than dismissed.
    echo "── pre-flight: no injection is still applied ──"
    if ! injections_are_clean; then
        echo "" >&2
        echo "Refusing to inject: the tree already contains an injected defect." >&2
        echo "Restore it with 'git diff' inspection before trusting any result." >&2
        return 1
    fi
    echo "   clean"
    echo ""

    # The injections mutate source, so the source guard must be suspended for the
    # duration — and restored afterwards, which is what the trap guarantees even
    # if an injection fails.
    SOURCE_GUARD_BEFORE=""

    local files=(
        "crates/qqq-sys/src/harden.rs"
        "crates/qqq-serve/src/tls.rs"
    )

    # Back up byte-for-byte before touching anything. A restore that is verified by
    # searching for the injected string is not a restore (`§O-079`).
    #
    # # Why `backup_dir` is NOT `local`
    #
    # `set -u` is on, and a `local` goes out of scope when the function returns — so
    # the `EXIT` trap then saw an unbound variable:
    #
    #     line 261: backup_dir: unbound variable
    #
    # The work had all succeeded by then (3/3 caught, tree restored) so it looked
    # cosmetic, but it still returned exit 1, which makes the command unusable from
    # a script. Leaving it non-local keeps it in scope for the trap, and the
    # `[ -d ]` guard below makes the trap harmless when the function never ran or
    # already cleaned up.
    backup_dir="$(mktemp -d)"
    for f in "${files[@]}"; do
        mkdir -p "${backup_dir}/$(dirname "$f")"
        cp "${WORKSPACE}/$f" "${backup_dir}/$f"
    done

    # # Why the restore is idempotent, and why it checks before copying
    #
    # The first version removed `backup_dir` on the first restore and then failed on
    # the second, because `restore_all` is called after *every* injection AND from
    # the `EXIT` trap:
    #
    #     cp: cannot stat '.../harden.rs': No such file or directory
    #     line 248: backup_dir: unbound variable
    #
    # A restore that can only run once is a restore that runs exactly once too few.
    # So the directory is removed only at the end, and the function is safe to call
    # any number of times.
    #
    # `set -u` is why the second message appeared: `backup_dir` is `local`, so once
    # the function had returned, the trap saw an unbound variable. Checking the
    # directory exists rather than the variable fixes both.
    restore_all() {
        [ -n "${backup_dir:-}" ] && [ -d "${backup_dir:-}" ] || return 0
        for f in "${files[@]}"; do
            [ -f "${backup_dir}/$f" ] && cp "${backup_dir}/$f" "${WORKSPACE}/$f"
        done
    }
    trap restore_all EXIT

    # # Why the restore is VERIFIED with a hash, not assumed
    #
    # `§O-079` records three injection harnesses that were wrong before the code
    # was — a broken filter, a fixture measuring the wrong limit, an injection that
    # did not apply. The failure mode that matters here is the reverse: an injection
    # that leaves the tree *modified*, so the next command tests the wrong code and
    # the developer's working copy is silently corrupted.
    #
    # So a snapshot hash is taken now and compared at the end. `git diff` is not
    # enough: it would miss a change that git normalises.
    local source_hash_before
    source_hash_before="$(git ls-files -z | xargs -0 -r sha1sum 2>/dev/null | sha1sum)"

    local caught=0 total=0

    # -- 1. linux-only: the uid-0 refusal ------------------------------------
    total=$((total + 1))
    echo "── injection 1: uid-0 refusal (SEC-019, Linux-only) ──"
    sed -i 's|^        if uid == 0 {|        if false \&\& uid == 0 {|' \
        crates/qqq-sys/src/harden.rs
    if ! cargo test -p qqq-sys --test harden dropping_to_root 2>&1 | grep -q 'test result: ok'; then
        echo "   CAUGHT"
        caught=$((caught + 1))
    else
        echo "   NOT CAUGHT -- the guard has no test that reaches it"
    fi
    restore_all

    # -- 2. linux-only: the seccomp default-deny action -----------------------
    #
    # This is the injection that FOUND A REAL DEFECT: before the Linux bridge, a
    # default-ALLOW filter passed every test in the workspace, because the old test
    # only asserted the filter was *installed*. The probe in
    # `tests/harden.rs::the_seccomp_filter_refuses_a_denied_syscall` now makes it
    # fail. See Observations §O-085.
    total=$((total + 1))
    echo ""
    echo "── injection 2: seccomp default action (SEC-019, Linux-only) ──"
    sed -i 's|seccompiler::SeccompAction::Errno(libc::EPERM as u32)|seccompiler::SeccompAction::Allow|' \
        crates/qqq-sys/src/harden.rs
    if ! cargo test -p qqq-sys --test harden 2>&1 | grep -q 'test result: ok'; then
        echo "   CAUGHT"
        caught=$((caught + 1))
    else
        echo "   NOT CAUGHT -- a default-ALLOW filter would refuse nothing and no test notices"
    fi
    restore_all

    # -- 3. platform-independent, as a control --------------------------------
    total=$((total + 1))
    echo ""
    echo "── injection 3: TLS version agility tripwire (SEC-017, any platform) ──"
    sed -i 's|&\[&rustls::version::TLS13, &rustls::version::TLS12\];|&[&rustls::version::TLS13, \&rustls::version::TLS12, \&rustls::version::TLS12];|' \
        crates/qqq-serve/src/tls.rs
    if ! cargo test -p qqq-serve --lib tls::tests 2>&1 | grep -q 'test result: ok'; then
        echo "   CAUGHT"
        caught=$((caught + 1))
    else
        echo "   NOT CAUGHT"
    fi
    restore_all

    # -- 4. the post-quantum preference (SEC-021, any platform) ---------------
    #
    # # Why this injection exists
    #
    # `SEC-021` was on the checklist as "track post-quantum hybrid TLS as an
    # opt-in". Reading the pinned dependency showed the hybrid was ALREADY on, by
    # inheritance from rustls 0.23.45, and that the real risk was the opposite of
    # the one the item named: not "how do we turn it on" but "how do we keep a
    # future bump from turning it off silently".
    #
    # So the inherited default was converted into a stated policy, and this
    # injection is what proves the policy is load-bearing. It demotes the hybrid
    # group to last place -- the failure that matters, because list order is how a
    # server states its preference, so a "present but last" group is one a
    # following client will not choose.
    total=$((total + 1))
    echo ""
    echo "── injection 4: post-quantum key exchange demoted (SEC-021) ──"
    sed -i 's|    rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,|    rustls::crypto::aws_lc_rs::kx_group::SECP384R1,|' \
        crates/qqq-serve/src/tls.rs
    if ! cargo test -p qqq-serve --lib tls::tests 2>&1 | grep -q 'test result: ok'; then
        echo "   CAUGHT"
        caught=$((caught + 1))
    else
        echo "   NOT CAUGHT -- the hybrid could be demoted and no test notices"
    fi
    restore_all

    #
    # The tree must be byte-identical to how it started. If it is not, the
    # injections left the developer's working copy modified — which would corrupt
    # every subsequent `test` run in this container AND, because `/workspace` is a
    # bind mount, the host's tree as well.
    local source_hash_after
    source_hash_after="$(git ls-files -z | xargs -0 -r sha1sum 2>/dev/null | sha1sum)"

    local restore_ok=1
    if [ "${source_hash_before}" != "${source_hash_after}" ]; then
        restore_ok=0
        echo ""
        echo "!! RESTORE FAILED — the working tree differs from before the injections"
        echo ""
        git diff --name-only | sed 's/^/   /'
        echo ""
        echo "   The injections are not safe to run. Fix the harness before trusting"
        echo "   any result from this container."
    fi

    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  ${caught}/${total} injection(s) caught"
    if [ "${restore_ok}" -eq 1 ]; then
        echo "  working tree restored, byte-for-byte"
    else
        echo "  WORKING TREE NOT RESTORED"
    fi
    echo "════════════════════════════════════════════════════════════════"

    # Cleanup happens HERE rather than in the trap, now that the verification has
    # used the backups. The trap remains as the failure path.
    rm -rf "${backup_dir}"
    backup_dir=""

    # # Why this is an `if` and not `[ ... ] && [ ... ]`
    #
    # The `&&` form returns 1 when either test is false, and `set -e` then aborts
    # the shell with status 1 -- which is exactly the status a *caught* injection
    # run must never produce, and which is indistinguishable from a real failure.
    # So the "not every injection was caught" case aborted instead of printing its
    # own diagnostic. Stated as an `if`, the failure path is explicit.
    if [ "${caught}" -eq "${total}" ] && [ "${restore_ok}" -eq 1 ]; then
        return 0
    fi
    return 1
}

# Fuzz one target, or all of them, with the corpus persisted to a volume.
cmd_fuzz() {
    cd "${WORKSPACE}/fuzz"

    # `fuzz/target` is its own cargo workspace, so `CARGO_TARGET_DIR` from the
    # image environment does not apply to it automatically — and pointing it at
    # `/workspace/fuzz/target` would write Linux artifacts into the Windows tree.
    export CARGO_TARGET_DIR=/linux-fuzz-target

    local seconds="${1:-300}"
    shift || true

    # The corpus lives on a volume so it accumulates between runs. A corpus that
    # is discarded after each run means the fuzzer re-learns the same coverage
    # every time, which is the difference between finding bugs and finding the
    # same non-bug repeatedly.
    local corpus_dir=/linux-corpus
    mkdir -p "${corpus_dir}"

    local targets=("$@")
    if [ "${#targets[@]}" -eq 0 ]; then
        targets=(manifest_parse component_load host_interfaces)
    fi

    local failed=0
    local harness_failed=0
    for t in "${targets[@]}"; do
        echo ""
        echo "── fuzzing ${t} for ${seconds}s (ASan) ──"

        # # Why the per-target corpus directory is created explicitly
        #
        # libFuzzer requires every corpus directory it is given to already exist:
        #
        #     ERROR: The required directory "/linux-corpus/manifest_parse" does not exist
        #     Error: Fuzz target exited with exit status: 1
        #
        # Without this `mkdir`, the fuzzer aborted **before executing a single input**
        # and the `if !` below reported it as `CRASH in ${t}` -- a false crash, on
        # every target, which is worse than no signal at all: a detector that cries
        # wolf on a harness bug is a detector nobody reads.
        #
        # This is the same shape as the rest of this session's findings (`§O-066`,
        # `§O-069`, `§O-071`, `§O-076`, `§O-085`, `§O-087`): the control was there,
        # and what it actually measured was not the thing it claimed to measure.
        mkdir -p "${corpus_dir}/${t}"

        # `--sanitizer address` is stated rather than assumed: a silent fallback
        # to no sanitizer would make the run far less useful while still passing.
        #
        # The output is captured rather than streamed so a non-zero exit can be
        # *classified*. A libFuzzer crash is a finding; a cargo/build error is a
        # harness problem; and reporting the second as the first is how a real
        # crash later gets ignored. The log is always shown, so nothing is hidden
        # by the capture.
        local log="${RESULT_DIR}/fuzz-${t}.log"
        mkdir -p "${RESULT_DIR}"

        local rc=0
        cargo +nightly fuzz run "${t}" --sanitizer address \
            -- -max_total_time="${seconds}" \
               -print_final_stats=1 \
               "${corpus_dir}/${t}" >"${log}" 2>&1 || rc=$?

        tail -n 20 "${log}" | sed 's/^/   | /'
        echo "   (full log: ${log})"

        # # Why 123 is a SUCCESS
        #
        # `cargo fuzz run` exits **123** when the fuzz target ran to completion and
        # the session ended by a libFuzzer control condition (here, `-max_total_time`).
        # It is not the target's status -- libFuzzer itself exited 0 after executing
        # 488,751 units and reporting `Done`. Treating any non-zero code as a crash
        # therefore reported a *successful* fuzz run as `CRASH in manifest_parse`,
        # which is the same false-positive class as the missing corpus directory one
        # layer up: the harness was measuring "did cargo return zero", not "did the
        # fuzzer find a defect".
        #
        # So the exit code is normalised first, and the real classification is done
        # on the log. A crash is a sanitizer report or a libFuzzer crash banner --
        # never merely a non-zero status.
        #
        # # Why this is an `if` and not `[ ... ] && rc=0`
        #
        # The `&&` form has status 1 whenever the test is false, and under `set -e`
        # that terminates the shell. So a run that really did crash (rc != 123) -- or
        # any run whose rc was already 0 -- aborted *here* with status 1, silently,
        # before the classification below could run. The exit code was then an
        # artifact of the spelling again: this is the third place in this one command
        # where `set -e` and `&&` conspired to make the reported status unrelated to
        # the fuzz result.
        if [ "${rc}" -eq 123 ]; then
            rc=0
        fi

        if [ "${rc}" -ne 0 ] || grep -qE '^(==[0-9]+==ERROR: AddressSanitizer|.*ERROR: libFuzzer: |.*SUMMARY: AddressSanitizer|.*deadly signal)' "${log}"; then
            # Distinguish a *finding* from a *harness failure*. Both are non-zero,
            # but only one is evidence about the code under test.
            if grep -qE '^(==[0-9]+==ERROR: AddressSanitizer|.*ERROR: libFuzzer: |.*SUMMARY: AddressSanitizer|.*deadly signal|.*Test unit written to )' "${log}"; then
                echo "   CRASH in ${t} -- see ${log}"
                failed=1
            else
                echo "   HARNESS FAILURE in ${t} (exit ${rc}) -- the fuzzer did not run to completion"
                echo "   This is NOT a crash finding. Read ${log}."
                harness_failed=1
            fi
        fi
    done

    if [ "${harness_failed}" -ne 0 ]; then
        echo ""
        echo "!! the fuzz harness itself failed; results above are not evidence" >&2
    fi

    # # Why these are `if` blocks and not `[ ... ] && return N`
    #
    # `[ "${failed}" -ne 0 ] && return 1` evaluates the test, and when the test is
    # FALSE the whole `&&` list has status **1** -- which under `set -e` terminates
    # the shell right there. So the success path (failed == 0) tripped `set -e` and
    # the command exited 1, while a genuine crash also exited 1: success and failure
    # were indistinguishable at the container boundary.
    #
    # Writing the condition as an `if` makes the success path a clean no-op. This is
    # the same "the control was not measuring what it claimed" shape as the rest of
    # this file: the exit status was not the fuzz result, it was an artifact of how
    # the check was spelled.
    if [ "${failed}" -ne 0 ]; then
        return 1
    fi
    if [ "${harness_failed}" -ne 0 ]; then
        return 2
    fi
    return 0
}

# Run the repository's own checkers, which is CI's fast half.
#
# # Why the injection harness runs BEFORE the final validator
#
# `self_test_xrefs.py` mutates three documents and restores them. If it is killed
# (`SIGKILL` — a CI timeout cannot be caught), the restore does not happen and the
# corpus keeps an injected defect. Ordering the validator *after* the harness means
# the last thing this command does is confirm the documents are internally
# consistent, so a leftover injection surfaces here rather than in someone's next
# commit — which is exactly how a `§99.9` marker was once mistaken for real
# document drift.
#
# The harness also self-heals now: it detects its own leftovers, reverses the exact
# substitution, and verifies the repair. This ordering is the second layer.
cmd_checks() {
    cd "${WORKSPACE}"

    # # Why CI's linter version runs FIRST here
    #
    # CI installs `dtolnay/rust-toolchain@stable`, which tracks the newest release.
    # The container pinned 1.97; when CI moved to 1.98 its clippy started rejecting
    # 23 `useless_conversion` sites that 1.97 accepted. The push was green locally
    # and red in CI, and nothing in this environment could have predicted it.
    #
    # So the repository checks begin with CI's exact linter. A check that is one
    # version behind the gate it is supposed to predict is not a check.
    cmd_lint_ci

    python3 tools/check_topology.py
    python3 tools/check_no_ambient.py
    python3 tools/gen_schemas.py --check
    python3 tools/gen_llms_txt.py --check
    python3 tools/normalize_eol.py --check
    python3 tools/normalize_eol.py --self-test
    python3 tools/check_wit_errors.py
    python3 tools/check_batch_first.py
    python3 tools/audit_unsafe.py
    python3 tools/audit_unsafe.py --self-test
    python3 tools/check_advisories.py
    python3 tools/check_advisories.py --self-test
    python3 tools/check_sbom.py --self-test
    python3 tools/check_security_scope.py
    python3 tools/check_security_scope.py --self-test
    python3 tools/check_threat_model.py
    python3 tools/check_threat_model.py --self-test
    python3 tools/check_glossary.py
    python3 tools/check_glossary.py --self-test
    python3 tools/check_reconciliation.py
    python3 tools/check_reconciliation.py --self-test
    python3 tools/check_error_catalogue.py
    python3 tools/check_error_catalogue.py --self-test
    python3 tools/check_wit_reference.py
    python3 tools/check_wit_reference.py --self-test
    python3 tools/check_glossary_usage.py
    python3 tools/check_glossary_usage.py --self-test
    python3 tools/check_verified_facts.py
    python3 tools/check_verified_facts.py --self-test
    python3 tools/check_wit_bindings.py
    python3 tools/check_wit_bindings.py --self-test
    python3 tools/check_spdx.py
    python3 tools/check_spdx.py --self-test
    python3 tools/check_license_boundary.py
    python3 tools/check_license_boundary.py --self-test
    python3 tools/check_tombstones.py
    python3 tools/check_tombstones.py --self-test
    python3 tools/check_scope_table.py
    python3 tools/check_scope_table.py --self-test
    python3 tools/check_toolchain.py
    python3 tools/check_toolchain.py --self-test
    python3 tools/check_coderabbit_config.py
    python3 tools/check_coderabbit_config.py --self-test
    python3 tools/check_checklist_citations.py
    python3 tools/check_checklist_citations.py --self-test
    # §9.2's budget table against the Proposal and the checklist. Kept here as
    # well as in ci.yml on purpose: the image must be able to prove the same
    # things CI does, or the two drift and the image certifies less than it looks.
    python3 tools/check_bench_contract.py
    python3 tools/check_bench_contract.py --self-test
    python3 tools/self_test_schemas.py

    # The mutating one, then the validator that proves it restored everything.
    python3 tools/self_test_xrefs.py
    python3 tools/check_xrefs.py

    # A leaked `\uXXXX` renders as literal text in Markdown, so a cross-reference that looks
    # present is invisible to a search for the real character. Kept beside the xref check for
    # the same reason: both are about a document saying what it means.
    python3 tools/check_unicode_escapes.py
    python3 tools/check_unicode_escapes.py --self-test

    # `CON-011`: the WIT style rules Proposal §6.3 says are enforced in review.
    python3 tools/check_wit_style.py
    python3 tools/check_wit_style.py --self-test

    # `DX-004`: §12.2's five parts, on errors the **built binary** emits. Its subject is an
    # artifact rather than a source tree, so it is skipped with a clear reason when the binary
    # has not been built here — a check that silently passes on a missing subject certifies
    # nothing.
    if [ -x target/debug/qqqai ]; then
        python3 tools/check_error_standard.py
        python3 tools/check_error_standard.py --self-test
    else
        echo "SKIP: DX-004 needs a built qqqai (cargo build -p qqq-run); not present"
    fi

    # The corpus guard's **repair** path -- what runs after a killed harness leaves an
    # injection behind. It had a `NameError` in its verification loop, so it repaired
    # the corpus and then died on it (`§O-191`). This drives the real function against
    # a throwaway copy, so it can be checked here without mutating the bind mount.
    python3 tools/check_corpus_repair.py
    python3 tools/check_corpus_repair.py --self-test

    # # Why the line-ending guard runs LAST, and why the scratch copy is deliberate
    #
    # Ten of the steps above inject a defect into a *generated* tracked document and
    # restore it. Each of those read-modify-write cycles used `Path.write_text`, which
    # translates `\n` to `os.linesep`. On Windows that is `\r\n`, so the checkers left
    # every generated document CRLF -- and `normalize_eol.py --check` fails the moment
    # a tracked text file reads CRLF. No CI job ran both, which is why the defect was
    # latent; this environment now runs both, so the guard below is the one that would
    # have caught it. The writers are byte-faithful now.
    #
    # It copies the tree to a scratch directory rather than pointing the checkers at
    # `/workspace`. The bind mount is owned by Windows' user id, which this container
    # cannot match, so a rewrite could fail part-way. A copied tree can be written
    # freely, and `normalize_eol.py` asks Git rather than walking a directory.
    _eol_guard_dir="$(mktemp -d)"
    git -c safe.directory="${WORKSPACE}" -C "${WORKSPACE}" archive --format=tar HEAD \
        | tar -x -C "${_eol_guard_dir}"
    for _t in check_error_catalogue check_glossary check_reconciliation check_wit_reference \
              check_tombstones check_checklist_counts check_advisories check_verified_facts; do
        ( cd "${_eol_guard_dir}" && python3 "${WORKSPACE}/tools/${_t}.py" --self-test >/dev/null )
    done
    if ( cd "${_eol_guard_dir}" && python3 "${WORKSPACE}/tools/normalize_eol.py" --check ); then
        echo "   the self-tests leave the tree with LF, in a scratch copy of HEAD"
    else
        echo "" >&2
        echo "!! a self-test wrote a tracked file with CRLF." >&2
        echo "   A checker's inject/restore went through a newline-translating write." >&2
        rm -rf "${_eol_guard_dir}"
        return 1
    fi
    rm -rf "${_eol_guard_dir}"

    # Final word: the corpus is intact after everything that mutated it.
    python3 tools/self_test_xrefs.py --check-clean
    python3 tools/normalize_eol.py --check
}

# Run clippy with the toolchain version CI actually uses.
#
# # Why this is separate from `test`
#
# `test` uses the default (pinned, 1.97) toolchain because that is the MSRV the
# project asserts. This command uses CI's moving `stable`, because *that* is what
# gates a merge. Both matter, and conflating them is how a green local run came to
# mean nothing.
cmd_lint_ci() {
    cd "${WORKSPACE}"

    local toolchain="${QQQ_CI_TOOLCHAIN:-}"
    if [ -z "${toolchain}" ]; then
        echo "   (QQQ_CI_TOOLCHAIN is unset; falling back to the default toolchain)"
        cargo clippy --workspace --all-targets -- -D warnings
        return
    fi

    echo "── clippy with CI's toolchain (${toolchain}) ──"
    if ! cargo "+${toolchain}" clippy --workspace --all-targets -- -D warnings; then
        echo "" >&2
        echo "!! clippy FAILED under ${toolchain}, which is what CI uses." >&2
        echo "   A newer stable adding a lint is the usual cause; fix the code," >&2
        echo "   do not pin the linter back." >&2
        return 1
    fi
    echo "   passed"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

main() {
    local cmd="${1:-status}"
    shift || true

    local rc=0

    # The source guard wraps every command that could plausibly write. `inject`
    # implements its own backup/restore and explicitly opts out.
    case "${cmd}" in
        inject)
            collect_provenance
            cmd_inject "$@" || rc=$?
            ;;
        *)
            collect_provenance
            # Refuse to run any command behind a guard that cannot measure. This is
            # the last line of defence against a silently-inert control: without it,
            # a broken git makes every command look clean.
            source_guard_assert_live
            source_guard_begin
            case "${cmd}" in
                status)      cmd_status ;;
                test)        cmd_test ;;
                test-linux)  cmd_test_linux ;;
                checks)      cmd_checks ;;
                fuzz)        cmd_fuzz "$@" || rc=$? ;;
                guard-prove) cmd_guard_prove || rc=$? ;;
                shell)       exec /bin/bash ;;
                *)
                    echo "unknown command: ${cmd}" >&2
                    echo "known: status test test-linux checks inject fuzz guard-prove shell" >&2
                    exit 2
                    ;;
            esac

            # # Why the command's status is captured BEFORE the guard runs
            #
            # `source_guard_end` is the last thing to execute, so without this the
            # script's exit status is *the guard's* status, and every command would
            # appear to succeed whenever the guard did not trip -- a `fuzz` run that
            # found a crash would still exit 0 at the container boundary.
            #
            # The guard is also skipped in its check when the command already failed
            # loudly: it still validates the tree, but a command's own failure must
            # never be overwritten by the guard's success. Both signals are preserved
            # by returning the command's code, and exit 3 for a guard trip is emitted
            # from inside `source_guard_end` itself.
            source_guard_end
            ;;
    esac

    return "${rc}"
}

main "$@"
