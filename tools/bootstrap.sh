#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The developer bootstrap — `FND-012`, and §12.1's "first ten minutes".
#
# # What this is, and what it is not
#
# §12.1 specifies the **end-user** path: `curl … | sh` installing `qqqai`. This
# script is the **contributor** path — what a person runs after `git clone` and
# before they can build or test anything. The item that asks for it records why:
#
#   > Install `wasm-tools` and the `wasmtime` CLI into the developer bootstrap
#   > script (both were found missing on the reference machine).
#
# **Measured on the reference machine while writing this**: `wasm-tools 1.259.0`
# is present, and **the `wasmtime` CLI is absent**. So the item's premise is
# still exactly true, and the second half of it is the part that bites: a
# contributor can run `cargo test` and have it pass while `wasmtime` is missing,
# because nothing exercises the CLI — and then fail later on a task that does,
# with an error that does not mention the missing tool.
#
# # Why the check is "does it work" rather than "is it the right version"
#
# The first version of this script pinned `wasm-tools` to a number I invented.
# The real latest is `1.259.0`, and the pinned `wasmtime` crate is `48.0.2` —
# the numbers matter, and a wrong one installs a CLI that cannot do the job.
#
# But a version string is still a proxy. What actually matters is whether the
# tool can **parse this project's WIT and instantiate this project's engine
# version**, so this script checks that directly:
#
#   * `wasm-tools component wit wit/` must succeed, which proves the tool
#     understands the Component Model encoding the repository uses.
#   * the `wasmtime` CLI must report a version whose **major** matches the
#     pinned crate, because a component validated by a mismatched CLI may not be
#     one the engine can instantiate — and that failure appears at run time, in
#     a different component, for a reason nothing connects to the CLI.
#
# A version check is a proxy for "will this work"; running the tool is the fact.
# `§O-109` records four measurements of one property where three were proxies and
# wrong; this is the same lesson applied before writing rather than after.
#
# # Usage
#
#     ./tools/bootstrap.sh            install what is missing, then verify
#     ./tools/bootstrap.sh --check    verify only; change nothing (CI uses this)
#     ./tools/bootstrap.sh --help

set -euo pipefail

# ---------------------------------------------------------------------------
# The facts this script is built on, each verified rather than assumed
# ---------------------------------------------------------------------------

# `wasm-tools` is not a Rust dependency; it is a CLI the verification harness
# shells out to. The version is therefore checked for *capability* (it must parse
# `wit/`) and reported, not pinned to a number that would go stale the day a new
# release lands.
WASM_TOOLS_MIN_MAJOR="1"

# The `wasmtime` CLI must match the crate the engine is built against. `Cargo.toml`
# says `wasmtime = "48"` and `Cargo.lock` resolves it to `48.0.2`, so the major is
# the contract and the patch is not.
WASMTIME_MAJOR="48"

# The MSRV the workspace asserts, read from `Cargo.toml`'s `rust-version`.
MIN_RUST="1.97"

readonly WASM_TOOLS_MIN_MAJOR WASMTIME_MAJOR MIN_RUST

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT

CHECK_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --check) CHECK_ONLY=1 ;;
        --help|-h)
            sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown argument: $arg (try --help)" >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Reporting: three outcomes, not two
# ---------------------------------------------------------------------------
#
# `WARN` exists because "present but wrong" and "absent" need different fixes —
# an upgrade versus an install. A script that reports both as "not found" sends
# the reader to the wrong command, which is the same distinction `SEC-019`'s
# hardening report makes with four variants where a bool would collapse two
# genuinely different situations.

FAILURES=0

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }
note() { printf '      %s\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# The first `x.y.z` token in a tool's `--version` output.
#
# # Why the parsing is defensive
#
# `wasm-tools --version` prints `wasm-tools 1.259.0` on one line; `wasmtime
# --version` prints a multi-line block. A parser assuming one shape returns
# nothing for the other, and "nothing" compares unequal to the pin — reporting a
# version mismatch that is really a parsing bug. The first version-looking token
# anywhere wins.
report_version() {
    "$1" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
}

major_of() { printf '%s' "${1%%.*}"; }

check_rust() {
    if ! have cargo; then
        bad "cargo is not on PATH"
        note "Install Rust $MIN_RUST or newer: https://rustup.rs"
        return
    fi
    local ver
    ver="$(rustc --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    if [ -z "$ver" ]; then
        bad "rustc reported no parseable version"
        return
    fi
    local lower
    lower="$(printf '%s\n%s\n' "$MIN_RUST" "$ver" | sort -V | head -1)"
    if [ "$lower" = "$MIN_RUST" ]; then
        ok "rustc $ver (MSRV $MIN_RUST satisfied)"
    else
        bad "rustc $ver is older than the MSRV $MIN_RUST"
        note "Update: rustup update"
    fi
}

check_wasm_tools() {
    if ! have wasm-tools; then
        if [ "$CHECK_ONLY" -eq 1 ]; then
            bad "wasm-tools is not installed"
            note "Install: cargo install wasm-tools --locked"
        else
            warn "wasm-tools is not installed; installing"
            cargo install wasm-tools --locked
        fi
        return
    fi
    local ver major
    ver="$(report_version wasm-tools)"
    major="$(major_of "$ver")"
    if [ -z "$ver" ]; then
        bad "wasm-tools reported no parseable version"
        return
    fi
    if [ "$major" -lt "$WASM_TOOLS_MIN_MAJOR" ] 2>/dev/null; then
        bad "wasm-tools $ver is older than $WASM_TOOLS_MIN_MAJOR.x"
        return
    fi

    # **The check that matters: can it parse this project's WIT?**
    #
    # A version string says what was installed; this says whether the tool does
    # the job.
    #
    # # Why per file and not the whole directory
    #
    # The first version ran `wasm-tools component wit wit/` and reported failure
    # on a working tool. `wit/` holds 15 *separate* packages, each declaring its
    # own `package`, and the tool correctly refuses to merge them:
    #
    #     error: failed to parse package: wit/: package identifier `qqq:ai@1.0.0`
    #     does not match previous package name of `qqq:agent@1.0.0`
    #
    # So the invocation was invalid, not the tool -- and the script said "too old
    # for this encoding", sending the reader to `cargo install --force`, which
    # would not have helped. `tools/check_wit.py` validates per file for the same
    # reason, so this matches what the harness actually does.
    if [ -d "$REPO_ROOT/wit" ]; then
        local total=0 broken=0
        for f in "$REPO_ROOT"/wit/*.wit; do
            [ -e "$f" ] || continue
            total=$((total + 1))
            if ! wasm-tools component wit "$f" >/dev/null 2>&1; then
                broken=$((broken + 1))
            fi
        done
        if [ "$total" -eq 0 ]; then
            warn "wasm-tools $ver (no .wit files to validate)"
        elif [ "$broken" -eq 0 ]; then
            ok "wasm-tools $ver (parses all $total wit/ file(s))"
        else
            bad "wasm-tools $ver cannot parse $broken of $total wit/ file(s)"
            note "Either the tool is too old, or a WIT file is malformed."
            note "Ask which: python tools/check_wit.py"
        fi
    else
        warn "wasm-tools $ver (no wit/ directory to validate against)"
    fi
}

check_wasmtime() {
    if ! have wasmtime; then
        if [ "$CHECK_ONLY" -eq 1 ]; then
            # This is the failure the item records, so it is a hard error rather
            # than a warning: the contributor path is broken without it.
            bad "the wasmtime CLI is not installed"
            note "Install: cargo install wasmtime-cli --version ${WASMTIME_MAJOR}.0.0 --locked"
        else
            warn "the wasmtime CLI is not installed; installing ${WASMTIME_MAJOR}.x"
            # `wasmtime-cli` is the package; the binary is `wasmtime`.
            cargo install wasmtime-cli --version "^${WASMTIME_MAJOR}" --locked
        fi
        return
    fi
    local ver
    ver="$(report_version wasmtime)"
    if [ -z "$ver" ]; then
        bad "the wasmtime CLI reported no parseable version"
        return
    fi
    if [ "$(major_of "$ver")" = "$WASMTIME_MAJOR" ]; then
        ok "wasmtime $ver (matches the pinned crate major)"
    else
        bad "wasmtime $ver does not match the engine's major ($WASMTIME_MAJOR)"
        note "A component the CLI validates may not be one the engine can load."
        note "Install the matching CLI:"
        note "    cargo install wasmtime-cli --version ^${WASMTIME_MAJOR} --locked --force"
    fi
}

# Tools the *full CI gate* needs. Absent ones are warnings rather than failures,
# because a contributor can run `cargo test` without them and should not be
# blocked from starting — but they should know before opening a PR that fails.
check_auxiliary() {
    local tool
    for tool in cargo-fuzz cargo-cyclonedx cargo-deny cargo-machete; do
        if have "$tool"; then
            ok "$tool present"
        else
            warn "$tool is not installed (needed for the full CI gate, not cargo test)"
            note "Install: cargo install $tool --locked"
        fi
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo "QQQ developer bootstrap"
echo "======================"
if [ "$CHECK_ONLY" -eq 1 ]; then
    echo "mode: --check (nothing will be installed)"
else
    echo "mode: install (missing tools are installed)"
fi
echo

echo "toolchain"
check_rust

echo
echo "component toolchain"
check_wasm_tools
check_wasmtime

echo
echo "auxiliary tools"
check_auxiliary

echo
if [ "$FAILURES" -gt 0 ]; then
    printf '\033[31m%d check(s) failed.\033[0m' "$FAILURES" >&2
    if [ "$CHECK_ONLY" -eq 1 ]; then
        printf ' Re-run without --check to install what is missing.\n' >&2
    else
        printf '\n' >&2
    fi
    exit 1
fi
echo "Environment is ready. Next:"
echo "    cargo test --workspace"
echo "    python tools/audit_requirements.py"
