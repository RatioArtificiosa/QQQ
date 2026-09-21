<#
.SYNOPSIS
    QQQ developer bootstrap — the Windows half of `tools/bootstrap.sh` (FND-012).

.DESCRIPTION
    Installs and verifies the tools a contributor needs before `cargo test` and
    `python tools/audit_requirements.py` will pass.

    # Why this exists, in the item's own words

    `FND-012`: "Install `wasm-tools` and the `wasmtime` CLI into the developer
    bootstrap script (both were found missing on the reference machine)."

    **Measured on the reference machine while writing this**: `wasm-tools
    1.259.0` is present and **the `wasmtime` CLI is absent**. The item's premise
    is still exactly true, and its second half is the part that bites — a
    contributor can run `cargo test` and have it pass while `wasmtime` is missing,
    because nothing exercises the CLI, and then fail later on a task that does,
    with an error that never mentions the missing tool.

    # Why this checks capability rather than a version string

    A version is a *proxy* for "will this work". `§O-109` records four
    measurements of one property where three were proxies and all three were
    wrong. So the check that matters here is direct: `wasm-tools component wit`
    must parse this repository's `wit/`, which proves the tool understands the
    Component Model encoding the project uses. A numeric comparison would pass
    for a tool that cannot do the job and fail for one that can.

    # Why three outcomes and not two

    `Warn` exists because "present but wrong" and "absent" need different fixes —
    an upgrade versus an install. Reporting both as "not found" sends the reader
    to the wrong command. This is the distinction `SEC-019`'s hardening report
    makes with four variants where a bool would collapse two real situations.

.PARAMETER Check
    Verify only; install nothing. CI uses this.

.EXAMPLE
    pwsh tools/bootstrap.ps1
    pwsh tools/bootstrap.ps1 -Check
#>

[CmdletBinding()]
param(
    [switch]$Check
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# The facts, each verified rather than assumed
# ---------------------------------------------------------------------------

# `wasm-tools` is a CLI the harness shells out to, not a Rust dependency, so its
# version is checked for *capability* (it must parse wit/) and reported.
$WasmToolsMinMajor = 1

# The `wasmtime` CLI must match the crate the engine is built against.
# Cargo.toml says `wasmtime = "48"`; Cargo.lock resolves it to 48.0.2, so the
# major is the contract and the patch is not.
$WasmtimeMajor = 48

# The MSRV Cargo.toml asserts.
$MinRust = '1.97'

$RepoRoot = Split-Path -Parent $PSScriptRoot

$script:Failures = 0

function Write-Ok { param([string]$Message) Write-Host "  [ok]   $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "  [warn] $Message" -ForegroundColor Yellow }
function Write-Bad { param([string]$Message) Write-Host "  [fail] $Message" -ForegroundColor Red; $script:Failures++ }
function Write-Note { param([string]$Message) Write-Host "         $Message" -ForegroundColor DarkGray }

function Test-Tool {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

<#
    The first `x.y.z` token in a tool's `--version` output.

    # Why the parsing is defensive

    `wasm-tools --version` prints one line; `wasmtime --version` prints several.
    A parser assuming one shape returns nothing for the other, and "nothing"
    compares unequal to the pin — reporting a mismatch that is really a parsing
    bug. The first version-looking token anywhere in the output wins.
#>
function Get-ToolVersion {
    param([string]$Name)
    $raw = & $Name --version 2>&1 | Out-String
    $m = [regex]::Match($raw, '\d+\.\d+\.\d+')
    if ($m.Success) { return $m.Value }
    return ''
}

function Get-Major {
    param([string]$Version)
    if ([string]::IsNullOrEmpty($Version)) { return 0 }
    return [int]($Version.Split('.')[0])
}

function Test-Rust {
    if (-not (Test-Tool 'cargo')) {
        Write-Bad 'cargo is not on PATH'
        Write-Note "Install Rust $MinRust or newer: https://rustup.rs"
        return
    }
    $ver = Get-ToolVersion 'rustc'
    if ([string]::IsNullOrEmpty($ver)) {
        Write-Bad 'rustc reported no parseable version'
        return
    }
    # Compare major.minor only: the patch is never the MSRV question.
    $want = [version]($MinRust + '.0')
    $have = [version]($ver)
    if ($have -ge $want) {
        Write-Ok "rustc $ver (MSRV $MinRust satisfied)"
    } else {
        Write-Bad "rustc $ver is older than the MSRV $MinRust"
        Write-Note 'Update: rustup update'
    }
}

function Test-WasmTools {
    if (-not (Test-Tool 'wasm-tools')) {
        if ($Check) {
            Write-Bad 'wasm-tools is not installed'
            Write-Note 'Install: cargo install wasm-tools --locked'
        } else {
            Write-Warn 'wasm-tools is not installed; installing'
            cargo install wasm-tools --locked
        }
        return
    }
    $ver = Get-ToolVersion 'wasm-tools'
    if ([string]::IsNullOrEmpty($ver)) {
        Write-Bad 'wasm-tools reported no parseable version'
        return
    }
    if ((Get-Major $ver) -lt $WasmToolsMinMajor) {
        Write-Bad "wasm-tools $ver is older than $WasmToolsMinMajor.x"
        return
    }

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
    # would not have helped. **A diagnostic that names the wrong cause sends the
    # reader to the wrong fix** (`§O-106`, fourth occurrence this session).
    #
    # `tools/check_wit.py` validates per file for the same reason, so this
    # matches what the harness actually does.
    $wit = Join-Path $RepoRoot 'wit'
    if (Test-Path $wit) {
        $files = @(Get-ChildItem (Join-Path $wit '*.wit'))
        $broken = 0
        foreach ($f in $files) {
            & wasm-tools component wit $f.FullName *> $null
            if ($LASTEXITCODE -ne 0) { $broken++ }
        }
        if ($files.Count -eq 0) {
            Write-Warn "wasm-tools $ver (no .wit files to validate)"
        } elseif ($broken -eq 0) {
            Write-Ok "wasm-tools $ver (parses all $($files.Count) wit/ file(s))"
        } else {
            Write-Bad "wasm-tools $ver cannot parse $broken of $($files.Count) wit/ file(s)"
            Write-Note 'Either the tool is too old, or a WIT file is malformed.'
            Write-Note 'Ask which: python tools/check_wit.py'
        }
    } else {
        Write-Warn "wasm-tools $ver (no wit/ directory to validate against)"
    }
}

function Test-Wasmtime {
    if (-not (Test-Tool 'wasmtime')) {
        if ($Check) {
            # The failure the item records, so it is a hard error rather than a
            # warning: the contributor path is broken without it.
            Write-Bad 'the wasmtime CLI is not installed'
            Write-Note "Install: cargo install wasmtime-cli --version ^$WasmtimeMajor --locked"
        } else {
            Write-Warn "the wasmtime CLI is not installed; installing $WasmtimeMajor.x"
            cargo install wasmtime-cli --version "^$WasmtimeMajor" --locked
        }
        return
    }
    $ver = Get-ToolVersion 'wasmtime'
    if ([string]::IsNullOrEmpty($ver)) {
        Write-Bad 'the wasmtime CLI reported no parseable version'
        return
    }
    if ((Get-Major $ver) -eq $WasmtimeMajor) {
        Write-Ok "wasmtime $ver (matches the pinned crate major)"
    } else {
        Write-Bad "wasmtime $ver does not match the engine's major ($WasmtimeMajor)"
        Write-Note 'A component the CLI validates may not be one the engine can load.'
        Write-Note "Install the matching CLI:"
        Write-Note "    cargo install wasmtime-cli --version ^$WasmtimeMajor --locked --force"
    }
}

<#
    Tools the full CI gate needs. Absent ones are warnings rather than failures,
    because a contributor can run `cargo test` without them and should not be
    blocked from starting — but they should know before opening a PR that fails.
#>
function Test-Auxiliary {
    foreach ($tool in @('cargo-fuzz', 'cargo-cyclonedx', 'cargo-deny', 'cargo-machete')) {
        if (Test-Tool $tool) {
            Write-Ok "$tool present"
        } else {
            Write-Warn "$tool is not installed (needed for the full CI gate, not cargo test)"
            Write-Note "Install: cargo install $tool --locked"
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host 'QQQ developer bootstrap'
Write-Host '======================'
if ($Check) {
    Write-Host 'mode: -Check (nothing will be installed)'
} else {
    Write-Host 'mode: install (missing tools are installed)'
}
Write-Host ''

Write-Host 'toolchain'
Test-Rust

Write-Host ''
Write-Host 'component toolchain'
Test-WasmTools
Test-Wasmtime

Write-Host ''
Write-Host 'auxiliary tools'
Test-Auxiliary

Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host "$($script:Failures) check(s) failed." -ForegroundColor Red
    if ($Check) {
        Write-Host 'Re-run without -Check to install what is missing.' -ForegroundColor Red
    }
    exit 1
}
Write-Host 'Environment is ready. Next:'
Write-Host '    cargo test --workspace'
Write-Host '    python tools/audit_requirements.py'
