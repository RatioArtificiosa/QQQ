<#
.SYNOPSIS
    QQQ development bridge — run the Linux half of verification from Windows.

.DESCRIPTION
    A thin wrapper over `docker compose run --rm` that never exposes raw Docker
    commands to a developer or an agent.

    # Why a wrapper rather than remembering the docker invocations

    Three reasons, and the third is the one that matters:

      1. The compose invocation has a fixed shape (profile, service, volume set)
         that is easy to get subtly wrong by hand.
      2. Output has to be shaped for a human reading a terminal *and* for an agent
         parsing a result, and that shaping belongs in one place.
      3. **A command name is a contract.** `qqqdev test-linux` states an intent;
         `docker compose run --rm -v ... linux test-linux` states an
         implementation, and an implementation invites someone to try a variant
         that violates the one-way source rule.

    # The commands

        qqqdev status        what the environment contains, and its provenance
        qqqdev test          the full gate set, natively on Linux
        qqqdev test-linux    the tests that only execute on Linux (SEC-019 and friends)
        qqqdev checks        the repository's own python checkers
        qqqdev inject        prove the security guards are live, on Linux
        qqqdev fuzz [secs]   run the fuzz targets with ASan, persistently
        qqqdev matrix        Windows + Linux together, as one report
        qqqdev build         rebuild the image (after a Dockerfile change)
        qqqdev shell         an interactive shell, for diagnosing a failure
        qqqdev clean         remove the Linux volumes (reclaims disk)

.EXAMPLE
    pwsh tools/qqqdev.ps1 test-linux
    pwsh tools/qqqdev.ps1 fuzz 300 manifest_parse
    pwsh tools/qqqdev.ps1 matrix
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'test', 'test-linux', 'checks', 'inject', 'guard-prove',
                 'fuzz', 'matrix', 'build', 'shell', 'clean', 'help')]
    [string]$Command = 'status',

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = 'Stop'

# # Why the exit code travels in a GLOBAL rather than a script-scoped variable
#
# `Invoke-Linux` writes the container's output to the success stream, and PowerShell
# returns everything on that stream *plus* any explicit `return` -- so a function
# that ran a native command and returned its exit code returns an **array**. The
# first working `status` therefore printed the whole report as the "exit code".
#
# A script-scoped variable did not fix it either: `$script:` resolves to the script
# scope of the file being executed, which for a `switch` dispatch calling a function
# is not the scope that function writes to. `$global:` is unambiguous and this
# script owns the process, so there is no collision to worry about.
$global:LastLinuxExit = 0

# Resolve the repository root from this script's own location, so the wrapper works
# from any working directory — an agent running a command from an unexpected cwd is
# a real failure mode, and `..`-relative paths in a script are how that breaks.
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$ComposeFile = Join-Path $RepoRoot 'docker/compose.yaml'

function Write-Header([string]$Text) {
    Write-Host ''
    Write-Host ('━' * 68) -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('━' * 68) -ForegroundColor DarkCyan
}

function Assert-Docker {
    # # Why this is checked rather than assumed
    #
    # A missing or stopped Docker produces a long, confusing error from compose.
    # The check costs milliseconds and turns that into one sentence naming the fix.
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "docker was not found on PATH. Install Docker Desktop and start it."
    }

    # `docker info` is the only reliable liveness check: the CLI can be present
    # while the daemon is stopped, which is the common state after a reboot.
    $null = docker info --format '{{.ServerVersion}}' 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "The Docker daemon is not running. Start Docker Desktop and retry."
    }
}

function Invoke-Linux {
    <#
    .SYNOPSIS
        Run one command inside the Linux service, streaming its output.

    .DESCRIPTION
        # Why `docker compose run` is invoked with redirection rather than bare

        Found by running it: the first working `qqqdev status` reported

            status failed with exit code ── QQQ Linux verification ── ...

        The exit code had been *replaced by the container's stdout text*. The cause
        is that `docker compose run` writes its progress lines ("Container ... Creating")
        to **stderr**, PowerShell merges native stderr into the success stream, and
        the merged text became the value of the `Invoke-Linux` return expression
        instead of the exit code.

        So the exit code is captured from `$LASTEXITCODE` into a local **immediately**
        after the native call, before any other statement can overwrite it, and that
        local is what is returned. The progress lines are suppressed with
        `--quiet-pull` plus `2>$null` because they are Docker's narration, not the
        command's result — an agent parsing output should not have to filter
        "Container Created" out of a test report.
    #>
    param(
        [string[]]$LinuxArgs,
        [switch]$NoSourceGuard
    )

    $envArgs = @()
    if ($NoSourceGuard) {
        # The injection command mutates and restores source by design; the
        # entrypoint already opts out of its own guard, and this flag documents
        # that at the call site rather than burying it.
        $envArgs = @('-e', 'QQQ_ALLOW_SOURCE_WRITES=1')
    }

    # `--quiet-pull` keeps image-pull progress off stderr. `2>$null` discards the
    # remaining compose narration. Neither affects the container's own stdout or
    # stderr, which pass through unchanged.
    & docker compose -f $ComposeFile run --rm --quiet-pull @envArgs linux @LinuxArgs 2>$null

    # **Capture immediately**, before any other statement can clobber
    # `$LASTEXITCODE`. An earlier version of this function lost the capture when a
    # doc comment was edited in above it, and the symptom was a report whose "exit
    # code" was the empty string — worth stating because the bug is invisible in
    # review and obvious only when run.
    $exitCode = $LASTEXITCODE

    # # Why the exit code travels in a global rather than being returned
    #
    # Found by running it: `Invoke-Linux` returned an **array**, not an integer,
    # because PowerShell returns everything a function writes to its success stream
    # *plus* any explicit `return`. The container's stdout was therefore prepended
    # to the exit code, and the caller's `$code -ne 0` comparison printed the whole
    # report as the "exit code".
    #
    # `return $exitCode` alone cannot fix that — the output is already on the
    # stream. So the code travels in a global, which is not part of the return
    # value, and the function explicitly returns nothing.
    $global:LastLinuxExit = $exitCode
}

function Show-Status {
    Write-Header 'QQQ Linux verification environment'
    Invoke-Linux @('status')
    $code = $global:LastLinuxExit
    if ($code -ne 0) { throw "status failed with exit code $code" }
}

function Invoke-Test {
    Write-Header 'Full gate set, on Linux'
    Invoke-Linux @('test')
    $code = $global:LastLinuxExit
    if ($code -ne 0) { throw "Linux tests FAILED (exit $code)" }
    Write-Host "`nAll Linux gates passed." -ForegroundColor Green
}

function Invoke-TestLinux {
    Write-Header 'Linux-only tests (the ones Windows cannot run)'
    Invoke-Linux @('test-linux')
    $code = $global:LastLinuxExit
    if ($code -ne 0) { throw "Linux-only tests FAILED (exit $code)" }
    Write-Host "`nLinux-only tests passed." -ForegroundColor Green
}

function Invoke-Checks {
    Write-Header 'Repository checkers, on Linux'
    Invoke-Linux @('checks')
    $code = $global:LastLinuxExit
    if ($code -ne 0) { throw "checkers FAILED (exit $code)" }
}

function Invoke-Inject {
    Write-Header 'Fault injection — proving the guards are live'
    Invoke-Linux @('inject') -NoSourceGuard
    $code = $global:LastLinuxExit
    if ($code -ne 0) { throw "NOT every injection was caught (exit $code)" }
    Write-Host "`nEvery injection was caught." -ForegroundColor Green
}

# Prove the source guard refuses a write to /workspace.
#
# The guard is the only thing enforcing the one-way rule (the bind mount is
# read-write on purpose), so it is exactly the class of control this project has
# been burned by before: believed live, never seen firing. This command makes it
# fire deliberately and asserts the exit code.
function Invoke-GuardProve {
    Write-Header 'Source guard — proving it refuses a write to /workspace'
    Invoke-Linux @('guard-prove') -NoSourceGuard
    $code = $global:LastLinuxExit
    if ($code -ne 0) { throw "the source guard did NOT trip (exit $code)" }
    Write-Host "`nThe source guard is live." -ForegroundColor Green
}

function Invoke-Fuzz {
    param([string[]]$Rest)

    $seconds = '300'
    $targets = @()

    if ($Rest.Count -gt 0) {
        # A leading integer is the duration; everything else is a target name. This
        # keeps `qqqdev fuzz 300` and `qqqdev fuzz 300 manifest_parse` both working
        # without requiring a flag for the common case.
        if ($Rest[0] -match '^\d+$') {
            $seconds = $Rest[0]
            $targets = $Rest[1..($Rest.Count - 1)]
        } else {
            $targets = $Rest
        }
    }

    if (-not $targets) {
        $fuzzDir = Join-Path $RepoRoot 'fuzz/fuzz_targets'
        $targets = Get-ChildItem $fuzzDir -Filter '*.rs' |
            ForEach-Object { $_.BaseName }
    }

    Write-Header "Fuzzing $($targets -join ', ') for ${seconds}s each, with ASan"
    Invoke-Linux (@('fuzz', $seconds) + $targets)
    $code = $global:LastLinuxExit

    # # Why the two failure codes are kept apart
    #
    # `1` is a real sanitizer/libFuzzer crash -- a finding worth investigating.
    # `2` is the harness aborting before any input ran (a missing corpus directory,
    # a compile error). Reporting the second as the first is how a genuine crash
    # later gets dismissed as "that fuzz thing again".
    switch ($code) {
        0 { Write-Host "`nNo crashes." -ForegroundColor Green }
        1 { throw "fuzzing found a crash (exit 1) -- read the log in the results volume" }
        2 { throw "the fuzz HARNESS failed (exit 2) -- no inputs were executed" }
        default { throw "fuzzing failed unexpectedly (exit $code)" }
    }
}

function Invoke-Matrix {
    <#
    .SYNOPSIS
        The headline command: Windows and Linux, one report.

    .DESCRIPTION
        # Why this is worth building rather than running two commands

        The question the bridge answers is *"is this change verified?"*, and the
        answer is only meaningful across both platforms. Two commands produce two
        logs and no answer; this produces one table and says PASS or FAIL, which is
        what an agent needs to decide whether work is finished.

        Windows failures and Linux failures are reported separately, because they
        mean different things: a Windows failure is usually local, while a Linux
        failure on code that only compiles there (`SEC-019`'s guards) is invisible
        from Windows entirely.
    #>

    Write-Header 'QQQ verification matrix'

    $results = [ordered]@{}

    # -- Windows --------------------------------------------------------------
    Write-Host "`n[1/3] Windows — cargo test" -ForegroundColor Yellow
    Push-Location $RepoRoot
    try {
        $out = & cargo test --workspace 2>&1 | Out-String
        $winOk = $LASTEXITCODE -eq 0
        $winSummary = ($out -split "`n" |
            Select-String -Pattern '^test result: ok\. (\d+) passed' |
            ForEach-Object { [int]$_.Matches[0].Groups[1].Value } |
            Measure-Object -Sum).Sum
        if ($null -eq $winSummary) { $winSummary = 0 }
        $results['Windows x64'] = @{ Ok = $winOk; Detail = "$winSummary passed" }
    }
    finally { Pop-Location }

    # -- Linux ----------------------------------------------------------------
    Write-Host "`n[2/3] Linux — cargo test" -ForegroundColor Yellow
    Invoke-Linux @('test')
    $linuxTestOk = ($global:LastLinuxExit -eq 0)
    $results['Linux x64'] = @{
        Ok     = $linuxTestOk
        Detail = if ($linuxTestOk) { 'gate set passed' } else { 'FAILED' }
    }

    # -- Linux checks ---------------------------------------------------------
    Write-Host "`n[3/3] Linux — repository checkers" -ForegroundColor Yellow
    Invoke-Linux @('checks')
    $checksOk = ($global:LastLinuxExit -eq 0)
    $results['Linux checkers'] = @{
        Ok     = $checksOk
        Detail = if ($checksOk) { 'all passed' } else { 'FAILED' }
    }

    # -- The report -----------------------------------------------------------
    Write-Host ''
    Write-Host ('╔' + ('═' * 60) + '╗') -ForegroundColor Cyan
    Write-Host ('║' + ' QQQ VERIFICATION MATRIX'.PadRight(60) + '║') -ForegroundColor Cyan
    Write-Host ('╠' + ('═' * 20) + '╦' + ('═' * 24) + '╦' + ('═' * 15) + '╣') -ForegroundColor Cyan
    Write-Host ('║' + ' Environment'.PadRight(20) + '║' + ' Detail'.PadRight(24) + '║' + ' Result'.PadRight(15) + '║') -ForegroundColor Cyan
    Write-Host ('╠' + ('═' * 20) + '╬' + ('═' * 24) + '╬' + ('═' * 15) + '╣') -ForegroundColor Cyan

    $allOk = $true
    foreach ($env in $results.Keys) {
        $r = $results[$env]
        if (-not $r.Ok) { $allOk = $false }
        $verdict = if ($r.Ok) { 'PASS' } else { 'FAIL' }
        $colour = if ($r.Ok) { 'Green' } else { 'Red' }

        Write-Host ('║ ' + $env.PadRight(18) + '║ ' + $r.Detail.PadRight(22) + '║ ') -NoNewline
        Write-Host $verdict.PadRight(13) -NoNewline -ForegroundColor $colour
        Write-Host '║'
    }
    Write-Host ('╚' + ('═' * 20) + '╩' + ('═' * 24) + '╩' + ('═' * 15) + '╝') -ForegroundColor Cyan

    if (-not $allOk) {
        throw 'The matrix has failures. See the sections above.'
    }
    Write-Host "`nEverything verified." -ForegroundColor Green
}

function Invoke-Build {
    Write-Header 'Rebuilding the Linux image'
    & docker compose -f $ComposeFile build --pull linux
    if ($LASTEXITCODE -ne 0) { throw 'image build failed' }
}

function Invoke-Shell {
    Write-Header 'Interactive shell (type `exit` to leave)'
    Invoke-Linux @('shell') | Out-Null
}

function Invoke-Clean {
    Write-Header 'Removing Linux volumes'

    # # Why this is a separate command with a warning
    #
    # The volumes hold the cargo registry cache and the fuzz corpus. Removing them
    # reclaims several gigabytes but costs a full re-download and loses accumulated
    # fuzzing coverage — so it is deliberate, never automatic.
    Write-Host 'This removes the Linux build trees, the cargo cache, and the fuzz corpus.' -ForegroundColor Yellow
    $answer = Read-Host 'Type "yes" to continue'
    if ($answer -ne 'yes') {
        Write-Host 'Cancelled.'
        return
    }

    & docker compose -f $ComposeFile down --volumes --remove-orphans
    Write-Host 'Volumes removed.' -ForegroundColor Green
}

function Show-Help {
    Write-Host ''
    Write-Host 'qqqdev — the QQQ development bridge' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  status        environment contents and provenance'
    Write-Host '  test          the full gate set, natively on Linux'
    Write-Host '  test-linux    the tests that only execute on Linux'
    Write-Host '  checks        the repository python checkers'
    Write-Host '  inject        prove the security guards are live, on Linux'
    Write-Host '  fuzz [secs] [targets...]   fuzz with ASan, corpus persisted'
    Write-Host '  matrix        Windows + Linux in one report'
    Write-Host '  build         rebuild the image'
    Write-Host '  shell         interactive shell for diagnosing a failure'
    Write-Host '  clean         remove the Linux volumes (reclaims disk)'
    Write-Host ''
    Write-Host 'Documentation: docs/development-bridge.md' -ForegroundColor DarkGray
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

Assert-Docker

switch ($Command) {
    'status'     { Show-Status }
    'test'       { Invoke-Test }
    'test-linux' { Invoke-TestLinux }
    'checks'     { Invoke-Checks }
    'inject'     { Invoke-Inject }
    'guard-prove' { Invoke-GuardProve }
    'fuzz'       { Invoke-Fuzz -Rest $Arguments }
    'matrix'     { Invoke-Matrix }
    'build'      { Invoke-Build }
    'shell'      { Invoke-Shell }
    'clean'      { Invoke-Clean }
    'help'       { Show-Help }
}
