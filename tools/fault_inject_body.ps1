#!/usr/bin/env pwsh
# Fault injection for qqq-serve::body (SRV-004 / SRV-005).
#
# Proves the new tests can FAIL. Each injection breaks one invariant, runs the
# body suite, and records which tests caught it.
#
# Line-based rather than multi-line string replacement: an earlier version
# matched "\r\n" against an LF-only file (injections silently did not apply) and
# then wrote with -NoNewline, which concatenated lines. Both failures were
# silent, which is exactly the class this project keeps recording.
#
# Every injection asserts that it APPLIED before running the suite, and every
# restore asserts the marker is GONE (Observations §M-008). A check that cannot
# fail is not a check.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src  = Join-Path $root 'crates/qqq-serve/src/body.rs'
$good = Join-Path $root '.scratch/body_good.rs'

Copy-Item $src $good -Force
Write-Host "backed up body.rs -> .scratch/body_good.rs`n"

function Set-Line {
    param([string]$Match, [string]$Replacement)
    $lines = [System.IO.File]::ReadAllLines($src)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -like "*$Match*") {
            $lines[$i] = $Replacement
            [System.IO.File]::WriteAllLines($src, $lines, [System.Text.UTF8Encoding]::new($false))
            return $true
        }
    }
    return $false
}

function Restore-And-Verify {
    param([string]$Marker)
    Copy-Item $good $src -Force
    if (Select-String -Path $src -SimpleMatch $Marker -Quiet) {
        Write-Host "  !! RESTORE FAILED: '$Marker' still present" -ForegroundColor Red
        exit 1
    }
    Write-Host "  restored, marker absent`n"
}

function Failed-Tests {
    # `--test body` names the target; the build is forced by touching nothing and
    # relying on cargo's mtime check. That check was **not** reliable here: this
    # script rewrites `body.rs` several times per second, and one run reported
    # seven failures *after* a byte-identical restore because cargo ran the
    # previously compiled binary. The source was correct and the report was
    # wrong, which is the most expensive kind of false alarm.
    #
    # So each run stamps the file first, which moves its mtime strictly forward
    # and makes the rebuild decision unambiguous.
    (Get-Item $src).LastWriteTime = Get-Date
    $out = cargo test -p qqq-serve --test body 2>&1 | Out-String
    return ([regex]::Matches($out, '(?m)^test (\S+) \.\.\. FAILED')) |
        ForEach-Object { $_.Groups[1].Value }
}

$results = @()

function Run-Injection {
    param([string]$Name, [string]$Match, [string]$Replacement, [string]$Marker)
    Write-Host "INJECTION: $Name" -ForegroundColor Cyan
    if (-not (Set-Line -Match $Match -Replacement $Replacement)) {
        Write-Host "  !! DID NOT APPLY (anchor not found: '$Match')" -ForegroundColor Red
        exit 1
    }
    if (-not (Select-String -Path $src -SimpleMatch $Marker -Quiet)) {
        Write-Host "  !! DID NOT APPLY (marker absent after edit)" -ForegroundColor Red
        exit 1
    }
    $failed = Failed-Tests
    $shown = if ($failed.Count -eq 0) { '<NOTHING - TEST IS NOT EVIDENCE>' } else { $failed -join ', ' }
    Write-Host "  caught by: $shown"
    $script:results += [pscustomobject]@{ Injection = $Name; CaughtBy = ($failed -join ', ') }
    Restore-And-Verify $Marker
}

# 1. The cap is recorded but never enforced == "enforced after buffering"
#    degraded to "not enforced at all".
Run-Injection -Name 'cap not enforced' `
    -Match 'if self.seen > self.max_bytes {' `
    -Replacement '        if false && self.seen > self.max_bytes {' `
    -Marker 'if false && self.seen'

# 2. Chunk terminator not consumed: the framing offset goes wrong, which is the
#    request-smuggling shape the module exists to prevent.
Run-Injection -Name 'chunk CRLF not consumed' `
    -Match 'self.expect_crlf(io).await?;' `
    -Replacement '            // injected: terminator skipped' `
    -Marker 'injected: terminator skipped'

# 3. Trailers not consumed: the connection is left pointing into the trailer.
Run-Injection -Name 'trailers not consumed' `
    -Match 'self.read_trailers(io).await?;' `
    -Replacement '                // injected: trailers skipped' `
    -Marker 'injected: trailers skipped'

# 4. The caller's `max` ignored: backpressure is gone, so the decoder reads as
#    much as it can regardless of what the caller asked for.
Run-Injection -Name "caller's max ignored" `
    -Match 'if self.finished {' `
    -Replacement '        let max = usize::MAX; if self.finished {' `
    -Marker 'let max = usize::MAX;'

# 5. Dual-framing head accepted: the redundant smuggling check removed.
Run-Injection -Name 'dual-framing head accepted' `
    -Match 'if head.chunked && head.content_length.is_some() {' `
    -Replacement '        if false && head.chunked && head.content_length.is_some() {' `
    -Marker 'if false && head.chunked'

# 6. The chunked terminator accepted without reading the zero chunk: the body
#    appears to end early and `End` is reported for a body still in flight.
Run-Injection -Name 'chunk size line ignored' `
    -Match 'let size = self.read_chunk_size(io).await?;' `
    -Replacement '        let size = { let _ = self.read_chunk_size(io).await?; 0u64 };' `
    -Marker '0u64 };'

# --- Final: green after restoration ----------------------------------------
#
# This is the assertion that would have caught the stale-binary false alarm:
# after every injection is undone, the suite must be green. When it is not, the
# restore is verified byte-for-byte against the backup before anything else is
# concluded — because the failure can be in the *reporting*, not the source.
Write-Host "FINAL: suite with everything restored" -ForegroundColor Green
(Get-Item $src).LastWriteTime = Get-Date
$out = cargo test -p qqq-serve --test body 2>&1 | Out-String
$finalLine = ([regex]::Matches($out, '(?m)^test result: .*')) | ForEach-Object { $_.Value }
Write-Host "  $finalLine"

if ($finalLine -notmatch 'test result: ok') {
    $same = (Get-FileHash $src).Hash -eq (Get-FileHash $good).Hash
    Write-Host "  source identical to backup: $same" -ForegroundColor Yellow
    Write-Host "  FAILING FINAL RUN - the restored tree must be green" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== SUMMARY ==="
$results | Format-Table -AutoSize | Out-String | Write-Host

$missed = @($results | Where-Object { [string]::IsNullOrWhiteSpace($_.CaughtBy) })
if ($missed.Count -eq 0) {
    Write-Host "ALL $($results.Count) INJECTIONS DETECTED - the body tests are live" -ForegroundColor Green
    exit 0
} else {
    Write-Host "$($missed.Count) INJECTION(S) NOT DETECTED - those tests are not evidence" -ForegroundColor Red
    $missed | ForEach-Object { Write-Host "  - $($_.Injection)" }
    exit 1
}
