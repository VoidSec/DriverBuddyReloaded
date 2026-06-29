<#
.SYNOPSIS
    Golden-output regression for Driver Buddy Reloaded.

.DESCRIPTION
    For each reference driver under tests/drivers that has a committed
    "<driver>.golden.json", copies the .i64 database and its golden file to an
    isolated temp directory (so IDA never re-saves the repo copy) and runs the
    full analysis pipeline headless via tests/ida_smoke.py.  ida_smoke
    auto-discovers the adjacent golden and compares the freshly produced findings
    against it order-insensitively on (category, title, severity, IOCTL
    code/method/access).  Any added finding (false positive), missing finding
    (false negative) or severity change fails the cell.

    The goldens are the captured output of the current pipeline; regenerate them
    deliberately (see tests/README or CLAUDE.md) only when an intended change
    alters the findings.

.PARAMETER IdaExe
    idat64 used to run the analysis.  Must match the IDA version the goldens were
    captured with (IDA Pro 8.4 by default); a different decompiler build can
    legitimately produce different heuristic findings.

.EXAMPLE
    pwsh tests\run_golden.ps1
    pwsh tests\run_golden.ps1 -IdaExe "C:\Program Files\IDA Pro 8.4\idat64.exe" -KeepTemp
#>

param(
    [string]$IdaExe = "C:\Program Files\IDA Pro 8.4\idat64.exe",
    [int]$Timeout = 180,
    [switch]$KeepTemp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$RepoRoot    = $PSScriptRoot | Split-Path -Parent
$SmokeScript = Join-Path $RepoRoot 'tests\ida_smoke.py'
$DriversDir  = Join-Path $RepoRoot 'tests\drivers'

if (-not (Test-Path $IdaExe)) {
    Write-Error "IDA executable not found: $IdaExe"
    exit 2
}

$goldens = Get-ChildItem $DriversDir -Filter '*.golden.json'
if (-not $goldens) {
    Write-Error "No golden files in $DriversDir"
    exit 2
}

Write-Host ""
Write-Host "Driver Buddy Reloaded - golden-output regression"
Write-Host "================================================"
Write-Host ("IDA : {0}" -f $IdaExe)
Write-Host ""

$results  = [System.Collections.Generic.List[PSObject]]::new()
$tempDirs = [System.Collections.Generic.List[string]]::new()

foreach ($golden in $goldens) {
    # "HEVD.sys.golden.json" -> idb "HEVD.sys.i64"
    $idbName = $golden.Name -replace '\.golden\.json$', '.i64'
    $idbPath = Join-Path $DriversDir $idbName
    if (-not (Test-Path $idbPath)) {
        Write-Warning ("No .i64 for golden {0}; skipping" -f $golden.Name)
        continue
    }

    $tmp = Join-Path $RepoRoot ("golden_tmp_" + ($idbName -replace '\.i64$',''))
    $null = New-Item -ItemType Directory -Force -Path $tmp
    $tempDirs.Add($tmp)
    Copy-Item $idbPath   (Join-Path $tmp $idbName) -Force
    Copy-Item $golden.FullName (Join-Path $tmp $golden.Name) -Force

    $idbCopy = Join-Path $tmp $idbName
    $logFile = Join-Path $tmp 'ida.log'
    $resultJson = [System.IO.Path]::ChangeExtension($idbCopy, '.smoke.json')

    Write-Host ("  {0,-22} ... " -f $idbName) -NoNewline

    try {
        $proc = Start-Process -FilePath $IdaExe `
            -ArgumentList @('-A', ('-L{0}' -f $logFile), ('-S{0}' -f $SmokeScript), $idbCopy) `
            -WindowStyle Hidden -PassThru
        $finished = $proc.WaitForExit($Timeout * 1000)
        if (-not $finished) { $proc.Kill(); $exit = -1 } else { $exit = $proc.ExitCode }
    } catch {
        $exit = -2
    }

    $status = 'no_result'; $detail = ''
    if (Test-Path $resultJson) {
        try {
            $json = Get-Content $resultJson -Raw | ConvertFrom-Json
            $status = $json.status
            if ($json.checks -and $json.checks.golden) { $detail = $json.checks.golden.detail }
        } catch { $status = 'parse_error' }
    }

    $pass = ($exit -eq 0) -and ($status -eq 'ok')
    if ($pass) {
        Write-Host "PASS" -ForegroundColor Green
    } else {
        Write-Host "FAIL" -ForegroundColor Red -NoNewline
        Write-Host (" (exit=$exit status=$status) $detail")
    }
    $results.Add([PSCustomObject]@{ Driver = $idbName; Pass = $pass })
}

if (-not $KeepTemp) {
    foreach ($d in $tempDirs) { Remove-Item -Path $d -Recurse -Force -ErrorAction SilentlyContinue }
}

$total  = $results.Count
$passed = ($results | Where-Object { $_.Pass } | Measure-Object).Count
$failed = $total - $passed
Write-Host ""
Write-Host ("Total: {0}   Passed: {1}   Failed: {2}" -f $total, $passed, $failed)
exit ($(if ($failed -gt 0) { 1 } else { 0 }))
