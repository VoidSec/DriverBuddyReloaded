<#
.SYNOPSIS
    Cross-version smoke test for Driver Buddy Reloaded.
    Invokes the full analysis pipeline under IDA 7.6 SP1, 8.4 and Free 9.3 on a
    matrix of representative Windows kernel drivers and prints a pass/fail table.

.DESCRIPTION
    Each cell in the matrix copies the driver to an isolated temp directory (so
    IDA never writes .i64 files into System32), launches IDA in autonomous batch
    mode with tests/ida_smoke.py, then parses the JSON summary it writes.

.PARAMETER ResultsDir
    Directory that receives per-cell JSON summaries and IDA log files.
    Defaults to <repo_root>\smoke_results.

.PARAMETER Timeout
    Maximum seconds to wait for each IDA invocation before killing it.
    Default: 120.

.PARAMETER KeepTemp
    When set, temporary driver copies are NOT deleted after the run.

.EXAMPLE
    pwsh tests\run_cross_version.ps1
    pwsh tests\run_cross_version.ps1 -Timeout 180 -KeepTemp
#>

param(
    [string]$ResultsDir = "",
    [int]$Timeout = 120,
    [switch]$KeepTemp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$RepoRoot    = $PSScriptRoot | Split-Path -Parent
$SmokeScript = Join-Path $RepoRoot 'tests\ida_smoke.py'

if (-not $ResultsDir) {
    $ResultsDir = Join-Path $RepoRoot 'smoke_results'
}
$ResultsDir = [System.IO.Path]::GetFullPath($ResultsDir)
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null

# ---------------------------------------------------------------------------
# IDA installations  (idat64 is the headless text-mode exe; ida.exe on 9.3)
# ---------------------------------------------------------------------------
$IDA_INSTALLS = @(
    [PSCustomObject]@{
        Version = '7.6'
        Exe     = 'C:\Users\c108\Desktop\IDA Pro 7.6 SP1\idat64.exe'
    },
    [PSCustomObject]@{
        Version = '8.4'
        Exe     = 'C:\Program Files\IDA Pro 8.4\idat64.exe'
    },
    [PSCustomObject]@{
        Version = '9.3'
        Exe     = 'C:\Program Files\IDA Free 9.3\ida.exe'
    }
)

# ---------------------------------------------------------------------------
# Test drivers - covers WDM (null, beep), minifilter (fltmgr), and a real
# IOCTL driver (ctrl2cap) to give meaningful finding counts.
# ---------------------------------------------------------------------------
$TEST_DRIVERS = @(
    [PSCustomObject]@{
        Name = 'ctrl2cap'
        Path = 'C:\Users\c108\Desktop\Portal\SysinternalsSuite\ctrl2cap.amd.sys'
    },
    [PSCustomObject]@{
        Name = 'null'
        Path = 'C:\Windows\System32\drivers\null.sys'
    },
    [PSCustomObject]@{
        Name = 'beep'
        Path = 'C:\Windows\System32\drivers\beep.sys'
    },
    [PSCustomObject]@{
        Name = 'fltmgr'
        Path = 'C:\Windows\System32\drivers\fltmgr.sys'
    }
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Invoke-IDA {
    param(
        [string]$IdaExe,
        [string]$DriverPath,
        [string]$ResultJson,
        [string]$LogFile,
        [int]$TimeoutSec
    )

    # -A        autonomous (suppress all dialogs)
    # -L<file>  append IDA console output to <file> (no space between L and path)
    # -S<...>   run <script> [arg...] after opening database (space-separated)
    # The driver path is the positional argument.
    #
    # None of these paths contain spaces (repo root is C:\Users\c108\Documents\DriverBuddyReloaded,
    # temp is under that).  If paths ever gain spaces the -S argument must be
    # quoted differently -- IDA parses it as whitespace-separated tokens.
    $sArg = '-S{0} {1}' -f $SmokeScript, $ResultJson
    $lArg = '-L{0}' -f $LogFile

    try {
        $proc = Start-Process `
            -FilePath $IdaExe `
            -ArgumentList @('-A', $lArg, $sArg, $DriverPath) `
            -WindowStyle Hidden `
            -PassThru

        $finished = $proc.WaitForExit($TimeoutSec * 1000)
        if (-not $finished) {
            $proc.Kill()
            return -1   # timeout
        }
        return $proc.ExitCode
    }
    catch {
        return -2       # launch failure
    }
}

# ---------------------------------------------------------------------------
# Run the matrix
# ---------------------------------------------------------------------------
$Results  = [System.Collections.Generic.List[PSObject]]::new()
$TempDirs = [System.Collections.Generic.List[string]]::new()

Write-Host ""
Write-Host "Driver Buddy Reloaded - cross-version smoke test"
Write-Host "================================================="
Write-Host ("Results dir : {0}" -f $ResultsDir)
Write-Host ("Timeout     : {0}s per cell" -f $Timeout)
Write-Host ""

foreach ($driver in $TEST_DRIVERS) {
    if (-not (Test-Path $driver.Path)) {
        Write-Warning ("Driver not found, skipping: {0}" -f $driver.Path)
        continue
    }

    foreach ($ida in $IDA_INSTALLS) {
        if (-not (Test-Path $ida.Exe)) {
            Write-Warning ("IDA executable not found, skipping: {0}" -f $ida.Exe)
            continue
        }

        # Copy driver to an isolated temp dir so IDA writes its .i64 there.
        $tmpDir     = Join-Path $RepoRoot "smoke_tmp_$($driver.Name)_$($ida.Version)"
        $null       = New-Item -ItemType Directory -Force -Path $tmpDir
        $TempDirs.Add($tmpDir)

        $driverCopy = Join-Path $tmpDir (Split-Path $driver.Path -Leaf)
        Copy-Item -Path $driver.Path -Destination $driverCopy -Force

        $cellId     = "$($ida.Version)_$($driver.Name)"
        $resultJson = Join-Path $ResultsDir "$cellId.json"
        $logFile    = Join-Path $ResultsDir "$cellId.log"

        Write-Host ("  IDA {0,-4}  {1,-10} ... " -f $ida.Version, $driver.Name) -NoNewline

        $exitCode = Invoke-IDA `
            -IdaExe     $ida.Exe `
            -DriverPath $driverCopy `
            -ResultJson $resultJson `
            -LogFile    $logFile `
            -TimeoutSec $Timeout

        # Parse the JSON summary written by ida_smoke.py.
        $status  = 'no_result'
        $summary = $null
        if (Test-Path $resultJson) {
            try {
                $json    = Get-Content $resultJson -Raw | ConvertFrom-Json
                $status  = $json.status
                $summary = $json.summary
            }
            catch {
                $status = 'parse_error'
            }
        }

        $pass   = ($exitCode -eq 0) -and ($status -eq 'ok')
        $symbol = if ($pass) { 'PASS' } else { 'FAIL' }
        $color  = if ($pass) { 'Green' } else { 'Red' }
        Write-Host $symbol -ForegroundColor $color -NoNewline

        if (-not $pass) {
            Write-Host (" (exit=$exitCode status=$status)") -NoNewline
        } elseif ($summary -and $summary.driver_type) {
            Write-Host (" driver=$($summary.driver_type)") -NoNewline
        }
        Write-Host ""

        $Results.Add([PSCustomObject]@{
            IDA     = $ida.Version
            Driver  = $driver.Name
            Pass    = $pass
            Exit    = $exitCode
            Status  = $status
            Summary = $summary
        })
    }
}

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
$Versions = $Results | Select-Object -ExpandProperty IDA    -Unique
$Drivers  = $Results | Select-Object -ExpandProperty Driver -Unique

Write-Host ""
Write-Host "Summary"
Write-Host "-------"

$header = "{0,-12}" -f "Driver"
foreach ($v in $Versions) { $header += "  IDA {0,-6}" -f $v }
Write-Host $header

foreach ($d in $Drivers) {
    $row = "{0,-12}" -f $d
    foreach ($v in $Versions) {
        $cell = $Results | Where-Object { $_.Driver -eq $d -and $_.IDA -eq $v } | Select-Object -First 1
        if ($null -ne $cell) {
            $sym = if ($cell.Pass) { 'PASS' } else { 'FAIL' }
            $row += "  {0,-10}" -f $sym
        } else {
            $row += "  {0,-10}" -f 'SKIP'
        }
    }
    Write-Host $row
}

$total  = $Results.Count
$passed = ($Results | Where-Object { $_.Pass } | Measure-Object).Count
$failed = $total - $passed
Write-Host ""
Write-Host ("Total: {0}   Passed: {1}   Failed: {2}" -f $total, $passed, $failed)

# ---------------------------------------------------------------------------
# Cleanup isolated temp dirs
# ---------------------------------------------------------------------------
if (-not $KeepTemp) {
    foreach ($d in $TempDirs) {
        Remove-Item -Path $d -Recurse -Force -ErrorAction SilentlyContinue
    }
}

exit ($failed -gt 0 ? 1 : 0)
