<#
.SYNOPSIS
  Launches BlackFlagCoopNetTest host and client on localhost and reports PASS/FAIL.

.NOTES
  Does not touch the game directory.
#>

[CmdletBinding()]
param(
    [string]$BuildDir = "",
    [uint16]$Port = 27015,
    [int]$HostStartupDelayMs = 700,
    [int]$Ticks = 3,
    [int]$StateIntervalMs = 100
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    $BuildDir = Join-Path $projectRoot "build\bin\Release"
}

$exe = Join-Path $BuildDir "BlackFlagCoopNetTest.exe"
if (-not (Test-Path $exe)) {
    Write-Host "FAIL: missing test executable: $exe"
    Write-Host "Build first:"
    Write-Host '  cmake -S . -B build -G "Visual Studio 18 2026" -A x64'
    Write-Host "  cmake --build build --config Release"
    exit 1
}

$outDir = Join-Path $projectRoot "build\nettest-output"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$hostOut = Join-Path $outDir "host.out.txt"
$hostErr = Join-Path $outDir "host.err.txt"
$clientOut = Join-Path $outDir "client.out.txt"
$clientErr = Join-Path $outDir "client.err.txt"
Remove-Item $hostOut, $hostErr, $clientOut, $clientErr -ErrorAction SilentlyContinue

Write-Host "=== BlackFlagCoop localhost net test (v0.4.0 presence/state) ==="
Write-Host "Exe : $exe"
Write-Host "Port: $Port"
Write-Host ""

$hostArgs = @(
    "--host", "--bind", "127.0.0.1", "--port", "$Port",
    "--accept-timeout-ms", "20000",
    "--ticks", "$Ticks", "--state-interval-ms", "$StateIntervalMs"
)
$clientArgs = @(
    "--client", "--connect", "127.0.0.1", "--port", "$Port",
    "--ticks", "$Ticks", "--state-interval-ms", "$StateIntervalMs"
)

$hostProc = Start-Process -FilePath $exe -ArgumentList $hostArgs `
    -RedirectStandardOutput $hostOut -RedirectStandardError $hostErr `
    -PassThru -NoNewWindow

Start-Sleep -Milliseconds $HostStartupDelayMs

$clientProc = Start-Process -FilePath $exe -ArgumentList $clientArgs `
    -RedirectStandardOutput $clientOut -RedirectStandardError $clientErr `
    -PassThru -NoNewWindow

$clientFinished = $clientProc.WaitForExit(60000)
$hostFinished = $hostProc.WaitForExit(60000)

if (-not $clientFinished) {
    try { $clientProc.Kill() } catch {}
}
if (-not $hostFinished) {
    try { $hostProc.Kill() } catch {}
}

$clientProc.Refresh()
$hostProc.Refresh()
if ($clientProc.HasExited) { [void]$clientProc.WaitForExit() }
if ($hostProc.HasExited) { [void]$hostProc.WaitForExit() }
$clientProc.Refresh()
$hostProc.Refresh()

Write-Host "----- HOST OUTPUT -----"
if (Test-Path $hostOut) { Get-Content $hostOut }
if ((Test-Path $hostErr) -and ((Get-Item $hostErr).Length -gt 0)) {
    Write-Host "----- HOST STDERR -----"
    Get-Content $hostErr
}
Write-Host ""
Write-Host "----- CLIENT OUTPUT -----"
if (Test-Path $clientOut) { Get-Content $clientOut }
if ((Test-Path $clientErr) -and ((Get-Item $clientErr).Length -gt 0)) {
    Write-Host "----- CLIENT STDERR -----"
    Get-Content $clientErr
}
Write-Host ""

$hostCode = if ($hostProc.HasExited) { [int]$hostProc.ExitCode } else { -1 }
$clientCode = if ($clientProc.HasExited) { [int]$clientProc.ExitCode } else { -1 }

Write-Host "Host exit code  : $hostCode"
Write-Host "Client exit code: $clientCode"

$hostText = ""
$clientText = ""
if (Test-Path $hostOut) { $hostText += Get-Content $hostOut -Raw }
if (Test-Path $hostErr) { $hostText += Get-Content $hostErr -Raw }
if (Test-Path $clientOut) { $clientText += Get-Content $clientOut -Raw }
if (Test-Path $clientErr) { $clientText += Get-Content $clientErr -Raw }

$passed =
    ($hostCode -eq 0) -and
    ($clientCode -eq 0) -and
    ($hostText -match "\[HOST\] PASS") -and
    ($clientText -match "\[CLIENT\] PASS") -and
    ($hostText -match "Presence event\s+:\s+Join") -and
    ($clientText -match "Presence event\s+:\s+Join") -and
    ($hostText -match "State update") -and
    ($clientText -match "State update")

if ($passed) {
    Write-Host ""
    Write-Host "RESULT: PASS — host and client exchanged presence/state on 127.0.0.1"
    exit 0
}

Write-Host ""
Write-Host "RESULT: FAIL — localhost host/client test did not fully succeed"
exit 1
