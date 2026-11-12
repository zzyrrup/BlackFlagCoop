<#
.SYNOPSIS
  Starts the BlackFlagCoop LAN client and connects to the host PC.

.NOTES
  Default connect target: 10.0.0.95:27016
  Run this on the second PC after the host is listening.
  Does not touch any game directory.
#>

[CmdletBinding()]
param(
    [string]$Connect = "10.0.0.95",
    [uint16]$Port = 27016,
    [string]$BuildDir = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    $BuildDir = Join-Path $projectRoot "build\bin\Release"
}

$exe = Join-Path $BuildDir "BlackFlagCoopNetTest.exe"
if (-not (Test-Path $exe)) {
    Write-Host "Missing $exe"
    Write-Host 'Build with: cmake -S . -B build -G "Visual Studio 18 2026" -A x64'
    Write-Host "            cmake --build build --config Release"
    exit 1
}

Write-Host "=== BlackFlagCoop LAN CLIENT ==="
Write-Host "Exe     : $exe"
Write-Host "Connect : ${Connect}:$Port"
Write-Host "Make sure the host is already listening."
Write-Host ""

& $exe --client --connect $Connect --port $Port
exit $LASTEXITCODE
