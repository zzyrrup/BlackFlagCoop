<#
.SYNOPSIS
  Starts the BlackFlagCoop LAN host listener on this PC.

.NOTES
  Default bind: 0.0.0.0
  Default port: 27016
  Does not touch any game directory.
  Does not create firewall rules. See Show-LanFirewallCommand.ps1.
#>

[CmdletBinding()]
param(
    [string]$Bind = "0.0.0.0",
    [uint16]$Port = 27016,
    [int]$AcceptTimeoutMs = 120000,
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

Write-Host "=== BlackFlagCoop LAN HOST ==="
Write-Host "Exe             : $exe"
Write-Host "Bind            : $Bind"
Write-Host "Port            : $Port"
Write-Host "Accept timeout  : $AcceptTimeoutMs ms"
Write-Host "Host PC IPv4    : 10.0.0.95 (expected)"
Write-Host "Client command  : BlackFlagCoopNetTest.exe --client --connect 10.0.0.95 --port $Port"
Write-Host "Firewall helper : scripts\Show-LanFirewallCommand.ps1"
Write-Host ""

& $exe --host --bind $Bind --port $Port --accept-timeout-ms $AcceptTimeoutMs
exit $LASTEXITCODE
