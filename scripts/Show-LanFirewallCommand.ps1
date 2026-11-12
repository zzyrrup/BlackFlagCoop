<#
.SYNOPSIS
  Shows a narrowly scoped Windows Firewall command for LAN testing.
  Does NOT create the rule unless you pass -Apply after reviewing it.

.NOTES
  Scope: inbound TCP 27016, Private profile only.
  No Public profile, no router changes, no UPnP.
#>

[CmdletBinding()]
param(
    [uint16]$Port = 27016,
    [string]$RuleName = "BlackFlagCoop NetTest TCP 27016 (Private)",
    [switch]$Apply
)

$command = @"
New-NetFirewallRule ``
  -DisplayName "$RuleName" ``
  -Direction Inbound ``
  -Action Allow ``
  -Protocol TCP ``
  -LocalPort $Port ``
  -Profile Private ``
  -Program "Any" ``
  -Description "Temporary LAN test allow for BlackFlagCoopNetTest. Private profile only."
"@

Write-Host "=== BlackFlagCoop firewall helper ==="
Write-Host "This script does not silently change firewall settings."
Write-Host ""
Write-Host "Review this command first:"
Write-Host $command
Write-Host ""
Write-Host "To apply it yourself in an elevated PowerShell window, copy/paste the command above,"
Write-Host "or re-run this script with -Apply (still requires elevation / approval)."
Write-Host ""

if (-not $Apply) {
    Write-Host "No firewall changes were made."
    exit 0
}

Write-Host "Attempting to apply the rule now (requires Administrator)..."
try {
    New-NetFirewallRule `
        -DisplayName $RuleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort $Port `
        -Profile Private `
        -Program Any `
        -Description "Temporary LAN test allow for BlackFlagCoopNetTest. Private profile only." `
        -ErrorAction Stop | Out-Null
    Write-Host "Firewall rule created: $RuleName"
    Write-Host "Remove later with:"
    Write-Host "  Remove-NetFirewallRule -DisplayName `"$RuleName`""
    exit 0
} catch {
    Write-Host "Failed to create firewall rule:"
    Write-Host $_.Exception.Message
    Write-Host "No firewall rule was created."
    Write-Host "Open an elevated PowerShell (Run as administrator), then run:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\scripts\Show-LanFirewallCommand.ps1 -Apply"
    exit 1
}
