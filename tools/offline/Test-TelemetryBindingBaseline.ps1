<#
.SYNOPSIS
  Offline regression baseline for v0.5.6 binding research prerequisites.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ExePath
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ExePath)) { throw "Missing exe: $ExePath" }

$edataRaw = 0x9035600L
$edataSize = 0x127C000L
$fs = [IO.File]::OpenRead($ExePath)
if (($edataRaw + $edataSize) -gt $fs.Length) { $fs.Close(); throw ".edata range invalid" }
$buf = New-Object byte[] $edataSize
$fs.Position = $edataRaw
[void]$fs.Read($buf, 0, $buf.Length)
$fs.Close()
$ascii = [Text.Encoding]::ASCII.GetString($buf)

$checks = @(
    '{"name":"PlayerPosX","type":"float","isOptional":true}',
    '{"name":"PlayerPosY","type":"float","isOptional":true}',
    '{"name":"PlayerPosZ","type":"float","isOptional":true}',
    '{"name":"player.position","type":"STANDARD"',
    '{"name":"PositionSource","type":"string","isOptional":true}',
    '{"name":"World","type":"string","isOptional":true}'
)

$fail = 0
foreach ($c in $checks) {
    if ($ascii.Contains($c)) { Write-Host "OK: $c" }
    else { Write-Host "FAIL: $c"; $fail++ }
}

# Export presence via dumpbin-free string search in whole file would be heavy; check export name strings in PE
$fs = [IO.File]::OpenRead($ExePath)
$all = New-Object byte[] ([Math]::Min($fs.Length, 256MB))
# Only need export names region roughly; read full if smaller
$fs.Close()
$bytes = [IO.File]::ReadAllBytes($ExePath)
$allAscii = [Text.Encoding]::ASCII.GetString($bytes)
foreach ($e in @('Harbour_StringId_Registry_Find','Harbour_StringId_Registry_DumpTo')) {
    if ($allAscii.Contains($e)) { Write-Host "OK export string: $e" }
    else { Write-Host "FAIL export string: $e"; $fail++ }
}

if ($fail -gt 0) { Write-Host 'TEST_FAIL'; exit 1 }
Write-Host 'TEST_PASS'
exit 0
