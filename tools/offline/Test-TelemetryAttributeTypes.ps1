<#
.SYNOPSIS
  Offline regression: verify PlayerPosX/Y/Z are declared as float in ACBlackFlag.exe .edata.

.DESCRIPTION
  Read-only. Does not launch the game or modify files. Used for BlackFlagCoop v0.5.5+.
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
if (($edataRaw + $edataSize) -gt $fs.Length) {
    $fs.Close()
    throw ".edata range invalid for this build"
}
$buf = New-Object byte[] $edataSize
$fs.Position = $edataRaw
[void]$fs.Read($buf, 0, $buf.Length)
$fs.Close()

$ascii = [Text.Encoding]::ASCII.GetString($buf)
$needles = @(
    '{"name":"PlayerPosX","type":"float","isOptional":true}',
    '{"name":"PlayerPosY","type":"float","isOptional":true}',
    '{"name":"PlayerPosZ","type":"float","isOptional":true}',
    '{"name":"player.position","type":"STANDARD"'
)

$fail = 0
foreach ($n in $needles) {
    if ($ascii.Contains($n)) {
        Write-Host "OK: found $n"
    } else {
        Write-Host "FAIL: missing $n"
        $fail++
    }
}

if ($fail -gt 0) {
    Write-Host "TEST_FAIL"
    exit 1
}
Write-Host "TEST_PASS"
exit 0
