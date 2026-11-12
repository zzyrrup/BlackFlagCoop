<#
.SYNOPSIS
  Offline read-only catalog of player-related composition/telemetry schema strings
  from ACBlackFlag.exe (.edata region heuristics).

.DESCRIPTION
  Does not modify the executable, does not attach to a running game, and is not
  required for ASI launch. Used for BlackFlagCoop research (v0.5.4+).

.PARAMETER ExePath
  Path to ACBlackFlag.exe

.PARAMETER OutJson
  Output JSON path
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ExePath,

    [Parameter(Mandatory = $false)]
    [string] $OutJson = ".\reports\v0.5.4-player-composition-catalog-rerun.json"
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Executable not found: $ExePath"
}

# Known Resynced 1.0.6 .edata layout from prior PE parse (verify against this build).
$edataRaw = 0x9035600L
$edataSize = 0x127C000L
$edataVA = 0x9036000L
$imageBase = 0x140000000L

function Get-Rva([long]$off) { '0x{0:X}' -f ($edataVA + ($off - $edataRaw)) }

$fs = [IO.File]::OpenRead($ExePath)
$fileLen = $fs.Length
if (($edataRaw + $edataSize) -gt $fileLen) {
    $fs.Close()
    throw "Configured .edata range exceeds file size; update section constants for this build."
}
$buf = New-Object byte[] $edataSize
$fs.Position = $edataRaw
[void]$fs.Read($buf, 0, $buf.Length)
$fs.Close()

$sb = New-Object System.Text.StringBuilder $buf.Length
for ($i = 0; $i -lt $buf.Length; $i++) {
    $b = $buf[$i]
    if ($b -ge 32 -and $b -lt 127) { [void]$sb.Append([char]$b) }
    else { [void]$sb.Append([char]1) }
}
$text = $sb.ToString()

$compRe = [regex]'\{"name":"([^"]+)","compositions":(\[[^\]]*\])\}'
$prefixes = @('player.', 'Player', 'SaveGame')
$comps = @()
foreach ($m in $compRe.Matches($text)) {
    $name = $m.Groups[1].Value
    $body = $m.Groups[2].Value
    $keep = $false
    foreach ($p in $prefixes) {
        if ($name.StartsWith($p) -or $body.Contains('player.') -or $body.Contains('Player') -or $body.Contains('SaveGame')) {
            $keep = $true
            break
        }
    }
    if (-not $keep) { continue }
    $off = $edataRaw + $m.Index
    $comps += [pscustomobject]@{
        name             = $name
        compositionsJson = $body
        fileOffset       = ('0x{0:X}' -f $off)
        rva              = Get-Rva $off
        section          = '.edata'
        fullMatch        = $m.Value
    }
}

$paths = New-Object System.Collections.Generic.HashSet[string]
foreach ($m in [regex]::Matches($text, '"(player\.[a-zA-Z0-9_\.]+)"')) {
    [void]$paths.Add($m.Groups[1].Value)
}

$report = [ordered]@{
    schemaVersion         = 1
    generatedUtc          = [DateTime]::UtcNow.ToString('o')
    executable            = (Resolve-Path -LiteralPath $ExePath).Path
    executableSha256      = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash
    compositionCount      = $comps.Count
    uniquePlayerDotPaths  = @($paths | Sort-Object)
    compositionObjects    = $comps
    notes                 = @(
        'Offline heuristic catalog only.',
        'Presence of player.position schema does not prove a live coordinate API.'
    )
}

$dir = Split-Path -Parent $OutJson
if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
($report | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $OutJson -Encoding UTF8
Write-Host "Wrote $OutJson"
Write-Host "compositionCount=$($comps.Count) playerDotPaths=$($paths.Count)"
exit 0
