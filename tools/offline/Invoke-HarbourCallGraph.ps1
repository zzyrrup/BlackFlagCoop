# Offline Harbour relative call-graph scan (read-only).
param(
  [string]$ExePath = "C:\Games\AC Black Flag Resynced\ACBlackFlag.exe",
  [string]$OutPath = "C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports\v0.5.8-harbour-callgraph.json"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $ExePath)) { throw "Missing exe: $ExePath" }

$bytes = [IO.File]::ReadAllBytes($ExePath)
function U16([int]$o) { [BitConverter]::ToUInt16($bytes, $o) }
function U32([int]$o) { [BitConverter]::ToUInt32($bytes, $o) }
function I32([int]$o) { [BitConverter]::ToInt32($bytes, $o) }
function HexU([uint64]$v) { "0x{0:X}" -f $v }
function HexI([int64]$v) { "0x{0:X}" -f $v }

$e = I32 0x3C
$numSec = U16 ($e + 6)
$optSize = U16 ($e + 20)
$magic = U16 ($e + 0x18)
$imageBase = if ($magic -eq 0x20B) { [BitConverter]::ToUInt64($bytes, $e + 0x18 + 24) } else { [uint64](U32 ($e + 0x18 + 28)) }
$secOff = $e + 24 + $optSize

$sections = @()
for ($i = 0; $i -lt $numSec; $i++) {
  $o = $secOff + $i * 40
  $name = [Text.Encoding]::ASCII.GetString($bytes, $o, 8).TrimEnd([char]0)
  $sections += [pscustomobject]@{
    Name = $name
    VirtualSize = U32 ($o + 8)
    VirtualAddress = U32 ($o + 12)
    SizeOfRawData = U32 ($o + 16)
    PointerToRawData = U32 ($o + 20)
    Characteristics = U32 ($o + 36)
  }
}

function SectionForRva([uint32]$rva) {
  foreach ($s in $sections) {
    $span = [Math]::Max($s.VirtualSize, $s.SizeOfRawData)
    if ($span -eq 0) { continue }
    if ($rva -ge $s.VirtualAddress -and $rva -lt ($s.VirtualAddress + $span)) { return $s.Name }
  }
  return $null
}

function FileOffsetToRva([int64]$fo) {
  foreach ($s in $sections) {
    if ($fo -ge $s.PointerToRawData -and $fo -lt ($s.PointerToRawData + $s.SizeOfRawData)) {
      return [uint32]($s.VirtualAddress + ($fo - $s.PointerToRawData))
    }
  }
  return $null
}

$execSecs = @($sections | Where-Object { ($_.Characteristics -band 0x20000000) -ne 0 })

$targets = @(
  @{ Name = "Harbour_StringId_Registry_Find"; Rva = [uint32]0x692E820; FileOffset = [int64]0x692DE20 },
  @{ Name = "Harbour_StringId_Registry_DumpTo"; Rva = [uint32]0x692E550; FileOffset = [int64]0x692DB50 },
  @{ Name = "Harbour_StringId_Registry_LoadFrom"; Rva = [uint32]0x692E3C0; FileOffset = [int64]0x692D9C0 },
  @{ Name = "Harbour_StringId_Registry_ClearUnsafe"; Rva = [uint32]0x69296F0; FileOffset = [int64]0x6928CF0 },
  @{ Name = "Harbour_StringId_Registry_Insert"; Rva = [uint32]0xD500; FileOffset = [int64]0xCB00 }
)

function FindCallers([uint32]$targetRva) {
  $hits = New-Object System.Collections.Generic.List[object]
  foreach ($s in $execSecs) {
    $start = [int64]$s.PointerToRawData
    $size = [int]$s.SizeOfRawData
    if ($start -le 0 -or $size -le 0 -or ($start + $size) -gt $bytes.Length) { continue }
    for ($i = 0; $i + 5 -le $size; $i++) {
      if ($bytes[$start + $i] -ne 0xE8) { continue }
      $rel = I32 ([int]($start + $i + 1))
      $callRva = [uint32]($s.VirtualAddress + $i)
      $dest = [uint32](($callRva + 5 + $rel) -band 0xFFFFFFFF)
      if ($dest -ne $targetRva) { continue }
      $hits.Add([pscustomobject]@{
        callSiteRva = (HexU $callRva)
        callSiteFileOffset = (HexI ($start + $i))
        section = $s.Name
        rel32 = $rel
        targetRva = (HexU $targetRva)
        confidence = "high_e8_rel32_match"
      }) | Out-Null
    }
  }
  return $hits
}

function ScanCallees([uint32]$funcRva, [int64]$fileOff, [int]$maxBytes) {
  $list = New-Object System.Collections.Generic.List[object]
  if ($fileOff -lt 0 -or $fileOff -ge $bytes.Length) { return $list }
  $end = [Math]::Min($bytes.Length, $fileOff + $maxBytes)
  $i = [int]$fileOff
  if (($end - $i) -ge 3 -and $bytes[$i] -eq 0x31 -and $bytes[$i+1] -eq 0xC0 -and $bytes[$i+2] -eq 0xC3) {
    $list.Add([pscustomobject]@{ kind = "stub_xor_eax_ret"; confidence = "high" }) | Out-Null
    return $list
  }
  $scanned = 0
  while (($i + 5) -le $end -and $scanned -lt $maxBytes) {
    if ($bytes[$i] -eq 0xCC -and ($i + 2) -lt $end -and $bytes[$i+1] -eq 0xCC -and $bytes[$i+2] -eq 0xCC) { break }
    if ($bytes[$i] -eq 0xC3 -and $scanned -gt 16) { break }
    if ($bytes[$i] -eq 0xE8 -or $bytes[$i] -eq 0xE9) {
      $rel = I32 $i
      $siteRva = [uint32]($funcRva + ($i - $fileOff))
      $dest = [uint32](($siteRva + 5 + $rel) -band 0xFFFFFFFF)
      $list.Add([pscustomobject]@{
        kind = $(if ($bytes[$i] -eq 0xE8) { "call" } else { "jmp" })
        siteRva = (HexU $siteRva)
        siteFileOffset = (HexI $i)
        destRva = (HexU $dest)
        destSection = (SectionForRva $dest)
        confidence = "medium_bounded_scan"
      }) | Out-Null
      $i += 5; $scanned += 5; continue
    }
    $i++; $scanned++
  }
  return $list
}

$targetReports = @()
foreach ($t in $targets) {
  Write-Host ("Scanning callers -> {0}" -f $t.Name)
  $callers = FindCallers $t.Rva
  $callees = ScanCallees $t.Rva $t.FileOffset 0x800
  $targetReports += [pscustomobject]@{
    name = $t.Name
    rva = (HexU $t.Rva)
    fileOffset = (HexI $t.FileOffset)
    section = (SectionForRva $t.Rva)
    callerCount = $callers.Count
    callers = @($callers)
    callees = @($callees)
    boundaryNote = "Callee scan uses bounded window from export; not a proven function end"
  }
}

# Cluster E8 destinations in Harbour neighborhood
$clusterCalls = 0
$clusterSamples = New-Object System.Collections.Generic.List[object]
foreach ($s in $execSecs) {
  $start = [int64]$s.PointerToRawData
  $size = [int]$s.SizeOfRawData
  for ($i = 0; $i + 5 -le $size; $i++) {
    if ($bytes[$start + $i] -ne 0xE8) { continue }
    $rel = I32 ([int]($start + $i + 1))
    $callRva = [uint32]($s.VirtualAddress + $i)
    $dest = [uint32](($callRva + 5 + $rel) -band 0xFFFFFFFF)
    if ($dest -lt 0x6928000 -or $dest -ge 0x6930000) { continue }
    $clusterCalls++
    if ($clusterSamples.Count -lt 40) {
      $clusterSamples.Add([pscustomobject]@{
        callSiteRva = (HexU $callRva)
        destRva = (HexU $dest)
        section = $s.Name
      }) | Out-Null
    }
  }
}

function CountImm64([uint64]$va) {
  $needle = [BitConverter]::GetBytes($va)
  $count = 0
  foreach ($s in $execSecs) {
    $start = [int64]$s.PointerToRawData
    $size = [int]$s.SizeOfRawData
    for ($i = 0; $i + 8 -le $size; $i++) {
      $ok = $true
      for ($j = 0; $j -lt 8; $j++) {
        if ($bytes[$start + $i + $j] -ne $needle[$j]) { $ok = $false; break }
      }
      if ($ok) { $count++ }
    }
  }
  return $count
}

$schemaNeedles = @(
  @{ name = "PlayerPosX_dict"; fileOffset = [int64]0xA1D6605 },
  @{ name = "player.position_event"; fileOffset = [int64]0xA1DE0FE },
  @{ name = "PlayerPosition_comp"; fileOffset = [int64]0xA1D77BE }
)
$schemaLinks = @()
foreach ($n in $schemaNeedles) {
  $rva = FileOffsetToRva $n.fileOffset
  $xrefs = 0
  if ($null -ne $rva) { $xrefs = CountImm64 ($imageBase + $rva) }
  $schemaLinks += [pscustomobject]@{
    name = $n.name
    fileOffset = (HexI $n.fileOffset)
    rva = $(if ($null -ne $rva) { HexU $rva } else { $null })
    absoluteVaXrefsInExecutableSections = $xrefs
    note = "VA immediate xref count; 0 does not prove absence of relative/indirection"
  }
}

$find = $targetReports | Where-Object { $_.name -like "*_Find" } | Select-Object -First 1
$dump = $targetReports | Where-Object { $_.name -like "*_DumpTo" } | Select-Object -First 1
$load = $targetReports | Where-Object { $_.name -like "*_LoadFrom" } | Select-Object -First 1
$clr = $targetReports | Where-Object { $_.name -like "*_ClearUnsafe" } | Select-Object -First 1

$report = [ordered]@{
  schemaVersion = 1
  generatedUtc = (Get-Date).ToUniversalTime().ToString("o")
  exe = $ExePath
  imageBase = (HexU $imageBase)
  method = "offline_e8_rel32_scan_executable_sections"
  targets = $targetReports
  harbourClusterE8CallSites = [ordered]@{
    rvaRange = "0x6928000-0x6930000"
    callSiteCount = $clusterCalls
    samples = @($clusterSamples)
  }
  schemaConnectionProbes = $schemaLinks
  conclusions = [ordered]@{
    registryFindCallersFound = $find.callerCount
    dumpToCallersFound = $dump.callerCount
    loadFromCallersFound = $load.callerCount
    clearUnsafeCallersFound = $clr.callerCount
    harbourConnectedToPlayerPosSchema = $false
    playerPositionTracedThroughHarbour = $false
    missingEvidence = @(
      "No absolute VA xrefs from executable sections to PlayerPos*/player.position sites in this probe",
      "Named schema-registration callers not identified from E8 destination match alone",
      "Shared registry object layout not fully recovered without deeper decompilation"
    )
  }
}

$dir = Split-Path $OutPath -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
($report | ConvertTo-Json -Depth 8) | Set-Content -Path $OutPath -Encoding UTF8
Write-Host "WROTE $OutPath"
Write-Host ("Find callers={0} DumpTo={1} LoadFrom={2} ClearUnsafe={3} Cluster={4}" -f `
  $find.callerCount, $dump.callerCount, $load.callerCount, $clr.callerCount, $clusterCalls)
