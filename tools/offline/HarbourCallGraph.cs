// Offline PE relative-call graph for Harbour StringId registry exports.
// Read-only. Does not launch or modify the game.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

static class HarbourCallGraph {
  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outPath = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports\v0.5.8-harbour-callgraph.json";
    if (!File.Exists(exe)) { Console.Error.WriteLine("missing exe"); return 2; }

    byte[] pe = File.ReadAllBytes(exe);
    var sections = ParseSections(pe);
    uint imageBase = BitConverter.ToUInt32(pe, BitConverter.ToInt32(pe, 0x3C) + 0x18 + 24); // PE32+ optional header ImageBase is 8 bytes at +24 from magic... handle carefully

    // Proper PE32+ parse
    int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
    ushort magic = BitConverter.ToUInt16(pe, e_lfanew + 0x18);
    ulong imgBase = magic == 0x20B
      ? BitConverter.ToUInt64(pe, e_lfanew + 0x18 + 24)
      : BitConverter.ToUInt32(pe, e_lfanew + 0x18 + 28);

    var targets = new[] {
      new Tgt("Harbour_StringId_Registry_Find", 0x692E820u, 0x692DE20L),
      new Tgt("Harbour_StringId_Registry_DumpTo", 0x692E550u, 0x692DB50L),
      new Tgt("Harbour_StringId_Registry_LoadFrom", 0x692E3C0u, 0x692D9C0L),
      new Tgt("Harbour_StringId_Registry_ClearUnsafe", 0x69296F0u, 0x6928CF0L),
      new Tgt("Harbour_StringId_Registry_Insert", 0xD500u, 0xCB00L),
    };

    // Scan executable sections for E8 rel32 calls to each target RVA.
    var textSecs = sections.Where(s => (s.Characteristics & 0x20000000) != 0).ToList(); // IMAGE_SCN_MEM_EXECUTE
    var callersByTarget = new Dictionary<string, List<object>>();
    var calleeByTarget = new Dictionary<string, List<object>>();

    foreach (var t in targets) {
      var callers = new List<object>();
      foreach (var sec in textSecs) {
        long start = sec.PointerToRawData;
        int size = (int)sec.SizeOfRawData;
        if (start <= 0 || size <= 0 || start + size > pe.Length) continue;
        for (int i = 0; i + 5 <= size; i++) {
          if (pe[start + i] != 0xE8) continue;
          int rel = BitConverter.ToInt32(pe, (int)(start + i + 1));
          uint callRva = sec.VirtualAddress + (uint)i;
          uint nextRva = callRva + 5;
          uint dest = unchecked((uint)(nextRva + rel));
          if (dest != t.Rva) continue;
          callers.Add(new {
            callSiteRva = Hex(callRva),
            callSiteFileOffset = Hex(start + i),
            section = sec.Name,
            rel32 = rel,
            targetRva = Hex(t.Rva),
            confidence = "high_e8_rel32_match"
          });
        }
      }
      callersByTarget[t.Name] = callers;

      // Callees: scan forward from export for E8/E9 within a bounded window until CC padding or max bytes.
      var callees = ScanCallees(pe, sections, t.Rva, t.FileOffset, 0x800);
      calleeByTarget[t.Name] = callees;
    }

    // Schema string proximity: search whether PlayerPos / player.position RVAs appear as immediates near Harbour bodies (weak evidence).
    var schemaNeedles = new Dictionary<string, long> {
      ["PlayerPosX_dict"] = 0xA1D6605L,
      ["player.position_event"] = 0xA1DE0FEL,
      ["PlayerPosition_comp"] = 0xA1D77BEL,
    };
    var schemaLinks = new List<object>();
    foreach (var kv in schemaNeedles) {
      // file offset of string; compute RVA via sections
      uint? rva = FileOffsetToRva(sections, kv.Value);
      schemaLinks.Add(new {
        name = kv.Key,
        fileOffset = Hex(kv.Value),
        rva = rva.HasValue ? Hex(rva.Value) : null,
        absoluteVaXrefsInText = rva.HasValue ? CountImm64VaXrefs(pe, textSecs, imgBase + rva.Value) : 0,
        note = "VA immediate xref count in executable sections; 0 does not prove absence of relative/indirection"
      });
    }

    // Also count E8 calls whose destination falls inside Harbour cluster 0x6928000-0x6930000
    int clusterCalls = 0;
    var clusterSamples = new List<object>();
    foreach (var sec in textSecs) {
      long start = sec.PointerToRawData;
      int size = (int)sec.SizeOfRawData;
      for (int i = 0; i + 5 <= size; i++) {
        if (pe[start + i] != 0xE8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(start + i + 1));
        uint callRva = sec.VirtualAddress + (uint)i;
        uint dest = unchecked((uint)(callRva + 5 + rel));
        if (dest < 0x6928000u || dest >= 0x6930000u) continue;
        clusterCalls++;
        if (clusterSamples.Count < 40) {
          clusterSamples.Add(new {
            callSiteRva = Hex(callRva),
            destRva = Hex(dest),
            section = sec.Name
          });
        }
      }
    }

    var report = new {
      schemaVersion = 1,
      generatedUtc = DateTime.UtcNow.ToString("o"),
      exe,
      imageBase = Hex(imgBase),
      method = "offline_e8_rel32_scan_executable_sections",
      targets = targets.Select(t => new {
        t.Name,
        rva = Hex(t.Rva),
        fileOffset = Hex(t.FileOffset),
        section = SectionForRva(sections, t.Rva),
        callerCount = callersByTarget[t.Name].Count,
        callers = callersByTarget[t.Name],
        callees = calleeByTarget[t.Name],
        boundaryNote = "Callee scan uses bounded window from export; not a proven function end"
      }),
      harbourClusterE8CallSites = new {
        rvaRange = "0x6928000-0x6930000",
        callSiteCount = clusterCalls,
        samples = clusterSamples
      },
      schemaConnectionProbes = schemaLinks,
      conclusions = new {
        registryFindCallersFound = callersByTarget["Harbour_StringId_Registry_Find"].Count,
        dumpToCallersFound = callersByTarget["Harbour_StringId_Registry_DumpTo"].Count,
        loadFromCallersFound = callersByTarget["Harbour_StringId_Registry_LoadFrom"].Count,
        clearUnsafeCallersFound = callersByTarget["Harbour_StringId_Registry_ClearUnsafe"].Count,
        harbourConnectedToPlayerPosSchema = false,
        playerPositionTracedThroughHarbour = false,
        missingEvidence = new[] {
          "No absolute VA xrefs from .text to PlayerPos*/player.position dictionary sites (probe)",
          "Caller attribution to named schema registration not established from E8 scan alone",
          "Shared registry object layout not fully recovered without deeper decompilation"
        }
      }
    };

    Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
    File.WriteAllText(outPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine("WROTE " + outPath);
    Console.WriteLine("Find callers=" + callersByTarget["Harbour_StringId_Registry_Find"].Count);
    Console.WriteLine("DumpTo callers=" + callersByTarget["Harbour_StringId_Registry_DumpTo"].Count);
    Console.WriteLine("LoadFrom callers=" + callersByTarget["Harbour_StringId_Registry_LoadFrom"].Count);
    Console.WriteLine("ClearUnsafe callers=" + callersByTarget["Harbour_StringId_Registry_ClearUnsafe"].Count);
    Console.WriteLine("Cluster E8 sites=" + clusterCalls);
    return 0;
  }

  record Tgt(string Name, uint Rva, long FileOffset);

  class Sec {
    public string Name = "";
    public uint VirtualAddress;
    public uint VirtualSize;
    public uint SizeOfRawData;
    public uint PointerToRawData;
    public uint Characteristics;
  }

  static List<Sec> ParseSections(byte[] pe) {
    int e = BitConverter.ToInt32(pe, 0x3C);
    ushort num = BitConverter.ToUInt16(pe, e + 6);
    ushort optSize = BitConverter.ToUInt16(pe, e + 20);
    int secOff = e + 24 + optSize;
    var list = new List<Sec>();
    for (int i = 0; i < num; i++) {
      int o = secOff + i * 40;
      string name = Encoding.ASCII.GetString(pe, o, 8).TrimEnd('\0');
      list.Add(new Sec {
        Name = name,
        VirtualSize = BitConverter.ToUInt32(pe, o + 8),
        VirtualAddress = BitConverter.ToUInt32(pe, o + 12),
        SizeOfRawData = BitConverter.ToUInt32(pe, o + 16),
        PointerToRawData = BitConverter.ToUInt32(pe, o + 20),
        Characteristics = BitConverter.ToUInt32(pe, o + 36)
      });
    }
    return list;
  }

  static string? SectionForRva(List<Sec> secs, uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VirtualSize, s.SizeOfRawData);
      if (span == 0) continue;
      if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span)
        return s.Name;
    }
    return null;
  }

  static uint? FileOffsetToRva(List<Sec> secs, long fileOff) {
    foreach (var s in secs) {
      if (fileOff >= s.PointerToRawData && fileOff < s.PointerToRawData + s.SizeOfRawData)
        return s.VirtualAddress + (uint)(fileOff - s.PointerToRawData);
    }
    return null;
  }

  static int CountImm64VaXrefs(byte[] pe, List<Sec> textSecs, ulong va) {
    byte[] needle = BitConverter.GetBytes(va);
    int count = 0;
    foreach (var sec in textSecs) {
      long start = sec.PointerToRawData;
      int size = (int)sec.SizeOfRawData;
      for (int i = 0; i + 8 <= size; i++) {
        bool ok = true;
        for (int j = 0; j < 8; j++) if (pe[start + i + j] != needle[j]) { ok = false; break; }
        if (ok) count++;
      }
    }
    return count;
  }

  static List<object> ScanCallees(byte[] pe, List<Sec> secs, uint funcRva, long fileOff, int maxBytes) {
    var list = new List<object>();
    if (fileOff < 0 || fileOff >= pe.Length) return list;
    int end = (int)Math.Min(pe.Length, fileOff + maxBytes);
    int i = (int)fileOff;
    int scanned = 0;
    // Skip trivial stub
    if (end - i >= 3 && pe[i] == 0x31 && pe[i + 1] == 0xC0 && pe[i + 2] == 0xC3) {
      list.Add(new { kind = "stub_xor_eax_ret", confidence = "high" });
      return list;
    }
    while (i + 5 <= end && scanned < maxBytes) {
      // stop at run of INT3
      if (pe[i] == 0xCC && i + 4 < end && pe[i + 1] == 0xCC && pe[i + 2] == 0xCC) break;
      if (pe[i] == 0xC3 && scanned > 16) break; // near ret after some body — weak boundary
      if (pe[i] == 0xE8 || pe[i] == 0xE9) {
        int rel = BitConverter.ToInt32(pe, i + 1);
        uint siteRva = funcRva + (uint)(i - fileOff);
        uint dest = unchecked((uint)(siteRva + 5 + rel));
        list.Add(new {
          kind = pe[i] == 0xE8 ? "call" : "jmp",
          siteRva = Hex(siteRva),
          siteFileOffset = Hex(i),
          destRva = Hex(dest),
          destSection = SectionForRva(secs, dest),
          confidence = "medium_bounded_scan"
        });
        i += 5;
        scanned += 5;
        continue;
      }
      i++;
      scanned++;
    }
    return list;
  }

  static string Hex(ulong v) => "0x" + v.ToString("X");
  static string Hex(long v) => "0x" + v.ToString("X");
  static string Hex(uint v) => "0x" + v.ToString("X");
  static string Hex(int v) => "0x" + v.ToString("X");
}
