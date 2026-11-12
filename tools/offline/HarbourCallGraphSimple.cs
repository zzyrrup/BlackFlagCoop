using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

class HarbourCallGraphSimple {
  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outPath = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports\v0.5.8-harbour-callgraph.json";
    byte[] pe = File.ReadAllBytes(exe);
    int e = BitConverter.ToInt32(pe, 0x3C);
    ushort num = BitConverter.ToUInt16(pe, e + 6);
    ushort opt = BitConverter.ToUInt16(pe, e + 20);
    ushort magic = BitConverter.ToUInt16(pe, e + 0x18);
    ulong imageBase = magic == 0x20B
      ? BitConverter.ToUInt64(pe, e + 0x18 + 24)
      : BitConverter.ToUInt32(pe, e + 0x18 + 28);
    int secOff = e + 24 + opt;
    List<Sec> sections = new List<Sec>();
    for (int i = 0; i < num; i++) {
      int o = secOff + i * 40;
      Sec s = new Sec();
      s.Name = Encoding.ASCII.GetString(pe, o, 8).TrimEnd('\0');
      s.VirtualSize = BitConverter.ToUInt32(pe, o + 8);
      s.VirtualAddress = BitConverter.ToUInt32(pe, o + 12);
      s.SizeOfRawData = BitConverter.ToUInt32(pe, o + 16);
      s.PointerToRawData = BitConverter.ToUInt32(pe, o + 20);
      s.Characteristics = BitConverter.ToUInt32(pe, o + 36);
      sections.Add(s);
    }

    Target[] targets = new Target[] {
      new Target("Harbour_StringId_Registry_Find", 0x692E820u, 0x692DE20L),
      new Target("Harbour_StringId_Registry_DumpTo", 0x692E550u, 0x692DB50L),
      new Target("Harbour_StringId_Registry_LoadFrom", 0x692E3C0u, 0x692D9C0L),
      new Target("Harbour_StringId_Registry_ClearUnsafe", 0x69296F0u, 0x6928CF0L),
      new Target("Harbour_StringId_Registry_Insert", 0xD500u, 0xCB00L),
    };

    StringBuilder sb = new StringBuilder();
    sb.Append("{\n");
    sb.Append("  \"schemaVersion\": 1,\n");
    sb.Append("  \"generatedUtc\": \"").Append(DateTime.UtcNow.ToString("o")).Append("\",\n");
    sb.Append("  \"exe\": ").Append(J(exe)).Append(",\n");
    sb.Append("  \"imageBase\": \"").Append(H(imageBase)).Append("\",\n");
    sb.Append("  \"method\": \"offline_e8_rel32_scan_executable_sections\",\n");
    sb.Append("  \"targets\": [\n");

    int findC = 0, dumpC = 0, loadC = 0, clearC = 0;
    for (int ti = 0; ti < targets.Length; ti++) {
      Target t = targets[ti];
      List<string> callers = FindCallers(pe, sections, t.Rva);
      List<string> callees = ScanCallees(pe, sections, t.Rva, t.FileOffset, 0x800);
      if (t.Name.EndsWith("_Find")) findC = callers.Count;
      if (t.Name.EndsWith("_DumpTo")) dumpC = callers.Count;
      if (t.Name.EndsWith("_LoadFrom")) loadC = callers.Count;
      if (t.Name.EndsWith("_ClearUnsafe")) clearC = callers.Count;

      Console.WriteLine(t.Name + " callers=" + callers.Count + " callees=" + callees.Count);
      sb.Append("    {\n");
      sb.Append("      \"name\": ").Append(J(t.Name)).Append(",\n");
      sb.Append("      \"rva\": \"").Append(H(t.Rva)).Append("\",\n");
      sb.Append("      \"fileOffset\": \"").Append(H((ulong)t.FileOffset)).Append("\",\n");
      sb.Append("      \"section\": ").Append(J(SectionForRva(sections, t.Rva))).Append(",\n");
      sb.Append("      \"callerCount\": ").Append(callers.Count).Append(",\n");
      sb.Append("      \"callers\": [\n");
      for (int i = 0; i < callers.Count; i++) {
        sb.Append("        ").Append(callers[i]);
        if (i + 1 < callers.Count) sb.Append(",");
        sb.Append("\n");
      }
      sb.Append("      ],\n");
      sb.Append("      \"callees\": [\n");
      for (int i = 0; i < callees.Count; i++) {
        sb.Append("        ").Append(callees[i]);
        if (i + 1 < callees.Count) sb.Append(",");
        sb.Append("\n");
      }
      sb.Append("      ],\n");
      sb.Append("      \"boundaryNote\": \"Callee scan uses bounded window from export; not a proven function end\"\n");
      sb.Append("    }");
      if (ti + 1 < targets.Length) sb.Append(",");
      sb.Append("\n");
    }
    sb.Append("  ],\n");

    int cluster = 0;
    StringBuilder samples = new StringBuilder();
    int sampleCount = 0;
    foreach (Sec s in sections) {
      if ((s.Characteristics & 0x20000000u) == 0) continue;
      long start = s.PointerToRawData;
      int size = (int)s.SizeOfRawData;
      if (start <= 0 || size <= 0 || start + size > pe.Length) continue;
      for (int i = 0; i + 5 <= size; i++) {
        if (pe[start + i] != 0xE8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(start + i + 1));
        uint callRva = s.VirtualAddress + (uint)i;
        uint dest = unchecked((uint)(callRva + 5 + rel));
        if (dest < 0x6928000u || dest >= 0x6930000u) continue;
        cluster++;
        if (sampleCount < 40) {
          if (sampleCount > 0) samples.Append(",\n");
          samples.Append("      {\"callSiteRva\":\"").Append(H(callRva))
            .Append("\",\"destRva\":\"").Append(H(dest))
            .Append("\",\"section\":").Append(J(s.Name)).Append("}");
          sampleCount++;
        }
      }
    }
    sb.Append("  \"harbourClusterE8CallSites\": {\n");
    sb.Append("    \"rvaRange\": \"0x6928000-0x6930000\",\n");
    sb.Append("    \"callSiteCount\": ").Append(cluster).Append(",\n");
    sb.Append("    \"samples\": [\n").Append(samples).Append("\n    ]\n");
    sb.Append("  },\n");

    sb.Append("  \"schemaConnectionProbes\": [\n");
    long[] offs = new long[] { 0xA1D6605L, 0xA1DE0FEL, 0xA1D77BEL };
    string[] names = new string[] { "PlayerPosX_dict", "player.position_event", "PlayerPosition_comp" };
    for (int i = 0; i < offs.Length; i++) {
      uint? rva = FileOffsetToRva(sections, offs[i]);
      int xrefs = 0;
      if (rva.HasValue) xrefs = CountImm64(pe, sections, imageBase + rva.Value);
      sb.Append("    {\"name\":").Append(J(names[i]))
        .Append(",\"fileOffset\":\"").Append(H((ulong)offs[i])).Append("\"")
        .Append(",\"rva\":").Append(rva.HasValue ? ("\"" + H(rva.Value) + "\"") : "null")
        .Append(",\"absoluteVaXrefsInExecutableSections\":").Append(xrefs)
        .Append(",\"note\":\"VA immediate xref count; 0 does not prove absence of relative/indirection\"}");
      if (i + 1 < offs.Length) sb.Append(",");
      sb.Append("\n");
    }
    sb.Append("  ],\n");

    sb.Append("  \"conclusions\": {\n");
    sb.Append("    \"registryFindCallersFound\": ").Append(findC).Append(",\n");
    sb.Append("    \"dumpToCallersFound\": ").Append(dumpC).Append(",\n");
    sb.Append("    \"loadFromCallersFound\": ").Append(loadC).Append(",\n");
    sb.Append("    \"clearUnsafeCallersFound\": ").Append(clearC).Append(",\n");
    sb.Append("    \"harbourConnectedToPlayerPosSchema\": false,\n");
    sb.Append("    \"playerPositionTracedThroughHarbour\": false,\n");
    sb.Append("    \"missingEvidence\": [\n");
    sb.Append("      \"No absolute VA xrefs from executable sections to PlayerPos*/player.position sites in this probe\",\n");
    sb.Append("      \"Named schema-registration callers not identified from E8 destination match alone\",\n");
    sb.Append("      \"Shared registry object layout not fully recovered without deeper decompilation\"\n");
    sb.Append("    ]\n");
    sb.Append("  }\n");
    sb.Append("}\n");

    Directory.CreateDirectory(Path.GetDirectoryName(outPath));
    File.WriteAllText(outPath, sb.ToString());
    Console.WriteLine("WROTE " + outPath);
    Console.WriteLine("Find=" + findC + " DumpTo=" + dumpC + " LoadFrom=" + loadC + " Clear=" + clearC + " Cluster=" + cluster);
    return 0;
  }

  class Sec {
    public string Name;
    public uint VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, Characteristics;
  }
  class Target {
    public string Name; public uint Rva; public long FileOffset;
    public Target(string n, uint r, long f) { Name = n; Rva = r; FileOffset = f; }
  }

  static string H(ulong v) { return "0x" + v.ToString("X"); }
  static string H(uint v) { return "0x" + v.ToString("X"); }
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }

  static string SectionForRva(List<Sec> secs, uint rva) {
    foreach (Sec s in secs) {
      uint span = Math.Max(s.VirtualSize, s.SizeOfRawData);
      if (span == 0) continue;
      if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span) return s.Name;
    }
    return null;
  }

  static uint? FileOffsetToRva(List<Sec> secs, long fo) {
    foreach (Sec s in secs) {
      if (fo >= s.PointerToRawData && fo < s.PointerToRawData + s.SizeOfRawData)
        return s.VirtualAddress + (uint)(fo - s.PointerToRawData);
    }
    return null;
  }

  static List<string> FindCallers(byte[] pe, List<Sec> sections, uint targetRva) {
    List<string> hits = new List<string>();
    foreach (Sec s in sections) {
      if ((s.Characteristics & 0x20000000u) == 0) continue;
      long start = s.PointerToRawData;
      int size = (int)s.SizeOfRawData;
      if (start <= 0 || size <= 0 || start + size > pe.Length) continue;
      for (int i = 0; i + 5 <= size; i++) {
        if (pe[start + i] != 0xE8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(start + i + 1));
        uint callRva = s.VirtualAddress + (uint)i;
        uint dest = unchecked((uint)(callRva + 5 + rel));
        if (dest != targetRva) continue;
        hits.Add("{\"callSiteRva\":\"" + H(callRva) + "\",\"callSiteFileOffset\":\"" +
          H((ulong)(start + i)) + "\",\"section\":" + J(s.Name) +
          ",\"rel32\":" + rel + ",\"targetRva\":\"" + H(targetRva) +
          "\",\"confidence\":\"high_e8_rel32_match\"}");
      }
    }
    return hits;
  }

  static List<string> ScanCallees(byte[] pe, List<Sec> secs, uint funcRva, long fileOff, int maxBytes) {
    List<string> list = new List<string>();
    if (fileOff < 0 || fileOff >= pe.Length) return list;
    int end = (int)Math.Min(pe.Length, fileOff + maxBytes);
    int i = (int)fileOff;
    if (end - i >= 3 && pe[i] == 0x31 && pe[i + 1] == 0xC0 && pe[i + 2] == 0xC3) {
      list.Add("{\"kind\":\"stub_xor_eax_ret\",\"confidence\":\"high\"}");
      return list;
    }
    int scanned = 0;
    while (i + 5 <= end && scanned < maxBytes) {
      if (pe[i] == 0xCC && i + 2 < end && pe[i + 1] == 0xCC && pe[i + 2] == 0xCC) break;
      if (pe[i] == 0xC3 && scanned > 16) break;
      if (pe[i] == 0xE8 || pe[i] == 0xE9) {
        int rel = BitConverter.ToInt32(pe, i + 1);
        uint siteRva = funcRva + (uint)(i - fileOff);
        uint dest = unchecked((uint)(siteRva + 5 + rel));
        list.Add("{\"kind\":\"" + (pe[i] == 0xE8 ? "call" : "jmp") +
          "\",\"siteRva\":\"" + H(siteRva) + "\",\"siteFileOffset\":\"" + H((ulong)i) +
          "\",\"destRva\":\"" + H(dest) + "\",\"destSection\":" + J(SectionForRva(secs, dest)) +
          ",\"confidence\":\"medium_bounded_scan\"}");
        i += 5; scanned += 5; continue;
      }
      i++; scanned++;
    }
    return list;
  }

  static int CountImm64(byte[] pe, List<Sec> sections, ulong va) {
    byte[] needle = BitConverter.GetBytes(va);
    int count = 0;
    foreach (Sec s in sections) {
      if ((s.Characteristics & 0x20000000u) == 0) continue;
      long start = s.PointerToRawData;
      int size = (int)s.SizeOfRawData;
      for (int i = 0; i + 8 <= size; i++) {
        bool ok = true;
        for (int j = 0; j < 8; j++) if (pe[start + i + j] != needle[j]) { ok = false; break; }
        if (ok) count++;
      }
    }
    return count;
  }
}
