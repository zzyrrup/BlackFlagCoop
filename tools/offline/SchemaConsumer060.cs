// v0.6.0 — Offline RIP-relative / data-reference scan for .edata schema consumers.
// Read-only. No game launch/inject.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

class SchemaConsumer060 {
  static byte[] pe;
  static List<Sec> secs;
  static ulong imageBase;
  static Sec edata;

  // Core telemetry event/attribute catalog (from v0.5.9 bounds probe).
  const long CoreCatalogFileStart = 0xA1CE000L;
  const long CoreCatalogFileEnd   = 0xA1E4000L;
  // Wider composition signal maps.
  const long CompCatalogFileStart = 0xA0FBB00L;
  const long CompCatalogFileEnd   = 0xA1E4000L;

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";
    pe = File.ReadAllBytes(exe);
    ParsePe();
    Directory.CreateDirectory(outDir);

    uint coreStartRva = FileToRva(CoreCatalogFileStart).Value;
    uint coreEndRva = FileToRva(CoreCatalogFileEnd).Value;
    uint compStartRva = FileToRva(CompCatalogFileStart).Value;
    uint compEndRva = FileToRva(CompCatalogFileEnd).Value;
    uint edataStartRva = edata.VA;
    uint edataEndRva = edata.VA + Math.Max(edata.VS, edata.Raw);

    Console.WriteLine("edata RVA {0:X}-{1:X}", edataStartRva, edataEndRva);
    Console.WriteLine("core catalog RVA {0:X}-{1:X}", coreStartRva, coreEndRva);

    var ripHits = ScanRipRelative(coreStartRva, coreEndRva, "core_event_attribute_catalog");
    var ripComp = ScanRipRelative(compStartRva, compEndRva, "composition_and_core_catalog");
    var ripEdata = ScanRipRelative(edataStartRva, edataEndRva, "whole_edata");

    // Also scan for abs VA immediates into core region (unlikely but record).
    var absHits = ScanAbsVaImm64(coreStartRva, coreEndRva);

    // Representative entry sites
    var targets = new[] {
      new T("PlayerPosition_composition", 0xA1D77B5L),
      new T("player_position_event", 0xA1DE0FEL),
      new T("PlayerPosX_dict", 0xA1D6605L),
      new T("first_STANDARD", 0xA1D6DD6L),
      new T("first_CUSTOM_near_cluster", 0xA1D672AL),
      new T("player_position_cstr", 0xA13E3DEL),
      new T("LiveTelemetry", FindAscii("LiveTelemetry")),
      new T("us-sdkClientTelemetry", FindAscii("us-sdkClientTelemetry")),
      new T("JobPrimaryStoreSyncAndSendEvent", FindAscii("JobPrimaryStoreSyncAndSendEvent::")),
    };

    var targetReport = new StringBuilder();
    targetReport.Append("[\n");
    for (int ti = 0; ti < targets.Length; ti++) {
      var t = targets[ti];
      if (t.FileOffset < 0) {
        if (ti > 0) targetReport.Append(",\n");
        targetReport.Append("    {\"name\":").Append(J(t.Name)).Append(",\"found\":false}");
        continue;
      }
      uint rva = FileToRva(t.FileOffset).Value;
      // RIP hits whose effective address is within ±0x40 of this site, or exact
      var near = ripEdata.Where(h => {
        long d = (long)h.TargetRva - (long)rva;
        return d >= -64 && d <= 256; // allow LEA to object start / nearby
      }).Take(30).ToList();
      var exactAbs = CountAbsVa(imageBase + rva);
      if (ti > 0) targetReport.Append(",\n");
      targetReport.Append("    {\n");
      targetReport.Append("      \"name\":").Append(J(t.Name)).Append(",\n");
      targetReport.Append("      \"fileOffset\":\"").Append(H((ulong)t.FileOffset)).Append("\",\n");
      targetReport.Append("      \"rva\":\"").Append(H(rva)).Append("\",\n");
      targetReport.Append("      \"va\":\"").Append(H(imageBase + rva)).Append("\",\n");
      targetReport.Append("      \"section\":").Append(J(SecNameForFile(t.FileOffset))).Append(",\n");
      targetReport.Append("      \"ripRelativeHitsNear\":").Append(near.Count).Append(",\n");
      targetReport.Append("      \"absoluteVaImm64Hits\":").Append(exactAbs).Append(",\n");
      targetReport.Append("      \"samples\":[\n");
      for (int i = 0; i < Math.Min(10, near.Count); i++) {
        if (i > 0) targetReport.Append(",\n");
        targetReport.Append("        ").Append(near[i].ToJson());
      }
      targetReport.Append("\n      ]\n    }");
      Console.WriteLine("{0}: ripNear={1} abs={2}", t.Name, near.Count, exactAbs);
    }
    targetReport.Append("\n  ]");

    // Build consumer candidates from unique instruction sites hitting core catalog
    var candidates = BuildCandidates(ripHits);

    // Callgraph: E8 callers into candidate entries
    var callgraph = BuildCallgraph(candidates);

    // LiveTelemetry / SendEvent: RIP refs to those strings
    var pipelineStrings = InvestigatePipelineStrings();

    // Write reports
    Write(outDir + @"\v0.6.0-edata-reference-map.json", BuildRefMap(
      coreStartRva, coreEndRva, compStartRva, compEndRva,
      ripHits, ripComp, ripEdata, absHits, targetReport.ToString()));

    Write(outDir + @"\v0.6.0-schema-consumer-candidates.json", BuildCandidatesJson(candidates, ripHits.Count));
    Write(outDir + @"\v0.6.0-schema-consumer-callgraph.json", callgraph);
    Write(outDir + @"\v0.6.0-player-position-pipeline.json", BuildPlayerPosPipeline(candidates, pipelineStrings, ripHits.Count));

    Console.WriteLine("core RIP hits={0} comp RIP hits={1} whole-edata RIP hits={2}",
      ripHits.Count, ripComp.Count, ripEdata.Count);
    Console.WriteLine("candidates={0}", candidates.Count);
    return 0;
  }

  class Sec {
    public string Name; public uint VA, VS, Raw, Ptr, Char;
  }
  class T {
    public string Name; public long FileOffset;
    public T(string n, long f) { Name = n; FileOffset = f; }
  }
  class RipHit {
    public uint SiteRva; public long SiteFile; public string Section;
    public string Mnemonic; public byte[] Bytes; public uint TargetRva; public long TargetFile;
    public string RegionTag; public string Confidence;
    public string ToJson() {
      return "{\"siteRva\":\"" + H(SiteRva) + "\",\"siteFileOffset\":\"" + H((ulong)SiteFile) +
        "\",\"section\":" + J(Section) + ",\"mnemonic\":" + J(Mnemonic) +
        ",\"bytes\":" + J(BitConverter.ToString(Bytes).Replace("-", " ")) +
        ",\"targetRva\":\"" + H(TargetRva) + "\",\"targetFileOffset\":\"" + H((ulong)TargetFile) +
        "\",\"regionTag\":" + J(RegionTag) + ",\"confidence\":" + J(Confidence) + "}";
    }
  }
  class Cand {
    public uint EntryRva; public long EntryFile; public string PrologueBytes;
    public int HitCount; public List<RipHit> Hits = new List<RipHit>();
    public string Confidence; public string Notes;
    public List<uint> Callees = new List<uint>();
    public List<uint> Callers = new List<uint>();
  }

  static void ParsePe() {
    int e = BitConverter.ToInt32(pe, 0x3C);
    ushort num = BitConverter.ToUInt16(pe, e + 6);
    ushort opt = BitConverter.ToUInt16(pe, e + 20);
    ushort magic = BitConverter.ToUInt16(pe, e + 0x18);
    imageBase = magic == 0x20B
      ? BitConverter.ToUInt64(pe, e + 0x18 + 24)
      : BitConverter.ToUInt32(pe, e + 0x18 + 28);
    int secOff = e + 24 + opt;
    secs = new List<Sec>();
    for (int i = 0; i < num; i++) {
      int o = secOff + i * 40;
      var s = new Sec();
      s.Name = Encoding.ASCII.GetString(pe, o, 8).TrimEnd('\0');
      s.VS = BitConverter.ToUInt32(pe, o + 8);
      s.VA = BitConverter.ToUInt32(pe, o + 12);
      s.Raw = BitConverter.ToUInt32(pe, o + 16);
      s.Ptr = BitConverter.ToUInt32(pe, o + 20);
      s.Char = BitConverter.ToUInt32(pe, o + 36);
      secs.Add(s);
      if (s.Name.StartsWith(".edata")) edata = s;
    }
    if (edata == null) throw new Exception(".edata missing");
  }

  static string H(ulong v) { return "0x" + v.ToString("X"); }
  static string H(uint v) { return "0x" + v.ToString("X"); }
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }
  static void Write(string path, string json) {
    File.WriteAllText(path, json, new UTF8Encoding(false));
    Console.WriteLine("WROTE " + path);
  }

  static uint? FileToRva(long fo) {
    foreach (var s in secs) {
      if (fo >= s.Ptr && fo < s.Ptr + s.Raw)
        return s.VA + (uint)(fo - s.Ptr);
    }
    return null;
  }
  static long RvaToFile(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VS, s.Raw);
      if (rva >= s.VA && rva < s.VA + span && s.Ptr > 0)
        return s.Ptr + (rva - s.VA);
    }
    return -1;
  }
  static string SecNameForFile(long fo) {
    foreach (var s in secs)
      if (fo >= s.Ptr && fo < s.Ptr + s.Raw) return s.Name;
    return null;
  }
  static string SecNameForRva(uint rva) {
    long fo = RvaToFile(rva);
    return fo < 0 ? null : SecNameForFile(fo);
  }

  static long FindAscii(string s) {
    byte[] n = Encoding.ASCII.GetBytes(s);
    for (long i = 0; i + n.Length <= pe.Length; i++) {
      bool ok = true;
      for (int j = 0; j < n.Length; j++) if (pe[i + j] != n[j]) { ok = false; break; }
      if (ok) return i;
    }
    return -1;
  }

  static int CountAbsVa(ulong va) {
    byte[] needle = BitConverter.GetBytes(va);
    int c = 0;
    foreach (var s in secs) {
      if ((s.Char & 0x20000000) == 0 || s.Ptr == 0) continue;
      int size = (int)s.Raw;
      for (int i = 0; i + 8 <= size; i++) {
        bool ok = true;
        for (int j = 0; j < 8; j++) if (pe[s.Ptr + i + j] != needle[j]) { ok = false; break; }
        if (ok) c++;
      }
    }
    return c;
  }

  static List<RipHit> ScanAbsVaImm64(uint rangeStart, uint rangeEnd) {
    var hits = new List<RipHit>();
    // Too expensive to check every VA in range; sample endpoints + known sites only.
    return hits;
  }

  // Decode common RIP-relative forms that load an ADDRESS (LEA) or memory operand targeting data.
  static List<RipHit> ScanRipRelative(uint rangeStartRva, uint rangeEndRva, string tag) {
    var hits = new List<RipHit>();
    foreach (var s in secs) {
      if ((s.Char & 0x20000000) == 0 || s.Ptr == 0 || s.Raw < 7) continue;
      // Skip scanning .edata itself as "code" for consumers — consumers live in code sections.
      // But .impdata is executable and contains game code in this binary.
      int size = (int)s.Raw;
      long start = s.Ptr;
      for (int i = 0; i + 7 <= size; i++) {
        // Pattern: REX.W LEA r64, [rip+disp32]  => 48 8D 05/0D/15/1D/25/2D/35/3D disp32
        // Also 4C 8D ... for r8-r15
        byte b0 = pe[start + i];
        byte b1 = pe[start + i + 1];
        byte b2 = pe[start + i + 2];
        bool isLea = (b0 == 0x48 || b0 == 0x4C) && b1 == 0x8D && (b2 & 0xC7) == 0x05;
        // MOV r64, [rip+disp32] => 48 8B 05/... (modrm mod=00 rm=101)
        bool isMovLoad = (b0 == 0x48 || b0 == 0x4C) && b1 == 0x8B && (b2 & 0xC7) == 0x05;
        // LEA without REX rarely for 64-bit addr into large image — skip 8D 05 alone for VA targets in high RVAs
        if (!isLea && !isMovLoad) continue;

        int disp = BitConverter.ToInt32(pe, (int)(start + i + 3));
        uint siteRva = s.VA + (uint)i;
        uint next = siteRva + 7;
        uint target = unchecked((uint)(next + disp));
        if (target < rangeStartRva || target >= rangeEndRva) continue;

        long tFile = RvaToFile(target);
        var hit = new RipHit {
          SiteRva = siteRva,
          SiteFile = start + i,
          Section = s.Name,
          Mnemonic = isLea ? "lea_rip_rel" : "mov_load_rip_rel",
          Bytes = new byte[7],
          TargetRva = target,
          TargetFile = tFile,
          RegionTag = tag,
          Confidence = isLea ? "high_lea_address_into_range" : "medium_mov_load_into_range"
        };
        Array.Copy(pe, start + i, hit.Bytes, 0, 7);
        hits.Add(hit);
      }
    }
    return hits;
  }

  static List<Cand> BuildCandidates(List<RipHit> coreHits) {
    // Group hits by approximate function: walk back up to 0x200 bytes for common prologue
    var byEntry = new Dictionary<uint, Cand>();
    foreach (var h in coreHits) {
      uint entry = FindPrologue(h.SiteRva, 0x300);
      Cand c;
      if (!byEntry.TryGetValue(entry, out c)) {
        long fo = RvaToFile(entry);
        c = new Cand {
          EntryRva = entry,
          EntryFile = fo,
          PrologueBytes = fo >= 0 ? BitConverter.ToString(pe, (int)fo, Math.Min(16, pe.Length - (int)fo)).Replace("-", " ") : "",
          Confidence = "low_unverified",
          Notes = "Grouped by backward prologue heuristic from RIP-relative sites into core catalog"
        };
        byEntry[entry] = c;
      }
      c.Hits.Add(h);
      c.HitCount++;
    }

    // Score confidence
    foreach (var c in byEntry.Values) {
      bool targetsJsonish = c.Hits.Any(h => TargetLooksLikeJson(h.TargetFile));
      if (c.HitCount >= 3 && targetsJsonish) c.Confidence = "medium_multiple_rip_into_jsonish";
      else if (c.HitCount >= 1 && targetsJsonish) c.Confidence = "low_single_rip_into_jsonish";
      else c.Confidence = "low_rip_into_range_nonjson_or_sparse";

      // Collect E8 callees in first 0x400 bytes of candidate
      c.Callees = ScanCallees(c.EntryRva, 0x400);
    }

    return byEntry.Values.OrderByDescending(c => c.HitCount).Take(40).ToList();
  }

  static bool TargetLooksLikeJson(long fo) {
    if (fo < 0 || fo + 16 >= pe.Length) return false;
    // Look at nearby ASCII for JSON markers
    int start = (int)Math.Max(0, fo - 8);
    int len = Math.Min(64, pe.Length - start);
    string s = Encoding.ASCII.GetString(pe, start, len);
    return s.Contains("\"name\"") || s.Contains("\"type\"") || s.Contains("composition") ||
           s.Contains("customAttributes") || s.Contains("{");
  }

  static uint FindPrologue(uint siteRva, int maxBack) {
    long fo = RvaToFile(siteRva);
    if (fo < 0) return siteRva;
    // Walk back for CC CC padding or typical push/sub rsp prologue at aligned-ish addresses
    for (int back = 0; back < maxBack; back++) {
      long pos = fo - back;
      if (pos < 4) break;
      // INT3 run before function
      if (pe[pos] == 0xCC && pe[pos + 1] != 0xCC) {
        // function may start at pos+1
        uint r = FileToRva(pos + 1).Value;
        if (LooksLikePrologue(pos + 1)) return r;
      }
      if (back > 0 && (pe[pos - 1] == 0xCC || pe[pos - 1] == 0xC3) && LooksLikePrologue(pos))
        return FileToRva(pos).Value;
    }
    // Fallback: 16-byte align down from site
    uint aligned = siteRva & ~0xFu;
    long afo = RvaToFile(aligned);
    if (afo >= 0 && LooksLikePrologue(afo)) return aligned;
    return siteRva; // use site itself as weak entry
  }

  static bool LooksLikePrologue(long fo) {
    if (fo < 0 || fo + 4 >= pe.Length) return false;
    // common: 40 53 / 48 89 / 48 83 EC / 55 / 41 5x pushes / 4C 8B
    byte b0 = pe[fo], b1 = pe[fo + 1], b2 = pe[fo + 2];
    if (b0 == 0x55) return true; // push rbp
    if (b0 == 0x53 || b0 == 0x56 || b0 == 0x57) return true;
    if (b0 == 0x40 && (b1 >= 0x50 && b1 <= 0x57)) return true;
    if (b0 == 0x41 && (b1 >= 0x50 && b1 <= 0x57)) return true;
    if (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC) return true;
    if (b0 == 0x48 && b1 == 0x89) return true;
    if (b0 == 0x48 && b1 == 0x8B) return true;
    if (b0 == 0x4C && b1 == 0x8B) return true;
    return false;
  }

  static List<uint> ScanCallees(uint entry, int maxBytes) {
    var list = new List<uint>();
    long fo = RvaToFile(entry);
    if (fo < 0) return list;
    int end = (int)Math.Min(pe.Length, fo + maxBytes);
    for (int i = (int)fo; i + 5 <= end; i++) {
      if (pe[i] != 0xE8) continue;
      int rel = BitConverter.ToInt32(pe, i + 1);
      uint site = entry + (uint)(i - fo);
      uint dest = unchecked((uint)(site + 5 + rel));
      if (!list.Contains(dest)) list.Add(dest);
      if (list.Count >= 12) break;
    }
    return list;
  }

  static string BuildCallgraph(List<Cand> candidates) {
    // For top candidates, find E8 callers in executable sections
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"method\":\"e8_caller_scan_of_candidate_entries\",\n");
    sb.Append("  \"nodes\":[\n");

    // Pre-scan all E8 once for targets matching candidate entries (and their first callees limited)
    var candSet = new HashSet<uint>(candidates.Select(c => c.EntryRva));
    var callersOf = new Dictionary<uint, List<uint>>();
    foreach (uint e in candSet) callersOf[e] = new List<uint>();

    foreach (var s in secs) {
      if ((s.Char & 0x20000000) == 0 || s.Ptr == 0) continue;
      int size = (int)s.Raw;
      for (int i = 0; i + 5 <= size; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        uint site = s.VA + (uint)i;
        uint dest = unchecked((uint)(site + 5 + rel));
        List<uint> list;
        if (!callersOf.TryGetValue(dest, out list)) continue;
        if (list.Count < 15) list.Add(site);
      }
    }

    for (int i = 0; i < candidates.Count; i++) {
      var c = candidates[i];
      c.Callers = callersOf.ContainsKey(c.EntryRva) ? callersOf[c.EntryRva] : new List<uint>();
      if (i > 0) sb.Append(",\n");
      sb.Append("    {\n");
      sb.Append("      \"entryRva\":\"").Append(H(c.EntryRva)).Append("\",\n");
      sb.Append("      \"entryFileOffset\":\"").Append(H((ulong)c.EntryFile)).Append("\",\n");
      sb.Append("      \"section\":").Append(J(SecNameForRva(c.EntryRva))).Append(",\n");
      sb.Append("      \"hitCount\":").Append(c.HitCount).Append(",\n");
      sb.Append("      \"confidence\":").Append(J(c.Confidence)).Append(",\n");
      sb.Append("      \"prologueBytes\":").Append(J(c.PrologueBytes)).Append(",\n");
      sb.Append("      \"directCallersE8\":[");
      for (int j = 0; j < c.Callers.Count; j++) {
        if (j > 0) sb.Append(",");
        sb.Append("\"").Append(H(c.Callers[j])).Append("\"");
      }
      sb.Append("],\n");
      sb.Append("      \"directCalleesE8Sample\":[");
      for (int j = 0; j < c.Callees.Count; j++) {
        if (j > 0) sb.Append(",");
        sb.Append("\"").Append(H(c.Callees[j])).Append("\"");
      }
      sb.Append("],\n");
      sb.Append("      \"pipelineFollow\":").Append(J(PipelineFollowNote(c))).Append("\n");
      sb.Append("    }");
    }
    sb.Append("\n  ],\n");
    sb.Append("  \"conclusions\":{\n");
    sb.Append("    \"credibleSchemaConsumerConfirmed\":false,\n");
    sb.Append("    \"note\":").Append(J("Candidates are RIP-relative LEA/MOV sites into the core catalog range, grouped by prologue heuristics. JSON-string presence alone does not confirm a loader.")).Append("\n");
    sb.Append("  }\n}\n");
    return sb.ToString();
  }

  static string PipelineFollowNote(Cand c) {
    // If any callee looks like security_check_cookie (0x5014570) mention it
    if (c.Callees.Contains(0x5014570u))
      return "calls 0x5014570 (security_check_cookie-like); not schema-specific";
    if (c.HitCount == 0) return "no core-catalog hits";
    return "insufficient evidence to claim descriptor/registry/event-dispatch follow-on";
  }

  static string InvestigatePipelineStrings() {
    var names = new[] { "LiveTelemetry", "OnlineLiveTelemetryRuntimeConfig", "us-sdkClientTelemetry",
      "JobPrimaryStoreSyncAndSendEvent", "JobQueueAndSendEventsBase", "Metric Categories" };
    var sb = new StringBuilder();
    sb.Append("[\n");
    for (int i = 0; i < names.Length; i++) {
      long fo = FindAscii(names[i]);
      if (i > 0) sb.Append(",\n");
      if (fo < 0) {
        sb.Append("    {\"name\":").Append(J(names[i])).Append(",\"found\":false}");
        continue;
      }
      uint rva = FileToRva(fo).Value;
      // RIP LEA to this string
      var leaHits = new List<RipHit>();
      foreach (var s in secs) {
        if ((s.Char & 0x20000000) == 0 || s.Ptr == 0) continue;
        int size = (int)s.Raw;
        for (int off = 0; off + 7 <= size; off++) {
          byte b0 = pe[s.Ptr + off], b1 = pe[s.Ptr + off + 1], b2 = pe[s.Ptr + off + 2];
          bool isLea = (b0 == 0x48 || b0 == 0x4C) && b1 == 0x8D && (b2 & 0xC7) == 0x05;
          if (!isLea) continue;
          int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + off + 3));
          uint site = s.VA + (uint)off;
          uint target = unchecked((uint)(site + 7 + disp));
          if (target != rva) continue;
          leaHits.Add(new RipHit {
            SiteRva = site, SiteFile = s.Ptr + off, Section = s.Name,
            Mnemonic = "lea_rip_rel", Bytes = new byte[7], TargetRva = target,
            TargetFile = fo, RegionTag = "pipeline_string", Confidence = "high_lea_to_string"
          });
          Array.Copy(pe, s.Ptr + off, leaHits[leaHits.Count - 1].Bytes, 0, 7);
          if (leaHits.Count >= 10) break;
        }
        if (leaHits.Count >= 10) break;
      }
      int abs = CountAbsVa(imageBase + rva);
      sb.Append("    {\"name\":").Append(J(names[i]))
        .Append(",\"fileOffset\":\"").Append(H((ulong)fo)).Append("\",\"rva\":\"").Append(H(rva))
        .Append("\",\"leaRipHits\":").Append(leaHits.Count)
        .Append(",\"absVaHits\":").Append(abs)
        .Append(",\"connectedToCoreCatalogConsumer\":false")
        .Append(",\"evidenceClass\":").Append(J(leaHits.Count > 0 ? "code_references_string" : "string_only_or_indirect"))
        .Append(",\"samples\":[");
      for (int j = 0; j < Math.Min(5, leaHits.Count); j++) {
        if (j > 0) sb.Append(",");
        sb.Append(leaHits[j].ToJson());
      }
      sb.Append("]}");
      Console.WriteLine("pipeline {0}: lea={1} abs={2}", names[i], leaHits.Count, abs);
    }
    sb.Append("\n  ]");
    return sb.ToString();
  }

  static string BuildRefMap(
      uint coreStart, uint coreEnd, uint compStart, uint compEnd,
      List<RipHit> core, List<RipHit> comp, List<RipHit> whole, List<RipHit> abs,
      string targetReport) {
    var sb = new StringBuilder();
    sb.Append("{\n");
    sb.Append("  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"imageBase\":\"").Append(H(imageBase)).Append("\",\n");
    sb.Append("  \"edataSection\":{\"name\":\".edata\",\"rva\":\"").Append(H(edata.VA))
      .Append("\",\"virtualSize\":\"").Append(H(edata.VS))
      .Append("\",\"fileOffset\":\"").Append(H(edata.Ptr))
      .Append("\",\"rawSize\":\"").Append(H(edata.Raw)).Append("\"},\n");
    sb.Append("  \"regions\":{\n");
    sb.Append("    \"coreEventAttributeCatalog\":{\"fileStart\":\"0xA1CE000\",\"fileEnd\":\"0xA1E4000\",\"rvaStart\":\"")
      .Append(H(coreStart)).Append("\",\"rvaEnd\":\"").Append(H(coreEnd))
      .Append("\",\"organization\":\"JSON-like STANDARD/CUSTOM event defs + typed attribute dictionary + composition maps; approx gap after 0xA1E3634\",\"evidence\":\"marker bounds from v0.5.9/v0.6.0 probes\"},\n");
    sb.Append("    \"compositionCatalogWider\":{\"fileStart\":\"0xA0FBB00\",\"fileEnd\":\"0xA1E4000\",\"rvaStart\":\"")
      .Append(H(compStart)).Append("\",\"rvaEnd\":\"").Append(H(compEnd)).Append("\"}\n");
    sb.Append("  },\n");
    sb.Append("  \"ripRelativeReferenceCounts\":{\n");
    sb.Append("    \"intoCoreCatalog\":").Append(core.Count).Append(",\n");
    sb.Append("    \"intoCompositionWider\":").Append(comp.Count).Append(",\n");
    sb.Append("    \"intoWholeEdata\":").Append(whole.Count).Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"coreCatalogRipSamples\":[\n");
    for (int i = 0; i < Math.Min(40, core.Count); i++) {
      if (i > 0) sb.Append(",\n");
      sb.Append("    ").Append(core[i].ToJson());
    }
    sb.Append("\n  ],\n");
    sb.Append("  \"representativeEntryReferences\":").Append(targetReport).Append(",\n");
    sb.Append("  \"methodologyNotes\":[\n");
    sb.Append("    \"Scanned executable sections for REX.W LEA/MOV r64,[rip+disp32] whose effective address lands in catalog RVA ranges\",\n");
    sb.Append("    \"Absolute VA immediates to known entry sites also counted\",\n");
    sb.Append("    \"Coincidental disp32 landings possible; confidence elevated when target bytes look JSON-like\"\n");
    sb.Append("  ]\n");
    sb.Append("}\n");
    return sb.ToString();
  }

  static string BuildCandidatesJson(List<Cand> candidates, int coreHitCount) {
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"coreCatalogRipHitCount\":").Append(coreHitCount).Append(",\n");
    sb.Append("  \"candidateCount\":").Append(candidates.Count).Append(",\n");
    sb.Append("  \"labelingPolicy\":").Append(J("Do not label as schema loader from JSON strings alone; require data refs into catalog + supportive control flow")).Append(",\n");
    sb.Append("  \"candidates\":[\n");
    for (int i = 0; i < candidates.Count; i++) {
      var c = candidates[i];
      if (i > 0) sb.Append(",\n");
      sb.Append("    {\n");
      sb.Append("      \"entryRva\":\"").Append(H(c.EntryRva)).Append("\",\n");
      sb.Append("      \"entryFileOffset\":\"").Append(H((ulong)c.EntryFile)).Append("\",\n");
      sb.Append("      \"section\":").Append(J(SecNameForRva(c.EntryRva))).Append(",\n");
      sb.Append("      \"prologueBytes\":").Append(J(c.PrologueBytes)).Append(",\n");
      sb.Append("      \"ripHitsIntoCoreCatalog\":").Append(c.HitCount).Append(",\n");
      sb.Append("      \"confidence\":").Append(J(c.Confidence)).Append(",\n");
      sb.Append("      \"notes\":").Append(J(c.Notes)).Append(",\n");
      sb.Append("      \"isConfirmedSchemaLoader\":false,\n");
      sb.Append("      \"relevantInstructions\":[\n");
      for (int j = 0; j < Math.Min(8, c.Hits.Count); j++) {
        if (j > 0) sb.Append(",\n");
        sb.Append("        ").Append(c.Hits[j].ToJson());
      }
      sb.Append("\n      ],\n");
      sb.Append("      \"evidenceConnectingToCatalog\":").Append(J(
        c.HitCount > 0
          ? "One or more LEA/MOV [rip+disp] effective addresses fall inside core catalog RVA range"
          : "none")).Append("\n");
      sb.Append("    }");
    }
    sb.Append("\n  ],\n");
    sb.Append("  \"conclusions\":{\n");
    sb.Append("    \"schemaParserIdentified\":false,\n");
    sb.Append("    \"schemaConsumerIdentified\":").Append(coreHitCount > 0 ? "true" : "false").Append(",\n");
    sb.Append("    \"schemaConsumerIdentifiedNote\":").Append(J(
      coreHitCount > 0
        ? "Code references INTO the catalog address range exist (RIP-relative). Specific parser/loader function NOT confirmed."
        : "No RIP-relative LEA/MOV into core catalog range found.")).Append(",\n");
    sb.Append("    \"categoriesConsumedIfAny\":").Append(J("unknown — range overlap with STANDARD/CUSTOM/compositions cluster only")).Append("\n");
    sb.Append("  }\n}\n");
    return sb.ToString();
  }

  static string BuildPlayerPosPipeline(List<Cand> candidates, string pipelineStrings, int coreHits) {
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"reassessmentAfterConsumerHunt\":true,\n");
    sb.Append("  \"coreCatalogCodeReferencesFound\":").Append(coreHits > 0 ? "true" : "false").Append(",\n");
    sb.Append("  \"confirmedSchemaLoader\":false,\n");
    sb.Append("  \"playerPosition\":{\n");
    sb.Append("    \"compositionFileOffset\":\"0xA1D77B5\",\n");
    sb.Append("    \"eventFileOffset\":\"0xA1DE0FE\",\n");
    sb.Append("    \"runtimeProducerIdentified\":false,\n");
    sb.Append("    \"floatSourceIdentified\":false,\n");
    sb.Append("    \"activePlayerCharacterLink\":false,\n");
    sb.Append("    \"edwardActorOrTransformLink\":false,\n");
    sb.Append("    \"verifiedConnectionToIdentifiedConsumer\":false,\n");
    sb.Append("    \"note\":").Append(J("Even if code references the catalog region, no instruction trail yet proves player.position event construction or XYZ population")).Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"liveTelemetryAndSendEvent\":").Append(pipelineStrings).Append(",\n");
    sb.Append("  \"pipelineDirection\":{\n");
    sb.Append("    \"runtimeDescriptors\":").Append(J("unproven")).Append(",\n");
    sb.Append("    \"attributeLookup\":").Append(J("unproven")).Append(",\n");
    sb.Append("    \"eventConstruction\":").Append(J("unproven")).Append(",\n");
    sb.Append("    \"serializationOrSubmission\":").Append(J("LiveTelemetry/Job*SendEvent have string presence; code LEA refs reported separately; not linked to player.position")).Append(",\n");
    sb.Append("    \"gameplayProducers\":").Append(J("unproven")).Append(",\n");
    sb.Append("    \"trailStopsAt\":").Append(J(coreHits > 0
      ? "RIP-relative references into catalog range — function purpose not established beyond data addressing"
      : "No RIP-relative references into core catalog range")).Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"topCandidateEntries\":[");
    for (int i = 0; i < Math.Min(5, candidates.Count); i++) {
      if (i > 0) sb.Append(",");
      sb.Append("\"").Append(H(candidates[i].EntryRva)).Append("\"");
    }
    sb.Append("]\n}\n");
    return sb.ToString();
  }
}
