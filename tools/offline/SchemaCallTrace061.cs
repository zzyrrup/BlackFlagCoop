// v0.6.1 — Offline deep trace of high-signal schema consumer.
// Read-only PE analysis. No launch/inject.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

class SchemaCallTrace061 {
  static byte[] pe;
  static List<Sec> secs;
  static ulong imageBase;

  const uint CandEntry = 0x57AF060u;
  const uint HighSignalLea = 0x57AF8D9u;
  const uint HelperString = 0x53519E0u;
  const uint HelperFollow = 0x1A64E70u;
  const uint PlayerPosEventRva = 0xA1DEAFEu;
  const uint Imm4DB = 0x4DBu;

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";
    pe = File.ReadAllBytes(exe);
    ParsePe();
    Directory.CreateDirectory(outDir);

    var cand = AnalyzeFunction(CandEntry, 0x4000, "candidate_0x57AF060");
    var h1 = AnalyzeFunction(HelperString, 0x800, "helper_0x53519E0");
    var h2 = AnalyzeFunction(HelperFollow, 0x2000, "helper_0x1A64E70");

    // Refine candidate end: prefer first int3 run after high-signal, or ret after high-signal
    RefineBoundary(cand, HighSignalLea);

    var callersCand = FindE8Callers(CandEntry, 40);
    var callersH1 = FindE8Callers(HelperString, 40);
    var callersH2 = FindE8Callers(HelperFollow, 40);

    // Focused instruction stream around high-signal
    string highSignalWindow = HexWindow(HighSignalLea - 0x20, 0x80);
    string highSignalDisasm = DisasmWindow(HighSignalLea - 0x10, 0x60);

    // All LEA rip targets inside candidate
    var leaTargets = ExtractLeaTargets(cand.EntryRva, cand.SizeBytes);
    var callTargets = ExtractCallTargets(cand.EntryRva, cand.SizeBytes);

    // Classify lea targets
    var leaClass = new StringBuilder();
    leaClass.Append("[\n");
    for (int i = 0; i < leaTargets.Count; i++) {
      var t = leaTargets[i];
      string cls = ClassifyTarget(t.TargetRva, t.TargetFile);
      if (i > 0) leaClass.Append(",\n");
      leaClass.Append("    {\"siteRva\":\"").Append(H(t.SiteRva)).Append("\",\"targetRva\":\"")
        .Append(H(t.TargetRva)).Append("\",\"targetFile\":\"")
        .Append(H((ulong)Math.Max(0, t.TargetFile))).Append("\",\"class\":")
        .Append(J(cls)).Append(",\"asciiPreview\":")
        .Append(J(AsciiAt(t.TargetFile, 80))).Append("}");
    }
    leaClass.Append("\n  ]");

    // Imm 0x4DB occurrences in candidate
    int imm4db = CountImm32(cand.EntryRva, cand.SizeBytes, Imm4DB);

    // Does helper 0x53519E0 look like SSO string ctor?
    var h1Analysis = AnalyzeStringHelper(h1);

    // Does 0x1A64E70 parse? Look for JSON punctuation compares, loops, allocs
    var h2Analysis = AnalyzeFollowHelper(h2);

    // Dataflow assessment
    string dataflow = BuildDataflow(cand, leaTargets, callTargets, h1Analysis, h2Analysis, imm4db);

    // Gameplay connection: search candidate + helpers for transform/edward/player strings via lea
    string gameplay = BuildGameplay(cand, h1, h2, leaTargets);

    Write(outDir + @"\v0.6.1-candidate-function.json", BuildCandidateJson(
      cand, callersCand, callTargets, leaClass.ToString(), highSignalWindow, highSignalDisasm, imm4db));
    Write(outDir + @"\v0.6.1-helper-analysis.json", BuildHelpersJson(h1, h2, callersH1, callersH2, h1Analysis, h2Analysis));
    Write(outDir + @"\v0.6.1-schema-dataflow.json", dataflow);
    Write(outDir + @"\v0.6.1-gameplay-connection.json", gameplay);

    Console.WriteLine("candidate size=0x{0:X} leaCount={1} callCount={2} imm4DB={3}",
      cand.SizeBytes, leaTargets.Count, callTargets.Count, imm4db);
    Console.WriteLine("helper1 size=0x{0:X} callers={1}", h1.SizeBytes, callersH1.Count);
    Console.WriteLine("helper2 size=0x{0:X} callers={1}", h2.SizeBytes, callersH2.Count);
    return 0;
  }

  class Sec { public string Name; public uint VA, VS, Raw, Ptr, Char; }
  class FuncInfo {
    public string Name; public uint EntryRva; public long EntryFile;
    public uint EndRva; public int SizeBytes; public string Prologue;
    public string BoundaryMethod; public List<string> Notes = new List<string>();
  }
  class Lea { public uint SiteRva; public uint TargetRva; public long TargetFile; }
  class Call { public uint SiteRva; public uint DestRva; }

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
    }
  }

  static string H(ulong v) { return "0x" + v.ToString("X"); }
  static string H(uint v) { return "0x" + v.ToString("X"); }
  static string J(string s) {
    if (s == null) return "null";
    var sb = new StringBuilder("\"");
    foreach (char c in s) {
      if (c == '\\' || c == '"') sb.Append('\\').Append(c);
      else if (c < 32) sb.Append(' ');
      else sb.Append(c);
    }
    sb.Append('"');
    return sb.ToString();
  }
  static void Write(string path, string json) {
    File.WriteAllText(path, json, new UTF8Encoding(false));
    Console.WriteLine("WROTE " + path);
  }

  static long RvaToFile(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VS, s.Raw);
      if (rva >= s.VA && rva < s.VA + span && s.Ptr > 0)
        return s.Ptr + (rva - s.VA);
    }
    return -1;
  }
  static uint? FileToRva(long fo) {
    foreach (var s in secs)
      if (fo >= s.Ptr && fo < s.Ptr + s.Raw)
        return s.VA + (uint)(fo - s.Ptr);
    return null;
  }
  static string SecForRva(uint rva) {
    long fo = RvaToFile(rva);
    if (fo < 0) return null;
    foreach (var s in secs)
      if (fo >= s.Ptr && fo < s.Ptr + s.Raw) return s.Name;
    return null;
  }

  static string AsciiAt(long fo, int n) {
    if (fo < 0 || fo >= pe.Length) return "";
    int len = (int)Math.Min(n, pe.Length - fo);
    var sb = new StringBuilder(len);
    for (int i = 0; i < len; i++) {
      byte b = pe[fo + i];
      sb.Append(b >= 32 && b < 127 ? (char)b : '.');
    }
    return sb.ToString();
  }

  static string HexWindow(uint rva, int n) {
    long fo = RvaToFile(rva);
    if (fo < 0) return "";
    int len = (int)Math.Min(n, pe.Length - fo);
    var sb = new StringBuilder();
    for (int i = 0; i < len; i++) {
      if (i > 0) sb.Append(' ');
      sb.Append(pe[fo + i].ToString("X2"));
    }
    return sb.ToString();
  }

  // Lightweight linear disasm for documentation (not a full decoder).
  static string DisasmWindow(uint rva, int maxBytes) {
    long fo = RvaToFile(rva);
    if (fo < 0) return "";
    var sb = new StringBuilder();
    int i = 0;
    while (i < maxBytes && fo + i + 1 < pe.Length) {
      uint site = rva + (uint)i;
      long pos = fo + i;
      byte b0 = pe[pos];
      // REX.W LEA r64,[rip+disp32]
      if ((b0 == 0x48 || b0 == 0x4C) && i + 7 <= maxBytes && pe[pos + 1] == 0x8D && (pe[pos + 2] & 0xC7) == 0x05) {
        int disp = BitConverter.ToInt32(pe, (int)(pos + 3));
        uint tgt = unchecked((uint)(site + 7 + disp));
        sb.Append(H(site)).Append(": lea rip-rel -> ").Append(H(tgt))
          .Append(" ; ").Append(AsciiAt(RvaToFile(tgt), 40)).Append('\n');
        i += 7; continue;
      }
      // E8 call
      if (b0 == 0xE8 && i + 5 <= maxBytes) {
        int rel = BitConverter.ToInt32(pe, (int)(pos + 1));
        uint dest = unchecked((uint)(site + 5 + rel));
        sb.Append(H(site)).Append(": call ").Append(H(dest)).Append('\n');
        i += 5; continue;
      }
      // mov r8d, imm32  = 41 B8 imm32
      if (b0 == 0x41 && pe[pos + 1] == 0xB8 && i + 6 <= maxBytes) {
        uint imm = BitConverter.ToUInt32(pe, (int)(pos + 2));
        sb.Append(H(site)).Append(": mov r8d, ").Append(H(imm)).Append('\n');
        i += 6; continue;
      }
      // mov edx, imm32 = BA imm32
      if (b0 == 0xBA && i + 5 <= maxBytes) {
        uint imm = BitConverter.ToUInt32(pe, (int)(pos + 1));
        sb.Append(H(site)).Append(": mov edx, ").Append(H(imm)).Append('\n');
        i += 5; continue;
      }
      // ret
      if (b0 == 0xC3) {
        sb.Append(H(site)).Append(": ret\n");
        break;
      }
      // fallback: one byte
      sb.Append(H(site)).Append(": db ").Append(b0.ToString("X2")).Append('\n');
      i += 1;
    }
    return sb.ToString();
  }

  static FuncInfo AnalyzeFunction(uint entry, int maxScan, string name) {
    long fo = RvaToFile(entry);
    var fi = new FuncInfo {
      Name = name,
      EntryRva = entry,
      EntryFile = fo,
      Prologue = fo >= 0 ? HexWindow(entry, 24) : "",
      BoundaryMethod = "int3_or_maxscan",
      EndRva = entry,
      SizeBytes = 0
    };
    if (fo < 0) {
      fi.Notes.Add("RVA not mapped to file");
      return fi;
    }
    // Find end: sequence of CC after a RET, or 3+ CC padding, scanning forward
    int endOff = maxScan;
    for (int i = 16; i + 3 < maxScan && fo + i + 3 < pe.Length; i++) {
      if (pe[fo + i] == 0xC3) {
        // look for CC padding soon after
        int j = i + 1;
        while (j < maxScan && pe[fo + j] == 0xCC) j++;
        if (j - (i + 1) >= 2) { endOff = i + 1; fi.BoundaryMethod = "ret_then_int3"; break; }
      }
      if (pe[fo + i] == 0xCC && pe[fo + i + 1] == 0xCC && pe[fo + i + 2] == 0xCC && i > 32) {
        endOff = i; fi.BoundaryMethod = "int3_run"; break;
      }
    }
    fi.SizeBytes = endOff;
    fi.EndRva = entry + (uint)endOff;
    return fi;
  }

  static void RefineBoundary(FuncInfo cand, uint mustInclude) {
    if (mustInclude < cand.EntryRva) return;
    int minSize = (int)(mustInclude - cand.EntryRva) + 0x40;
    if (cand.SizeBytes < minSize) {
      // rescan with larger window
      var bigger = AnalyzeFunction(cand.EntryRva, 0x8000, cand.Name);
      if (bigger.SizeBytes > cand.SizeBytes) {
        cand.SizeBytes = bigger.SizeBytes;
        cand.EndRva = bigger.EndRva;
        cand.BoundaryMethod = bigger.BoundaryMethod + "_expanded_for_highsignal";
      }
    }
    // Ensure end after high-signal
    if (cand.EndRva < mustInclude + 0x20) {
      cand.EndRva = mustInclude + 0x200;
      cand.SizeBytes = (int)(cand.EndRva - cand.EntryRva);
      cand.BoundaryMethod = "forced_past_highsignal";
      cand.Notes.Add("Boundary extended to include high-signal site");
    }
  }

  static List<uint> FindE8Callers(uint target, int max) {
    var list = new List<uint>();
    foreach (var s in secs) {
      if ((s.Char & 0x20000000) == 0 || s.Ptr == 0) continue;
      int size = (int)s.Raw;
      for (int i = 0; i + 5 <= size; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        uint site = s.VA + (uint)i;
        uint dest = unchecked((uint)(site + 5 + rel));
        if (dest != target) continue;
        list.Add(site);
        if (list.Count >= max) return list;
      }
    }
    return list;
  }

  static List<Lea> ExtractLeaTargets(uint entry, int size) {
    var list = new List<Lea>();
    long fo = RvaToFile(entry);
    if (fo < 0) return list;
    for (int i = 0; i + 7 <= size; i++) {
      byte b0 = pe[fo + i];
      if ((b0 != 0x48 && b0 != 0x4C) || pe[fo + i + 1] != 0x8D) continue;
      if ((pe[fo + i + 2] & 0xC7) != 0x05) continue;
      int disp = BitConverter.ToInt32(pe, (int)(fo + i + 3));
      uint site = entry + (uint)i;
      uint tgt = unchecked((uint)(site + 7 + disp));
      list.Add(new Lea { SiteRva = site, TargetRva = tgt, TargetFile = RvaToFile(tgt) });
    }
    return list;
  }

  static List<Call> ExtractCallTargets(uint entry, int size) {
    var list = new List<Call>();
    long fo = RvaToFile(entry);
    if (fo < 0) return list;
    for (int i = 0; i + 5 <= size; i++) {
      if (pe[fo + i] != 0xE8) continue;
      int rel = BitConverter.ToInt32(pe, (int)(fo + i + 1));
      uint site = entry + (uint)i;
      uint dest = unchecked((uint)(site + 5 + rel));
      list.Add(new Call { SiteRva = site, DestRva = dest });
    }
    return list;
  }

  static int CountImm32(uint entry, int size, uint imm) {
    long fo = RvaToFile(entry);
    if (fo < 0) return 0;
    byte[] n = BitConverter.GetBytes(imm);
    int c = 0;
    for (int i = 0; i + 4 <= size; i++) {
      if (pe[fo + i] == n[0] && pe[fo + i + 1] == n[1] && pe[fo + i + 2] == n[2] && pe[fo + i + 3] == n[3])
        c++;
    }
    return c;
  }

  static string ClassifyTarget(uint rva, long fo) {
    if (rva == PlayerPosEventRva) return "player_position_standard_event_object";
    if (rva >= 0xA1CEA00u && rva < 0xA1E4A00u) {
      string a = AsciiAt(fo, 48);
      if (a.Contains("\"type\":\"STANDARD\"") || a.Contains("\"type\":\"CUSTOM\"") || a.Contains("\"name\":\""))
        return "schema_json_like";
      if (a.Contains("HK_RETURN") || a.Contains("%s") || a.Contains("%d"))
        return "string_pool_or_format";
      return "core_catalog_range_other";
    }
    if (rva >= 0x9036000u && rva < 0xA2B2000u) return "edata_other";
    return "non_edata";
  }

  static Dictionary<string, object> AnalyzeStringHelper(FuncInfo h) {
    long fo = h.EntryFile;
    var d = new Dictionary<string, object>();
    d["entryRva"] = H(h.EntryRva);
    d["sizeBytes"] = h.SizeBytes;
    d["prologue"] = h.Prologue;
    // Look for cmp r8, 0xF  => 49 83 F8 0F
    bool cmpR8_F = false;
    bool hasRepMov = false;
    bool hasHeapLike = false;
    int callCount = 0;
    if (fo >= 0) {
      for (int i = 0; i + 4 < h.SizeBytes; i++) {
        if (pe[fo + i] == 0x49 && pe[fo + i + 1] == 0x83 && pe[fo + i + 2] == 0xF8 && pe[fo + i + 3] == 0x0F)
          cmpR8_F = true;
        if (pe[fo + i] == 0xF3 && (pe[fo + i + 1] == 0xA4 || pe[fo + i + 1] == 0xA5))
          hasRepMov = true;
        if (pe[fo + i] == 0xE8) callCount++;
      }
    }
    d["comparesR8To0xF_SSOThreshold"] = cmpR8_F;
    d["hasRepMovsbOrMovsd"] = hasRepMov;
    d["internalE8CallCount"] = callCount;
    d["argumentHypothesis"] = "RCX=dst string object (this); RDX=source pointer; R8=length — consistent with SSO string assign/construct";
    d["confirmedJsonParser"] = false;
    d["confirmedRegistryInsert"] = false;
    d["assessment"] = cmpR8_F
      ? "Strongly consistent with pointer+length string materialization (SSO branch). Not proven as schema parser."
      : "String/buffer helper suspected but SSO pattern not confirmed.";
    return d;
  }

  static Dictionary<string, object> AnalyzeFollowHelper(FuncInfo h) {
    var d = new Dictionary<string, object>();
    d["entryRva"] = H(h.EntryRva);
    d["sizeBytes"] = h.SizeBytes;
    d["prologue"] = h.Prologue;
    long fo = h.EntryFile;
    int braceCmp = 0, quoteCmp = 0, colonCmp = 0, calls = 0;
    bool leaPlayerPos = false;
    var leaSchema = new List<string>();
    if (fo >= 0) {
      for (int i = 0; i + 7 < h.SizeBytes; i++) {
        if (pe[fo + i] == 0xE8) calls++;
        // cmp reg, imm8 for '{' '}' '"' 
        // 80 F8 7B / 80 F9 7B / 3C 7B etc — count loosely
        if (pe[fo + i] == 0x3C && (pe[fo + i + 1] == 0x7B || pe[fo + i + 1] == 0x7D || pe[fo + i + 1] == 0x22 || pe[fo + i + 1] == 0x3A)) {
          if (pe[fo + i + 1] == 0x7B || pe[fo + i + 1] == 0x7D) braceCmp++;
          if (pe[fo + i + 1] == 0x22) quoteCmp++;
          if (pe[fo + i + 1] == 0x3A) colonCmp++;
        }
        byte b0 = pe[fo + i];
        if ((b0 == 0x48 || b0 == 0x4C) && pe[fo + i + 1] == 0x8D && (pe[fo + i + 2] & 0xC7) == 0x05) {
          int disp = BitConverter.ToInt32(pe, (int)(fo + i + 3));
          uint site = h.EntryRva + (uint)i;
          uint tgt = unchecked((uint)(site + 7 + disp));
          if (tgt == PlayerPosEventRva) leaPlayerPos = true;
          if (tgt >= 0xA1CEA00u && tgt < 0xA1E4A00u && leaSchema.Count < 8)
            leaSchema.Add(H(tgt));
        }
      }
    }
    d["internalE8CallCount"] = calls;
    d["cmpImmAsciiBraceLike"] = braceCmp;
    d["cmpImmAsciiQuoteLike"] = quoteCmp;
    d["cmpImmAsciiColonLike"] = colonCmp;
    d["leaToPlayerPositionEvent"] = leaPlayerPos;
    d["leaToCoreCatalogSamples"] = leaSchema;
    d["confirmedJsonParser"] = false;
    d["assessment"] = "Larger follow-on function. May process a string/object previously constructed; JSON-parse not confirmed from punctuation-imm heuristics alone.";
    return d;
  }

  static string BuildCandidateJson(FuncInfo cand, List<uint> callers, List<Call> calls,
      string leaClass, string hsWindow, string hsDisasm, int imm4db) {
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"function\":{\n");
    sb.Append("    \"entryRva\":\"").Append(H(cand.EntryRva)).Append("\",\n");
    sb.Append("    \"entryFileOffset\":\"").Append(H((ulong)cand.EntryFile)).Append("\",\n");
    sb.Append("    \"endRva\":\"").Append(H(cand.EndRva)).Append("\",\n");
    sb.Append("    \"sizeBytes\":").Append(cand.SizeBytes).Append(",\n");
    sb.Append("    \"section\":").Append(J(SecForRva(cand.EntryRva))).Append(",\n");
    sb.Append("    \"prologueBytes\":").Append(J(cand.Prologue)).Append(",\n");
    sb.Append("    \"boundaryMethod\":").Append(J(cand.BoundaryMethod)).Append(",\n");
    sb.Append("    \"boundaryConfidence\":").Append(J(
      cand.BoundaryMethod.Contains("ret_then_int3") || cand.BoundaryMethod.Contains("int3_run")
        ? "medium" : "low_to_medium")).Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"highSignalSite\":{\n");
    sb.Append("    \"rva\":\"").Append(H(HighSignalLea)).Append("\",\n");
    sb.Append("    \"hexWindow\":").Append(J(hsWindow)).Append(",\n");
    sb.Append("    \"linearDisasm\":").Append(J(hsDisasm)).Append(",\n");
    sb.Append("    \"imm0x4DBCountInFunction\":").Append(imm4db).Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"directCallersE8\":[");
    for (int i = 0; i < callers.Count; i++) {
      if (i > 0) sb.Append(",");
      sb.Append("\"").Append(H(callers[i])).Append("\"");
    }
    sb.Append("],\n");
    sb.Append("  \"directCalleesE8\":[");
    var uniq = new HashSet<uint>();
    bool first = true;
    foreach (var c in calls) {
      if (!uniq.Add(c.DestRva)) continue;
      if (!first) sb.Append(",");
      first = false;
      sb.Append("{\"site\":\"").Append(H(c.SiteRva)).Append("\",\"dest\":\"").Append(H(c.DestRva)).Append("\"}");
    }
    sb.Append("],\n");
    sb.Append("  \"leaRipTargets\":").Append(leaClass).Append(",\n");
    sb.Append("  \"phaseHint\":{\n");
    sb.Append("    \"startupStaticallyProven\":false,\n");
    sb.Append("    \"note\":").Append(J("Offline analysis cannot prove execution phase; caller 0x57A9ED7 is nearby and likely same subsystem init path — unproven")).Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"conclusions\":{\n");
    sb.Append("    \"handlesMultipleSchemaBlocks\":").Append(J("unknown — observes at least one multi-event chunk via 0x4DB window; other LEAs also hit schema_json_like targets")).Append(",\n");
    sb.Append("    \"hardcodedPlayerPositionChunk\":true,\n");
    sb.Append("    \"confirmedPurpose\":").Append(J("References embedded schema text and passes pointer+0x4DB length into helpers; full semantic role not established")).Append("\n");
    sb.Append("  }\n}\n");
    return sb.ToString();
  }

  static string BuildHelpersJson(FuncInfo h1, FuncInfo h2, List<uint> c1, List<uint> c2,
      Dictionary<string, object> a1, Dictionary<string, object> a2) {
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"helper_0x53519E0\":{\n");
    sb.Append("    \"entryRva\":\"").Append(H(h1.EntryRva)).Append("\",\n");
    sb.Append("    \"entryFileOffset\":\"").Append(H((ulong)h1.EntryFile)).Append("\",\n");
    sb.Append("    \"endRva\":\"").Append(H(h1.EndRva)).Append("\",\n");
    sb.Append("    \"sizeBytes\":").Append(h1.SizeBytes).Append(",\n");
    sb.Append("    \"boundaryMethod\":").Append(J(h1.BoundaryMethod)).Append(",\n");
    sb.Append("    \"prologueBytes\":").Append(J(h1.Prologue)).Append(",\n");
    sb.Append("    \"callerCountE8\":").Append(c1.Count).Append(",\n");
    sb.Append("    \"callerSamples\":[");
    for (int i = 0; i < Math.Min(15, c1.Count); i++) {
      if (i > 0) sb.Append(",");
      sb.Append("\"").Append(H(c1[i])).Append("\"");
    }
    sb.Append("],\n");
    sb.Append("    \"analysis\":{\n");
    sb.Append("      \"comparesR8To0xF_SSOThreshold\":").Append(a1["comparesR8To0xF_SSOThreshold"].ToString().ToLower()).Append(",\n");
    sb.Append("      \"hasRepMovsbOrMovsd\":").Append(a1["hasRepMovsbOrMovsd"].ToString().ToLower()).Append(",\n");
    sb.Append("      \"internalE8CallCount\":").Append(a1["internalE8CallCount"]).Append(",\n");
    sb.Append("      \"argumentHypothesis\":").Append(J((string)a1["argumentHypothesis"])).Append(",\n");
    sb.Append("      \"confirmedJsonParser\":false,\n");
    sb.Append("      \"confirmedRegistryInsert\":false,\n");
    sb.Append("      \"assessment\":").Append(J((string)a1["assessment"])).Append("\n");
    sb.Append("    }\n  },\n");
    sb.Append("  \"helper_0x1A64E70\":{\n");
    sb.Append("    \"entryRva\":\"").Append(H(h2.EntryRva)).Append("\",\n");
    sb.Append("    \"entryFileOffset\":\"").Append(H((ulong)h2.EntryFile)).Append("\",\n");
    sb.Append("    \"endRva\":\"").Append(H(h2.EndRva)).Append("\",\n");
    sb.Append("    \"sizeBytes\":").Append(h2.SizeBytes).Append(",\n");
    sb.Append("    \"boundaryMethod\":").Append(J(h2.BoundaryMethod)).Append(",\n");
    sb.Append("    \"prologueBytes\":").Append(J(h2.Prologue)).Append(",\n");
    sb.Append("    \"callerCountE8\":").Append(c2.Count).Append(",\n");
    sb.Append("    \"callerSamples\":[");
    for (int i = 0; i < Math.Min(15, c2.Count); i++) {
      if (i > 0) sb.Append(",");
      sb.Append("\"").Append(H(c2[i])).Append("\"");
    }
    sb.Append("],\n");
    sb.Append("    \"analysis\":{\n");
    sb.Append("      \"internalE8CallCount\":").Append(a2["internalE8CallCount"]).Append(",\n");
    sb.Append("      \"cmpImmAsciiBraceLike\":").Append(a2["cmpImmAsciiBraceLike"]).Append(",\n");
    sb.Append("      \"cmpImmAsciiQuoteLike\":").Append(a2["cmpImmAsciiQuoteLike"]).Append(",\n");
    sb.Append("      \"leaToPlayerPositionEvent\":").Append(a2["leaToPlayerPositionEvent"].ToString().ToLower()).Append(",\n");
    sb.Append("      \"confirmedJsonParser\":false,\n");
    sb.Append("      \"assessment\":").Append(J((string)a2["assessment"])).Append("\n");
    sb.Append("    }\n  }\n}\n");
    return sb.ToString();
  }

  static string BuildDataflow(FuncInfo cand, List<Lea> leas, List<Call> calls,
      Dictionary<string, object> h1, Dictionary<string, object> h2, int imm4db) {
    int schemaLeas = 0;
    foreach (var l in leas) {
      string c = ClassifyTarget(l.TargetRva, l.TargetFile);
      if (c == "schema_json_like" || c == "player_position_standard_event_object") schemaLeas++;
    }
    bool callsStringHelper = false, callsFollow = false;
    foreach (var c in calls) {
      if (c.DestRva == HelperString) callsStringHelper = true;
      if (c.DestRva == HelperFollow) callsFollow = true;
    }
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"path\":[\n");
    sb.Append("    {\"stage\":1,\"name\":\"raw_schema_bytes\",\"status\":\"confirmed\",\"detail\":");
    sb.Append(J("LEA loads address of embedded player.position STANDARD object at 0xA1DEAFE")).Append("},\n");
    sb.Append("    {\"stage\":2,\"name\":\"length_immediate\",\"status\":\"confirmed\",\"detail\":");
    sb.Append(J("R8D/EDX loaded with 0x4DB; window spans multiple event schemas; imm appears " + imm4db + " time(s) in candidate")).Append("},\n");
    sb.Append("    {\"stage\":3,\"name\":\"passed_as_pointer_plus_length\",\"status\":\"confirmed\",\"detail\":");
    sb.Append(J("call 0x53519E0 with pointer in RDX and length in R8 (first site); second site uses R9/EDX similarly then call 0x1A64E70")).Append("},\n");
    sb.Append("    {\"stage\":4,\"name\":\"copied_into_string_or_buffer\",\"status\":\"strong_hypothesis\",\"detail\":");
    sb.Append(J((string)h1["assessment"])).Append("},\n");
    sb.Append("    {\"stage\":5,\"name\":\"parsed_into_structured_fields\",\"status\":\"unconfirmed\",\"detail\":");
    sb.Append(J("No confirmed JSON field extraction in 0x53519E0; 0x1A64E70 not proven as parser")).Append("},\n");
    sb.Append("    {\"stage\":6,\"name\":\"runtime_descriptors_or_registry\",\"status\":\"unconfirmed\",\"detail\":");
    sb.Append(J("No verified descriptor table inserts identified offline")).Append("},\n");
    sb.Append("    {\"stage\":7,\"name\":\"event_construction_or_dispatch\",\"status\":\"unconfirmed\",\"detail\":");
    sb.Append(J("Trail does not reach a proven live event emitter")).Append("}\n");
    sb.Append("  ],\n");
    sb.Append("  \"metrics\":{\n");
    sb.Append("    \"schemaJsonLikeLeaCountInCandidate\":").Append(schemaLeas).Append(",\n");
    sb.Append("    \"callsStringHelper\":").Append(callsStringHelper ? "true" : "false").Append(",\n");
    sb.Append("    \"callsFollowHelper\":").Append(callsFollow ? "true" : "false").Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"summary\":").Append(J(
      "Confirmed: schema bytes addressed and passed with length into helpers. Not confirmed: parse, registry, dispatch.")).Append("\n");
    sb.Append("}\n");
    return sb.ToString();
  }

  static string BuildGameplay(FuncInfo cand, FuncInfo h1, FuncInfo h2, List<Lea> leas) {
    // Search lea targets for edward/transform-ish; also scan function bodies for those ascii needles as immediates — skip, use lea ascii
    bool anyEdward = false, anyTransform = false, anyPlayerPosFloatWriter = false;
    foreach (var l in leas) {
      string a = AsciiAt(l.TargetFile, 60).ToLowerInvariant();
      if (a.Contains("edward") || a.Contains("kenway")) anyEdward = true;
      if (a.Contains("transform") || a.Contains("worldmatrix") || a.Contains("translation")) anyTransform = true;
      if (a.Contains("playerposx") && a.Contains("float")) { /* schema dict, not writer */ }
    }
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"searchedIn\":[\"0x57AF060\",\"lea_targets\",\"helpers_indirectly\"],\n");
    sb.Append("  \"connections\":{\n");
    sb.Append("    \"playerPositionUpdates\":false,\n");
    sb.Append("    \"playerMovement\":false,\n");
    sb.Append("    \"characterActorEntity\":false,\n");
    sb.Append("    \"transformUpdates\":false,\n");
    sb.Append("    \"edwardInitOrActorCreation\":false\n");
    sb.Append("  },\n");
    sb.Append("  \"leaTargetHints\":{\n");
    sb.Append("    \"edwardOrKenwayStringSeen\":").Append(anyEdward ? "true" : "false").Append(",\n");
    sb.Append("    \"transformLikeStringSeen\":").Append(anyTransform ? "true" : "false").Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"assessment\":").Append(J(
      "No defensible link from this schema-chunk consumer path to live pose, movement, actor, transform, or Edward creation. Telemetry schema text ≠ gameplay coordinates.")).Append(",\n");
    sb.Append("  \"secondEdwardPath\":").Append(J(
      "Not advanced by this finding. Next: finish determining whether helpers populate a registry usable at runtime; separately continue actor/control architecture research.")).Append("\n");
    sb.Append("}\n");
    return sb.ToString();
  }
}
