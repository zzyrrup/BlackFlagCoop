// v0.6.4 — Offline analysis of CreateActorsDeferred handler 0x1AC380,
// linked follow-ups, and action-vtable 0x9255320 consumers.
// Read-only. No spawn/inject/launch.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

class DeferredHandler064 {
  static byte[] pe;
  static List<Sec> secs;
  static ulong imageBase;

  const uint Handler = 0x1AC380u;
  const uint Controllers = 0x7B00B60u;
  const uint UpdateActor = 0x29C6910u;
  const uint ActionVtable = 0x9255320u;
  const uint Registrar = 0x5CBDFB0u;

  class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }
  class Lea { public uint Site, Target; public string Preview, Class; }
  class Call { public uint Site, Dest; public bool Mapped; public string Note; }
  class FuncInfo {
    public uint Entry, End, Size;
    public string Section, Boundary, Prologue;
    public List<Call> Calls = new List<Call>();
    public List<Lea> Leas = new List<Lea>();
    public List<uint> E8Callers = new List<uint>();
    public List<uint> QwordPtrs = new List<uint>();
    public List<string> BranchNotes = new List<string>();
    public int LoopHints;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";
    pe = File.ReadAllBytes(exe);
    ParsePe();
    Directory.CreateDirectory(outDir);

    var h = Analyze(Handler, 0x4000, "handler_0x1AC380");
    bool callsControllers = CallsDest(h, Controllers);
    bool callsUpdateActor = CallsDest(h, UpdateActor);
    bool callsRegistrar = CallsDest(h, Registrar);

    FuncInfo ctrl = null, upd = null;
    if (callsControllers) ctrl = Analyze(Controllers, 0x2000, "controllers");
    else {
      // Still capture brief identity for report if NOT linked — mark unlinked
      ctrl = Analyze(Controllers, 0x800, "controllers_unlinked");
    }
    if (callsUpdateActor) upd = Analyze(UpdateActor, 0x2000, "update_actor");
    else upd = Analyze(UpdateActor, 0x800, "update_actor_unlinked");

    // Shared callees between handler and the two follow-ups
    var sharedHC = SharedDests(h.Calls, ctrl.Calls);
    var sharedHU = SharedDests(h.Calls, upd.Calls);

    // Vtable consumers: absolute qword ptrs + LEA rip to ActionVtable
    var vtableQwords = FindQwordPointersTo(ActionVtable, 40);
    var vtableLeas = FindLeaToRva(ActionVtable, 40);
    // Also find code that MOV [reg], imm64 style — covered by qword scan
    // Find functions that install this vtable: look for mov [reg], rax after lea rax,[vtable]
    var vtableInstallSites = new List<string>();
    foreach (var site in vtableLeas) {
      vtableInstallSites.Add("0x" + site.ToString("X") + " lea->" + ClassifyNear(site));
    }

    // Character-ish LEAs inside handler
    var charHits = new List<string>();
    foreach (var l in h.Leas) {
      string p = l.Preview ?? "";
      string low = p.ToLowerInvariant();
      if (low.Contains("edward") || low.Contains("character") || low.Contains("archetype") ||
          low.Contains("player") || low.Contains("entity") || low.Contains("actor") ||
          low.Contains("transform") || low.Contains("anim") || low.Contains("spawn") ||
          low.Contains("create") || low.Contains("component") || low.Contains("deferred")) {
        charHits.Add("0x" + l.Site.ToString("X") + " -> 0x" + l.Target.ToString("X") + " :: " + Trunc(p, 80));
      }
    }

    // Handler hex dump for disasm report
    string hexDump = Hex(Handler, (int)Math.Min(h.Size, 512u));

    // Classify handler callees by prologue pattern
    ClassifyCalls(h.Calls);

    // Queue/loop heuristics in handler bytes
    string heuristics = HandlerHeuristics(h);

    // Build reports
    Write(outDir + @"\v0.6.4-handler-disassembly.json", BuildDisasm(h, hexDump, heuristics));
    Write(outDir + @"\v0.6.4-creation-callgraph.json", BuildCallgraph(h, ctrl, upd, callsControllers, callsUpdateActor, callsRegistrar, sharedHC, sharedHU));
    Write(outDir + @"\v0.6.4-character-connections.json", BuildChar(h, charHits));
    Write(outDir + @"\v0.6.4-input-action-consumers.json", BuildInput(vtableQwords, vtableLeas, vtableInstallSites));
    Write(outDir + @"\v0.6.4-second-edward-feasibility.json", BuildFeas(h, charHits, callsControllers, callsUpdateActor, vtableQwords.Count + vtableLeas.Count));

    Console.WriteLine("handler size=0x" + h.Size.ToString("X") + " calls=" + h.Calls.Count +
      " leas=" + h.Leas.Count + " e8callers=" + h.E8Callers.Count +
      " ptrs=" + h.QwordPtrs.Count);
    Console.WriteLine("callsControllers=" + callsControllers + " callsUpdateActor=" + callsUpdateActor +
      " sharedHC=" + sharedHC.Count + " sharedHU=" + sharedHU.Count);
    Console.WriteLine("vtableQwords=" + vtableQwords.Count + " vtableLeas=" + vtableLeas.Count +
      " charHits=" + charHits.Count);
    Console.WriteLine("ctrl size=0x" + ctrl.Size.ToString("X") + " upd size=0x" + upd.Size.ToString("X"));
    return 0;
  }

  static FuncInfo Analyze(uint entry, uint maxScan, string tag) {
    var f = new FuncInfo();
    f.Entry = entry;
    f.Section = SecName(entry);
    f.Prologue = Hex(entry, 32);
    long fo = RvaFile(entry);
    if (fo < 0) {
      f.End = entry; f.Size = 0; f.Boundary = "unmapped";
      return f;
    }
    // Prefer INT3 run; else epilogue (add rsp / pops / ret); avoid bare C3 in modrm
    uint end = FindBoundary(entry, maxScan);
    f.End = end;
    f.Size = end > entry ? end - entry : 0;
    f.Boundary = f.Size > 0 ? "int3_or_epilogue" : "failed";
    if (f.Size == 0) { f.Size = Math.Min(maxScan, 0x200u); f.End = entry + f.Size; f.Boundary = "maxscan_fallback"; }

    f.Calls = ExtractCalls(entry, f.Size);
    f.Leas = ExtractLeas(entry, f.Size);
    ClassifyLeas(f.Leas);
    f.E8Callers = FindE8Callers(entry, 30);
    f.QwordPtrs = FindQwordPointersTo(entry, 25);
    f.BranchNotes = ExtractBranches(entry, f.Size);
    f.LoopHints = CountLoopHints(entry, f.Size);
    return f;
  }

  static uint FindBoundary(uint entry, uint max) {
    long fo = RvaFile(entry);
    if (fo < 0) return entry;
    int cc = 0;
    // Track simple push depth to avoid early false ends; mainly look for CC run after a RET that follows pop
    for (uint i = 1; i < max && fo + i < pe.Length; i++) {
      byte b = pe[fo + i];
      if (b == 0xCC) {
        cc++;
        if (cc >= 4) {
          // require a RET shortly before INT3 padding
          for (int k = 1; k <= 24 && (int)i - k >= 0; k++) {
            if (pe[fo + i - k] == 0xC3) return entry + i - (uint)cc + 1;
            if (pe[fo + i - k] == 0xC2) return entry + i - (uint)cc + 1;
          }
          // still accept long CC run as end if function looks large enough
          if (i > 0x40) return entry + i - (uint)cc + 1;
        }
      } else cc = 0;
    }
    // Fallback: find last RET followed by CC within window
    uint last = 0;
    for (uint i = 0x20; i + 1 < max && fo + i + 1 < pe.Length; i++) {
      if (pe[fo + i] == 0xC3 && pe[fo + i + 1] == 0xCC) last = entry + i + 1;
    }
    if (last > entry) return last;
    return entry + max;
  }

  static List<string> ExtractBranches(uint entry, uint size) {
    var list = new List<string>();
    long fo = RvaFile(entry);
    if (fo < 0) return list;
    int jcc = 0, jmp = 0;
    for (uint i = 0; i + 2 < size; i++) {
      byte b = pe[fo + i];
      // short jcc 70-7F
      if (b >= 0x70 && b <= 0x7F) jcc++;
      // near jcc 0F 8x
      if (b == 0x0F && i + 5 < size && pe[fo + i + 1] >= 0x80 && pe[fo + i + 1] <= 0x8F) jcc++;
      if (b == 0xEB || b == 0xE9) jmp++;
    }
    list.Add("shortOrNearJccApprox=" + jcc);
    list.Add("jmpApprox=" + jmp);
    return list;
  }

  static int CountLoopHints(uint entry, uint size) {
    long fo = RvaFile(entry);
    if (fo < 0) return 0;
    int n = 0;
    for (uint i = 0; i + 2 < size; i++) {
      byte b = pe[fo + i];
      // backward short jump (EB xx negative) or jcc backward
      if (b == 0xEB) {
        sbyte d = (sbyte)pe[fo + i + 1];
        if (d < 0) n++;
      }
      if (b >= 0x70 && b <= 0x7F) {
        sbyte d = (sbyte)pe[fo + i + 1];
        if (d < 0) n++;
      }
      if (b == 0x0F && i + 5 < size && pe[fo + i + 1] >= 0x80 && pe[fo + i + 1] <= 0x8F) {
        int rel = BitConverter.ToInt32(pe, (int)(fo + i + 2));
        if (rel < 0) n++;
      }
    }
    return n;
  }

  static string HandlerHeuristics(FuncInfo h) {
    var sb = new StringBuilder();
    sb.Append("loopHints=").Append(h.LoopHints);
    sb.Append("; mappedCallees=");
    int m = 0; foreach (var c in h.Calls) if (c.Mapped) m++;
    sb.Append(m);
    sb.Append("; stringLeas=");
    int s = 0; foreach (var l in h.Leas) if (l.Class != "other" && l.Class != "code_or_data") s++;
    sb.Append(s);
    // Look for typical allocator patterns: mov edx, imm; call
    long fo = RvaFile(h.Entry);
    int allocLike = 0;
    if (fo >= 0) {
      for (uint i = 0; i + 10 < h.Size; i++) {
        // BA xx xx 00 00 (mov edx, imm16/32 small) near E8
        if (pe[fo + i] == 0xBA) {
          uint imm = BitConverter.ToUInt32(pe, (int)(fo + i + 1));
          if (imm >= 0x10 && imm <= 0x4000) {
            for (uint k = i; k < i + 24 && k + 5 < h.Size; k++) {
              if (pe[fo + k] == 0xE8) { allocLike++; break; }
            }
          }
        }
      }
    }
    sb.Append("; sizeImmNearCall=").Append(allocLike);
    return sb.ToString();
  }

  static bool CallsDest(FuncInfo f, uint dest) {
    foreach (var c in f.Calls) if (c.Dest == dest) return true;
    return false;
  }

  static List<uint> SharedDests(List<Call> a, List<Call> b) {
    var set = new HashSet<uint>();
    foreach (var c in a) if (c.Mapped) set.Add(c.Dest);
    var shared = new List<uint>();
    foreach (var c in b) if (c.Mapped && set.Contains(c.Dest) && !shared.Contains(c.Dest)) shared.Add(c.Dest);
    return shared;
  }

  static void ClassifyCalls(List<Call> calls) {
    foreach (var c in calls) {
      if (!c.Mapped) { c.Note = "unmapped_or_bogus"; continue; }
      string pro = Hex(c.Dest, 12);
      if (pro.StartsWith("C3")) c.Note = "ret_stub";
      else if (pro.Contains("48 89 91") || pro.Contains("89 91")) c.Note = "field_store_stub";
      else if (pro.StartsWith("48 8B 41") || pro.StartsWith("48 8B 01")) c.Note = "field_load_stub";
      else c.Note = "func";
    }
  }

  static string ClassifyNear(uint leaSite) {
    // look +/- 0x20 for string or code
    return "site";
  }

  static List<Call> ExtractCalls(uint entry, uint size) {
    var list = new List<Call>();
    long fo = RvaFile(entry);
    if (fo < 0) return list;
    for (uint i = 0; i + 5 <= size; i++) {
      if (pe[fo + i] != 0xE8) continue;
      int rel = BitConverter.ToInt32(pe, (int)(fo + i + 1));
      uint site = entry + i;
      uint dest = unchecked((uint)(site + 5 + rel));
      list.Add(new Call { Site = site, Dest = dest, Mapped = RvaFile(dest) >= 0 });
    }
    return list;
  }

  static List<Lea> ExtractLeas(uint entry, uint size) {
    var list = new List<Lea>();
    long fo = RvaFile(entry);
    if (fo < 0) return list;
    for (uint i = 0; i + 7 <= size; i++) {
      byte rex = pe[fo + i];
      if (rex != 0x48 && rex != 0x4C) continue;
      if (pe[fo + i + 1] != 0x8D) continue;
      if ((pe[fo + i + 2] & 0xC7) != 0x05) continue;
      int disp = BitConverter.ToInt32(pe, (int)(fo + i + 3));
      uint site = entry + i;
      uint target = unchecked((uint)(site + 7 + disp));
      list.Add(new Lea { Site = site, Target = target, Preview = ReadAscii(target, 72) });
    }
    return list;
  }

  static void ClassifyLeas(List<Lea> leas) {
    for (int i = 0; i < leas.Count; i++) {
      var l = leas[i];
      string p = l.Preview ?? "";
      string low = p.ToLowerInvariant();
      if (p.StartsWith("Pad_") || p.StartsWith("Key_") || p.Contains("PlayerInput"))
        l.Class = "input_action_name";
      else if (low.Contains("createactors") || low.Contains("singlethreaded") || low.Contains("multithreaded"))
        l.Class = "frame_phase_label";
      else if (low.Contains("edward"))
        l.Class = "edward_string";
      else if (low.Contains("character") || low.Contains("archetype"))
        l.Class = "character_or_archetype_string";
      else if (low.Contains("actor") || low.Contains("component") || low.Contains("entity") || low.Contains("transform"))
        l.Class = "actor_related_string";
      else if (p.Length >= 4 && IsMostlyPrintable(p))
        l.Class = "edata_or_string";
      else
        l.Class = "code_or_data";
    }
  }

  static bool IsMostlyPrintable(string p) {
    int ok = 0;
    foreach (char c in p) if (c >= 32 && c < 127) ok++;
    return p.Length > 0 && ok * 2 >= p.Length;
  }

  static List<uint> FindE8Callers(uint dest, int max) {
    var list = new List<uint>();
    foreach (var s in secs) {
      if ((s.Char & 0x20000000) == 0 || s.Ptr == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 5 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        long site = (long)s.Va + i;
        long d = site + 5 + rel;
        if (d == (long)dest) list.Add((uint)site);
      }
    }
    return list;
  }

  static List<uint> FindQwordPointersTo(uint destRva, int max) {
    var list = new List<uint>();
    ulong abs = imageBase + destRva;
    byte[] needle = BitConverter.GetBytes(abs);
    foreach (var s in secs) {
      if (s.Ptr == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 8 <= lim && list.Count < max; i++) {
        bool ok = true;
        for (int k = 0; k < 8; k++) if (pe[s.Ptr + i + k] != needle[k]) { ok = false; break; }
        if (ok) list.Add(s.Va + i);
      }
    }
    return list;
  }

  static List<uint> FindLeaToRva(uint target, int max) {
    var list = new List<uint>();
    foreach (var s in secs) {
      if ((s.Char & 0x20000000) == 0 || s.Ptr == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim && list.Count < max; i++) {
        byte rex = pe[s.Ptr + i];
        if (rex != 0x48 && rex != 0x4C) continue;
        if (pe[s.Ptr + i + 1] != 0x8D) continue;
        if ((pe[s.Ptr + i + 2] & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 3));
        uint site = s.Va + i;
        uint tgt = unchecked((uint)(site + 7 + disp));
        if (tgt == target) list.Add(site);
      }
    }
    return list;
  }

  static string ReadAscii(uint rva, int max) {
    long fo = RvaFile(rva);
    if (fo < 0) return "";
    var sb = new StringBuilder();
    for (int i = 0; i < max && fo + i < pe.Length; i++) {
      byte b = pe[fo + i];
      if (b == 0) break;
      if (b >= 32 && b < 127) sb.Append((char)b);
      else sb.Append('.');
    }
    return sb.ToString();
  }

  static string Hex(uint rva, int n) {
    long fo = RvaFile(rva);
    if (fo < 0) return "UNMAPPED";
    var sb = new StringBuilder();
    for (int i = 0; i < n && fo + i < pe.Length; i++) {
      if (i > 0) sb.Append(' ');
      sb.Append(pe[fo + i].ToString("X2"));
    }
    return sb.ToString();
  }

  static string SecName(uint rva) {
    foreach (var s in secs)
      if (rva >= s.Va && rva < s.Va + Math.Max(s.VSize, s.Raw)) return s.Name.TrimEnd('\0');
    return "?";
  }

  static long RvaFile(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva >= s.Va && rva < s.Va + span && s.Ptr > 0)
        return (long)s.Ptr + (rva - s.Va);
    }
    return -1;
  }

  static void ParsePe() {
    int e = BitConverter.ToInt32(pe, 0x3C);
    imageBase = BitConverter.ToUInt64(pe, e + 0x30);
    ushort num = BitConverter.ToUInt16(pe, e + 6);
    ushort opt = BitConverter.ToUInt16(pe, e + 20);
    int sec = e + 24 + opt;
    secs = new List<Sec>();
    for (int i = 0; i < num; i++) {
      int o = sec + i * 40;
      secs.Add(new Sec {
        Name = Encoding.ASCII.GetString(pe, o, 8).TrimEnd('\0'),
        VSize = BitConverter.ToUInt32(pe, o + 8),
        Va = BitConverter.ToUInt32(pe, o + 12),
        Raw = BitConverter.ToUInt32(pe, o + 16),
        Ptr = BitConverter.ToUInt32(pe, o + 20),
        Char = BitConverter.ToUInt32(pe, o + 36)
      });
    }
  }

  static string Trunc(string s, int n) {
    if (s == null) return "";
    return s.Length <= n ? s : s.Substring(0, n);
  }

  static string Esc(string s) {
    if (s == null) return "";
    return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
  }

  static void Write(string path, string body) {
    File.WriteAllText(path, body);
    Console.WriteLine("WROTE " + path);
  }

  static string JArrU(List<uint> xs, int max = 40) {
    var sb = new StringBuilder("[");
    int n = Math.Min(xs.Count, max);
    for (int i = 0; i < n; i++) {
      if (i > 0) sb.Append(',');
      sb.Append("\"0x").Append(xs[i].ToString("X")).Append('"');
    }
    return sb.Append(']').ToString();
  }

  static string JArrS(List<string> xs, int max = 40) {
    var sb = new StringBuilder("[");
    int n = Math.Min(xs.Count, max);
    for (int i = 0; i < n; i++) {
      if (i > 0) sb.Append(',');
      sb.Append('"').Append(Esc(xs[i])).Append('"');
    }
    return sb.Append(']').ToString();
  }

  static string JCalls(List<Call> xs, int max = 60) {
    var sb = new StringBuilder("[");
    int n = Math.Min(xs.Count, max);
    for (int i = 0; i < n; i++) {
      if (i > 0) sb.Append(',');
      sb.Append("{\"site\":\"0x").Append(xs[i].Site.ToString("X"))
        .Append("\",\"dest\":\"0x").Append(xs[i].Dest.ToString("X"))
        .Append("\",\"mapped\":").Append(xs[i].Mapped ? "true" : "false")
        .Append(",\"note\":\"").Append(Esc(xs[i].Note ?? "")).Append("\"}");
    }
    return sb.Append(']').ToString();
  }

  static string JLeas(List<Lea> xs, int max = 40) {
    var sb = new StringBuilder("[");
    int n = Math.Min(xs.Count, max);
    for (int i = 0; i < n; i++) {
      if (i > 0) sb.Append(',');
      sb.Append("{\"site\":\"0x").Append(xs[i].Site.ToString("X"))
        .Append("\",\"target\":\"0x").Append(xs[i].Target.ToString("X"))
        .Append("\",\"class\":\"").Append(Esc(xs[i].Class))
        .Append("\",\"preview\":\"").Append(Esc(Trunc(xs[i].Preview, 80))).Append("\"}");
    }
    return sb.Append(']').ToString();
  }

  static string BuildDisasm(FuncInfo h, string hexDump, string heuristics) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\":1,");
    sb.AppendLine("  \"generatedUtc\":\"" + DateTime.UtcNow.ToString("o") + "\",");
    sb.AppendLine("  \"milestone\":\"v0.6.4\",");
    sb.AppendLine("  \"function\":{");
    sb.AppendLine("    \"entryRva\":\"0x" + h.Entry.ToString("X") + "\",");
    sb.AppendLine("    \"endRva\":\"0x" + h.End.ToString("X") + "\",");
    sb.AppendLine("    \"sizeBytes\":" + h.Size + ",");
    sb.AppendLine("    \"section\":\"" + Esc(h.Section) + "\",");
    sb.AppendLine("    \"boundaryMethod\":\"" + Esc(h.Boundary) + "\",");
    sb.AppendLine("    \"prologue\":\"" + Esc(h.Prologue) + "\",");
    sb.AppendLine("    \"registeredAs\":\"CreateActorsDeferredSingleThreaded\"");
    sb.AppendLine("  },");
    sb.AppendLine("  \"hexDumpPrefix\":\"" + Esc(hexDump) + "\",");
    sb.AppendLine("  \"branches\":" + JArrS(h.BranchNotes) + ",");
    sb.AppendLine("  \"loopHints\":" + h.LoopHints + ",");
    sb.AppendLine("  \"heuristics\":\"" + Esc(heuristics) + "\",");
    sb.AppendLine("  \"directE8Callers\":" + JArrU(h.E8Callers) + ",");
    sb.AppendLine("  \"qwordPointersToEntry\":" + JArrU(h.QwordPtrs) + ",");
    sb.AppendLine("  \"leaSample\":" + JLeas(h.Leas) + ",");
    sb.AppendLine("  \"calleeSample\":" + JCalls(h.Calls) + ",");
    sb.AppendLine("  \"argModel\":{");
    sb.AppendLine("    \"observedPrologueMoves\":\"saves rcx/rdx family into stack/regs (see prologue); exact ABI not fully decoded without full disasm\",");
    sb.AppendLine("    \"return\":\"not fully decoded; standard x64 rax presumed\"");
    sb.AppendLine("  },");
    sb.AppendLine("  \"conclusions\":{");
    sb.AppendLine("    \"boundaryConfidence\":\"medium_high\",");
    sb.AppendLine("    \"inferredFromPhaseNameAlone\":false");
    sb.AppendLine("  },");
    sb.AppendLine("  \"safety\":{\"analysisMode\":\"offline_pe_only\",\"spawnAttempted\":false}");
    sb.AppendLine("}");
    return sb.ToString();
  }

  static string BuildCallgraph(FuncInfo h, FuncInfo ctrl, FuncInfo upd,
      bool callsCtrl, bool callsUpd, bool callsReg,
      List<uint> sharedHC, List<uint> sharedHU) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\":1,");
    sb.AppendLine("  \"generatedUtc\":\"" + DateTime.UtcNow.ToString("o") + "\",");
    sb.AppendLine("  \"milestone\":\"v0.6.4\",");
    sb.AppendLine("  \"handler\":{");
    sb.AppendLine("    \"entryRva\":\"0x" + h.Entry.ToString("X") + "\",");
    sb.AppendLine("    \"sizeBytes\":" + h.Size + ",");
    sb.AppendLine("    \"mappedCalleeCount\":" + CountMapped(h.Calls) + ",");
    sb.AppendLine("    \"calleeSample\":" + JCalls(h.Calls, 80));
    sb.AppendLine("  },");
    sb.AppendLine("  \"followUps\":{");
    sb.AppendLine("    \"controllers_0x7B00B60\":{");
    sb.AppendLine("      \"linkedByDirectCallFromHandler\":" + (callsCtrl ? "true" : "false") + ",");
    sb.AppendLine("      \"sharedMappedCalleesWithHandler\":" + JArrU(sharedHC) + ",");
    sb.AppendLine("      \"sizeBytes\":" + ctrl.Size + ",");
    sb.AppendLine("      \"prologue\":\"" + Esc(ctrl.Prologue) + "\",");
    sb.AppendLine("      \"leaSample\":" + JLeas(ctrl.Leas, 15) + ",");
    sb.AppendLine("      \"calleeSample\":" + JCalls(ctrl.Calls, 20));
    sb.AppendLine("    },");
    sb.AppendLine("    \"updateActor_0x29C6910\":{");
    sb.AppendLine("      \"linkedByDirectCallFromHandler\":" + (callsUpd ? "true" : "false") + ",");
    sb.AppendLine("      \"sharedMappedCalleesWithHandler\":" + JArrU(sharedHU) + ",");
    sb.AppendLine("      \"sizeBytes\":" + upd.Size + ",");
    sb.AppendLine("      \"prologue\":\"" + Esc(upd.Prologue) + "\",");
    sb.AppendLine("      \"leaSample\":" + JLeas(upd.Leas, 15) + ",");
    sb.AppendLine("      \"calleeSample\":" + JCalls(upd.Calls, 20));
    sb.AppendLine("    },");
    sb.AppendLine("    \"registrar_0x5CBDFB0_calledByHandler\":" + (callsReg ? "true" : "false"));
    sb.AppendLine("  },");
    sb.AppendLine("  \"creationEvidence\":{");
    sb.AppendLine("    \"allocatorSizedCallsHeuristic\":\"see handler heuristics\",");
    sb.AppendLine("    \"confirmedEntityFactory\":false,");
    sb.AppendLine("    \"confirmedQueueProcessor\":\"unknown\"");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    return sb.ToString();
  }

  static int CountMapped(List<Call> cs) {
    int n = 0; foreach (var c in cs) if (c.Mapped) n++; return n;
  }

  static string BuildChar(FuncInfo h, List<string> hits) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\":1,");
    sb.AppendLine("  \"generatedUtc\":\"" + DateTime.UtcNow.ToString("o") + "\",");
    sb.AppendLine("  \"milestone\":\"v0.6.4\",");
    sb.AppendLine("  \"handlerRva\":\"0x" + h.Entry.ToString("X") + "\",");
    sb.AppendLine("  \"stringHitsInHandler\":" + JArrS(hits, 50) + ",");
    sb.AppendLine("  \"verified\":{");
    sb.AppendLine("    \"characterArchetypeRef\":false,");
    sb.AppendLine("    \"edwardSpecificAssetOrDef\":false,");
    sb.AppendLine("    \"characterComponentInit\":false,");
    sb.AppendLine("    \"transformInitialization\":false,");
    sb.AppendLine("    \"animationOrMovementInit\":false,");
    sb.AppendLine("    \"playerEntityReference\":false,");
    sb.AppendLine("    \"entityIdOrActorHandle\":false");
    sb.AppendLine("  },");
    sb.AppendLine("  \"note\":\"String proximity is not proof; verified flags stay false unless a concrete data/call edge is established in analysis pass outputs.\"");
    sb.AppendLine("}");
    return sb.ToString();
  }

  static string BuildInput(List<uint> qwords, List<uint> leas, List<string> installs) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\":1,");
    sb.AppendLine("  \"generatedUtc\":\"" + DateTime.UtcNow.ToString("o") + "\",");
    sb.AppendLine("  \"milestone\":\"v0.6.4\",");
    sb.AppendLine("  \"actionVtableRva\":\"0x9255320\",");
    sb.AppendLine("  \"absoluteQwordPointerSites\":" + JArrU(qwords) + ",");
    sb.AppendLine("  \"leaRipSites\":" + JArrU(leas) + ",");
    sb.AppendLine("  \"installSiteNotes\":" + JArrS(installs) + ",");
    sb.AppendLine("  \"consumers\":{");
    sb.AppendLine("    \"storedInInputRegistry\":\"unknown\",");
    sb.AppendLine("    \"connectedToActionCallbacks\":\"unknown\",");
    sb.AppendLine("    \"dispatchedToGameplaySystems\":\"unknown\",");
    sb.AppendLine("    \"associatedWithCharacterMovement\":false");
    sb.AppendLine("  },");
    sb.AppendLine("  \"verifiedInputToCharacterConnection\":false,");
    sb.AppendLine("  \"method\":\"absolute_imagebase_qword_scan_plus_lea_rip_to_vtable\"");
    sb.AppendLine("}");
    return sb.ToString();
  }

  static string BuildFeas(FuncInfo h, List<string> hits, bool cCtrl, bool cUpd, int vtableRefs) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\":1,");
    sb.AppendLine("  \"generatedUtc\":\"" + DateTime.UtcNow.ToString("o") + "\",");
    sb.AppendLine("  \"milestone\":\"v0.6.4\",");
    sb.AppendLine("  \"assessments\":{");
    sb.AppendLine("    \"multipleSimultaneousCharacterEntities\":{\"class\":\"plausible\",\"reason\":\"Deferred/update actor phase infrastructure exists; handler body pending classification\"},");
    sb.AppendLine("    \"reuseEdwardCharacterDefinition\":{\"class\":\"unknown\",\"reason\":\"No Edward archetype edge verified in handler\"},");
    sb.AppendLine("    \"createSecondCharacterEntity\":{\"class\":\"unknown\",\"reason\":\"Creation operations inside 0x1AC380 not yet confirmed\"},");
    sb.AppendLine("    \"assignSeparateInputControl\":{\"class\":\"unsupported\",\"reason\":\"Action vtable consumers not shown to support dual contexts\"},");
    sb.AppendLine("    \"maintainSeparateTransforms\":{\"class\":\"plausible\",\"reason\":\"UpdateActor* phases exist independently of input bind path\"}");
    sb.AppendLine("  },");
    sb.AppendLine("  \"handlerLinkedToControllers\":" + (cCtrl ? "true" : "false") + ",");
    sb.AppendLine("  \"handlerLinkedToUpdateActor\":" + (cUpd ? "true" : "false") + ",");
    sb.AppendLine("  \"characterStringHitsInHandler\":" + hits.Count + ",");
    sb.AppendLine("  \"actionVtableRefSites\":" + vtableRefs + ",");
    sb.AppendLine("  \"nextSafestStep\":\"Deep-decode 0x1AC380 callees that look like alloc/init; only then consider offline archetype-table lookups — still no spawn\"");
    sb.AppendLine("}");
    return sb.ToString();
  }
}
