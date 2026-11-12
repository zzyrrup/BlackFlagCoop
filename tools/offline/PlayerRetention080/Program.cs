// v0.8.0 — Offline: local-player Entity / handle retention roles on Resynced.
// Blueprint: Agent 1 docs/v0.8.0-ac4coop-source-map.md (reference-only).
// Avoids Spawn*Params schema visitors and PlayerProgression name-range registrar.
// Read-only PE. No launch, inject, live memory, or game writes.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;

internal static class Program {
  const string ExpectedExeSha =
    "19920F34BB2FAC814023EE3C27F0CECA1872E80A2AAFB37C092C419FFF77CC0D";

  // Role needles from AC4Coop World / LoadingAdvisor / Handle retention,
  // not schema Spawn*Params names.
  static readonly string[] Needles = {
    "StartupPlayerSpawner",
    "PlayerSpace",
    "PlayerSpaceReference",
    "FakeEntities",
    "WhiteRoom",
    "IsLoading",
    "LoadingManager",
    "LoadingAdvisorUpdate",
    "HumanBehaviorState",
    "LocalPlayer",
    "PlayerEntity",
    "PlayerSpawner",
    "CreateReference",
    "AddLoadTask",
    "ManagedObject",
    "ObjectID",
    "BhvAssassin",
    "BehaviorComponent",
    "AssassinBehavior",
    "GetPlayer"
  };

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);

  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }
  sealed class Hit { public string Needle; public uint Rva; public string Text; }
  sealed class Lea { public string Needle; public uint Site; public uint Func; }
  sealed class Ins {
    public uint Rva; public string Text; public Mnemonic Mnemonic;
    public bool IpRel; public uint DataRva; public bool IsCall;
    public uint NearTarget; public int Length; public bool IsStore; public bool IsLoad;
  }
  sealed class FuncRep {
    public uint Entry;
    public string Klass;
    public List<string> Strings = new List<string>();
    public List<uint> GlobalStores = new List<uint>();
    public List<uint> GlobalLoads = new List<uint>();
    public List<uint> Callees = new List<uint>();
    public List<string> Head = new List<string>();
    public int Size;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0
      ? args[0]
      : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1
      ? args[1]
      : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha256Hex(pe);
    Console.WriteLine("exeSha256=" + hash);
    if (!hash.Equals(ExpectedExeSha, StringComparison.OrdinalIgnoreCase)) {
      Console.Error.WriteLine("REFUSING: EXE hash mismatch.");
      return 2;
    }
    ParsePe();
    string rawDir = Path.Combine(root, "reports", "v080-player-retain-raw");
    Directory.CreateDirectory(rawDir);
    Directory.CreateDirectory(Path.Combine(root, "reports"));

    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 LOCAL-PLAYER ENTITY RETENTION =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("blueprint=Agent1 docs/v0.8.0-ac4coop-source-map.md (reference-only)");
    sb.AppendLine("firstChain=LoadingAdvisor / PlayerSpace / FakeEntities / HumanBehavior roles");
    sb.AppendLine("avoided=Spawn*Params schema visitors; PlayerProgression name-range registrar");

    var hits = FindNeedles();
    sb.AppendLine();
    sb.AppendLine("===== STRING HITS =====");
    foreach (var hit in hits)
      sb.AppendLine(hit.Needle + " rva=0x" + hit.Rva.ToString("X") + " text=" + Trunc(hit.Text, 96));

    var leas = new List<Lea>();
    sb.AppendLine();
    sb.AppendLine("===== STRING LEA SITES =====");
    foreach (var hit in hits) {
      var sites = FindLeaTo(hit.Rva, 32);
      sb.AppendLine("LEA " + hit.Needle + " @0x" + hit.Rva.ToString("X") + " count=" + sites.Count);
      foreach (uint site in sites) {
        uint fs = FindFuncStart(site);
        leas.Add(new Lea { Needle = hit.Needle, Site = site, Func = fs });
        sb.AppendLine("  site=0x" + site.ToString("X") + " func=0x" + fs.ToString("X"));
      }
    }

    var focus = new HashSet<uint>();
    foreach (var lea in leas) {
      if (IsRetentionNeedle(lea.Needle))
        focus.Add(lea.Func);
    }
    // Always include LoadingAdvisorUpdate installer if present.
    foreach (var lea in leas)
      if (lea.Needle == "LoadingAdvisorUpdate")
        focus.Add(lea.Func);

    var reps = new List<FuncRep>();
    sb.AppendLine();
    sb.AppendLine("===== FOCUS FUNCTIONS =====");
    foreach (uint fs in focus.Where(x => x != 0).OrderBy(x => x).Take(48)) {
      var rep = AnalyzeAroundLeas(fs, leas);
      reps.Add(rep);
      EmitFunc(sb, rep);
      var callers = FindE8(fs, 16);
      sb.AppendLine("  E8_callers count=" + callers.Count);
      foreach (uint c in callers.Take(8)) {
        uint cfs = FindFuncStart(c);
        sb.AppendLine("    site=0x" + c.ToString("X") + " func=0x" + cfs.ToString("X"));
        if (cfs != 0 && focus.Add(cfs) && reps.Count < 72) {
          var crep = AnalyzeAroundLeas(cfs, leas);
          reps.Add(crep);
          EmitFunc(sb, crep);
        }
      }
    }

    // Decode windows centered on the most interesting LEAs (not only guessed func starts).
    sb.AppendLine();
    sb.AppendLine("===== LEA WINDOWS (retention needles) =====");
    foreach (var lea in leas.Where(l => IsRetentionNeedle(l.Needle)).Take(24)) {
      DumpWindow(sb, lea.Site, 0x60, 0x100, lea.Needle);
    }

    var storeHeavy = reps
      .Where(r => r.GlobalStores.Count >= 2)
      .OrderByDescending(r => r.GlobalStores.Count)
      .ToList();

    sb.AppendLine();
    sb.AppendLine("===== SUMMARY =====");
    sb.AppendLine("stringHits=" + hits.Count);
    sb.AppendLine("leaSites=" + leas.Count);
    sb.AppendLine("focusFuncs=" + reps.Select(r => r.Entry).Distinct().Count());
    sb.AppendLine("multiGlobalStoreFuncs=" + storeHeavy.Count);
    foreach (var r in storeHeavy.Take(12))
      sb.AppendLine("  STORE 0x" + r.Entry.ToString("X") + " class=" + r.Klass
        + " stores=" + string.Join(",", r.GlobalStores.Distinct().Take(8).Select(x => "0x" + x.ToString("X")))
        + " strs=" + string.Join("|", r.Strings.Distinct().Take(4)));

    bool playerSpace = hits.Any(h => h.Needle.IndexOf("PlayerSpace", StringComparison.Ordinal) >= 0);
    bool fakeEntities = hits.Any(h => h.Needle.IndexOf("FakeEntities", StringComparison.Ordinal) >= 0);
    bool humanBhv = hits.Any(h => h.Needle.IndexOf("HumanBehavior", StringComparison.Ordinal) >= 0);
    bool loadingAdv = hits.Any(h => h.Needle == "LoadingAdvisorUpdate");
    sb.AppendLine("playerSpaceString=" + playerSpace);
    sb.AppendLine("fakeEntitiesString=" + fakeEntities);
    sb.AppendLine("humanBehaviorString=" + humanBhv);
    sb.AppendLine("loadingAdvisorUpdateString=" + loadingAdv);
    sb.AppendLine("playerEntityAcquisitionResolved=false");
    sb.AppendLine("builderSelectorRetentionResolved=false");
    sb.AppendLine("decision=" + (
      playerSpace || fakeEntities || humanBhv || loadingAdv
        ? "retention-role-strings-found-entity-owner-unresolved"
        : "retention-role-strings-absent"));
    sb.AppendLine("blocker=Local-player Entity*/HandleContainer retention owner not yet identified;");
    sb.AppendLine("        builder/selector-equivalent cache remains unresolved.");

    string evidence = sb.ToString();
    File.WriteAllText(Path.Combine(rawDir, "evidence.txt"), evidence);
    WriteJson(root, hash, hits, leas, reps, storeHeavy, playerSpace, fakeEntities, humanBhv, loadingAdv);
    Console.WriteLine(evidence);
    return 0;
  }

  static bool IsRetentionNeedle(string n) {
    return n.IndexOf("PlayerSpace", StringComparison.Ordinal) >= 0
      || n.IndexOf("FakeEntities", StringComparison.Ordinal) >= 0
      || n.IndexOf("StartupPlayer", StringComparison.Ordinal) >= 0
      || n.IndexOf("HumanBehavior", StringComparison.Ordinal) >= 0
      || n.IndexOf("WhiteRoom", StringComparison.Ordinal) >= 0
      || n.IndexOf("LoadingAdvisor", StringComparison.Ordinal) >= 0
      || n.IndexOf("PlayerSpawner", StringComparison.Ordinal) >= 0
      || n.IndexOf("LocalPlayer", StringComparison.Ordinal) >= 0
      || n.IndexOf("PlayerEntity", StringComparison.Ordinal) >= 0
      || n.IndexOf("CreateReference", StringComparison.Ordinal) >= 0
      || n.IndexOf("AddLoadTask", StringComparison.Ordinal) >= 0
      || n.IndexOf("IsLoading", StringComparison.Ordinal) >= 0
      || n.IndexOf("LoadingManager", StringComparison.Ordinal) >= 0;
  }

  static void EmitFunc(StringBuilder sb, FuncRep rep) {
    sb.AppendLine("0x" + rep.Entry.ToString("X")
      + " class=" + rep.Klass
      + " size=" + rep.Size
      + " stores=" + rep.GlobalStores.Count
      + " loads=" + rep.GlobalLoads.Count
      + " callees=" + string.Join(",", rep.Callees.Distinct().Take(12).Select(c => "0x" + c.ToString("X"))));
    foreach (string s in rep.Strings.Distinct().Take(8))
      sb.AppendLine("    str " + Trunc(s, 96));
    foreach (string line in rep.Head.Take(16))
      sb.AppendLine("    " + line);
    if (rep.GlobalStores.Count > 0)
      sb.AppendLine("    globalStores=" + string.Join(",", rep.GlobalStores.Distinct().Take(10).Select(x => "0x" + x.ToString("X"))));
  }

  static FuncRep AnalyzeAroundLeas(uint entry, List<Lea> leas) {
    // If a retention LEA for this func lies far from the guessed start, decode a
    // window around that LEA instead of only the first 0x900 bytes.
    var near = leas.Where(l => l.Func == entry && IsRetentionNeedle(l.Needle)).ToList();
    if (near.Count > 0) {
      uint site = near[0].Site;
      uint start = site > 0x80 ? site - 0x80 : site;
      return AnalyzeRange(entry, start, start + 0x180);
    }
    return AnalyzeRange(entry, entry, entry + 0x400);
  }

  static FuncRep AnalyzeRange(uint entryLabel, uint start, uint end) {
    var rep = new FuncRep { Entry = entryLabel, Klass = "unclassified" };
    var insns = DisasmRaw(start, end);
    rep.Size = insns.Count == 0 ? 0 : (int)(insns[insns.Count - 1].Rva + insns[insns.Count - 1].Length - start);
    foreach (var ins in insns) {
      if (rep.Head.Count < 24)
        rep.Head.Add("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 100));
      if (ins.IsCall && ins.NearTarget != 0)
        rep.Callees.Add(ins.NearTarget);
      if (ins.IpRel && ins.DataRva != 0) {
        string s = ReadAscii(ins.DataRva, 96);
        if (IsString(s))
          rep.Strings.Add(s);
        else if (IsData(ins.DataRva)) {
          if (ins.IsStore) rep.GlobalStores.Add(ins.DataRva);
          if (ins.IsLoad) rep.GlobalLoads.Add(ins.DataRva);
        }
      }
    }
    bool role = rep.Strings.Any(IsRetentionNeedle);
    if (rep.GlobalStores.Count >= 2) rep.Klass = role ? "retention-role-multi-store" : "multi-global-store";
    else if (role) rep.Klass = "retention-role-ref";
    else if (rep.Strings.Count > 0) rep.Klass = "named-ref";
    else rep.Klass = "unrelated";
    return rep;
  }

  static void DumpWindow(StringBuilder sb, uint center, int before, int after, string label) {
    uint start = center > (uint)before ? center - (uint)before : center;
    uint end = center + (uint)after;
    sb.AppendLine("--- " + label + " center=0x" + center.ToString("X") + " ---");
    foreach (var ins in DisasmRaw(start, end).Take(48)) {
      string extra = "";
      if (ins.IpRel && ins.DataRva != 0) {
        string s = ReadAscii(ins.DataRva, 72);
        extra = IsString(s) ? "  ;str=" + Trunc(s, 72) : "  ;data=0x" + ins.DataRva.ToString("X");
      }
      if (ins.IsCall && ins.NearTarget != 0)
        extra += "  ;call=0x" + ins.NearTarget.ToString("X");
      string mark = (ins.Rva == center || (ins.Rva <= center && ins.Rva + ins.Length > center)) ? " <<<" : "";
      sb.AppendLine("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 90) + extra + mark);
    }
  }

  static void WriteJson(string root, string hash, List<Hit> hits, List<Lea> leas,
      List<FuncRep> reps, List<FuncRep> storeHeavy,
      bool playerSpace, bool fakeEntities, bool humanBhv, bool loadingAdv) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.8.0\",");
    sb.AppendLine("  \"mode\": \"offline-pe-readonly\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"blueprint\": " + J("Agent1 docs/v0.8.0-ac4coop-source-map.md reference-only") + ",");
    sb.AppendLine("  \"playerEntityAcquisitionResolved\": false,");
    sb.AppendLine("  \"builderSelectorRetentionResolved\": false,");
    sb.AppendLine("  \"playerSpaceString\": " + T(playerSpace) + ",");
    sb.AppendLine("  \"fakeEntitiesString\": " + T(fakeEntities) + ",");
    sb.AppendLine("  \"humanBehaviorString\": " + T(humanBhv) + ",");
    sb.AppendLine("  \"loadingAdvisorUpdateString\": " + T(loadingAdv) + ",");
    sb.AppendLine("  \"decision\": " + J("retention-role-strings-found-entity-owner-unresolved") + ",");
    sb.AppendLine("  \"blocker\": " + J("Local-player Entity*/HandleContainer retention owner not identified; builder/selector cache unresolved") + ",");
    sb.AppendLine("  \"strings\": [");
    for (int i = 0; i < hits.Count; i++) {
      var h = hits[i];
      sb.Append("    {\"needle\": " + J(h.Needle) + ", \"rva\": \"0x" + h.Rva.ToString("X")
        + "\", \"text\": " + J(Trunc(h.Text, 80)) + "\"}");
      sb.AppendLine(i + 1 < hits.Count ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"leaSites\": [");
    for (int i = 0; i < Math.Min(leas.Count, 80); i++) {
      var s = leas[i];
      sb.Append("    {\"needle\": " + J(s.Needle) + ", \"site\": \"0x" + s.Site.ToString("X")
        + "\", \"func\": \"0x" + s.Func.ToString("X") + "\"}");
      sb.AppendLine(i + 1 < Math.Min(leas.Count, 80) ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"multiGlobalStoreFuncs\": [");
    for (int i = 0; i < Math.Min(storeHeavy.Count, 24); i++) {
      var r = storeHeavy[i];
      sb.Append("    {\"entry\": \"0x" + r.Entry.ToString("X") + "\", \"class\": " + J(r.Klass)
        + ", \"stores\": [" + string.Join(", ", r.GlobalStores.Distinct().Take(12).Select(x => "\"0x" + x.ToString("X") + "\"")) + "]"
        + ", \"strings\": [" + string.Join(", ", r.Strings.Distinct().Take(6).Select(J)) + "]}");
      sb.AppendLine(i + 1 < Math.Min(storeHeavy.Count, 24) ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-player-retention.json"), sb.ToString());
    Console.WriteLine("WROTE reports/v0.8.0-player-retention.json");
  }

  static List<Hit> FindNeedles() {
    var hits = new List<Hit>();
    foreach (string needle in Needles) {
      byte[] pat = Encoding.ASCII.GetBytes(needle);
      int from = 0;
      int guard = 0;
      while (from < pe.Length && guard++ < 64) {
        int at = IndexOf(pe, pat, from);
        if (at < 0) break;
        if (at > 0) {
          byte prev = pe[at - 1];
          if (prev != 0 && prev >= 32 && prev < 127) {
            from = at + 1;
            continue;
          }
        }
        uint rva = FileToRva(at);
        string text = ReadAscii(rva, 96);
        if (rva != 0 && IsString(text))
          hits.Add(new Hit { Needle = needle, Rva = rva, Text = text });
        from = at + pat.Length;
      }
    }
    return hits
      .GroupBy(h => h.Rva)
      .Select(g => g.OrderByDescending(h => h.Needle.Length).First())
      .OrderBy(h => h.Rva)
      .ToList();
  }

  static int IndexOf(byte[] data, byte[] pat, int start) {
    int at = data.AsSpan(start).IndexOf(pat);
    return at < 0 ? -1 : at + start;
  }

  static List<Ins> DisasmRaw(uint start, uint endExclusive) {
    var list = new List<Ins>();
    int fo = RvaToFile(start);
    if (fo < 0) return list;
    var reader = new ByteArrayCodeReader(pe);
    reader.Position = fo;
    var dec = Decoder.Create(64, reader);
    dec.IP = imageBase + start;
    ulong limit = imageBase + endExclusive;
    int guard = 0;
    while (dec.IP < limit && guard++ < 2400) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      if (raw.IP < imageBase) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      var ins = new Ins {
        Rva = (uint)(raw.IP - imageBase), Text = o.ToString(),
        Mnemonic = raw.Mnemonic, Length = raw.Length,
        IsCall = raw.FlowControl == FlowControl.Call || raw.FlowControl == FlowControl.IndirectCall
      };
      if (ins.IsCall && raw.FlowControl == FlowControl.Call && raw.NearBranchTarget != 0 && raw.NearBranchTarget >= imageBase)
        ins.NearTarget = (uint)(raw.NearBranchTarget - imageBase);
      for (int oi = 0; oi < raw.OpCount; oi++) {
        var kind = raw.GetOpKind(oi);
        if (kind != OpKind.Memory || !raw.IsIPRelativeMemoryOperand) continue;
        ins.IpRel = true;
        ulong va = raw.IPRelativeMemoryAddress;
        if (va >= imageBase) ins.DataRva = (uint)(va - imageBase);
      }
      string t = ins.Text;
      int comma = t.IndexOf(',');
      if (comma > 0) {
        if (t.Substring(0, comma).IndexOf('[') >= 0) ins.IsStore = true;
        if (t.Substring(comma + 1).IndexOf('[') >= 0) ins.IsLoad = true;
      }
      list.Add(ins);
      if (ins.Mnemonic == Mnemonic.Int3) break;
    }
    return list;
  }

  static List<uint> FindE8(uint dest, int max) {
    var list = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 5 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        if ((long)s.Va + i + 5 + rel == dest) list.Add(s.Va + i);
      }
    }
    return list;
  }

  static List<uint> FindLeaTo(uint target, int max) {
    var list = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim && list.Count < max; i++) {
        int off = 0;
        byte b0 = pe[s.Ptr + i];
        if (b0 == 0x48 || b0 == 0x4C || b0 == 0x49 || b0 == 0x4D) off = 1;
        if (pe[s.Ptr + i + off] != 0x8D) continue;
        byte modrm = pe[s.Ptr + i + off + 1];
        if ((modrm & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + off + 2));
        uint site = s.Va + i;
        uint len = (uint)(off + 6);
        if (unchecked((uint)(site + len + disp)) == target) list.Add(site);
      }
    }
    return list;
  }

  static IEnumerable<Sec> CodeSecs() {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      bool ok = (s.Char & 0x20000000) != 0
        || s.Name.IndexOf("text", StringComparison.OrdinalIgnoreCase) >= 0;
      if (ok) yield return s;
    }
  }

  static bool IsData(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva < s.Va || rva >= s.Va + span) continue;
      bool exec = (s.Char & 0x20000000) != 0
        || s.Name.IndexOf("text", StringComparison.OrdinalIgnoreCase) >= 0;
      return !exec;
    }
    return false;
  }

  static uint FindFuncStart(uint site) {
    int fo = RvaToFile(site);
    if (fo < 0) return 0;
    int back = Math.Min(fo, 0x4000);
    int pad = -1;
    for (int i = 1; i < back; i++) {
      if (pe[fo - i] == 0xCC && i + 1 < back && pe[fo - i - 1] == 0xCC) { pad = i; break; }
    }
    if (pad < 0) return site > 0x40 ? site - 0x40 : site;
    uint rva = site - (uint)pad;
    int p = RvaToFile(rva);
    while (p >= 0 && p < pe.Length && pe[p] == 0xCC) { rva++; p++; }
    return rva;
  }

  static string ReadAscii(uint rva, int max) {
    int fo = RvaToFile(rva);
    if (fo < 0) return "";
    var sb = new StringBuilder();
    for (int i = 0; i < max && fo + i < pe.Length; i++) {
      byte b = pe[fo + i];
      if (b == 0) break;
      if (b >= 32 && b < 127) sb.Append((char)b);
      else return sb.Length >= 4 ? sb.ToString() : "";
    }
    return sb.ToString();
  }

  static bool IsString(string s) {
    if (string.IsNullOrEmpty(s) || s.Length < 4) return false;
    int ok = 0;
    foreach (char c in s) if (c >= 32 && c < 127) ok++;
    return ok * 5 >= s.Length * 4;
  }

  static string Trunc(string s, int n) => s == null ? "" : (s.Length <= n ? s : s.Substring(0, n));
  static string T(bool b) => b ? "true" : "false";
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }

  static int RvaToFile(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva >= s.Va && rva < s.Va + span && s.Ptr > 0)
        return (int)s.Ptr + (int)(rva - s.Va);
    }
    return -1;
  }

  static uint FileToRva(int fileOff) {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      if (fileOff >= s.Ptr && fileOff < s.Ptr + s.Raw)
        return s.Va + (uint)(fileOff - s.Ptr);
    }
    return 0;
  }

  static void ParsePe() {
    int e = BitConverter.ToInt32(pe, 0x3C);
    ushort magic = BitConverter.ToUInt16(pe, e + 24);
    if (magic != 0x20B) throw new InvalidOperationException("Expected PE32+");
    imageBase = BitConverter.ToUInt64(pe, e + 24 + 24);
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

  static string Sha256Hex(byte[] data) {
    using (var sha = SHA256.Create()) {
      byte[] h = sha.ComputeHash(data);
      var sb = new StringBuilder(h.Length * 2);
      foreach (byte b in h) sb.Append(b.ToString("X2"));
      return sb.ToString();
    }
  }
}
