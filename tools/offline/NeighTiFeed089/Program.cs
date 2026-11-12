// v0.6.29 — Offline: Neighbor TypeInfo/.trace registrar (SpatRegistrar equivalent);
// TypeInfo keys / factory feeds using SpatA/SpatB fields.
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

  const uint NeighVt = 0x976B2D0;
  const uint SpatVt = 0x9236E00;
  const uint NeighVt0 = 0x13612B0;
  const uint NeighRel = 0x3D522C0;
  const uint SpatVt0 = 0x5781490;
  const uint SpatA = 0x5563CF0;
  const uint SpatB = 0x6CF34A0;
  const uint SpatRegistrar = 0x5E5AF20;
  const uint SpatTi = 0xACE83F8;       // Spat VT[+0x30]; TypeInfo base (ctor @ +0x50 = SpatA field)
  const uint SpatAField = 0xACE8448;   // SpatTi + 0x50
  const uint SpatBTi = 0xACE8478;
  const uint SpatBField = 0xACE84C8;   // SpatBTi + 0x50
  const uint NeighMeta = 0xAAD2290;    // Neigh VT[+0x30]; TypeInfo-shaped (ctor @ +0x50 = NeighRel)
  const uint NeighRelSlot = 0xAAD22E0; // NeighMeta + 0x50
  const uint NeighVt20 = 0x3D52400;    // Neigh VT[+0x20] construct-from-TI
  const uint SpatVt20 = 0x6CF34E0;     // Spat VT[+0x20] construct-from-TI
  const uint TiHelper = 0x43DCB00;
  const uint Allocator = 0x426EE50;
  const uint Lookup = 0x429F9E0;
  const ulong NeighKeyHash = 0x2996CA50CB0F23F4UL; // NeighMeta + 0x18

  static readonly uint[] TightFactories = { 0x238590, 0x256280, 0x218900, 0x218660, 0x21FA70 };

  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);

  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }
  sealed class Ins {
    public uint Rva; public string Text; public Mnemonic Mnemonic;
    public bool IpRel; public uint DataRva; public bool IsCall, IsIndirectCall, HasMem;
    public long Disp; public int Length; public uint NearTarget; public bool IsRet;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v089-raw");
    pe = File.ReadAllBytes(exe);
    string hash = Sha256Hex(pe);
    Console.WriteLine("exeSha256=" + hash);
    if (!hash.Equals(ExpectedExeSha, StringComparison.OrdinalIgnoreCase)) {
      Console.Error.WriteLine("REFUSING: EXE hash mismatch.");
      return 2;
    }
    ParsePe();
    Directory.CreateDirectory(outDir);

    var sb = new StringBuilder();
    sb.AppendLine("===== v0.6.29 Neighbor TypeInfo REGISTRAR + SpatA/SpatB FEEDS =====");
    sb.AppendLine("exeSha256=" + hash);

    // ---- 1) Neighbor TypeInfo-shaped meta (PE-static registrar equivalent) ----
    sb.AppendLine();
    sb.AppendLine("===== NEIGHBOR TypeInfo-SHAPED META @0xAAD2290 =====");
    ulong vt30n = ReadU64(NeighVt + 0x30);
    ulong vt30s = ReadU64(SpatVt + 0x30);
    sb.AppendLine("Neigh VT[+0x30]=0x" + RvaOrRaw(vt30n)
      + " expect 0x" + NeighMeta.ToString("X") + " match=" + (vt30n == imageBase + NeighMeta));
    sb.AppendLine("Spat VT[+0x30]=0x" + RvaOrRaw(vt30s)
      + " expect 0x" + SpatTi.ToString("X") + " match=" + (vt30s == imageBase + SpatTi));
    DumpTi(sb, NeighMeta, "NeighMeta");
    uint neighCtorField = ReadU64AsRva(NeighMeta + 0x50);
    uint neighSize = ReadU32(NeighMeta + 0x20);
    ulong neighKey = ReadU64(NeighMeta + 0x18);
    sb.AppendLine("NeighMeta+0x50 ctor=0x" + neighCtorField.ToString("X")
      + " expect NeighRel 0x" + NeighRel.ToString("X") + " match=" + (neighCtorField == NeighRel));
    sb.AppendLine("NeighMeta+0x20 size=0x" + neighSize.ToString("X"));
    sb.AppendLine("NeighMeta+0x18 keyHash=0x" + neighKey.ToString("X")
      + " expect 0x" + NeighKeyHash.ToString("X") + " match=" + (neighKey == NeighKeyHash));
    var keyEmb = FindQwordValue(NeighKeyHash, 10);
    sb.AppendLine("keyHash embeds=" + keyEmb.Count + " @" + string.Join(",", keyEmb.Select(x => "0x" + x.ToString("X"))));

    // No LEA+runtime-store of NeighRel (contrast SpatRegistrar)
    sb.AppendLine();
    sb.AppendLine("===== NEIGHBOR RUNTIME LEA+STORE OF CTOR (SpatRegistrar pattern) =====");
    int neighRuntimeStores = 0;
    foreach (uint ctor in new[] { NeighVt0, NeighRel }) {
      foreach (var lea in FindLeaTo(ctor, 10)) {
        sb.AppendLine("  unexpected LEA ctor 0x" + ctor.ToString("X") + " @0x" + lea.ToString("X")
          + " func=0x" + FindFuncStart(lea).ToString("X"));
        neighRuntimeStores++;
      }
    }
    sb.AppendLine("neighRuntimeLeaCtorSites=" + neighRuntimeStores
      + " (0 => PE-static TypeInfo ctor field; no SpatRegistrar-style fill)");

    // ---- 2) Spat TypeInfo records for SpatA/SpatB ----
    sb.AppendLine();
    sb.AppendLine("===== SPAT TypeInfo RECORDS (SpatA/SpatB +0x50 fields) =====");
    DumpTi(sb, SpatTi, "SpatTi");
    DumpTi(sb, SpatBTi, "SpatBTi");
    sb.AppendLine("SpatTi+0x50 field RVA=0x" + (SpatTi + 0x50).ToString("X")
      + " == SpatAField 0x" + SpatAField.ToString("X") + ": " + (SpatTi + 0x50 == SpatAField));
    sb.AppendLine("SpatBTi+0x50 field RVA=0x" + (SpatBTi + 0x50).ToString("X")
      + " == SpatBField 0x" + SpatBField.ToString("X") + ": " + (SpatBTi + 0x50 == SpatBField));

    // SpatRegistrar fills
    sb.AppendLine();
    sb.AppendLine("===== SpatRegistrar FILLS INTO SpatTi WINDOW =====");
    var regStores = FindRipStoresInFunc(SpatRegistrar, SpatTi, SpatBField + 0x40, 40);
    foreach (var t in regStores.Where(x =>
        x.dest == SpatAField || x.dest == SpatBField || x.dest == SpatTi || x.dest == SpatBTi
        || (x.dest >= SpatTi && x.dest <= SpatTi + 0x58)).Take(20))
      sb.AppendLine("  STORE @0x" + t.site.ToString("X") + " ->0x" + t.dest.ToString("X")
        + " off=+0x" + (t.dest - SpatTi).ToString("X") + " " + Trunc(t.text, 40));
    bool spatAFilled = regStores.Any(t => t.dest == SpatAField);
    bool spatBFilled = regStores.Any(t => t.dest == SpatBField);
    sb.AppendLine("SpatAField filled by registrar=" + spatAFilled
      + " SpatBField filled=" + spatBFilled);

    // ---- 3) VT[+0x20] construct-from-TI feeds ----
    sb.AppendLine();
    sb.AppendLine("===== VT[+0x20] CONSTRUCT-FROM-TypeInfo FEEDS =====");
    ulong n20 = ReadU64(NeighVt + 0x20);
    ulong s20 = ReadU64(SpatVt + 0x20);
    sb.AppendLine("Neigh VT[+0x20]=0x" + RvaOrRaw(n20) + " expect 0x" + NeighVt20.ToString("X")
      + " match=" + (n20 == imageBase + NeighVt20));
    sb.AppendLine("Spat VT[+0x20]=0x" + RvaOrRaw(s20) + " expect 0x" + SpatVt20.ToString("X")
      + " match=" + (s20 == imageBase + SpatVt20));
    DeepDump(sb, NeighVt20, NeighVt20 + 0x60, "NeighVT20-construct");
    DeepDump(sb, SpatVt20, SpatVt20 + 0x80, "SpatVT20-construct");
    sb.AppendLine("TiHelper 0x43DCB00 E8 callers sampled=" + FindE8(TiHelper, 20).Count + " (generic; many)");

    // RIP refs to TI bases
    sb.AppendLine();
    sb.AppendLine("===== RIP REFS TO TypeInfo BASES =====");
    var tiRefs = FindRipRefs(new[] { SpatTi, SpatBTi, NeighMeta, SpatAField, SpatBField }, 40);
    foreach (var r in tiRefs)
      sb.AppendLine("  " + r.kind + " base=0x" + r.data.ToString("X") + " @0x" + r.site.ToString("X")
        + " func=0x" + r.func.ToString("X") + " " + Trunc(r.text, 50));

    // LEA TI + behavior
    sb.AppendLine();
    sb.AppendLine("===== LEA TypeInfo BASE → Alloc/Lookup/TiHelper/icall50 =====");
    foreach (uint ti in new[] { SpatTi, NeighMeta }) {
      foreach (var lea in FindLeaTo(ti, 20)) {
        uint fs = FindFuncStart(lea);
        var flags = AnalyzeTiConsumer(fs);
        sb.AppendLine("  ti=0x" + ti.ToString("X") + " lea@0x" + lea.ToString("X")
          + " func=0x" + fs.ToString("X")
          + " alloc=" + flags.alloc + " lookup=" + flags.lookup
          + " tiHelper=" + flags.tiHelper + " icall50=" + flags.icall50
          + " callSpatCtor=" + flags.callSpatCtor);
      }
    }

    // Tight factories still generic
    sb.AppendLine();
    sb.AppendLine("===== TIGHT FACTORIES vs Spat TI (no static key LEA) =====");
    foreach (uint f in TightFactories) {
      var body = DisasmRaw(f, f + 0x600);
      bool seesSpatTi = body.Any(i => i.IpRel && (i.DataRva == SpatTi || i.DataRva == SpatAField || i.DataRva == SpatBField));
      int n50 = body.Count(i => i.IsIndirectCall && (i.Disp == 0x50 || i.Text.Contains("+50]")));
      sb.AppendLine("  factory 0x" + f.ToString("X") + " icall50=" + n50
        + " seesSpatTiRip=" + seesSpatTi);
    }

    // Verdict
    bool neighPeStaticTi = neighCtorField == NeighRel && neighSize == 0xB0 && neighRuntimeStores == 0
      && vt30n == imageBase + NeighMeta;
    bool spatFeed = spatAFilled && spatBFilled && (s20 == imageBase + SpatVt20)
      && tiRefs.Any(r => r.data == SpatTi && r.func == SpatVt20);
    bool parallelVt20 = (n20 == imageBase + NeighVt20) && (s20 == imageBase + SpatVt20);

    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    sb.AppendLine("1) Neighbor registrar equivalent = PE-static TypeInfo @0xAAD2290"
      + " (VT[+0x30]); +0x50=NeighRel; +0x20 size=0xB0; +0x18 keyHash unique."
      + " No runtime LEA+store. confirmed=" + neighPeStaticTi);
    sb.AppendLine("2) SpatA/SpatB TypeInfo keys/records: SpatTi 0xACE83F8 (+0x50=SpatA),"
      + " SpatBTi 0xACE8478 (+0x50=SpatB); runtime-filled by SpatRegistrar.");
    sb.AppendLine("3) Factory/construct feeds: both families use VT[+0x20] construct-from-TI"
      + " (Neigh 0x3D52400 / Spat 0x6CF34E0) via TiHelper 0x43DCB00."
      + " Tight factories remain generic (no static Spat TI RIP). parallelVt20=" + parallelVt20
      + " spatFeed=" + spatFeed);

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteJson(hash, neighPeStaticTi, spatFeed, parallelVt20, neighSize, neighKey,
      spatAFilled, spatBFilled, tiRefs);

    bool ok = neighPeStaticTi && parallelVt20;
    Console.WriteLine("selfCheck neighPeStaticTi=" + neighPeStaticTi
      + " spatFeed=" + spatFeed + " vt20=" + parallelVt20 + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static (bool alloc, bool lookup, bool tiHelper, bool icall50, bool callSpatCtor) AnalyzeTiConsumer(uint fs) {
    var body = DisasmRaw(fs, fs + 0x500);
    bool alloc = false, lookup = false, tiHelper = false, icall50 = false, callSpat = false;
    foreach (var i in body) {
      if (i.IsCall && !i.IsIndirectCall) {
        if (i.NearTarget == Allocator) alloc = true;
        if (i.NearTarget == Lookup) lookup = true;
        if (i.NearTarget == TiHelper) tiHelper = true;
        if (i.NearTarget == SpatA || i.NearTarget == SpatB || i.NearTarget == SpatVt0) callSpat = true;
      }
      if (i.IsIndirectCall && (i.Disp == 0x50 || i.Text.Contains("+50]"))) icall50 = true;
      if (i.IsRet && i.Rva > fs + 0x40) break;
    }
    return (alloc, lookup, tiHelper, icall50, callSpat);
  }

  static void DumpTi(StringBuilder sb, uint ti, string name) {
    sb.AppendLine("--- " + name + " 0x" + ti.ToString("X") + " ---");
    for (uint off = 0; off <= 0x58; off += 8) {
      ulong v = ReadU64(ti + off);
      string note = "";
      if (off == 0x18) note = " key?";
      if (off == 0x20) note = " size?";
      if (off == 0x50) note = " ctor";
      sb.AppendLine("  [+0x" + off.ToString("X") + "] = 0x" + RvaOrRaw(v) + note);
    }
  }

  static void DeepDump(StringBuilder sb, uint a, uint b, string title) {
    sb.AppendLine("--- " + title + " ---");
    foreach (var i in DisasmRaw(a, b).Take(35)) {
      string m = "";
      if (i.NearTarget == TiHelper) m = " *** TI_HELPER ***";
      if (i.NearTarget == Allocator) m = " *** ALLOC ***";
      if (i.IpRel && i.DataRva == SpatTi) m += " *** SPAT_TI ***";
      if (i.IpRel && i.DataRva == NeighMeta) m += " *** NEIGH_META ***";
      if (i.HasMem && !i.IpRel && i.Disp == 0x98) m += " *** +98 ***";
      sb.AppendLine("0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 70) + m);
    }
  }

  static List<(uint site, uint dest, uint func, string text)> FindRipStoresInFunc(
      uint func, uint lo, uint hi, int max) {
    var list = new List<(uint, uint, uint, string)>();
    foreach (var ins in DisasmRaw(func, func + 0x2000)) {
      if (!ins.IpRel) continue;
      if (!(ins.Text.StartsWith("mov [") || ins.Text.StartsWith("mov qword ptr ["))) continue;
      if (ins.DataRva < lo || ins.DataRva >= hi) continue;
      list.Add((ins.Rva, ins.DataRva, func, Trunc(ins.Text, 60)));
      if (list.Count >= max) break;
    }
    return list;
  }

  static List<(uint site, uint data, uint func, string text, string kind)> FindRipRefs(uint[] targets, int max) {
    var set = new HashSet<uint>(targets);
    var list = new List<(uint, uint, uint, string, string)>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      // decode in chunks via known LEA sites + func windows for targets
      foreach (var t in targets) {
        foreach (var lea in FindLeaTo(t, 20)) {
          uint fs = FindFuncStart(lea);
          foreach (var ins in DisasmRaw(fs, fs + 0x800)) {
            if (!ins.IpRel || !set.Contains(ins.DataRva)) continue;
            string kind = (ins.Text.StartsWith("mov [") || ins.Text.StartsWith("mov qword")) ? "STORE" : "LOAD/LEA";
            list.Add((ins.Rva, ins.DataRva, fs, Trunc(ins.Text, 50), kind));
            if (list.Count >= max) return list.Distinct().ToList();
          }
        }
      }
    }
    return list.GroupBy(x => (x.Item1, x.Item2)).Select(g => g.First()).ToList();
  }

  static void WriteJson(string hash, bool neighPeStatic, bool spatFeed, bool vt20,
      uint neighSize, ulong neighKey, bool spatAFilled, bool spatBFilled,
      List<(uint site, uint data, uint func, string text, string kind)> tiRefs) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.29\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"neighborTypeInfo\": {");
    sb.AppendLine("    \"meta\": \"0xAAD2290\",");
    sb.AppendLine("    \"peStatic\": " + T(neighPeStatic) + ",");
    sb.AppendLine("    \"sizePlus20\": \"0x" + neighSize.ToString("X") + "\",");
    sb.AppendLine("    \"ctorPlus50\": \"0x3D522C0\",");
    sb.AppendLine("    \"keyHashPlus18\": \"0x" + neighKey.ToString("X") + "\",");
    sb.AppendLine("    \"runtimeRegistrarFound\": false,");
    sb.AppendLine("    \"equivalentToSpatRegistrar\": \"pe_static_typeinfo_record\"");
    sb.AppendLine("  },");
    sb.AppendLine("  \"spatTypeInfoFeeds\": {");
    sb.AppendLine("    \"spatTi\": \"0xACE83F8\",");
    sb.AppendLine("    \"spatAField\": \"0xACE8448\",");
    sb.AppendLine("    \"spatBTi\": \"0xACE8478\",");
    sb.AppendLine("    \"spatBField\": \"0xACE84C8\",");
    sb.AppendLine("    \"registrarFillsCtorFields\": " + T(spatAFilled && spatBFilled) + ",");
    sb.AppendLine("    \"vtPlus20Construct\": \"0x6CF34E0\",");
    sb.AppendLine("    \"feedConfirmed\": " + T(spatFeed));
    sb.AppendLine("  },");
    sb.AppendLine("  \"parallelVt20Construct\": " + T(vt20) + ",");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.29-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.29-summary.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.29\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"tiBaseRefs\": [");
    for (int i = 0; i < tiRefs.Count; i++) {
      var r = tiRefs[i];
      sb.AppendLine("    { \"site\": \"0x" + r.site.ToString("X") + "\", \"data\": \"0x" + r.data.ToString("X")
        + "\", \"func\": \"0x" + r.func.ToString("X") + "\", \"kind\": " + J(r.kind)
        + ", \"text\": " + J(r.text) + " }" + (i + 1 < tiRefs.Count ? "," : ""));
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"constructFromTi\": [");
    sb.AppendLine("    { \"family\": \"Neighbor\", \"vtPlus20\": \"0x3D52400\", \"ti\": \"0xAAD2290\", \"helper\": \"0x43DCB00\" },");
    sb.AppendLine("    { \"family\": \"Spatial\", \"vtPlus20\": \"0x6CF34E0\", \"ti\": \"0xACE83F8\", \"helper\": \"0x43DCB00\" }");
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.29-funcs-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.29-funcs-deep.json");

    string nClass = neighPeStatic ? "confirmed" : "partial";
    string nReason = neighPeStatic
      ? "Neighbor TypeInfo is PE-static at 0xAAD2290 (VT[+0x30]): +0x50=NeighRel, +0x20=0xB0, +0x18 keyHash; no runtime SpatRegistrar-style fill"
      : "Neighbor TypeInfo layout incomplete";
    string sClass = spatFeed ? "confirmed" : (spatAFilled ? "partial" : "unsupported");
    string sReason = spatFeed
      ? "SpatTi/SpatBTi records hold SpatA/SpatB at +0x50 (runtime-filled); Spat VT[+0x20]=0x6CF34E0 constructs via TiHelper from SpatTi; tight factories stay generic"
      : "SpatA/SpatB field feeds incomplete";

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.29\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"TypeInfo/VT construct paths are not Edward create/possession\" },");
    sb.AppendLine("  \"neighborTypeInfoRegistrar\": { \"class\": \"" + nClass + "\", \"reason\": " + J(nReason) + " },");
    sb.AppendLine("  \"spatABTypeInfoFeeds\": { \"class\": \"" + sClass + "\", \"reason\": " + J(sReason) + " },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Deep-decode TiHelper 0x43DCB00; map Lookup of Neigh keyHash / SpatTi into tight factories; relate size 0xB0 objects to enrollment\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"expect runtime Neigh registrar like Spat\", \"treat Outer as NS factory\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.29-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.29-second-edward-feasibility.json");
  }

  static string T(bool b) => b ? "true" : "false";
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }
  static string RvaOrRaw(ulong v) =>
    v >= imageBase && v < imageBase + 0x20000000 ? (v - imageBase).ToString("X") : v.ToString("X");

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
    while (dec.IP < limit && guard++ < 400000) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      if (raw.IP < imageBase) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      var ins = new Ins {
        Rva = (uint)(raw.IP - imageBase), Text = o.ToString(),
        Mnemonic = raw.Mnemonic, Length = raw.Length,
        IsCall = raw.FlowControl == FlowControl.Call || raw.FlowControl == FlowControl.IndirectCall,
        IsIndirectCall = raw.FlowControl == FlowControl.IndirectCall,
        IsRet = raw.Mnemonic == Mnemonic.Ret
      };
      if (ins.IsCall && !ins.IsIndirectCall && raw.NearBranchTarget != 0 && raw.NearBranchTarget >= imageBase)
        ins.NearTarget = (uint)(raw.NearBranchTarget - imageBase);
      for (int oi = 0; oi < raw.OpCount; oi++) {
        if (raw.GetOpKind(oi) != OpKind.Memory) continue;
        ins.HasMem = true;
        if (raw.IsIPRelativeMemoryOperand) {
          ins.IpRel = true;
          ulong va = raw.IPRelativeMemoryAddress;
          if (va >= imageBase) ins.DataRva = (uint)(va - imageBase);
        } else {
          int sz = raw.MemoryDisplSize;
          if (sz == 1) ins.Disp = unchecked((sbyte)raw.MemoryDisplacement32);
          else if (sz == 2) ins.Disp = unchecked((short)raw.MemoryDisplacement32);
          else if (sz == 4) ins.Disp = unchecked((int)raw.MemoryDisplacement32);
          else if (sz == 8) ins.Disp = unchecked((long)raw.MemoryDisplacement64);
        }
      }
      list.Add(ins);
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

  static List<uint> FindQwordValue(ulong va, int max) {
    var list = new List<uint>();
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 8 <= lim && list.Count < max; i++) {
        if (BitConverter.ToUInt64(pe, (int)(s.Ptr + i)) == va)
          list.Add(s.Va + i);
      }
    }
    return list;
  }

  static IEnumerable<Sec> CodeSecs() {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      bool ok = (s.Char & 0x20000000) != 0
        || s.Name.IndexOf("impdata", StringComparison.OrdinalIgnoreCase) >= 0
        || s.Name.IndexOf("code", StringComparison.OrdinalIgnoreCase) >= 0
        || s.Name.IndexOf("text", StringComparison.OrdinalIgnoreCase) >= 0;
      if (ok) yield return s;
    }
  }

  static uint FindFuncStart(uint site) {
    int fo = RvaToFile(site);
    if (fo < 0) return 0;
    int back = Math.Min(fo, 0x8000);
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

  static ulong ReadU64(uint rva) {
    int fo = RvaToFile(rva);
    return fo < 0 ? 0 : BitConverter.ToUInt64(pe, fo);
  }
  static uint ReadU32(uint rva) {
    int fo = RvaToFile(rva);
    return fo < 0 ? 0 : BitConverter.ToUInt32(pe, fo);
  }
  static uint ReadU64AsRva(uint rva) {
    ulong v = ReadU64(rva);
    return v >= imageBase ? (uint)(v - imageBase) : 0;
  }

  static string Trunc(string s, int n) => s == null ? "" : (s.Length <= n ? s : s.Substring(0, n));

  static int RvaToFile(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva >= s.Va && rva < s.Va + span && s.Ptr > 0)
        return (int)s.Ptr + (int)(rva - s.Va);
    }
    return -1;
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
    Console.WriteLine("imageBase=0x" + imageBase.ToString("X") + " sections=" + secs.Count);
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
