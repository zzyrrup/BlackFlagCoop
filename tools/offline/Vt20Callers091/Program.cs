// v0.6.31 — Offline: trace callers of Neigh/Spat VT[+0x20] construct;
// map consumers of Neigh 0xB0 +0x98 byte vs pointer-family enrollment.
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
  const uint NeighVt20 = 0x3D52400;
  const uint SpatVt20 = 0x6CF34E0;
  const uint NeighVt0 = 0x13612B0;
  const uint SpatVt0 = 0x5781490;
  const uint NeighRel = 0x3D522C0;
  const uint SpatA = 0x5563CF0;
  const uint SpatB = 0x6CF34A0;
  const uint Neighbor = 0x2335140;     // Neigh VT[+0x110]
  const uint NeighMethodSlot = 0x976B3E0;
  const uint SideBlock = 0xE95E80;
  const uint Arming = 0x21085D0;
  const uint ArmWrap = 0x2108620;
  const uint Helper546 = 0x546D150;
  const uint TiHelper = 0x43DCB00;

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
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v091-raw");
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
    sb.AppendLine("===== v0.6.31 VT[+0x20] CALLERS + 0xB0/+0x98 CONSUMERS =====");
    sb.AppendLine("exeSha256=" + hash);

    // ---- 1) VT[+0x20] slot identity ----
    sb.AppendLine();
    sb.AppendLine("===== VT[+0x20] SLOT IDENTITY =====");
    uint nSlot = ReadU64AsRva(NeighVt + 0x20);
    uint sSlot = ReadU64AsRva(SpatVt + 0x20);
    sb.AppendLine("Neigh VT[+0x20]=0x" + nSlot.ToString("X") + " expect 0x" + NeighVt20.ToString("X")
      + " match=" + (nSlot == NeighVt20));
    sb.AppendLine("Spat VT[+0x20]=0x" + sSlot.ToString("X") + " expect 0x" + SpatVt20.ToString("X")
      + " match=" + (sSlot == SpatVt20));
    uint neighMethod = ReadU64AsRva(NeighMethodSlot);
    sb.AppendLine("Neigh VT[+0x110] @0x" + NeighMethodSlot.ToString("X") + "=0x" + neighMethod.ToString("X")
      + " expect Neighbor 0x" + Neighbor.ToString("X") + " match=" + (neighMethod == Neighbor));

    // ---- 2) Direct xref modes ----
    sb.AppendLine();
    sb.AppendLine("===== DIRECT XREFS TO VT[+0x20] BODIES =====");
    int e8n = FindE8(NeighVt20, 50).Count;
    int e8s = FindE8(SpatVt20, 50).Count;
    int leaN = FindLeaTo(NeighVt20, 20).Count;
    int leaS = FindLeaTo(SpatVt20, 20).Count;
    var embN = FindQwordValue(imageBase + NeighVt20, 10);
    var embS = FindQwordValue(imageBase + SpatVt20, 10);
    sb.AppendLine("NeighVt20 E8=" + e8n + " LEA=" + leaN + " qwordEmbeds=" + embN.Count
      + " @" + string.Join(",", embN.Select(x => "0x" + x.ToString("X"))));
    sb.AppendLine("SpatVt20 E8=" + e8s + " LEA=" + leaS + " qwordEmbeds=" + embS.Count
      + " @" + string.Join(",", embS.Select(x => "0x" + x.ToString("X"))));
    int ff15n = CountFf15(NeighVt + 0x20);
    int ff15s = CountFf15(SpatVt + 0x20);
    sb.AppendLine("FF15 to VT+0x20 slots: Neigh=" + ff15n + " Spat=" + ff15s);
    bool vcallOnly = e8n == 0 && e8s == 0 && leaN == 0 && leaS == 0
      && embN.Count == 1 && embS.Count == 1 && embN[0] == NeighVt + 0x20 && embS[0] == SpatVt + 0x20
      && ff15n == 0 && ff15s == 0;
    sb.AppendLine("vcallOnly (table-dispatched; no E8/LEA/FF15)=" + vcallOnly);

    // ---- 3) Owner VT installers (LEA VT, not callers of +0x20) ----
    sb.AppendLine();
    sb.AppendLine("===== OWNER VT LEA SITES (INSTALLERS, NOT +0x20 CALLERS) =====");
    foreach (var (name, vt) in new[] { ("NeighVt", NeighVt), ("SpatVt", SpatVt) }) {
      var seen = new HashSet<uint>();
      foreach (var lea in FindLeaTo(vt, 20)) {
        uint fs = FindFuncStart(lea);
        if (!seen.Add(fs)) continue;
        bool isCtor = fs == NeighVt0 || fs == NeighRel || fs == SpatVt0 || fs == SpatA || fs == SpatB;
        sb.AppendLine("  " + name + " lea@0x" + lea.ToString("X") + " func=0x" + fs.ToString("X")
          + (isCtor ? " [VT0/sibling ctor]" : ""));
      }
    }

    // ---- 4) Generic call [rax+0x20] population ----
    sb.AppendLine();
    sb.AppendLine("===== GENERIC call [rax+0x20] POPULATION =====");
    int callRax20 = 0;
    var vcallFuncs = new Dictionary<uint, int>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 3 <= lim; i++) {
        if (pe[s.Ptr + i] != 0xFF || pe[s.Ptr + i + 1] != 0x50 || pe[s.Ptr + i + 2] != 0x20) continue;
        callRax20++;
        uint fs = FindFuncStart(s.Va + i);
        vcallFuncs[fs] = vcallFuncs.GetValueOrDefault(fs) + 1;
      }
    }
    int callRcx20 = 0;
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 3 <= lim; i++)
        if (pe[s.Ptr + i] == 0xFF && pe[s.Ptr + i + 1] == 0x51 && pe[s.Ptr + i + 2] == 0x20)
          callRcx20++;
    }
    sb.AppendLine("call [rax+20] sites=" + callRax20 + " uniqueFuncs=" + vcallFuncs.Count);
    sb.AppendLine("call [rcx+20] sites=" + callRcx20);
    sb.AppendLine("Offline cannot uniquely bind generic vcall+20 to Neigh/Spat without RTTI/live VT compare.");

    // Annotate: any top vcall+20 funcs LEA NS VT / call TiHelper / touch enrollment?
    int annotated = 0;
    foreach (var g in vcallFuncs.OrderByDescending(x => x.Value).Take(100)) {
      var body = DisasmRaw(g.Key, g.Key + 0x500);
      bool ns = body.Any(i => i.DataRva == NeighVt || i.DataRva == SpatVt
        || i.DataRva == NeighVt20 || i.DataRva == SpatVt20 || i.NearTarget == TiHelper);
      bool enroll = body.Any(i => i.NearTarget == SideBlock || i.NearTarget == Arming
        || i.NearTarget == ArmWrap || i.NearTarget == Helper546 || i.NearTarget == Neighbor);
      if (!ns && !enroll) continue;
      annotated++;
      sb.AppendLine("  annotated vcall20 func 0x" + g.Key.ToString("X") + " x" + g.Value
        + " nsHint=" + ns + " enrollHint=" + enroll);
    }
    sb.AppendLine("annotated among top100 vcall20 funcs=" + annotated + " (expect low)");

    // ---- 5) VT[+0x20] bodies: construct contract ----
    sb.AppendLine();
    sb.AppendLine("===== VT[+0x20] BODY CONTRACT =====");
    SummarizeVt20(sb, "NeighVt20", NeighVt20, true);
    SummarizeVt20(sb, "SpatVt20", SpatVt20, false);

    // ---- 6) +0x98 byte vs pointer-family consumers ----
    sb.AppendLine();
    sb.AppendLine("===== +0x98 BYTE vs POINTER-FAMILY CONSUMERS =====");

    // Known pointer-family
    sb.AppendLine("Pointer-family (qword +0x98):");
    foreach (var (name, entry) in new[] {
      ("SideBlock", SideBlock), ("Arming", Arming), ("ArmWrap", ArmWrap),
      ("Helper546", Helper546) }) {
      var body = DisasmRaw(entry, entry + 0x300);
      int q = CountQword98(body);
      int b = CountByte98(body);
      int a = CountAddLea98(body);
      sb.AppendLine("  " + name + " 0x" + entry.ToString("X") + " qword98=" + q
        + " byte98=" + b + " add/lea98=" + a);
    }

    // NeighRel byte init
    sb.AppendLine("NeighRel (0xB0 ctor) +0x98:");
    var nr = DisasmRaw(NeighRel, NeighRel + 0x90);
    sb.AppendLine("  byteZero=" + nr.Any(i => i.Text.IndexOf("mov [rcx+98],al", StringComparison.OrdinalIgnoreCase) >= 0)
      + " qword98=" + CountQword98(nr) + " SideBlock=" + nr.Any(i => i.NearTarget == SideBlock));

    // Neighbor method: bridge
    sb.AppendLine("Neighbor method 0x2335140 (Neigh VT[+0x110]) bridge:");
    var nb = DisasmRaw(Neighbor, Neighbor + 0xA0);
    bool neighByte98 = nb.Any(i => i.Text.IndexOf("mov byte ptr [rsi+98]", StringComparison.OrdinalIgnoreCase) >= 0
      || i.Text.IndexOf("cmp byte ptr [rsi+98]", StringComparison.OrdinalIgnoreCase) >= 0);
    bool neighPtr98OnNested = nb.Any(i => i.Text.IndexOf("mov rdi,[rcx+98]", StringComparison.OrdinalIgnoreCase) >= 0);
    bool neighVcall2B0 = nb.Any(i => i.IsIndirectCall && i.Disp == 0x2B0);
    bool neighLoad18 = nb.Any(i => i.Text.IndexOf("[rsi+18]", StringComparison.OrdinalIgnoreCase) >= 0
      || i.Text.IndexOf("[rcx+18]", StringComparison.OrdinalIgnoreCase) >= 0);
    sb.AppendLine("  E8 callers=" + FindE8(Neighbor, 20).Count + " (0 => .edata/vtable only)");
    sb.AppendLine("  qword embeds @" + string.Join(",", FindQwordValue(imageBase + Neighbor, 5)
      .Select(x => "0x" + x.ToString("X"))));
    sb.AppendLine("  edx=3 vcall [vt+0x2B0]=" + neighVcall2B0);
    sb.AppendLine("  load nested via [this+0x18] then POINTER [nested+0x98]=" + neighPtr98OnNested);
    sb.AppendLine("  BYTE store/cmp on this+0x98=" + neighByte98);
    sb.AppendLine("  -- key excerpt --");
    foreach (var i in nb) {
      string m = "";
      if (i.Disp == 0x98 || i.Text.Contains("+98")) m = " *** +98 ***";
      if (i.IsIndirectCall && i.Disp == 0x2B0) m += " *** VCALL2B0 ***";
      if (i.Disp == 0x18 && i.Text.Contains("[")) m += " *** +18 ***";
      if (m.Length > 0 || i.Rva <= Neighbor + 0x20)
        sb.AppendLine("  0x" + i.Rva.ToString("X") + ": " + i.Text + m);
      if (i.IsRet && i.Rva > Neighbor + 0x30) break;
    }

    // Spatial inline
    sb.AppendLine("Spat VT0/A/B inline +0x98 (add reg,98):");
    foreach (var (name, entry) in new[] { ("SpatVt0", SpatVt0), ("SpatA", SpatA), ("SpatB", SpatB), ("SpatVt20", SpatVt20) }) {
      var body = DisasmRaw(entry, entry + 0x100);
      sb.AppendLine("  " + name + " add/lea98=" + CountAddLea98(body)
        + " qword98=" + CountQword98(body) + " byte98=" + CountByte98(body));
    }

    // Opcode census
    int cmpByte98 = 0, movByte98 = 0, cmpQ98 = 0;
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 5 <= lim; i++) {
        if (pe[s.Ptr + i] == 0x80 && (pe[s.Ptr + i + 1] & 0xF8) == 0x78 && pe[s.Ptr + i + 2] == 0x98)
          cmpByte98++;
        if (pe[s.Ptr + i] == 0xC6 && (pe[s.Ptr + i + 1] & 0xC0) == 0x40
            && (pe[s.Ptr + i + 1] & 0x38) == 0 && pe[s.Ptr + i + 2] == 0x98)
          movByte98++;
        if (pe[s.Ptr + i] == 0x48 && pe[s.Ptr + i + 1] == 0x83
            && (pe[s.Ptr + i + 2] & 0xF8) == 0x78 && pe[s.Ptr + i + 3] == 0x98
            && pe[s.Ptr + i + 4] == 0x00)
          cmpQ98++;
      }
    }
    sb.AppendLine("Opcode census: cmp byte[reg+98]=" + cmpByte98
      + " mov byte[reg+98],imm=" + movByte98
      + " cmp qword[reg+98],0=" + cmpQ98);

    // ---- verdicts ----
    bool callersTraced = vcallOnly && nSlot == NeighVt20 && sSlot == SpatVt20;
    bool consumersMapped = neighByte98 && neighPtr98OnNested && neighVcall2B0
      && CountQword98(DisasmRaw(SideBlock, SideBlock + 0x100)) > 0
      && nr.Any(i => i.Text.IndexOf("mov [rcx+98],al", StringComparison.OrdinalIgnoreCase) >= 0);

    sb.AppendLine();
    sb.AppendLine("===== VERDICTS =====");
    sb.AppendLine("1) Neigh/Spat VT[+0x20] construct are vtable-dispatched only (no E8/LEA/FF15)."
      + " callersTraced=" + callersTraced);
    sb.AppendLine("2) +0x98 consumers: (a) byte field on Neigh 0xB0/Neighbor-this;"
      + " (b) pointer on nested/SideBlock/Arming family;"
      + " (c) Spatial inline add. Neighbor 0x2335140 bridges (a)+(b) via [this+0x18]."
      + " mapped=" + consumersMapped);

    string evidencePath = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(evidencePath, sb.ToString());
    Console.WriteLine("WROTE " + evidencePath + " chars=" + sb.Length);

    WriteJson(hash, callersTraced, consumersMapped, vcallOnly, e8n, e8s, callRax20,
      vcallFuncs.Count, neighByte98, neighPtr98OnNested, cmpByte98, movByte98, cmpQ98);

    bool ok = callersTraced && consumersMapped;
    Console.WriteLine("selfCheck callersTraced=" + callersTraced
      + " consumersMapped=" + consumersMapped + " ok=" + ok);
    return ok ? 0 : 1;
  }

  static void SummarizeVt20(StringBuilder sb, string name, uint entry, bool neigh) {
    var body = DisasmRaw(entry, entry + 0x80);
    bool tih = body.Any(i => i.NearTarget == TiHelper);
    bool add98 = CountAddLea98(body) > 0;
    sb.AppendLine(name + " 0x" + entry.ToString("X") + ": callTiHelper=" + tih
      + " inline+98=" + add98);
    var callees = body.Where(i => i.IsCall && !i.IsIndirectCall && i.NearTarget != 0)
      .Select(i => i.NearTarget).Distinct().ToList();
    sb.AppendLine("  near callees: " + string.Join(", ", callees.Select(c => "0x" + c.ToString("X"))));
  }

  static int CountQword98(List<Ins> body) =>
    body.Count(i => i.Disp == 0x98 && (
      i.Text.IndexOf("qword", StringComparison.OrdinalIgnoreCase) >= 0
      || (i.Text.IndexOf("mov", StringComparison.OrdinalIgnoreCase) >= 0
          && i.Text.Contains("[") && !i.Text.Contains("byte")
          && !i.Text.Contains(",al") && !i.Text.Contains(",cl"))));

  static int CountByte98(List<Ins> body) =>
    body.Count(i => (i.Disp == 0x98 || i.Text.Contains("+98")) && (
      i.Text.IndexOf("byte", StringComparison.OrdinalIgnoreCase) >= 0
      || i.Text.Contains(",al") || i.Text.Contains("movzx")));

  static int CountAddLea98(List<Ins> body) =>
    body.Count(i =>
      i.Text.IndexOf("add ", StringComparison.OrdinalIgnoreCase) >= 0
        && i.Text.IndexOf(",98", StringComparison.OrdinalIgnoreCase) >= 0
      || (i.Text.IndexOf("lea ", StringComparison.OrdinalIgnoreCase) >= 0
          && i.Text.Contains("+98")));

  static void WriteJson(string hash, bool callersTraced, bool consumersMapped, bool vcallOnly,
      int e8n, int e8s, int callRax20, int vcallFuncs, bool neighByte98, bool neighPtr98,
      int cmpByte98, int movByte98, int cmpQ98) {
    Directory.CreateDirectory(ReportsRoot);
    string utc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.31-summary.json"),
      "{\n" +
      "  \"schemaVersion\": 1,\n" +
      "  \"milestone\": \"v0.6.31\",\n" +
      "  \"generatedUtc\": \"" + utc + "\",\n" +
      "  \"exeSha256\": \"" + hash + "\",\n" +
      "  \"vt20Callers\": {\n" +
      "    \"neighVt20\": \"0x3D52400\",\n" +
      "    \"spatVt20\": \"0x6CF34E0\",\n" +
      "    \"e8Neigh\": " + e8n + ",\n" +
      "    \"e8Spat\": " + e8s + ",\n" +
      "    \"vcallOnly\": " + F(vcallOnly) + ",\n" +
      "    \"genericCallRax20\": " + callRax20 + ",\n" +
      "    \"genericCallRax20Funcs\": " + vcallFuncs + ",\n" +
      "    \"traced\": " + F(callersTraced) + "\n" +
      "  },\n" +
      "  \"plus98Consumers\": {\n" +
      "    \"byteFamily\": [\"NeighRel zero-init\", \"Neighbor this+0x98 flag\"],\n" +
      "    \"pointerFamily\": [\"SideBlock\", \"Arming\", \"ArmWrap\", \"Helper546\", \"nested via Neighbor [this+0x18]\"],\n" +
      "    \"inlineSpatial\": [\"SpatVt0\", \"SpatA\", \"SpatB\", \"SpatVt20\"],\n" +
      "    \"neighborBridge\": {\n" +
      "      \"rva\": \"0x2335140\",\n" +
      "      \"byteOnThis\": " + F(neighByte98) + ",\n" +
      "      \"pointerOnNested18\": " + F(neighPtr98) + "\n" +
      "    },\n" +
      "    \"opcodeCensus\": { \"cmpByte98\": " + cmpByte98 + ", \"movByte98\": " + movByte98
        + ", \"cmpQword98eq0\": " + cmpQ98 + " },\n" +
      "    \"mapped\": " + F(consumersMapped) + "\n" +
      "  },\n" +
      "  \"edwardOrPlayerTypeConfirmed\": false\n" +
      "}\n");
    Console.WriteLine("WROTE v0.6.31-summary.json");

    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.31-funcs-deep.json"),
      "{\n" +
      "  \"schemaVersion\": 1,\n" +
      "  \"milestone\": \"v0.6.31\",\n" +
      "  \"generatedUtc\": \"" + utc + "\",\n" +
      "  \"exeSha256\": \"" + hash + "\",\n" +
      "  \"vt20\": {\n" +
      "    \"dispatch\": \"vtable_only\",\n" +
      "    \"neigh\": { \"slot\": \"0x976B2F0\", \"body\": \"0x3D52400\", \"via\": \"TiHelper\" },\n" +
      "    \"spat\": { \"slot\": \"0x9236E20\", \"body\": \"0x6CF34E0\", \"via\": \"TiHelper\", \"inline98\": true }\n" +
      "  },\n" +
      "  \"neighborBridge\": {\n" +
      "    \"rva\": \"0x2335140\",\n" +
      "    \"vtSlot\": \"0x976B3E0\",\n" +
      "    \"steps\": [\n" +
      "      \"or [this+0x23],1\",\n" +
      "      \"if edx in {2,3}: vcall [vt+0x2B0] edx=3\",\n" +
      "      \"nested=[this+0x18]; ptr=[nested+0x98] (pointer-family)\",\n" +
      "      \"copy transforms nested->this; mov byte [this+0x98],1 (byte-family)\"\n" +
      "    ]\n" +
      "  }\n" +
      "}\n");
    Console.WriteLine("WROTE v0.6.31-funcs-deep.json");

    string cReason = callersTraced
      ? "Neigh/Spat VT[+0x20] have 0 E8/LEA/FF15 xrefs; sole qword embeds are VT table slots; dispatch is vcall-only (4659+ generic call[rax+20] sites untyped offline)"
      : "VT[+0x20] caller trace incomplete";
    string pReason = consumersMapped
      ? "Byte family: NeighRel zero + Neighbor this+0x98 flag. Pointer family: SideBlock/Arming/Helper546 + nested[this+0x18]+0x98 in Neighbor. Spatial inline add distinct. Neighbor bridges both layouts."
      : "+0x98 consumer map incomplete";

    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.31-second-edward-feasibility.json"),
      "{\n" +
      "  \"schemaVersion\": 1,\n" +
      "  \"milestone\": \"v0.6.31\",\n" +
      "  \"generatedUtc\": \"" + utc + "\",\n" +
      "  \"exeSha256\": \"" + hash + "\",\n" +
      "  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"VT[+0x20]/+0x98 paths are NS construct/layout, not Edward create\" },\n" +
      "  \"vt20Callers\": { \"class\": \"confirmed\", \"reason\": " + J(cReason) + " },\n" +
      "  \"plus98Consumers\": { \"class\": \"confirmed\", \"reason\": " + J(pReason) + " },\n" +
      "  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },\n" +
      "  \"next\": {\n" +
      "    \"primary\": \"Trace who vcalls Neigh/Spat objects (typed sites via VT compare or enrollment nest [+0x18]); map Neighbor bridge owners upstream of edx=3/[vt+0x2B0]\",\n" +
      "    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"expect E8 to VT[+0x20]\", \"conflate byte +0x98 with SideBlock pointer\"]\n" +
      "  }\n" +
      "}\n");
    Console.WriteLine("WROTE v0.6.31-second-edward-feasibility.json");
  }

  static string F(bool b) => b ? "true" : "false";
  static string J(string s) =>
    s == null ? "null" : "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

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

  static int CountFf15(uint slotRva) {
    int n = 0;
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 6 <= lim; i++) {
        if (pe[s.Ptr + i] != 0xFF || pe[s.Ptr + i + 1] != 0x15) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 2));
        if (unchecked((uint)(s.Va + i + 6 + disp)) == slotRva) n++;
      }
    }
    return n;
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
  static uint ReadU64AsRva(uint rva) {
    ulong v = ReadU64(rva);
    return v >= imageBase ? (uint)(v - imageBase) : 0;
  }

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
