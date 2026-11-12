// v0.6.32 — Offline: typed vcall sites into Neigh/Spat (VT compare or nest +0x18);
// Neighbor bridge owners upstream of edx=3 / [vt+0x2B0].
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
  const uint Neighbor = 0x2335140;       // Neigh VT[+0x110]
  const uint NeighSlot110 = 0x976B3E0;
  const uint LookupHelper = 0x4DBF820;   // returns object used for +0x110 vcalls
  const uint GateHelper = 0x4DEAC50;
  const uint OwnerEdx3 = 0x6193380;
  const uint OwnerEdx2 = 0x61934C0;
  const uint OwnerTable = 0x9242FE8;
  const uint TiHelper = 0x43DCB00;

  static readonly uint[] OwnerCluster = {
    0x61932E0, 0x6193380, 0x6193420, 0x61934C0, 0x6193560, 0x6193600, 0x61936A0
  };

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
  sealed class OwnerHit {
    public uint Func, Site, CallSite; public int Edx;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v092-raw");
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
    sb.AppendLine("===== v0.6.32 TYPED VCALL + NEIGHBOR UPSTREAM =====");
    sb.AppendLine("exeSha256=" + hash);

    // ---- 1) Slot identity ----
    sb.AppendLine();
    sb.AppendLine("===== SLOT IDENTITY =====");
    sb.AppendLine("Neigh VT[+0x110] @0x" + NeighSlot110.ToString("X") + "=0x"
      + ReadU64AsRva(NeighSlot110).ToString("X") + " expect Neighbor match="
      + (ReadU64AsRva(NeighSlot110) == Neighbor));
    sb.AppendLine("Neigh VT[+0x20]=0x" + ReadU64AsRva(NeighVt + 0x20).ToString("X")
      + " Spat VT[+0x20]=0x" + ReadU64AsRva(SpatVt + 0x20).ToString("X"));

    // ---- 2) Static VT-compare typing (expect absent) ----
    sb.AppendLine();
    sb.AppendLine("===== STATIC VT-COMPARE / MOVABS TYPING =====");
    int movabsN = CountMovabs(imageBase + NeighVt);
    int movabsS = CountMovabs(imageBase + SpatVt);
    int movabsNbr = CountMovabs(imageBase + Neighbor);
    int movabsN20 = CountMovabs(imageBase + NeighVt20);
    int movabsS20 = CountMovabs(imageBase + SpatVt20);
    int leaN = FindLeaTo(NeighVt, 20).Count;
    int leaS = FindLeaTo(SpatVt, 20).Count;
    sb.AppendLine("movabs NeighVt=" + movabsN + " SpatVt=" + movabsS
      + " Neighbor=" + movabsNbr + " NeighVt20=" + movabsN20 + " SpatVt20=" + movabsS20);
    sb.AppendLine("LEA NeighVt=" + leaN + " SpatVt=" + leaS + " (installers only; see prior)");
    bool staticVtCompareAbsent = movabsN == 0 && movabsS == 0 && movabsNbr == 0
      && movabsN20 == 0 && movabsS20 == 0;
    sb.AppendLine("staticVtCompareAbsent=" + staticVtCompareAbsent);

    // ---- 3) Sole edx=3 -> [vt+0x2B0] is Neighbor ----
    sb.AppendLine();
    sb.AppendLine("===== edx=3 -> call [reg+0x2B0] =====");
    var edx3_2b0 = FindEdxThenVcall(3, 0x2B0, 0x40);
    sb.AppendLine("sites=" + edx3_2b0.Count);
    foreach (var h in edx3_2b0)
      sb.AppendLine("  @0x" + h.Site.ToString("X") + " call@0x" + h.CallSite.ToString("X")
        + " func=0x" + h.Func.ToString("X")
        + (h.Func == Neighbor ? " *** NEIGHBOR ***" : ""));
    bool soleNeighborEdx3 = edx3_2b0.Count == 1 && edx3_2b0[0].Func == Neighbor;
    sb.AppendLine("soleNeighborEdx3_2B0=" + soleNeighborEdx3);

    // ---- 4) Upstream: mov edx,2|3 then call [reg+0x110] ----
    sb.AppendLine();
    sb.AppendLine("===== UPSTREAM: mov edx,2|3 then call [reg+0x110] =====");
    var owners = new List<OwnerHit>();
    owners.AddRange(FindEdxThenVcall(2, 0x110, 0x40));
    owners.AddRange(FindEdxThenVcall(3, 0x110, 0x40));
    sb.AppendLine("owner sites=" + owners.Count + " uniqueFuncs="
      + owners.Select(o => o.Func).Distinct().Count());
    foreach (var g in owners.GroupBy(o => o.Func).OrderByDescending(g => g.Count())) {
      bool inCluster = OwnerCluster.Contains(g.Key);
      sb.AppendLine("  func 0x" + g.Key.ToString("X") + " x" + g.Count()
        + " edx=[" + string.Join(",", g.Select(x => x.Edx).Distinct().OrderBy(x => x)) + "]"
        + (inCluster ? " *** OWNER CLUSTER ***" : ""));
    }

    // Decode primary owners
    sb.AppendLine();
    sb.AppendLine("===== PRIMARY OWNER BODIES =====");
    DumpOwner(sb, OwnerEdx3, "edx=3 primary");
    DumpOwner(sb, OwnerEdx2, "edx=2 primary (field +0x18 arg to +0x118, then +0x110)");

    // Owner table embeds
    sb.AppendLine();
    sb.AppendLine("===== OWNER CLUSTER TABLE EMBEDS =====");
    foreach (uint fs in OwnerCluster) {
      var emb = FindQwordValue(imageBase + fs, 5);
      sb.AppendLine("  0x" + fs.ToString("X") + " embeds=" + emb.Count
        + " @" + string.Join(",", emb.Select(x => "0x" + x.ToString("X"))));
    }
    sb.AppendLine("table window @0x" + OwnerTable.ToString("X") + ":");
    for (int off = 0; off <= 0x60; off += 8) {
      uint rva = (uint)(OwnerTable + off);
      uint val = ReadU64AsRva(rva);
      string tag = OwnerCluster.Contains(val) ? " *** OWNER ***" : "";
      sb.AppendLine("  0x" + rva.ToString("X") + "=0x" + val.ToString("X") + tag);
    }

    // Helpers
    sb.AppendLine();
    sb.AppendLine("===== LOOKUP HELPERS =====");
    sb.AppendLine("GateHelper 0x4DEAC50 E8 callers sampled=" + FindE8(GateHelper, 40).Count);
    sb.AppendLine("LookupHelper 0x4DBF820 (hash-bucket object get) E8 sampled="
      + FindE8(LookupHelper, 40).Count);
    sb.AppendLine("Pattern: GateHelper -> LookupHelper -> mov r8,[obj]; mov edx,2|3; call [r8+0x110]");
    sb.AppendLine("NOTE: lea [rsi+18] in edx=2 owner is FIELD ADDRESS arg to vcall +0x118,"
      + " NOT the Neighbor nested-object load (mov rcx,[this+18]).");

    // ---- 5) nest+0x18 typing ----
    sb.AppendLine();
    sb.AppendLine("===== NEST +0x18 IDIOMS =====");
    // Neighbor bridge nest load
    var nb = DisasmRaw(Neighbor, Neighbor + 0x90);
    bool neighMov18 = nb.Any(i => i.Text.IndexOf("mov rcx,[rsi+18]", StringComparison.OrdinalIgnoreCase) >= 0);
    bool neighPtr98 = nb.Any(i => i.Text.IndexOf("mov rdi,[rcx+98]", StringComparison.OrdinalIgnoreCase) >= 0);
    sb.AppendLine("Neighbor nested load mov [this+0x18] then pointer[+0x98]="
      + (neighMov18 && neighPtr98));

    int nestTo20 = CountNest18ThenVcall(0x20);
    int nestTo110 = CountNest18ThenVcall(0x110);
    sb.AppendLine("mov [reg+18] then call [reg+0x20] sites~=" + nestTo20
      + " (common untyped idiom; not NS-specific offline)");
    sb.AppendLine("mov [reg+18] then call [reg+0x110] sites~=" + nestTo110);

    // VT[+0x20] still vcall-only
    int e8n20 = FindE8(NeighVt20, 10).Count;
    int e8s20 = FindE8(SpatVt20, 10).Count;
    sb.AppendLine("NeighVt20/SpatVt20 E8 still " + e8n20 + "/" + e8s20 + " (vcall-only construct)");

    // ---- verdicts ----
    bool typedSites = staticVtCompareAbsent && soleNeighborEdx3
      && owners.Any(o => o.Func == OwnerEdx3) && owners.Any(o => o.Func == OwnerEdx2);
    bool upstreamMapped = typedSites && FindQwordValue(imageBase + OwnerEdx3, 3).Count == 1
      && FindQwordValue(imageBase + OwnerEdx2, 3).Count == 1;

    sb.AppendLine();
    sb.AppendLine("===== VERDICTS =====");
    sb.AppendLine("1) No static Neigh/Spat VT-compare typing offline; VT[+0x20] remains vcall-only."
      + " Typed Neighbor entry is slot +0x110 with edx in {2,3}."
      + " typedSites=" + typedSites);
    sb.AppendLine("2) Upstream of Neighbor edx=3/[vt+0x2B0]: owner cluster (e.g. 0x6193380 edx=3,"
      + " 0x61934C0 edx=2) via LookupHelper 0x4DBF820 then call [vt+0x110]; table @0x9242FE8."
      + " upstreamMapped=" + upstreamMapped);

    string evidencePath = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(evidencePath, sb.ToString());
    Console.WriteLine("WROTE " + evidencePath + " chars=" + sb.Length);

    WriteJson(hash, typedSites, upstreamMapped, staticVtCompareAbsent, soleNeighborEdx3,
      owners, nestTo20, nestTo110, e8n20, e8s20);

    bool ok = typedSites && upstreamMapped;
    Console.WriteLine("selfCheck typedSites=" + typedSites
      + " upstreamMapped=" + upstreamMapped + " ok=" + ok);
    return ok ? 0 : 1;
  }

  static void DumpOwner(StringBuilder sb, uint fs, string label) {
    sb.AppendLine(label + " 0x" + fs.ToString("X") + ":");
    foreach (var i in DisasmRaw(fs, fs + 0xE0)) {
      string m = "";
      if (i.Disp == 0x110) m = " *** +110 ***";
      if (i.Disp == 0x118) m += " *** +118 ***";
      if (i.Disp == 0x18) m += " *** +18 ***";
      if (i.Disp == 0x58) m += " *** +58 ***";
      if (i.NearTarget == LookupHelper) m += " *** LOOKUP ***";
      if (i.NearTarget == GateHelper) m += " *** GATE ***";
      if (i.Text.IndexOf("edx,2", StringComparison.Ordinal) >= 0
          || i.Text.IndexOf("edx,3", StringComparison.Ordinal) >= 0) m += " *** EDX ***";
      if (m.Length > 0 || i.Rva < fs + 0x20 || i.IsRet)
        sb.AppendLine("  0x" + i.Rva.ToString("X") + ": " + i.Text + m);
    }
    sb.AppendLine("  E8 callers=" + FindE8(fs, 10).Count + " (0 => table-dispatched owners)");
  }

  static List<OwnerHit> FindEdxThenVcall(int edxImm, int vcallDisp, int window) {
    var list = new List<OwnerHit>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 5 <= lim; i++) {
        if (pe[s.Ptr + i] != 0xBA) continue; // mov edx,imm32
        if (BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1)) != edxImm) continue;
        for (uint j = i + 5; j + 6 <= lim && j < i + (uint)window; j++) {
          int o = 0;
          byte b = pe[s.Ptr + j];
          if (b == 0x48 || b == 0x49 || b == 0x41 || b == 0x4C) o = 1;
          if (pe[s.Ptr + j + o] != 0xFF) continue;
          if ((pe[s.Ptr + j + o + 1] & 0xF8) != 0x90) continue;
          int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + j + o + 2));
          if (disp != vcallDisp) continue;
          uint site = s.Va + i;
          list.Add(new OwnerHit {
            Site = site, CallSite = s.Va + j, Func = FindFuncStart(site), Edx = edxImm
          });
          break;
        }
      }
    }
    return list;
  }

  static int CountNest18ThenVcall(int vcallDisp) {
    int n = 0;
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 4 <= lim; i++) {
        int off = 0;
        if ((pe[s.Ptr + i] & 0xF0) == 0x40) off = 1;
        if (pe[s.Ptr + i + off] != 0x8B) continue;
        byte modrm = pe[s.Ptr + i + off + 1];
        if ((modrm & 0xC0) != 0x40) continue;
        if (pe[s.Ptr + i + off + 2] != 0x18) continue;
        for (uint j = (uint)(i + off + 3); j + 6 <= lim && j < i + 0x50; j++) {
          int o2 = 0;
          if ((pe[s.Ptr + j] & 0xF0) == 0x40) o2 = 1;
          if (pe[s.Ptr + j + o2] != 0xFF) continue;
          byte m = pe[s.Ptr + j + o2 + 1];
          if (vcallDisp == 0x20 && m == 0x50) { n++; break; }
          if ((m & 0xF8) == 0x90) {
            int d = BitConverter.ToInt32(pe, (int)(s.Ptr + j + o2 + 2));
            if (d == vcallDisp) { n++; break; }
          }
        }
      }
    }
    return n;
  }

  static int CountMovabs(ulong abs) {
    int n = 0;
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 10 <= lim; i++) {
        byte b0 = pe[s.Ptr + i];
        if ((b0 & 0xF0) != 0x40 || (b0 & 0x08) == 0) continue;
        byte b1 = pe[s.Ptr + i + 1];
        if (b1 < 0xB8 || b1 > 0xBF) continue;
        if (BitConverter.ToUInt64(pe, (int)(s.Ptr + i + 2)) == abs) n++;
      }
    }
    return n;
  }

  static void WriteJson(string hash, bool typedSites, bool upstreamMapped,
      bool staticAbsent, bool soleEdx3, List<OwnerHit> owners,
      int nestTo20, int nestTo110, int e8n20, int e8s20) {
    Directory.CreateDirectory(ReportsRoot);
    string utc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
    var ownerFuncs = owners.Select(o => o.Func).Distinct().OrderBy(x => x)
      .Select(f => "\"0x" + f.ToString("X") + "\"").ToList();

    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.32-summary.json"),
      "{\n" +
      "  \"schemaVersion\": 1,\n" +
      "  \"milestone\": \"v0.6.32\",\n" +
      "  \"generatedUtc\": \"" + utc + "\",\n" +
      "  \"exeSha256\": \"" + hash + "\",\n" +
      "  \"typedVcalls\": {\n" +
      "    \"staticVtCompareAbsent\": " + F(staticAbsent) + ",\n" +
      "    \"neighborSlot\": \"0x110\",\n" +
      "    \"neighborEdxFilter\": [2, 3],\n" +
      "    \"soleEdx3To2B0\": " + F(soleEdx3) + ",\n" +
      "    \"vt20StillVcallOnly\": " + F(e8n20 == 0 && e8s20 == 0) + ",\n" +
      "    \"nest18ToVcall20\": " + nestTo20 + ",\n" +
      "    \"nest18ToVcall110\": " + nestTo110 + ",\n" +
      "    \"typed\": " + F(typedSites) + "\n" +
      "  },\n" +
      "  \"neighborUpstream\": {\n" +
      "    \"ownerEdx3\": \"0x6193380\",\n" +
      "    \"ownerEdx2\": \"0x61934C0\",\n" +
      "    \"ownerTable\": \"0x9242FE8\",\n" +
      "    \"lookupHelper\": \"0x4DBF820\",\n" +
      "    \"gateHelper\": \"0x4DEAC50\",\n" +
      "    \"ownerFuncs\": [" + string.Join(", ", ownerFuncs) + "],\n" +
      "    \"mapped\": " + F(upstreamMapped) + "\n" +
      "  },\n" +
      "  \"edwardOrPlayerTypeConfirmed\": false\n" +
      "}\n");
    Console.WriteLine("WROTE v0.6.32-summary.json");

    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.32-funcs-deep.json"),
      "{\n" +
      "  \"schemaVersion\": 1,\n" +
      "  \"milestone\": \"v0.6.32\",\n" +
      "  \"generatedUtc\": \"" + utc + "\",\n" +
      "  \"exeSha256\": \"" + hash + "\",\n" +
      "  \"neighbor\": {\n" +
      "    \"rva\": \"0x2335140\",\n" +
      "    \"entryContract\": \"test edx,~2; if edx in {2,3}: edx=3; call [vt+0x2B0]; nested=[this+0x18]\",\n" +
      "    \"soleEdx3To2B0\": true\n" +
      "  },\n" +
      "  \"upstreamOwners\": {\n" +
      "    \"pattern\": \"GateHelper; LookupHelper -> obj; mov edx,2|3; call [obj.vt+0x110]\",\n" +
      "    \"edx3\": \"0x6193380\",\n" +
      "    \"edx2\": \"0x61934C0\",\n" +
      "    \"note\": \"lea [this+0x18] in edx2 owner is float-field arg to +0x118, not Neighbor nested pointer load\"\n" +
      "  }\n" +
      "}\n");
    Console.WriteLine("WROTE v0.6.32-funcs-deep.json");

    string tReason = typedSites
      ? "No static Neigh/Spat VT-compare; Neighbor typed by slot +0x110 with edx in {2,3}; sole edx=3->[vt+0x2B0] is Neighbor itself; VT[+0x20] still vcall-only"
      : "typed vcall sites incomplete";
    string uReason = upstreamMapped
      ? "Owner cluster 0x6193380 (edx=3) / 0x61934C0 (edx=2) call [vt+0x110] after LookupHelper 0x4DBF820; published at table 0x9242FE8; E8=0 (table-dispatched)"
      : "upstream map incomplete";

    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.32-second-edward-feasibility.json"),
      "{\n" +
      "  \"schemaVersion\": 1,\n" +
      "  \"milestone\": \"v0.6.32\",\n" +
      "  \"generatedUtc\": \"" + utc + "\",\n" +
      "  \"exeSha256\": \"" + hash + "\",\n" +
      "  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Typed +0x110 / nest paths are NS bridge dispatch, not Edward create\" },\n" +
      "  \"typedVcalls\": { \"class\": \"confirmed\", \"reason\": " + J(tReason) + " },\n" +
      "  \"neighborUpstream\": { \"class\": \"confirmed\", \"reason\": " + J(uReason) + " },\n" +
      "  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },\n" +
      "  \"next\": {\n" +
      "    \"primary\": \"Identify runtime type returned by LookupHelper 0x4DBF820 (live or deeper static); map who dispatches owner table 0x9242FE8; relate nest+0x18 pointer objects to enrollment SideBlock family\",\n" +
      "    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"expect static VT-compare to Neigh/Spat\", \"conflate owner lea[+0x18] field arg with Neighbor nested pointer\"]\n" +
      "  }\n" +
      "}\n");
    Console.WriteLine("WROTE v0.6.32-second-edward-feasibility.json");
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
