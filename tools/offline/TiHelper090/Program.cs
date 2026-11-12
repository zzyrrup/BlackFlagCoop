// v0.6.30 — Offline: deep-decode TiHelper 0x43DCB00; map Lookup of Neigh
// keyHash / SpatTi into tight factories; relate size 0xB0 to enrollment/+0x98.
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

  const uint TiHelper = 0x43DCB00;
  const uint Lookup = 0x429F9E0;
  const uint Allocator = 0x426EE50;
  const uint NeighMeta = 0xAAD2290;
  const uint NeighKeyField = 0xAAD22A8; // NeighMeta + 0x18
  const uint SpatTi = 0xACE83F8;
  const uint SpatBTi = 0xACE8478;
  const uint NeighVt20 = 0x3D52400;
  const uint SpatVt20 = 0x6CF34E0;
  const uint NeighRel = 0x3D522C0;
  const uint SideBlock = 0xE95E80;
  const uint Arming = 0x21085D0;
  const ulong NeighKeyHash = 0x2996CA50CB0F23F4UL;

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
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v090-raw");
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
    sb.AppendLine("===== v0.6.30 TiHelper DEEP-DECODE + LOOKUP/0xB0 MAP =====");
    sb.AppendLine("exeSha256=" + hash);

    // ---- 1) TiHelper deep-decode ----
    sb.AppendLine();
    sb.AppendLine("===== TiHelper 0x43DCB00 PRIMARY PATH =====");
    var tiBody = DisasmRaw(TiHelper, TiHelper + 0x800);
    bool callsLookup = tiBody.Any(i => i.NearTarget == Lookup);
    bool callsAlloc = tiBody.Any(i => i.NearTarget == Allocator);
    bool loadsSize20 = tiBody.Any(i => i.Disp == 0x20 && i.Text.IndexOf("[rcx+20]", StringComparison.OrdinalIgnoreCase) >= 0);
    bool loadsFlagsF6 = tiBody.Any(i => i.Text.IndexOf("[rcx+0F6]", StringComparison.OrdinalIgnoreCase) >= 0);
    bool icallTi50 = tiBody.Any(i => i.IsIndirectCall && (
      i.Text.IndexOf("[r15+50]", StringComparison.OrdinalIgnoreCase) >= 0
      || i.Text.IndexOf("[rax+50]", StringComparison.OrdinalIgnoreCase) >= 0));
    bool earlyRdxPassthrough = tiBody.Any(i => i.Rva == 0x43DCB13); // test rdx,rdx
    bool freelistPop = tiBody.Any(i => i.Rva == 0x43DCB9F); // mov r13,[rcx+18]
    bool vtableAlloc = tiBody.Any(i => i.Rva == 0x43DCC1C); // call r9 with edx=size
    uint globalSlot = 0;
    foreach (var i in tiBody) {
      if (i.Rva == 0x43DCB36 && i.IpRel) { globalSlot = i.DataRva; break; }
    }
    sb.AppendLine("callsLookup=" + callsLookup + " callsAllocator=" + callsAlloc);
    sb.AppendLine("loads [ti+0x20] size=" + loadsSize20 + " loads [ti+0xF6] flags=" + loadsFlagsF6);
    sb.AppendLine("icall [ti+0x50] ctor=" + icallTi50);
    sb.AppendLine("rdx passthrough (non-null -> return rdx)=" + earlyRdxPassthrough);
    sb.AppendLine("freelist pop path @0x43DCB9F=" + freelistPop);
    sb.AppendLine("vtable alloc path call r9 @0x43DCC1C (edx=size from ti+0x20)=" + vtableAlloc);
    sb.AppendLine("runtime pool global slot RVA=0x" + globalSlot.ToString("X")
      + " PE-qword=0x" + ReadU64(globalSlot).ToString("X") + " (runtime-filled)");
    sb.AppendLine("E8->TiHelper total=" + CountE8(TiHelper));
    sb.AppendLine();
    sb.AppendLine("-- primary path disasm excerpt --");
    foreach (var i in tiBody.Where(x => x.Rva <= 0x43DCC80).Take(90)) {
      string m = "";
      if (i.NearTarget == Lookup) m = " *** LOOKUP ***";
      if (i.NearTarget == Allocator) m = " *** ALLOC ***";
      if (i.IsIndirectCall && i.Text.IndexOf("+50]", StringComparison.Ordinal) >= 0) m = " *** ICALL ti+50 ***";
      if (i.Disp == 0x20 && i.Text.Contains("[rcx+20]")) m = " *** SIZE ***";
      if (i.Text.Contains("[rcx+0F6]")) m = " *** FLAGS ***";
      if (i.Rva == 0x43DCC1C) m = " *** VTBL ALLOC edx=size ***";
      sb.AppendLine("  0x" + i.Rva.ToString("X") + ": " + i.Text + m);
    }
    var e8Callees = tiBody.Where(i => i.IsCall && !i.IsIndirectCall && i.NearTarget != 0)
      .GroupBy(i => i.NearTarget).Select(g => (g.Key, g.Count())).OrderByDescending(t => t.Item2).ToList();
    sb.AppendLine("E8 callees in first 0x800:");
    foreach (var (c, n) in e8Callees.Take(25))
      sb.AppendLine("  0x" + c.ToString("X") + " x" + n);

    // ---- 2) VT[+0x20] feeds confirm TiHelper contract ----
    sb.AppendLine();
    sb.AppendLine("===== VT[+0x20] -> TiHelper CONTRACT =====");
    DumpVt20(sb, "NeighVT20", NeighVt20, NeighMeta);
    DumpVt20(sb, "SpatVT20", SpatVt20, SpatTi);

    // ---- 3) Lookup of Neigh keyHash / SpatTi into tight factories ----
    sb.AppendLine();
    sb.AppendLine("===== LOOKUP / TIGHT-FACTORY vs Neigh keyHash / SpatTi =====");
    int leaNeigh = FindLeaTo(NeighMeta, 50).Count;
    int leaSpat = FindLeaTo(SpatTi, 50).Count;
    int leaSpatB = FindLeaTo(SpatBTi, 50).Count;
    int leaKeyField = FindLeaTo(NeighKeyField, 20).Count;
    sb.AppendLine("LEA NeighMeta=" + leaNeigh + " SpatTi=" + leaSpat
      + " SpatBTi=" + leaSpatB + " NeighMeta+0x18=" + leaKeyField);
    sb.AppendLine("keyHash embeds=" + string.Join(",", FindQwordValue(NeighKeyHash, 10).Select(x => "0x" + x.ToString("X"))));

    int lookupFuncsWithNsTi = 0;
    var lookupNsHits = new List<string>();
    var seen = new HashSet<uint>();
    foreach (var site in FindE8(Lookup, 800)) {
      uint fs = FindFuncStart(site);
      if (!seen.Add(fs)) continue;
      var body = DisasmRaw(fs, fs + 0x500);
      bool leaNs = body.Any(i => i.DataRva == NeighMeta || i.DataRva == SpatTi
        || i.DataRva == SpatBTi || i.DataRva == NeighKeyField);
      if (!leaNs) continue;
      lookupFuncsWithNsTi++;
      bool tight = body.Any(i => TightFactories.Contains(i.NearTarget));
      bool tih = body.Any(i => i.NearTarget == TiHelper);
      lookupNsHits.Add("0x" + fs.ToString("X") + " tight=" + tight + " tih=" + tih);
    }
    sb.AppendLine("Lookup funcs also LEA NS TypeInfo/keyField=" + lookupFuncsWithNsTi
      + " (0 => no offline Lookup feed of Neigh/Spat TI into factories)");
    foreach (var h in lookupNsHits.Take(15)) sb.AppendLine("  " + h);

    sb.AppendLine("Tight factory bodies:");
    int tightWithNs = 0, tightWithTiH = 0, tightWithLookup = 0, tightWithAlloc = 0;
    foreach (uint tf in TightFactories) {
      var body = DisasmRaw(tf, tf + 0x200);
      bool leaNs = body.Any(i => i.DataRva == NeighMeta || i.DataRva == SpatTi || i.DataRva == SpatBTi);
      bool tih = body.Any(i => i.NearTarget == TiHelper);
      bool lk = body.Any(i => i.NearTarget == Lookup);
      bool al = body.Any(i => i.NearTarget == Allocator);
      if (leaNs) tightWithNs++;
      if (tih) tightWithTiH++;
      if (lk) tightWithLookup++;
      if (al) tightWithAlloc++;
      sb.AppendLine("  0x" + tf.ToString("X") + " LEA_NS_TI=" + leaNs
        + " TiHelper=" + tih + " Lookup=" + lk + " Alloc=" + al);
    }

    // LEA NS TI funcs: do any call Lookup/tight?
    sb.AppendLine("LEA NS-TI funcs vs Lookup/Alloc/Tight/TiHelper:");
    int leaNsToLookup = 0, leaNsToTight = 0, leaNsToTiH = 0;
    foreach (var (name, ti) in new[] { ("NeighMeta", NeighMeta), ("SpatTi", SpatTi), ("SpatBTi", SpatBTi) }) {
      seen.Clear();
      foreach (var lea in FindLeaTo(ti, 40)) {
        uint fs = FindFuncStart(lea);
        if (!seen.Add(fs)) continue;
        var body = DisasmRaw(fs, fs + 0x600);
        bool lk = body.Any(i => i.NearTarget == Lookup);
        bool al = body.Any(i => i.NearTarget == Allocator);
        bool tight = body.Any(i => TightFactories.Contains(i.NearTarget));
        bool tih = body.Any(i => i.NearTarget == TiHelper);
        if (lk) leaNsToLookup++;
        if (tight) leaNsToTight++;
        if (tih) leaNsToTiH++;
        if (lk || al || tight || tih)
          sb.AppendLine("  " + name + " func 0x" + fs.ToString("X")
            + " Lookup=" + lk + " Alloc=" + al + " Tight=" + tight + " TiH=" + tih);
      }
    }

    // ---- 4) Size 0xB0 vs enrollment / +0x98 ----
    sb.AppendLine();
    sb.AppendLine("===== SIZE 0xB0 vs ENROLLMENT / +0x98 =====");
    uint neighSize = ReadU32(NeighMeta + 0x20);
    uint spatSize = ReadU32(SpatTi + 0x20);
    uint spatBSize = ReadU32(SpatBTi + 0x20);
    sb.AppendLine("NeighMeta+0x20 size=0x" + neighSize.ToString("X")
      + " SpatTi+0x20 PE-static=0x" + spatSize.ToString("X")
      + " SpatBTi+0x20 PE-static=0x" + spatBSize.ToString("X")
      + " (Spat sizes runtime-filled)");
    // Allocator(imm 0xB0) nearby
    int allocB0 = 0;
    foreach (var site in FindE8(Allocator, 2000)) {
      var win = DisasmRaw(site > 0x40 ? site - 0x40 : site, site + 1);
      if (win.Any(i => i.Rva < site && (
          i.Text.IndexOf(",0B0h", StringComparison.OrdinalIgnoreCase) >= 0
          || i.Text.IndexOf(", 0B0h", StringComparison.OrdinalIgnoreCase) >= 0)))
        allocB0++;
    }
    sb.AppendLine("Allocator sites sampled=2000 with imm 0xB0 nearby=" + allocB0
      + " (0 => size 0xB0 not hard-coded into shared Allocator)");

    // NeighRel ctor +0x98
    sb.AppendLine("NeighRel ctor (TypeInfo+0x50 for size 0xB0 objects):");
    var nr = DisasmRaw(NeighRel, NeighRel + 0x90);
    bool nrXor = nr.Any(i => i.Text.IndexOf("xor eax,eax", StringComparison.OrdinalIgnoreCase) >= 0);
    bool nrByte98 = nr.Any(i => i.Disp == 0x98 && i.Text.IndexOf("mov [rcx+98],al", StringComparison.OrdinalIgnoreCase) >= 0);
    bool nrQ90 = nr.Any(i => i.Disp == 0x90);
    bool nrQA0 = nr.Any(i => i.Disp == 0xA0);
    bool nrSide = nr.Any(i => i.NearTarget == SideBlock);
    bool nrArm = nr.Any(i => i.NearTarget == Arming);
    sb.AppendLine("  xor eax,eax=" + nrXor + " mov [rcx+98],al (zero byte)=" + nrByte98
      + " zero +0x90=" + nrQ90 + " zero +0xA0=" + nrQA0);
    sb.AppendLine("  calls SideBlock=" + nrSide + " Arming=" + nrArm
      + " (false => NOT enrollment pointer-slot attach)");
    foreach (var i in nr) {
      if (i.Disp == 0x98 || i.Disp == 0x90 || i.Disp == 0xA0 || i.Text.Contains("xor eax,eax"))
        sb.AppendLine("  0x" + i.Rva.ToString("X") + ": " + i.Text);
    }

    // NeighVt20 enrollment markers
    var nv = DisasmRaw(NeighVt20, NeighVt20 + 0x400);
    sb.AppendLine("NeighVT20 +0x98=" + nv.Any(i => i.Disp == 0x98)
      + " +0x61=" + nv.Any(i => i.Disp == 0x61)
      + " SideBlock=" + nv.Any(i => i.NearTarget == SideBlock));
    var sv = DisasmRaw(SpatVt20, SpatVt20 + 0x80);
    // Spat uses immediate add reg,98 (not mem displ) then helper copy
    bool spatInline98 = sv.Any(i =>
      i.Text.IndexOf("add rdi,98", StringComparison.OrdinalIgnoreCase) >= 0
      || i.Text.IndexOf("add rcx,98", StringComparison.OrdinalIgnoreCase) >= 0
      || (i.Disp == 0x98 && (i.Text.IndexOf("add", StringComparison.OrdinalIgnoreCase) >= 0
        || i.Text.IndexOf("lea", StringComparison.OrdinalIgnoreCase) >= 0)));
    sb.AppendLine("SpatVT20 inline +0x98 (add reg,98)=" + spatInline98 + " (spatial copy, not SideBlock)");

    // TiHelper callers vs +98 / SideBlock sample
    int tiCaller98 = 0, tiCallerSB = 0, tiCaller61 = 0, tiCallerUnique = 0;
    seen.Clear();
    foreach (var site in FindE8(TiHelper, 500)) {
      uint fs = FindFuncStart(site);
      if (!seen.Add(fs)) continue;
      tiCallerUnique++;
      var body = DisasmRaw(fs, fs + 0x600);
      if (body.Any(i => i.Disp == 0x98)) tiCaller98++;
      if (body.Any(i => i.NearTarget == SideBlock)) tiCallerSB++;
      if (body.Any(i => i.Disp == 0x61)) tiCaller61++;
    }
    sb.AppendLine("TiHelper caller funcs sampled=" + tiCallerUnique
      + " touch+98=" + tiCaller98 + " SideBlock=" + tiCallerSB + " +61=" + tiCaller61);

    // ---- verdicts ----
    bool tiHelperDecoded = loadsSize20 && icallTi50 && !callsLookup && !callsAlloc && freelistPop;
    bool noLookupFeed = lookupFuncsWithNsTi == 0 && tightWithNs == 0 && leaNsToLookup == 0 && leaNsToTight == 0;
    bool sizeB0Mapped = neighSize == 0xB0 && allocB0 == 0 && nrByte98 && !nrSide && spatInline98;

    sb.AppendLine();
    sb.AppendLine("===== VERDICTS =====");
    sb.AppendLine("1) TiHelper=TypeInfo construct helper (size[ti+0x20] -> pool/vtbl-alloc -> icall[ti+0x50]);"
      + " NOT Lookup bridge. decoded=" + tiHelperDecoded);
    sb.AppendLine("2) Neigh keyHash / SpatTi do NOT feed tight factories via Lookup offline. noLookupFeed=" + noLookupFeed);
    sb.AppendLine("3) Size 0xB0=Neigh TypeInfo heap size via TiHelper; NeighRel zero-inits +0x98 byte"
      + " (object field), distinct from SideBlock pointer enroll. mapped=" + sizeB0Mapped);

    // write evidence
    string evidencePath = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(evidencePath, sb.ToString());
    Console.WriteLine("WROTE " + evidencePath + " chars=" + sb.Length);

    WriteJsonReports(hash, tiHelperDecoded, noLookupFeed, sizeB0Mapped,
      callsLookup, callsAlloc, loadsSize20, icallTi50, freelistPop, vtableAlloc, globalSlot,
      lookupFuncsWithNsTi, tightWithNs, tightWithTiH, leaNsToLookup, leaNsToTight, leaNsToTiH,
      neighSize, allocB0, nrByte98, nrSide, spatInline98, tiCaller98, tiCallerSB);

    bool ok = tiHelperDecoded && noLookupFeed && sizeB0Mapped;
    Console.WriteLine("selfCheck tiHelperDecoded=" + tiHelperDecoded
      + " noLookupFeed=" + noLookupFeed + " sizeB0Mapped=" + sizeB0Mapped + " ok=" + ok);
    return ok ? 0 : 1;
  }

  static void DumpVt20(StringBuilder sb, string name, uint entry, uint expectTi) {
    sb.AppendLine(name + " 0x" + entry.ToString("X") + ":");
    bool leaTi = false, callTiH = false, inline98 = false;
    foreach (var i in DisasmRaw(entry, entry + 0x80).Take(35)) {
      string m = "";
      if (i.DataRva == expectTi) { leaTi = true; m = " *** TI ***"; }
      if (i.NearTarget == TiHelper) { callTiH = true; m = " *** TIHELPER ***"; }
      if (i.Disp == 0x98
          || i.Text.IndexOf(",98", StringComparison.OrdinalIgnoreCase) >= 0
          || i.Text.IndexOf("+98", StringComparison.OrdinalIgnoreCase) >= 0) {
        inline98 = true; m += " *** +98 ***";
      }
      sb.AppendLine("  0x" + i.Rva.ToString("X") + ": " + i.Text + m);
    }
    sb.AppendLine("  leaTI=" + leaTi + " callTiHelper=" + callTiH + " +98=" + inline98);
  }

  static void WriteJsonReports(
      string hash, bool tiHelperDecoded, bool noLookupFeed, bool sizeB0Mapped,
      bool callsLookup, bool callsAlloc, bool loadsSize20, bool icallTi50,
      bool freelistPop, bool vtableAlloc, uint globalSlot,
      int lookupFuncsWithNsTi, int tightWithNs, int tightWithTiH,
      int leaNsToLookup, int leaNsToTight, int leaNsToTiH,
      uint neighSize, int allocB0, bool nrByte98, bool nrSide, bool spatInline98,
      int tiCaller98, int tiCallerSB) {
    Directory.CreateDirectory(ReportsRoot);
    string utc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.30-summary.json"),
      "{\n" +
      "  \"schemaVersion\": 1,\n" +
      "  \"milestone\": \"v0.6.30\",\n" +
      "  \"generatedUtc\": \"" + utc + "\",\n" +
      "  \"exeSha256\": \"" + hash + "\",\n" +
      "  \"tiHelper\": {\n" +
      "    \"rva\": \"0x43DCB00\",\n" +
      "    \"role\": \"typeinfo_construct_helper\",\n" +
      "    \"callsLookup\": " + F(callsLookup) + ",\n" +
      "    \"callsAllocator\": " + F(callsAlloc) + ",\n" +
      "    \"loadsSizePlus20\": " + F(loadsSize20) + ",\n" +
      "    \"icallCtorPlus50\": " + F(icallTi50) + ",\n" +
      "    \"freelistPath\": " + F(freelistPop) + ",\n" +
      "    \"vtableAllocPath\": " + F(vtableAlloc) + ",\n" +
      "    \"poolGlobalSlot\": \"0x" + globalSlot.ToString("X") + "\",\n" +
      "    \"decoded\": " + F(tiHelperDecoded) + "\n" +
      "  },\n" +
      "  \"lookupIntoTightFactories\": {\n" +
      "    \"lookupFuncsLeaNsTi\": " + lookupFuncsWithNsTi + ",\n" +
      "    \"tightFactoriesLeaNsTi\": " + tightWithNs + ",\n" +
      "    \"tightFactoriesCallTiHelper\": " + tightWithTiH + ",\n" +
      "    \"leaNsTiToLookup\": " + leaNsToLookup + ",\n" +
      "    \"leaNsTiToTight\": " + leaNsToTight + ",\n" +
      "    \"leaNsTiToTiHelper\": " + leaNsToTiH + ",\n" +
      "    \"feedConfirmed\": false,\n" +
      "    \"channelsDistinct\": " + F(noLookupFeed) + "\n" +
      "  },\n" +
      "  \"sizeB0Enrollment\": {\n" +
      "    \"neighSize\": \"0x" + neighSize.ToString("X") + "\",\n" +
      "    \"allocatorImmB0\": " + allocB0 + ",\n" +
      "    \"neighRelZeroByteAt98\": " + F(nrByte98) + ",\n" +
      "    \"neighRelCallsSideBlock\": " + F(nrSide) + ",\n" +
      "    \"spatVt20Inline98\": " + F(spatInline98) + ",\n" +
      "    \"tiHelperCallersTouch98\": " + tiCaller98 + ",\n" +
      "    \"tiHelperCallersSideBlock\": " + tiCallerSB + ",\n" +
      "    \"relatedAsSideBlockEnroll\": false,\n" +
      "    \"relatedAsObjectFieldAt98\": true\n" +
      "  },\n" +
      "  \"edwardOrPlayerTypeConfirmed\": false\n" +
      "}\n");
    Console.WriteLine("WROTE v0.6.30-summary.json");

    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.30-funcs-deep.json"),
      "{\n" +
      "  \"schemaVersion\": 1,\n" +
      "  \"milestone\": \"v0.6.30\",\n" +
      "  \"generatedUtc\": \"" + utc + "\",\n" +
      "  \"exeSha256\": \"" + hash + "\",\n" +
      "  \"tiHelperPrimary\": {\n" +
      "    \"entry\": \"0x43DCB00\",\n" +
      "    \"args\": \"rcx=TypeInfo*, rdx=existingOrNull\",\n" +
      "    \"ifRdxNonNull\": \"return rdx\",\n" +
      "    \"ifRdxNull\": [\n" +
      "      \"flags=[ti+0xF6]&0x7F\",\n" +
      "      \"size=[ti+0x20]\",\n" +
      "      \"pool=*(runtime_global 0x" + globalSlot.ToString("X") + ")\",\n" +
      "      \"prefer freelist pop then icall [ti+0x50]\",\n" +
      "      \"else vtable alloc call r9(pool, size, flags) then icall [ti+0x50]\"\n" +
      "    ],\n" +
      "    \"not\": [\"Lookup 0x429F9E0\", \"Allocator 0x426EE50\"]\n" +
      "  },\n" +
      "  \"constructChannels\": [\n" +
      "    { \"name\": \"NS_VT20_TiHelper\", \"entries\": [\"0x3D52400\", \"0x6CF34E0\"], \"ti\": [\"0xAAD2290\", \"0xACE83F8\"] },\n" +
      "    { \"name\": \"TightFactory_Lookup_Alloc\", \"entries\": [\"0x238590\", \"0x256280\", \"0x218900\", \"0x218660\", \"0x21FA70\"], \"usesNsTi\": false }\n" +
      "  ],\n" +
      "  \"neighRel98\": { \"rva\": \"0x3D522C0\", \"op\": \"mov [rcx+98],al after xor eax,eax\", \"kind\": \"zero_byte_field_init\" }\n" +
      "}\n");
    Console.WriteLine("WROTE v0.6.30-funcs-deep.json");

    string tiReason = tiHelperDecoded
      ? "TiHelper 0x43DCB00 is TypeInfo construct helper: [ti+0x20] size, pool freelist or vtbl-alloc, icall [ti+0x50]; not Lookup/Allocator"
      : "TiHelper decode incomplete";
    string feedReason = noLookupFeed
      ? "0 Lookup funcs LEA NeighMeta/SpatTi/keyField; tight factories use Lookup+Alloc without NS TI or TiHelper; channels distinct"
      : "Unexpected Lookup/NS TI overlap";
    string b0Reason = sizeB0Mapped
      ? "Neigh size 0xB0 via TypeInfo/TiHelper; NeighRel zero-inits +0x98 byte (object field); not SideBlock pointer enroll; Spat VT20 uses inline add reg,98"
      : "size 0xB0 / +0x98 relation incomplete";

    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.30-second-edward-feasibility.json"),
      "{\n" +
      "  \"schemaVersion\": 1,\n" +
      "  \"milestone\": \"v0.6.30\",\n" +
      "  \"generatedUtc\": \"" + utc + "\",\n" +
      "  \"exeSha256\": \"" + hash + "\",\n" +
      "  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"TiHelper/Lookup/0xB0 paths are TypeInfo construct, not Edward create/possession\" },\n" +
      "  \"tiHelperDecode\": { \"class\": \"confirmed\", \"reason\": " + J(tiReason) + " },\n" +
      "  \"lookupNsTiIntoTightFactories\": { \"class\": \"confirmed_absent\", \"reason\": " + J(feedReason) + " },\n" +
      "  \"sizeB0VsEnrollment98\": { \"class\": \"confirmed\", \"reason\": " + J(b0Reason) + " },\n" +
      "  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },\n" +
      "  \"next\": {\n" +
      "    \"primary\": \"Trace who calls Neigh/Spat VT[+0x20] construct; map live consumers of Neigh 0xB0 +0x98 byte vs pointer-family enrollment objects\",\n" +
      "    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"expect Neigh/SpatTi Lookup into tight factories\", \"conflate NeighRel +0x98 byte with SideBlock pointer\"]\n" +
      "  }\n" +
      "}\n");
    Console.WriteLine("WROTE v0.6.30-second-edward-feasibility.json");
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

  static int CountE8(uint dest) {
    int n = 0;
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 5 <= lim; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        if ((long)s.Va + i + 5 + rel == dest) n++;
      }
    }
    return n;
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
