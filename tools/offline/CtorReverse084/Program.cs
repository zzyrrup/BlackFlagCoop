// v0.6.24 — Offline: reverse InstallerA / outer ctor 0x59D9660 into create/use sites;
// who owns objects that neighbor / 0x1D25E20 transform-copy.
// Note Lookup+Alloc candidates 0x1B6AFF0, 0x26D28E0, 0x2F2C1A0 if on reverse path.
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
  const uint OuterCtor = 0x59D9660;
  const uint InstallerA = 0x5F11A40;
  const uint InstallerB = 0x59D96A0;
  const uint Lookup = 0x429F9E0;
  const uint Allocator = 0x426EE50;
  const uint LookupKey = 0xB2898C8;
  const uint SizeField = 0xB2898E8;
  const uint CtorField = 0xB289918;
  const uint Neighbor = 0x2335140;
  const uint Spatial = 0x1D25E20;
  const uint Helper546 = 0x546D150;
  const uint ActivNotify = 0x2335040;
  static readonly uint[] LookupAllocCands = { 0x1B6AFF0, 0x26D28E0, 0x2F2C1A0 };
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
    public long Disp; public int Length; public uint NearTarget;
    public bool IsRet; public ulong Imm; public bool HasImm;
  }
  sealed class SiteRep {
    public uint Entry; public string Role;
    public bool UsesKey, CallsLookup, CallsAlloc, CallsOuter, CallsInstallerA;
    public bool CallsNeighbor, CallsSpatial, CallsHelper, CallsFactory;
    public bool HitsLookupAllocCand, Vcall2B0, BlockCopy;
    public List<uint> Callees = new List<uint>();
    public List<uint> CandHits = new List<uint>();
    public List<string> Notes = new List<string>();
    public List<string> Disasm = new List<string>();
    public List<string> Strings = new List<string>();
    public int Size;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v084-raw");
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
    sb.AppendLine("===== v0.6.24 CTOR REVERSE + TRANSFORM OWNERSHIP =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("note: v0.6.23 closed key-tied tight-factory feed (honest negative)");

    // ---- 1) Outer ctor 0x59D9660 reverse ----
    sb.AppendLine();
    sb.AppendLine("===== OUTER CTOR 0x59D9660 REFS =====");
    var outerE8 = FindE8(OuterCtor, 120);
    var outerLea = FindLeaTo(OuterCtor, 80);
    sb.AppendLine("E8->OuterCtor count=" + outerE8.Count);
    sb.AppendLine("LEA->OuterCtor count=" + outerLea.Count);
    foreach (var s in outerE8.Take(20))
      sb.AppendLine("  E8 @0x" + s.ToString("X") + " fromFunc=0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in outerLea.Take(20))
      sb.AppendLine("  LEA @0x" + s.ToString("X") + " fromFunc=0x" + FindFuncStart(s).ToString("X"));

    // Ctor field writers/readers
    sb.AppendLine();
    sb.AppendLine("===== CTOR FIELD 0xB289918 / SIZE 0xB2898E8 REFS =====");
    var ctorFieldLea = FindLeaTo(CtorField, 40);
    var sizeFieldLea = FindLeaTo(SizeField, 40);
    sb.AppendLine("LEA->CtorField=" + ctorFieldLea.Count + " LEA->SizeField=" + sizeFieldLea.Count);
    foreach (var s in ctorFieldLea)
      sb.AppendLine("  CTORFLD LEA @0x" + s.ToString("X") + " func=0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in sizeFieldLea)
      sb.AppendLine("  SIZEFLD LEA @0x" + s.ToString("X") + " func=0x" + FindFuncStart(s).ToString("X"));

    // InstallerA callers
    sb.AppendLine();
    sb.AppendLine("===== INSTALLERA 0x5F11A40 =====");
    var instAE8 = FindE8(InstallerA, 80);
    var instALea = FindLeaTo(InstallerA, 40);
    sb.AppendLine("E8->InstallerA=" + instAE8.Count + " LEA->InstallerA=" + instALea.Count);
    foreach (var s in instAE8.Take(15))
      sb.AppendLine("  E8 @0x" + s.ToString("X") + " func=0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in instALea.Take(15))
      sb.AppendLine("  LEA @0x" + s.ToString("X") + " func=0x" + FindFuncStart(s).ToString("X"));

    // Deep-decode outer ctor body + InstallerA registration window
    sb.AppendLine();
    sb.AppendLine("===== DEEP OUTER CTOR BODY =====");
    DeepDump(sb, OuterCtor, OuterCtor + 0x200, "outer-ctor");

    sb.AppendLine();
    sb.AppendLine("===== DEEP INSTALLERA (registration window) =====");
    // Registration was around 0x5F148DA — may be same/near InstallerA
    DeepDump(sb, InstallerA, InstallerA + 0x180, "installerA-head");
    // Also dump the known registration RVA region
    DeepDump(sb, 0x5F148C0, 0x5F14940, "installerA-reg-window");

    // Collect create/use candidate funcs: callers of outer, LEA of outer, InstallerA callers
    var createFuncs = new HashSet<uint>();
    foreach (var s in outerE8) createFuncs.Add(FindFuncStart(s));
    foreach (var s in outerLea) createFuncs.Add(FindFuncStart(s));
    foreach (var s in instAE8) createFuncs.Add(FindFuncStart(s));
    // Plus Lookup+Alloc candidates themselves
    foreach (var c in LookupAllocCands) createFuncs.Add(c);

    sb.AppendLine();
    sb.AppendLine("===== CREATE/USE CANDIDATE FUNCS =====");
    sb.AppendLine("unique=" + createFuncs.Count);
    var createReps = new List<SiteRep>();
    int decoded = 0;
    foreach (uint fs in createFuncs.OrderBy(x => x)) {
      bool isCand = LookupAllocCands.Contains(fs);
      bool isOuterSelf = fs == OuterCtor || fs == InstallerA || fs == InstallerB;
      if (decoded >= 24 && !isCand && !isOuterSelf) {
        sb.AppendLine("  (skip remaining non-priority func 0x" + fs.ToString("X") + ")");
        continue;
      }
      var rep = AnalyzeFunc(sb, fs, isCand ? "lookup-alloc-cand"
        : (fs == OuterCtor ? "outer-ctor" : (fs == InstallerA ? "installerA" : "ctor-reverse")));
      createReps.Add(rep);
      if (!isCand && !isOuterSelf) decoded++;
    }

    // Cross: do Lookup+Alloc cands appear?
    sb.AppendLine();
    sb.AppendLine("===== LOOKUP+ALLOC CANDIDATES ON REVERSE PATH =====");
    foreach (uint c in LookupAllocCands) {
      bool asCreate = createFuncs.Contains(c);
      bool calledFromCreate = createReps.Any(r => r.Callees.Contains(c));
      bool callsOuter = createReps.Any(r => r.Entry == c && r.CallsOuter);
      sb.AppendLine("  CAND 0x" + c.ToString("X")
        + " inCreateSet=" + asCreate
        + " calledFromCreateRep=" + calledFromCreate
        + " itselfCallsOuter=" + callsOuter);
      // Also check E8 to cand from outer/installer neighborhood
      var e8c = FindE8(c, 40);
      sb.AppendLine("    E8->cand count=" + e8c.Count);
      foreach (var s in e8c.Take(8))
        sb.AppendLine("      site@0x" + s.ToString("X") + " func=0x" + FindFuncStart(s).ToString("X"));
    }

    // ---- 2) Ownership: Neighbor/Spatial are .edata vtable slots (no E8) ----
    sb.AppendLine();
    sb.AppendLine("===== NEIGHBOR / SPATIAL .edata OWNERSHIP =====");
    var neighQ = FindQwordEmbed(Neighbor, 20);
    var spatQ = FindQwordEmbed(Spatial, 20);
    var activQ = FindQwordEmbed(ActivNotify, 20);
    var instAQ = FindQwordEmbed(InstallerA, 20);
    sb.AppendLine("QWORD Neighbor embeds=" + neighQ.Count);
    foreach (var s in neighQ) sb.AppendLine("  slot @0x" + s.ToString("X") + " sec=" + SecName(s));
    sb.AppendLine("QWORD Spatial embeds=" + spatQ.Count);
    foreach (var s in spatQ) sb.AppendLine("  slot @0x" + s.ToString("X") + " sec=" + SecName(s));
    sb.AppendLine("QWORD Activ embeds=" + activQ.Count);
    foreach (var s in activQ) sb.AppendLine("  slot @0x" + s.ToString("X") + " sec=" + SecName(s));
    sb.AppendLine("QWORD InstallerA embeds=" + instAQ.Count);
    foreach (var s in instAQ) sb.AppendLine("  slot @0x" + s.ToString("X") + " sec=" + SecName(s));

    // Known slots from census
    uint neighSlot = neighQ.Count > 0 ? neighQ[0] : 0x976B3E0;
    uint spatSlot = spatQ.Count > 0 ? spatQ[0] : 0x9236E58;
    sb.AppendLine("neighborSlot=0x" + neighSlot.ToString("X") + " spatialSlot=0x" + spatSlot.ToString("X"));

    // Dump local table context
    sb.AppendLine();
    sb.AppendLine("===== VTABLE CONTEXT =====");
    DumpQwordTable(sb, neighSlot > 0x80 ? neighSlot - 0x80 : neighSlot, 36, "near-neighbor");
    DumpQwordTable(sb, spatSlot > 0x40 ? spatSlot - 0x40 : spatSlot, 20, "near-spatial");

    // LEA installers of table bases in windows around slots
    var ownerReps = new List<SiteRep>();
    var ownerFuncs = new HashSet<uint>();
    sb.AppendLine();
    sb.AppendLine("===== TABLE-BASE LEA INSTALLERS (ownership) =====");
    CollectTableInstallers(sb, ownerFuncs, neighSlot - 0x200, neighSlot + 0x200, "neighbor-table");
    CollectTableInstallers(sb, ownerFuncs, spatSlot - 0x200, spatSlot + 0x200, "spatial-table");
    // Priority seeds from prior probe
    foreach (uint seed in new uint[] {
      0x13612B0, 0x3D522C0, 0x3D526D0, 0x8D74E90, 0x8D75360,
      0x5563CF0, 0x5781490, 0x6CF34A0, 0x6CF36A0, 0x3962500, 0x3967190
    }) ownerFuncs.Add(seed);

    sb.AppendLine("uniqueOwnerInstallerFuncs=" + ownerFuncs.Count);
    int od = 0;
    foreach (uint fs in ownerFuncs.OrderBy(x => x)) {
      if (od >= 18) {
        sb.AppendLine("  (capped remaining owner 0x" + fs.ToString("X") + ")");
        continue;
      }
      var rep = AnalyzeFunc(sb, fs, "vtable-installer");
      // Note if func LEAs near neighbor/spatial slots
      uint fe = FindFuncEnd(fs, 0x800);
      if (fe <= fs) fe = fs + 0x200;
      foreach (var ins in DisasmRaw(fs, Math.Min(fe, fs + 0x400))) {
        if (!ins.IpRel) continue;
        if (ins.DataRva >= neighSlot - 0x200 && ins.DataRva <= neighSlot + 0x200)
          rep.Notes.Add("LEA_NEIGH_TABLE ->0x" + ins.DataRva.ToString("X")
            + " off=" + ((int)neighSlot - (int)ins.DataRva).ToString("X"));
        if (ins.DataRva >= spatSlot - 0x200 && ins.DataRva <= spatSlot + 0x200)
          rep.Notes.Add("LEA_SPAT_TABLE ->0x" + ins.DataRva.ToString("X")
            + " off=" + ((int)spatSlot - (int)ins.DataRva).ToString("X"));
      }
      ownerReps.Add(rep);
      od++;
    }

    sb.AppendLine();
    sb.AppendLine("===== DEEP NEIGHBOR / SPATIAL (this=rcx owner object) =====");
    DeepDump(sb, Neighbor, Neighbor + 0x1C0, "neighbor");
    DeepDump(sb, Spatial, Spatial + 0x100, "spatial-head");
    // Sibling edx=2 method at neighSlot+0x18 = 0x23352D0 (from table dump)
    DeepDump(sb, 0x23352D0, 0x2335360, "neighbor-sibling-edx2");

    // Cross
    sb.AppendLine();
    sb.AppendLine("===== CROSS =====");
    // Honest cand-on-path: only if cand calls Outer OR InstallerA calls/refs cand OR cand LEAs ctor field
    foreach (var r in createReps) {
      foreach (var c in r.Callees)
        if (LookupAllocCands.Contains(c)) { r.HitsLookupAllocCand = true; r.CandHits.Add(c); }
    }
    bool candCallsOuter = createReps.Any(r => LookupAllocCands.Contains(r.Entry) && r.CallsOuter);
    bool installerTouchesCand = createReps.Any(r => r.Entry == InstallerA && r.HitsLookupAllocCand);
    bool candOnPath = candCallsOuter || installerTouchesCand;
    sb.AppendLine("outerCtorE8=" + outerE8.Count + " outerCtorLea=" + outerLea.Count);
    sb.AppendLine("installerA_E8=" + instAE8.Count + " installerA_QWORD=" + instAQ.Count);
    sb.AppendLine("createFuncsDecoded=" + createReps.Count);
    sb.AppendLine("lookupAllocCandCallsOuter=" + candCallsOuter);
    sb.AppendLine("installerTouchesCand=" + installerTouchesCand);
    sb.AppendLine("lookupAllocCandOnReversePath=" + candOnPath
      + " (cands analyzed separately; key+Lookup+Alloc but not Outer feed)");
    sb.AppendLine("neighborQword=" + neighQ.Count + " spatialQword=" + spatQ.Count);
    sb.AppendLine("ownerInstallersDecoded=" + ownerReps.Count);
    sb.AppendLine("ownerWithKey=" + ownerReps.Count(r => r.UsesKey));
    sb.AppendLine("ownerWithOuter=" + ownerReps.Count(r => r.CallsOuter));
    sb.AppendLine("ownerWithFactory=" + ownerReps.Count(r => r.CallsFactory));
    sb.AppendLine("ownerWithV2B0=" + ownerReps.Count(r => r.Vcall2B0));

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteJson(hash, outerE8, outerLea, createReps, ownerReps, candOnPath, instAE8.Count,
      neighQ.Count, spatQ.Count, neighSlot, spatSlot);

    bool ok = (outerLea.Count > 0 || outerE8.Count > 0) && ownerReps.Count > 0 && neighQ.Count > 0;
    Console.WriteLine("selfCheck outerLea=" + outerLea.Count
      + " createDecoded=" + createReps.Count
      + " owners=" + ownerReps.Count
      + " neighQ=" + neighQ.Count
      + " candOnPath=" + candOnPath
      + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static void CollectTableInstallers(StringBuilder sb, HashSet<uint> funcs, uint lo, uint hi, string tag) {
    int hits = 0;
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim && hits < 60; i++) {
        int off = 0;
        byte b0 = pe[s.Ptr + i];
        if (b0 == 0x48 || b0 == 0x4C || b0 == 0x49 || b0 == 0x4D) off = 1;
        if (pe[s.Ptr + i + off] != 0x8D) continue;
        byte modrm = pe[s.Ptr + i + off + 1];
        if ((modrm & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + off + 2));
        uint site = s.Va + i;
        uint len = (uint)(off + 6);
        uint tgt = unchecked((uint)(site + len + disp));
        if (tgt < lo || tgt >= hi || (tgt & 7) != 0) continue;
        uint fs = FindFuncStart(site);
        if (funcs.Add(fs)) {
          sb.AppendLine("  " + tag + " LEA @0x" + site.ToString("X")
            + " -> 0x" + tgt.ToString("X") + " func=0x" + fs.ToString("X"));
        }
        hits++;
      }
    }
  }

  static void DumpQwordTable(StringBuilder sb, uint start, int count, string title) {
    sb.AppendLine("--- " + title + " @0x" + start.ToString("X") + " ---");
    int fo = RvaToFile(start);
    if (fo < 0) { sb.AppendLine("UNMAPPED"); return; }
    for (int i = 0; i < count; i++) {
      uint rva = start + (uint)(i * 8);
      ulong q = BitConverter.ToUInt64(pe, fo + i * 8);
      string mark = "";
      if (q >= imageBase) {
        uint t = (uint)(q - imageBase);
        if (t == Neighbor) mark = " *** NEIGHBOR ***";
        if (t == Spatial) mark = " *** SPATIAL ***";
        if (t == ActivNotify) mark = " *** ACTIV ***";
        if (t == 0x23352D0) mark = " *** NEIGH_EDX2 ***";
        if (RvaToFile(t) >= 0)
          sb.AppendLine("  +0x" + (i * 8).ToString("X") + " slot=0x" + rva.ToString("X")
            + " rva=0x" + t.ToString("X") + mark);
        else
          sb.AppendLine("  +0x" + (i * 8).ToString("X") + " slot=0x" + rva.ToString("X")
            + " va=0x" + q.ToString("X"));
      } else {
        sb.AppendLine("  +0x" + (i * 8).ToString("X") + " slot=0x" + rva.ToString("X")
          + " raw=0x" + q.ToString("X"));
      }
    }
  }

  static List<uint> FindQwordEmbed(uint rva, int max) {
    var list = new List<uint>();
    ulong va = imageBase + rva;
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

  static SiteRep AnalyzeFunc(StringBuilder sb, uint entry, string role) {
    var r = new SiteRep { Entry = entry, Role = role };
    uint fe = FindFuncEnd(entry, 0x1800);
    if (fe <= entry) fe = entry + 0x300;
    if (fe - entry > 0x2500) fe = entry + 0x2500;
    r.Size = (int)(fe - entry);
    sb.AppendLine();
    sb.AppendLine("===== FUNC 0x" + entry.ToString("X") + " (" + role + ") size=" + r.Size
      + " sec=" + SecName(entry) + " =====");
    var body = DisasmRaw(entry, fe);
    int head = 0;
    foreach (var i in body) {
      if (head++ < 50) {
        string mark = Mark(i);
        r.Disasm.Add("0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 88) + mark);
      }
      if (i.IpRel && i.DataRva == LookupKey) { r.UsesKey = true; r.Notes.Add("KEY @0x" + i.Rva.ToString("X")); }
      if (i.IpRel && (i.DataRva == CtorField || i.DataRva == SizeField))
        r.Notes.Add("FIELD @" + i.DataRva.ToString("X") + " @0x" + i.Rva.ToString("X"));
      if (i.HasMem && !i.IpRel && i.Disp == 0x2B0) r.Vcall2B0 = true;
      if (i.IsIndirectCall && (i.Disp == 0x2B0 || i.Text.Contains("+2B0"))) r.Vcall2B0 = true;
      if (i.Mnemonic == Mnemonic.Vmovups || i.Text.Contains("vmovups") || i.Text.Contains("movaps"))
        r.BlockCopy = true;
      if (i.IsCall && !i.IsIndirectCall) {
        r.Callees.Add(i.NearTarget);
        if (i.NearTarget == Lookup) { r.CallsLookup = true; r.Notes.Add("LOOKUP @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Allocator) { r.CallsAlloc = true; r.Notes.Add("ALLOC @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == OuterCtor) { r.CallsOuter = true; r.Notes.Add("OUTER @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == InstallerA) { r.CallsInstallerA = true; r.Notes.Add("INSTALLERA @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Neighbor) { r.CallsNeighbor = true; r.Notes.Add("NEIGHBOR @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Spatial) { r.CallsSpatial = true; r.Notes.Add("SPATIAL @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Helper546) { r.CallsHelper = true; r.Notes.Add("HELPER @0x" + i.Rva.ToString("X")); }
        if (TightFactories.Contains(i.NearTarget)) {
          r.CallsFactory = true;
          r.Notes.Add("FACTORY 0x" + i.NearTarget.ToString("X") + " @0x" + i.Rva.ToString("X"));
        }
        if (LookupAllocCands.Contains(i.NearTarget)) {
          r.HitsLookupAllocCand = true;
          r.CandHits.Add(i.NearTarget);
          r.Notes.Add("LOOKUP_ALLOC_CAND 0x" + i.NearTarget.ToString("X") + " @0x" + i.Rva.ToString("X"));
        }
      }
      if (i.IpRel) {
        string s = ReadAscii(i.DataRva, 48);
        if (IsString(s) && s.Length >= 5 && !r.Strings.Contains(s)) r.Strings.Add(s);
      }
    }
    if (LookupAllocCands.Contains(entry)) {
      r.HitsLookupAllocCand = true;
      r.CandHits.Add(entry);
    }
    sb.AppendLine("key=" + r.UsesKey + " lookup=" + r.CallsLookup + " alloc=" + r.CallsAlloc
      + " outer=" + r.CallsOuter + " factory=" + r.CallsFactory
      + " neigh=" + r.CallsNeighbor + " spat=" + r.CallsSpatial
      + " helper=" + r.CallsHelper + " v2B0=" + r.Vcall2B0
      + " cand=" + r.HitsLookupAllocCand
      + " callees=" + r.Callees.Distinct().Count());
    foreach (var n in r.Notes.Take(14)) sb.AppendLine("  " + n);
    foreach (var s in r.Strings.Take(5)) sb.AppendLine("  str \"" + Trunc(s, 55) + "\"");
    foreach (var c in r.Callees.Distinct().Take(14)) {
      string mark = c == OuterCtor ? " *** OUTER ***"
        : c == InstallerA ? " *** INSTALLERA ***"
        : LookupAllocCands.Contains(c) ? " *** CAND ***"
        : TightFactories.Contains(c) ? " *** FACTORY ***"
        : c == Neighbor ? " *** NEIGHBOR ***"
        : c == Spatial ? " *** SPATIAL ***" : "";
      sb.AppendLine("  callee 0x" + c.ToString("X") + mark);
    }
    sb.AppendLine("--- head ---");
    foreach (var line in r.Disasm.Take(35)) sb.AppendLine(line);
    return r;
  }

  static string Mark(Ins i) {
    string mark = "";
    if (i.NearTarget == OuterCtor) mark = " *** OUTER ***";
    if (i.NearTarget == InstallerA) mark = " *** INSTALLERA ***";
    if (i.NearTarget == Lookup) mark = " *** LOOKUP ***";
    if (i.NearTarget == Allocator) mark = " *** ALLOC ***";
    if (i.NearTarget == Neighbor) mark = " *** NEIGHBOR ***";
    if (i.NearTarget == Spatial) mark = " *** SPATIAL ***";
    if (i.NearTarget == Helper546) mark = " *** HELPER ***";
    if (TightFactories.Contains(i.NearTarget)) mark = " *** FACTORY ***";
    if (LookupAllocCands.Contains(i.NearTarget)) mark = " *** CAND ***";
    if (i.IpRel && i.DataRva == LookupKey) mark += " *** KEY ***";
    if (i.IpRel && i.DataRva == CtorField) mark += " *** CTORFLD ***";
    if (i.IpRel && i.DataRva == SizeField) mark += " *** SIZEFLD ***";
    if (i.IsIndirectCall) mark += " *** ICALL ***";
    if (i.HasMem && !i.IpRel && i.Disp == 0x2B0) mark += " *** +2B0 ***";
    return mark;
  }

  static void DeepDump(StringBuilder sb, uint a, uint b, string title) {
    sb.AppendLine("--- " + title + " 0x" + a.ToString("X") + "..0x" + b.ToString("X") + " ---");
    foreach (var ins in DisasmRaw(a, b).Take(80))
      sb.AppendLine("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 90) + Mark(ins));
  }

  static void WriteJson(string hash, List<uint> outerE8, List<uint> outerLea,
      List<SiteRep> create, List<SiteRep> owners, bool candOnPath, int instACallers,
      int neighQ, int spatQ, uint neighSlot, uint spatSlot) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.24\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"ctorReverse\": {");
    sb.AppendLine("    \"outerE8\": " + outerE8.Count + ",");
    sb.AppendLine("    \"outerLea\": " + outerLea.Count + ",");
    sb.AppendLine("    \"installerADirectE8\": " + instACallers + ",");
    sb.AppendLine("    \"createFuncsDecoded\": " + create.Count + ",");
    sb.AppendLine("    \"lookupAllocCandOnPath\": " + T(candOnPath) + ",");
    sb.AppendLine("    \"lookupAllocCandsAnalyzed\": [\"0x1B6AFF0\", \"0x26D28E0\", \"0x2F2C1A0\"],");
    sb.AppendLine("    \"candHits\": [" + string.Join(", ",
      create.SelectMany(c => c.CandHits).Distinct().Select(x => "\"0x" + x.ToString("X") + "\"")) + "]");
    sb.AppendLine("  },");
    sb.AppendLine("  \"ownership\": {");
    sb.AppendLine("    \"neighborEdataSlot\": \"0x" + neighSlot.ToString("X") + "\",");
    sb.AppendLine("    \"spatialEdataSlot\": \"0x" + spatSlot.ToString("X") + "\",");
    sb.AppendLine("    \"neighborQwordEmbeds\": " + neighQ + ",");
    sb.AppendLine("    \"spatialQwordEmbeds\": " + spatQ + ",");
    sb.AppendLine("    \"ownerInstallerFuncsDecoded\": " + owners.Count + ",");
    sb.AppendLine("    \"withV2B0\": " + owners.Count(o => o.Vcall2B0) + ",");
    sb.AppendLine("    \"withKey\": " + owners.Count(o => o.UsesKey) + ",");
    sb.AppendLine("    \"withFactory\": " + owners.Count(o => o.CallsFactory) + ",");
    sb.AppendLine("    \"withOuter\": " + owners.Count(o => o.CallsOuter));
    sb.AppendLine("  },");
    sb.AppendLine("  \"priorNote\": \"v0.6.23 closed key-tied tight-factory feed\",");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.24-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.24-summary.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.24\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createUse\": [");
    for (int i = 0; i < create.Count; i++) {
      EmitRep(sb, create[i], i + 1 < create.Count);
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"owners\": [");
    for (int i = 0; i < owners.Count; i++) {
      EmitRep(sb, owners[i], i + 1 < owners.Count);
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.24-funcs-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.24-funcs-deep.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.24\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Outer ctor reverse and transform ownership do not prove Edward create/possession\" },");
    string cClass = outerLea.Count > 0 ? "confirmed" : "unsupported";
    sb.AppendLine("  \"outerCtorReverse\": { \"class\": \"" + cClass + "\", \"reason\": "
      + J("Outer ctor has 0 E8 callers; only InstallerA LEA-registers it into TypeInfo ctor field; create is icall [ti+0x50]. lookupAllocCandOnPath="
        + candOnPath) + " },");
    sb.AppendLine("  \"transformOwnership\": { \"class\": \"partial\", \"reason\": "
      + J("Neighbor/Spatial are .edata vtable methods (no E8); decoded " + owners.Count
        + " table-base installers; this=rcx owner type not named") + " },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Deep-decode strongest neighbor/spatial vtable installers; follow who constructs objects that receive those vtables\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\", \"field-offset 0x20F0 as heap size\", \"treat helper position extract as possession\", \"assume key-tied tight-factory feed\", \"expect E8 to outer ctor\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.24-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.24-second-edward-feasibility.json");
  }

  static void EmitRep(StringBuilder sb, SiteRep r, bool comma) {
    sb.AppendLine("    {");
    sb.AppendLine("      \"entry\": \"0x" + r.Entry.ToString("X") + "\",");
    sb.AppendLine("      \"role\": " + J(r.Role) + ",");
    sb.AppendLine("      \"size\": " + r.Size + ",");
    sb.AppendLine("      \"usesKey\": " + T(r.UsesKey) + ",");
    sb.AppendLine("      \"callsLookup\": " + T(r.CallsLookup) + ",");
    sb.AppendLine("      \"callsAlloc\": " + T(r.CallsAlloc) + ",");
    sb.AppendLine("      \"callsOuter\": " + T(r.CallsOuter) + ",");
    sb.AppendLine("      \"callsFactory\": " + T(r.CallsFactory) + ",");
    sb.AppendLine("      \"hitsLookupAllocCand\": " + T(r.HitsLookupAllocCand) + ",");
    sb.AppendLine("      \"vcall2B0\": " + T(r.Vcall2B0) + ",");
    sb.AppendLine("      \"notes\": [" + string.Join(", ", r.Notes.Take(16).Select(J)) + "],");
    sb.AppendLine("      \"callees\": [" + string.Join(", ",
      r.Callees.Distinct().Take(16).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("      \"candHits\": [" + string.Join(", ",
      r.CandHits.Distinct().Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", r.Disasm.Take(30).Select(J)) + "]");
    sb.Append("    }");
    sb.AppendLine(comma ? "," : "");
  }

  static string T(bool b) => b ? "true" : "false";
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
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
        var kind = raw.GetOpKind(oi);
        if (kind == OpKind.Immediate8 || kind == OpKind.Immediate8to16 || kind == OpKind.Immediate8to32
            || kind == OpKind.Immediate8to64 || kind == OpKind.Immediate16 || kind == OpKind.Immediate32
            || kind == OpKind.Immediate32to64 || kind == OpKind.Immediate64) {
          ins.HasImm = true;
          try { ins.Imm = raw.GetImmediate(oi); } catch { }
        }
        if (kind != OpKind.Memory) continue;
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

  static uint FindFuncEnd(uint entry, int maxScan) {
    var list = DisasmRaw(entry, entry + (uint)maxScan);
    foreach (var ins in list) {
      if (ins.Mnemonic == Mnemonic.Int3) return ins.Rva;
      if (ins.Mnemonic == Mnemonic.Ret) {
        uint next = ins.Rva + (uint)ins.Length;
        int fo = RvaToFile(next);
        if (fo >= 0 && fo < pe.Length && pe[fo] == 0xCC) return next;
      }
    }
    return list.Count > 0 ? list[list.Count - 1].Rva + (uint)list[list.Count - 1].Length : entry;
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
        byte op = pe[s.Ptr + i + off];
        if (op != 0x8D) continue;
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
  static string SecName(uint rva) {
    foreach (var s in secs)
      if (rva >= s.Va && rva < s.Va + Math.Max(s.VSize, s.Raw)) return s.Name;
    return "?";
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
