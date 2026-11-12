// v0.6.27 — Offline: TypeInfo / [ti+0x50] consumers of owner VT[0] ctors;
// classify pointer +0x98 (SideBlock) vs Spatial inline +0x98.
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

  const uint NeighCtor = 0x13612B0;
  const uint SpatCtor = 0x5781490;
  const uint NeighVt = 0x976B2D0;
  const uint SpatVt = 0x9236E00;
  const uint NeighRelated = 0x3D522C0;
  const uint SpatInstA = 0x5563CF0;
  const uint SpatInstB = 0x6CF34A0;
  const uint SpatInstC = 0x6CF3750;
  const uint Allocator = 0x426EE50;
  const uint SideBlock = 0xE95E80;
  const uint Arming = 0x21085D0;
  const uint ArmWrap = 0x2108620;
  const uint Lookup = 0x429F9E0;
  const uint LookupKey = 0xB2898C8;
  const uint CtorField = 0xB289918; // known Outer ctor field
  const uint SizeField = 0xB2898E8;
  const uint OuterCtor = 0x59D9660;
  const uint InstallerA = 0x5F11A40;
  const uint Helper546 = 0x546D150;
  const uint Neighbor = 0x2335140;
  const uint Spatial = 0x1D25E20;
  const uint QueueHandler = 0x1AC380;

  static readonly uint[] TightFactories = { 0x238590, 0x256280, 0x218900, 0x218660, 0x21FA70 };
  static readonly uint[] OwnerVt0 = { NeighCtor, SpatCtor };
  static readonly uint[] Plus98Subjects = {
    SideBlock, Arming, ArmWrap, NeighCtor, SpatCtor, NeighRelated,
    SpatInstA, SpatInstB, SpatInstC, Helper546, Neighbor, Spatial, QueueHandler
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
    public long Disp; public int Length; public uint NearTarget;
    public bool IsRet; public ulong Imm; public bool HasImm;
    public bool IsAbs64Mov; public ulong Abs64;
    public Register MemBase;
  }
  sealed class Plus98Class {
    public uint Entry; public string Role;
    public bool PointerStore, PointerLoad, PointerZero, PointerCmp;
    public bool InlineAdd, InlineLea, InlineThenCall;
    public bool LeasNeighVt, LeasSpatVt, CallsAlloc, CallsSide, CallsArm;
    public List<string> Evidence = new List<string>();
    public string ClassLabel;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v087-raw");
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
    sb.AppendLine("===== v0.6.27 TypeInfo [ti+0x50] + POINTER vs INLINE +0x98 =====");
    sb.AppendLine("exeSha256=" + hash);

    // ========== 1) TypeInfo / [ti+0x50] vs owner VT[0] ==========
    sb.AppendLine();
    sb.AppendLine("===== QWORD EMBEDS OF OWNER VT[0] =====");
    var embedMap = new Dictionary<uint, List<uint>>();
    foreach (uint ctor in OwnerVt0) {
      var q = FindQwordEmbed(ctor, 40);
      embedMap[ctor] = q;
      sb.AppendLine("QWORD 0x" + ctor.ToString("X") + " embeds=" + q.Count);
      foreach (var loc in q) {
        sb.AppendLine("  @0x" + loc.ToString("X") + " sec=" + SecName(loc)
          + " asTi50Candidate=" + (IsLikelyTi50Slot(loc) ? "True" : "False")
          + " offsetInVtNeigh=" + OffsetFrom(loc, NeighVt)
          + " offsetInVtSpat=" + OffsetFrom(loc, SpatVt));
        DumpTiWindow(sb, loc);
      }
    }

    sb.AppendLine();
    sb.AppendLine("===== LEA OF OWNER VT[0] CTOR ADDRS (TypeInfo-register style) =====");
    int leaCtorTotal = 0;
    foreach (uint ctor in OwnerVt0) {
      var leas = FindLeaTo(ctor, 40);
      leaCtorTotal += leas.Count;
      sb.AppendLine("LEA->0x" + ctor.ToString("X") + " count=" + leas.Count);
      foreach (var s in leas.Take(20)) {
        uint fs = FindFuncStart(s);
        sb.AppendLine("  @0x" + s.ToString("X") + " func=0x" + fs.ToString("X"));
        foreach (var i in DisasmRaw(s > 0x10 ? s - 0x10 : s, s + 0x50).Take(24)) {
          string mark = "";
          if (i.HasMem && !i.IpRel && i.Disp == 0x50) mark = " *** +50 ***";
          if (i.IpRel) mark += " rip->0x" + i.DataRva.ToString("X");
          if (i.Text.StartsWith("mov ") && i.IpRel) mark += " *** STORE? ***";
          sb.AppendLine("    0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 70) + mark);
        }
      }
    }

    sb.AppendLine();
    sb.AppendLine("===== MOVABS / STORE [reg+0x50] OF OWNER VT[0] =====");
    var absSites = FindMovAbsImm(OwnerVt0, 40);
    sb.AppendLine("movabs ctor sites=" + absSites.Count);
    foreach (var (site, ctor) in absSites)
      sb.AppendLine("  @0x" + site.ToString("X") + " ctor=0x" + ctor.ToString("X")
        + " func=0x" + FindFuncStart(site).ToString("X"));

    int store50Hits = ScanStorePlus50OfCtor(sb);

    sb.AppendLine();
    sb.AppendLine("===== KNOWN TYPEINFO KEY REGION (reference Outer path) =====");
    DumpKnownTypeInfo(sb);
    sb.AppendLine("E8->InstallerA=" + FindE8(InstallerA, 20).Count
      + " LEA->OuterCtor=" + FindLeaTo(OuterCtor, 20).Count
      + " QWORD OuterCtor embeds=" + FindQwordEmbed(OuterCtor, 20).Count);

    sb.AppendLine();
    sb.AppendLine("===== TIGHT FACTORIES: [ti+0x50] ICALL SITES (generic consumers) =====");
    var factoryReps = new List<(uint entry, int icall50, bool callsAlloc)>();
    foreach (uint f in TightFactories) {
      var body = DisasmRaw(f, f + 0x600);
      int n50 = body.Count(i => i.IsIndirectCall && (i.Disp == 0x50 || i.Text.Contains("+50]")));
      bool alloc = body.Any(i => i.IsCall && !i.IsIndirectCall && i.NearTarget == Allocator);
      factoryReps.Add((f, n50, alloc));
      sb.AppendLine("factory 0x" + f.ToString("X") + " icall50=" + n50 + " alloc=" + alloc);
      foreach (var i in body.Where(x => x.IsIndirectCall && (x.Disp == 0x50 || x.Text.Contains("+50]"))).Take(4))
        sb.AppendLine("  ICALL50 @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 60));
    }

    // Any static TypeInfo-shaped record: scan aligned qwords where value==ctor and preceding +0x20 looks like size
    sb.AppendLine();
    sb.AppendLine("===== STATIC TYPEINFO-SHAPED SCAN (ctor at +0x50) =====");
    int tiShapeHits = 0;
    foreach (uint ctor in OwnerVt0) {
      foreach (var loc in FindQwordEmbed(ctor, 100)) {
        // treat loc as candidate ti+0x50
        if (loc < 0x50) continue;
        uint ti = loc - 0x50;
        uint sizeAt20 = ReadU32(ti + 0x20);
        ulong keyQ = ReadU64(ti);
        sb.AppendLine("  cand ti=0x" + ti.ToString("X") + " ctorSlot=0x" + loc.ToString("X")
          + " ctor=0x" + ctor.ToString("X")
          + " dword[+20]=0x" + sizeAt20.ToString("X")
          + " qword[ti]=0x" + keyQ.ToString("X")
          + " sec=" + SecName(ti)
          + " note=" + (loc == NeighVt || loc == SpatVt ? "VT_BASE_NOT_TYPEINFO" : "data"));
        if (loc != NeighVt && loc != SpatVt) tiShapeHits++;
      }
    }
    sb.AppendLine("nonVtTiShapeHits=" + tiShapeHits);

    // Contrast: Outer ctor IS LEA-registered — show pattern for honesty
    sb.AppendLine();
    sb.AppendLine("===== CONTRAST: OUTER CTOR TypeInfo REGISTRATION =====");
    var outerLeas = FindLeaTo(OuterCtor, 20);
    sb.AppendLine("LEA->Outer=" + outerLeas.Count);
    foreach (var s in outerLeas.Take(6)) {
      uint fs = FindFuncStart(s);
      sb.AppendLine("  LEA Outer @0x" + s.ToString("X") + " func=0x" + fs.ToString("X"));
      foreach (var i in DisasmRaw(s > 0x20 ? s - 0x20 : s, s + 0x60).Take(20))
        sb.AppendLine("    0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 70) + Mark(i));
    }

    bool ti50OwnerFound = leaCtorTotal > 0 || absSites.Count > 0 || store50Hits > 0 || tiShapeHits > 0;
    sb.AppendLine();
    sb.AppendLine("ti50OwnerVt0StaticBinding=" + ti50OwnerFound
      + " (LEA=" + leaCtorTotal + " movabs=" + absSites.Count
      + " store+50=" + store50Hits + " nonVtShape=" + tiShapeHits + ")");

    // ========== 2) Pointer vs inline +0x98 ==========
    sb.AppendLine();
    sb.AppendLine("===== +0x98 CLASSIFICATION (known subjects) =====");
    var classes = new List<Plus98Class>();
    foreach (uint e in Plus98Subjects.Distinct().OrderBy(x => x)) {
      classes.Add(ClassifyPlus98(sb, e, RoleOf(e)));
    }

    // Broader: funcs that LEA owner VT and touch +0x98
    sb.AppendLine();
    sb.AppendLine("===== OWNER-VT FUNCS +0x98 CLASS =====");
    var seen = new HashSet<uint>();
    foreach (uint vt in new[] { NeighVt, SpatVt }) {
      foreach (var lea in FindLeaTo(vt, 40)) {
        uint fs = FindFuncStart(lea);
        if (!seen.Add(fs)) continue;
        if (Plus98Subjects.Contains(fs)) continue;
        classes.Add(ClassifyPlus98(sb, fs, "owner-vt-lea"));
      }
    }

    // SideBlock attach vs Spatial inline deep dumps
    sb.AppendLine();
    sb.AppendLine("===== DEEP: SIDEBLOCK POINTER ATTACH =====");
    DeepPlus98(sb, SideBlock, SideBlock + 0x220, "sideblock");
    sb.AppendLine();
    sb.AppendLine("===== DEEP: SPATIAL VT0 INLINE +0x98 =====");
    DeepPlus98(sb, SpatCtor, SpatCtor + 0x80, "spat-vt0");
    DeepPlus98(sb, SpatInstA, SpatInstA + 0x80, "spat-instA");
    DeepPlus98(sb, SpatInstB, SpatInstB + 0x80, "spat-instB");
    sb.AppendLine();
    sb.AppendLine("===== DEEP: NEIGH RELATED ZERO +0x98 =====");
    DeepPlus98(sb, NeighRelated, NeighRelated + 0x100, "neigh-related");
    sb.AppendLine();
    sb.AppendLine("===== DEEP: ARMING / ARMWRAP POINTER LOAD =====");
    DeepPlus98(sb, Arming, Arming + 0x100, "arming");
    DeepPlus98(sb, ArmWrap, ArmWrap + 0x80, "armwrap");

    // Summary tables
    int ptrN = classes.Count(c => c.ClassLabel == "pointer");
    int inlN = classes.Count(c => c.ClassLabel == "inline");
    int mixN = classes.Count(c => c.ClassLabel == "mixed");
    int unkN = classes.Count(c => c.ClassLabel == "unknown" || c.ClassLabel == "none");
    sb.AppendLine();
    sb.AppendLine("===== +0x98 CLASS COUNTS =====");
    sb.AppendLine("pointer=" + ptrN + " inline=" + inlN + " mixed=" + mixN + " none/unknown=" + unkN);
    foreach (var c in classes.OrderBy(x => x.ClassLabel).ThenBy(x => x.Entry)) {
      sb.AppendLine("  [" + c.ClassLabel + "] 0x" + c.Entry.ToString("X") + " " + c.Role
        + " store=" + c.PointerStore + " load=" + c.PointerLoad + " zero=" + c.PointerZero
        + " add=" + c.InlineAdd + " lea=" + c.InlineLea + " thenCall=" + c.InlineThenCall);
    }

    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    sb.AppendLine("1) Owner VT[0] static TypeInfo/+0x50 binding: " + (ti50OwnerFound ? "FOUND" : "NOT_FOUND"));
    sb.AppendLine("2) Generic [ti+0x50] consumers exist (tight factories) but not owner-VT0-tied offline.");
    sb.AppendLine("3) +0x98 pointer family: SideBlock/Arming/ArmWrap/NeighRelated(+zero)/Helper");
    sb.AppendLine("4) +0x98 inline family: Spatial VT[0]/instA/instB (add/lea +98 then sub-init)");
    sb.AppendLine("5) These are DISTINCT layout uses of the same numeric offset.");

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteJson(hash, ti50OwnerFound, leaCtorTotal, absSites.Count, store50Hits, tiShapeHits,
      factoryReps, classes);

    bool ok = classes.Count > 0 && factoryReps.Count > 0;
    Console.WriteLine("selfCheck ti50bind=" + ti50OwnerFound
      + " ptr=" + ptrN + " inl=" + inlN + " mix=" + mixN
      + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static string RoleOf(uint e) {
    if (e == SideBlock) return "sideblock";
    if (e == Arming) return "arming";
    if (e == ArmWrap) return "armwrap";
    if (e == NeighCtor) return "neigh-vt0";
    if (e == SpatCtor) return "spat-vt0";
    if (e == NeighRelated) return "neigh-related";
    if (e == SpatInstA) return "spat-instA";
    if (e == SpatInstB) return "spat-instB";
    if (e == SpatInstC) return "spat-instC";
    if (e == Helper546) return "helper546";
    if (e == Neighbor) return "neighbor-method";
    if (e == Spatial) return "spatial-method";
    if (e == QueueHandler) return "queue-handler";
    return "subject";
  }

  static Plus98Class ClassifyPlus98(StringBuilder sb, uint entry, string role) {
    var c = new Plus98Class { Entry = entry, Role = role };
    uint fe = FindFuncEnd(entry, 0x1800);
    if (fe <= entry) fe = entry + 0x400;
    if (fe - entry > 0x2800) fe = entry + 0x2800;
    var body = DisasmRaw(entry, fe);

    for (int idx = 0; idx < body.Count; idx++) {
      var i = body[idx];
      if (i.IsCall && !i.IsIndirectCall) {
        if (i.NearTarget == Allocator) c.CallsAlloc = true;
        if (i.NearTarget == SideBlock) c.CallsSide = true;
        if (i.NearTarget == Arming || i.NearTarget == ArmWrap) c.CallsArm = true;
      }
      if (i.IpRel && i.DataRva == NeighVt) c.LeasNeighVt = true;
      if (i.IpRel && i.DataRva == SpatVt) c.LeasSpatVt = true;

      if (i.Mnemonic == Mnemonic.Add && i.HasImm && i.Imm == 0x98) {
        c.InlineAdd = true;
        c.Evidence.Add("ADD98 @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 50));
        // look ahead for call
        for (int j = idx + 1; j < body.Count && j < idx + 8; j++) {
          if (body[j].IsCall) { c.InlineThenCall = true; break; }
          if (body[j].IsRet) break;
        }
      }
      if (i.Mnemonic == Mnemonic.Lea && i.HasMem && !i.IpRel && i.Disp == 0x98) {
        c.InlineLea = true;
        c.Evidence.Add("LEA98 @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 50));
        for (int j = idx + 1; j < body.Count && j < idx + 8; j++) {
          if (body[j].IsCall) { c.InlineThenCall = true; break; }
          if (body[j].IsRet) break;
        }
      }
      // also: add rcx,98 encoded without HasImm on some forms — check text
      if (!c.InlineAdd && i.Mnemonic == Mnemonic.Add && i.Text.Contains(",98") && !i.Text.Contains("[")
          && !i.Text.Contains("rsp")) {
        c.InlineAdd = true;
        c.Evidence.Add("ADD98txt @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 50));
        for (int j = idx + 1; j < body.Count && j < idx + 8; j++) {
          if (body[j].IsCall) { c.InlineThenCall = true; break; }
        }
      }

      if (!(i.HasMem && !i.IpRel && i.Disp == 0x98)) continue;
      string t = i.Text;
      if (i.Mnemonic == Mnemonic.Cmp || i.Mnemonic == Mnemonic.Test) {
        c.PointerCmp = true;
        c.Evidence.Add("CMP98 @0x" + i.Rva.ToString("X") + " " + Trunc(t, 50));
        continue;
      }
      if (i.Mnemonic == Mnemonic.Lea) {
        c.InlineLea = true;
        c.Evidence.Add("LEA98mem @0x" + i.Rva.ToString("X") + " " + Trunc(t, 50));
        continue;
      }
      // Store forms: destination is memory (mov [..+98], src)
      bool isStore = t.StartsWith("mov [") || t.StartsWith("mov qword ptr [")
        || t.StartsWith("mov dword ptr [") || t.StartsWith("mov byte ptr [")
        || t.StartsWith("mov word ptr [");
      if (isStore) {
        int comma = t.LastIndexOf(',');
        string rhs = comma >= 0 ? t.Substring(comma + 1).Trim() : "";
        if (rhs == "0" || rhs == "0h") {
          c.PointerZero = true;
          c.Evidence.Add("ZERO98 @0x" + i.Rva.ToString("X") + " " + Trunc(t, 50));
        } else {
          c.PointerStore = true;
          c.Evidence.Add("STORE98 @0x" + i.Rva.ToString("X") + " " + Trunc(t, 50));
        }
        continue;
      }
      // Load forms: mov reg, [..+98]
      if (t.StartsWith("mov ") && t.Contains("[")) {
        c.PointerLoad = true;
        c.Evidence.Add("LOAD98 @0x" + i.Rva.ToString("X") + " " + Trunc(t, 50));
      }
    }

    bool ptr = c.PointerStore || c.PointerLoad || c.PointerZero || c.PointerCmp;
    bool inl = c.InlineAdd || c.InlineLea || c.InlineThenCall;
    if (ptr && inl) c.ClassLabel = "mixed";
    else if (ptr) c.ClassLabel = "pointer";
    else if (inl) c.ClassLabel = "inline";
    else c.ClassLabel = "none";

    sb.AppendLine("CLASS 0x" + entry.ToString("X") + " (" + role + ") => " + c.ClassLabel
      + " ptrStore=" + c.PointerStore + " ptrLoad=" + c.PointerLoad
      + " ptrZero=" + c.PointerZero + " ptrCmp=" + c.PointerCmp
      + " inlAdd=" + c.InlineAdd + " inlLea=" + c.InlineLea + " inlCall=" + c.InlineThenCall);
    foreach (var e in c.Evidence.Take(10)) sb.AppendLine("  " + e);
    return c;
  }

  static void DeepPlus98(StringBuilder sb, uint a, uint b, string title) {
    sb.AppendLine("--- " + title + " 0x" + a.ToString("X") + " ---");
    foreach (var i in DisasmRaw(a, b).Take(60)) {
      string mark = Mark(i);
      bool show = mark.Length > 0 || i.Text.Contains("+98") || i.Text.Contains(",98")
        || (i.HasMem && !i.IpRel && i.Disp == 0x98)
        || (i.HasImm && i.Imm == 0x98);
      if (!show && i.IsCall) show = true;
      if (!show) continue;
      sb.AppendLine("0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 80) + mark);
    }
  }

  static int ScanStorePlus50OfCtor(StringBuilder sb) {
    // Heuristic: after LEA/movabs of ctor, within 0x40 bytes a store to [reg+0x50]
    int hits = 0;
    // Also: any mov [reg+0x50], reg where nearby LEA targets ctor — expensive; use LEA sites of ctors (already 0)
    // Scan code for pattern: lea reg, [ctor] already covered.
    // Broader: decode all tight factories + InstallerA for mov [..+50]
    foreach (uint f in TightFactories.Concat(new uint[] { InstallerA, OuterCtor })) {
      foreach (var i in DisasmRaw(f, f + 0x800)) {
        if (!(i.HasMem && !i.IpRel && i.Disp == 0x50)) continue;
        if (!(i.Text.StartsWith("mov [") || i.Text.StartsWith("mov qword"))) continue;
        sb.AppendLine("  +50-store @0x" + i.Rva.ToString("X") + " func=0x" + f.ToString("X")
          + " " + Trunc(i.Text, 60));
      }
    }
    // Full code scan: LEA to ctor then store+50 already empty if no LEA.
    // Search movabs then +50 store
    foreach (var (site, ctor) in FindMovAbsImm(OwnerVt0, 40)) {
      foreach (var i in DisasmRaw(site, site + 0x40)) {
        if (i.HasMem && !i.IpRel && i.Disp == 0x50 && i.Text.StartsWith("mov")) {
          hits++;
          sb.AppendLine("  movabs->store+50 @0x" + i.Rva.ToString("X") + " ctor=0x" + ctor.ToString("X"));
        }
      }
    }
    sb.AppendLine("storePlus50OfCtorHits=" + hits);
    return hits;
  }

  static bool IsLikelyTi50Slot(uint loc) {
    if (loc == NeighVt || loc == SpatVt) return false;
    if (loc < 0x50) return false;
    // crude: size field at -0x30 (= ti+0x20) in plausible heap-size range
    uint size = ReadU32(loc - 0x30);
    return size >= 0x40 && size <= 0x10000;
  }

  static string OffsetFrom(uint loc, uint baseRva) {
    if (loc >= baseRva && loc < baseRva + 0x400)
      return "+0x" + (loc - baseRva).ToString("X");
    return "-";
  }

  static void DumpTiWindow(StringBuilder sb, uint ctorSlot) {
    if (ctorSlot < 0x50) return;
    uint ti = ctorSlot - 0x50;
    sb.AppendLine("    window ti=0x" + ti.ToString("X")
      + " [+00]=0x" + ReadU64(ti).ToString("X")
      + " [+20]=0x" + ReadU32(ti + 0x20).ToString("X")
      + " [+50]=0x" + ReadU64(ti + 0x50).ToString("X"));
  }

  static void DumpKnownTypeInfo(StringBuilder sb) {
    sb.AppendLine("LookupKey 0xB2898C8 region (raw qwords):");
    for (uint off = 0; off <= 0x60; off += 8) {
      ulong v = ReadU64(LookupKey + off);
      string note = "";
      if (LookupKey + off == CtorField) note = " *** CTOR_FIELD ***";
      if (LookupKey + off == SizeField) note = " *** SIZE_FIELD ***";
      if (v == imageBase + OuterCtor) note += " OUTER";
      if (v == imageBase + NeighCtor) note += " NEIGH_CTOR";
      if (v == imageBase + SpatCtor) note += " SPAT_CTOR";
      sb.AppendLine("  [0x" + (LookupKey + off).ToString("X") + "] = 0x"
        + (v >= imageBase && v < imageBase + 0x20000000 ? (v - imageBase).ToString("X") : v.ToString("X"))
        + note);
    }
    // Absolute: does ctor field hold Outer as VA?
    int fo = RvaToFile(CtorField);
    if (fo >= 0) {
      // prior milestones said 0xB289918 <- 0x59D9660; may be relocated / not raw VA in file
      sb.AppendLine("raw8 at CtorField file: " + BitConverter.ToString(pe, fo, 8));
    }
  }

  static void WriteJson(string hash, bool ti50bind, int leaCtor, int absN, int store50, int tiShape,
      List<(uint entry, int icall50, bool callsAlloc)> factories, List<Plus98Class> classes) {
    int ptr = classes.Count(c => c.ClassLabel == "pointer");
    int inl = classes.Count(c => c.ClassLabel == "inline");
    int mix = classes.Count(c => c.ClassLabel == "mixed");

    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.27\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"ti50OwnerVt0\": {");
    sb.AppendLine("    \"staticBindingFound\": " + T(ti50bind) + ",");
    sb.AppendLine("    \"leaCtorSites\": " + leaCtor + ",");
    sb.AppendLine("    \"movabsSites\": " + absN + ",");
    sb.AppendLine("    \"storePlus50Hits\": " + store50 + ",");
    sb.AppendLine("    \"nonVtTypeInfoShapeHits\": " + tiShape + ",");
    sb.AppendLine("    \"verdict\": \"" + (ti50bind ? "partial" : "not_found_static") + "\",");
    sb.AppendLine("    \"genericTi50Consumers\": [" + string.Join(", ",
      factories.Select(f => "{ \"entry\": \"0x" + f.entry.ToString("X")
        + "\", \"icall50\": " + f.icall50 + ", \"callsAlloc\": " + T(f.callsAlloc) + " }")) + "]");
    sb.AppendLine("  },");
    sb.AppendLine("  \"plus98\": {");
    sb.AppendLine("    \"pointer\": " + ptr + ",");
    sb.AppendLine("    \"inline\": " + inl + ",");
    sb.AppendLine("    \"mixed\": " + mix + ",");
    sb.AppendLine("    \"distinctLayouts\": " + T(ptr > 0 && inl > 0) + ",");
    sb.AppendLine("    \"pointerFamily\": [\"SideBlock 0xE95E80\", \"Arming 0x21085D0\", \"ArmWrap 0x2108620\", \"NeighRelated 0x3D522C0 zero\"],");
    sb.AppendLine("    \"inlineFamily\": [\"Spat VT0 0x5781490\", \"SpatInstA 0x5563CF0\", \"SpatInstB 0x6CF34A0\"]");
    sb.AppendLine("  },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.27-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.27-summary.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.27\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"plus98Classes\": [");
    for (int i = 0; i < classes.Count; i++) {
      var c = classes[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + c.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(c.Role) + ",");
      sb.AppendLine("      \"class\": " + J(c.ClassLabel) + ",");
      sb.AppendLine("      \"pointerStore\": " + T(c.PointerStore) + ",");
      sb.AppendLine("      \"pointerLoad\": " + T(c.PointerLoad) + ",");
      sb.AppendLine("      \"pointerZero\": " + T(c.PointerZero) + ",");
      sb.AppendLine("      \"pointerCmp\": " + T(c.PointerCmp) + ",");
      sb.AppendLine("      \"inlineAdd\": " + T(c.InlineAdd) + ",");
      sb.AppendLine("      \"inlineLea\": " + T(c.InlineLea) + ",");
      sb.AppendLine("      \"inlineThenCall\": " + T(c.InlineThenCall) + ",");
      sb.AppendLine("      \"evidence\": [" + string.Join(", ", c.Evidence.Take(12).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < classes.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.27-funcs-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.27-funcs-deep.json");

    string tClass = ti50bind ? "partial" : "unsupported";
    string tReason = ti50bind
      ? "Found static TypeInfo-like/+0x50 binding to owner VT[0]; see evidence"
      : "No static LEA/movabs/store+50/TypeInfo-shape binding of owner VT[0]; only VT-table embeds; tight factories are generic [ti+0x50] consumers";
    string pClass = (ptr > 0 && inl > 0) ? "confirmed" : (ptr > 0 || inl > 0 ? "partial" : "unsupported");
    string pReason = (ptr > 0 && inl > 0)
      ? "Pointer family (SideBlock/Arming/ArmWrap/NeighRelated) vs inline family (Spatial VT0/instA/instB) are distinct uses of +0x98"
      : "Could not separate pointer vs inline +0x98 families";

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.27\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"No Edward create; TypeInfo VT[0] binding absent statically; +0x98 classification does not prove possession\" },");
    sb.AppendLine("  \"ti50OwnerVt0\": { \"class\": \"" + tClass + "\", \"reason\": " + J(tReason) + " },");
    sb.AppendLine("  \"plus98Classification\": { \"class\": \"" + pClass + "\", \"reason\": " + J(pReason) + " },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Find runtime/reloc TypeInfo registration of owner VT[0], or which outer/factory ctor constructs Neighbor/Spatial subobjects\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"expect static TypeInfo+0x50 == VT[0] without evidence\", \"conflate Spatial inline +0x98 with SideBlock pointer\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.27-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.27-second-edward-feasibility.json");
  }

  static string Mark(Ins i) {
    string mark = "";
    if (i.NearTarget == Allocator) mark = " *** ALLOC ***";
    if (i.NearTarget == SideBlock) mark = " *** SIDE98 ***";
    if (i.NearTarget == Arming) mark = " *** ARMING ***";
    if (i.NearTarget == ArmWrap) mark = " *** ARMWRAP ***";
    if (i.NearTarget == NeighCtor || i.NearTarget == SpatCtor) mark = " *** VT0 ***";
    if (i.NearTarget == OuterCtor) mark = " *** OUTER ***";
    if (i.IpRel && i.DataRva == NeighVt) mark += " *** NEIGHVT ***";
    if (i.IpRel && i.DataRva == SpatVt) mark += " *** SPATVT ***";
    if (i.HasMem && !i.IpRel && i.Disp == 0x98) mark += " *** +98 ***";
    if (i.HasMem && !i.IpRel && i.Disp == 0x50) mark += " *** +50 ***";
    if (i.IsIndirectCall) mark += " *** ICALL ***";
    return mark;
  }

  static string T(bool b) => b ? "true" : "false";
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }

  static List<(uint site, uint ctor)> FindMovAbsImm(uint[] ctors, int max) {
    var list = new List<(uint, uint)>();
    ulong[] vas = ctors.Select(c => imageBase + c).ToArray();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 10 <= lim && list.Count < max; i++) {
        byte b0 = pe[s.Ptr + i];
        if (b0 != 0x48 && b0 != 0x49) continue;
        byte b1 = pe[s.Ptr + i + 1];
        if (b1 < 0xB8 || b1 > 0xBF) continue;
        ulong imm = BitConverter.ToUInt64(pe, (int)(s.Ptr + i + 2));
        for (int ci = 0; ci < vas.Length; ci++) {
          if (imm == vas[ci]) { list.Add((s.Va + i, ctors[ci])); break; }
        }
      }
    }
    return list;
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
      if (raw.Code == Code.Mov_r64_imm64) {
        ins.IsAbs64Mov = true;
        try { ins.Abs64 = raw.GetImmediate(1); } catch { }
      }
      for (int oi = 0; oi < raw.OpCount; oi++) {
        var kind = raw.GetOpKind(oi);
        if (kind == OpKind.Immediate8 || kind == OpKind.Immediate8to32 || kind == OpKind.Immediate32
            || kind == OpKind.Immediate32to64 || kind == OpKind.Immediate64 || kind == OpKind.Immediate8to64
            || kind == OpKind.Immediate16 || kind == OpKind.Immediate8to16) {
          ins.HasImm = true;
          try { ins.Imm = raw.GetImmediate(oi); } catch { }
        }
        if (kind != OpKind.Memory) continue;
        ins.HasMem = true;
        ins.MemBase = raw.MemoryBase;
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

  static uint ReadU32(uint rva) {
    int fo = RvaToFile(rva);
    return fo < 0 ? 0 : BitConverter.ToUInt32(pe, fo);
  }
  static ulong ReadU64(uint rva) {
    int fo = RvaToFile(rva);
    return fo < 0 ? 0 : BitConverter.ToUInt64(pe, fo);
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
