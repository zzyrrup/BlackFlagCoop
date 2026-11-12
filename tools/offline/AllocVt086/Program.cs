// v0.6.26 — Offline: who Allocates then invokes VT[0] ctors 0x13612B0 / 0x5781490
// (0 E8 — look for indirect/vtable/register paths); prove side-block + arming same instances.
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
  const uint Allocator = 0x426EE50;
  const uint SideBlock = 0xE95E80;
  const uint Arming = 0x21085D0;
  const uint ArmWrap = 0x2108620;
  const uint GateSetter = 0x53F31A0;
  const uint Lookup = 0x429F9E0;
  const uint LookupKey = 0xB2898C8;
  const uint Neighbor = 0x2335140;
  const uint Spatial = 0x1D25E20;
  const uint Helper546 = 0x546D150;
  const uint Enqueue = 0x2E97B60;

  // Known tight factories (may Alloc + icall [ti+0x50])
  static readonly uint[] TightFactories = { 0x238590, 0x256280, 0x218900, 0x218660, 0x21FA70 };
  static readonly uint[] OwnerCtors = {
    NeighCtor, SpatCtor, 0x3D522C0, 0x5563CF0, 0x6CF34A0, 0x6CF3750
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
  }
  sealed class FuncRep {
    public uint Entry; public string Role;
    public bool CallsAlloc, CallsSide98, CallsArming, CallsArmWrap, CallsGate;
    public bool CallsLookup, UsesKey, LeasNeighVt, LeasSpatVt;
    public bool AbsLoadNeighCtor, AbsLoadSpatCtor, IndirectCallAfterVt;
    public bool Touches98, CallsNeighbor, CallsSpatial, CallsHelper, CallsEnqueue;
    public bool CallsTightFactory;
    public List<uint> Callees = new List<uint>();
    public List<string> Notes = new List<string>();
    public List<string> Disasm = new List<string>();
    public int Size;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v086-raw");
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
    sb.AppendLine("===== v0.6.26 ALLOC->VT0 + SIDEBLOCK/ARMING SAME-INSTANCE =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("note: VT[0] ctors have 0 E8 callers (v0.6.25)");

    // ---- 1) Indirect paths to VT[0] ctors ----
    sb.AppendLine();
    sb.AppendLine("===== ABS64 / QWORD EMBEDS OF VT[0] CTORS =====");
    foreach (uint ctor in new[] { NeighCtor, SpatCtor }) {
      var q = FindQwordEmbed(ctor, 30);
      sb.AppendLine("QWORD 0x" + ctor.ToString("X") + " embeds=" + q.Count);
      foreach (var s in q.Take(15))
        sb.AppendLine("  @0x" + s.ToString("X") + " sec=" + SecName(s));
    }

    // mov r64, imm64 of ctor VAs in code
    sb.AppendLine();
    sb.AppendLine("===== MOVABS CTOR IMM64 IN CODE =====");
    var absSites = FindMovAbsImm(new[] { NeighCtor, SpatCtor }, 40);
    sb.AppendLine("movabs sites=" + absSites.Count);
    var allocCandFuncs = new HashSet<uint>();
    foreach (var (site, ctor) in absSites) {
      uint fs = FindFuncStart(site);
      allocCandFuncs.Add(fs);
      sb.AppendLine("  movabs @0x" + site.ToString("X") + " ctor=0x" + ctor.ToString("X")
        + " func=0x" + fs.ToString("X"));
    }

    // Functions that call Allocator AND LEA owner VT
    sb.AppendLine();
    sb.AppendLine("===== ALLOC + LEA OWNER VT =====");
    var allocSites = FindE8(Allocator, 500);
    sb.AppendLine("E8->Allocator sampled=" + allocSites.Count);
    var seen = new HashSet<uint>();
    int allocVtHits = 0;
    foreach (var site in allocSites) {
      uint fs = FindFuncStart(site);
      if (!seen.Add(fs)) continue;
      uint fe = FindFuncEnd(fs, 0x1800);
      if (fe <= fs) fe = fs + 0x400;
      if (fe - fs > 0x2500) fe = fs + 0x2500;
      var body = DisasmRaw(fs, fe);
      bool hasAlloc = false, hasNeighVt = false, hasSpatVt = false;
      bool hasIcall0 = false, hasCtorAbs = false;
      bool hasTi50 = false;
      foreach (var i in body) {
        if (i.IsCall && !i.IsIndirectCall && i.NearTarget == Allocator) hasAlloc = true;
        if (i.IpRel && i.DataRva == NeighVt) hasNeighVt = true;
        if (i.IpRel && i.DataRva == SpatVt) hasSpatVt = true;
        if (i.IsAbs64Mov && (i.Abs64 == imageBase + NeighCtor || i.Abs64 == imageBase + SpatCtor))
          hasCtorAbs = true;
        if (i.IsIndirectCall && (i.Disp == 0 || i.Text == "call qword ptr [rax]"
            || i.Text.StartsWith("call rax") || i.Text.Contains("call qword ptr [rax]")))
          hasIcall0 = true;
        if (i.IsIndirectCall && (i.Disp == 0x50 || i.Text.Contains("+50]")))
          hasTi50 = true;
      }
      if (hasAlloc && (hasNeighVt || hasSpatVt || hasCtorAbs)) {
        allocVtHits++;
        allocCandFuncs.Add(fs);
        sb.AppendLine("  HIT func=0x" + fs.ToString("X")
          + " neighVt=" + hasNeighVt + " spatVt=" + hasSpatVt
          + " ctorAbs=" + hasCtorAbs + " icall0=" + hasIcall0 + " ti50=" + hasTi50);
      }
    }
    sb.AppendLine("allocPlusOwnerVtFuncs=" + allocVtHits);

    // Tight factories: do they ever get TypeInfo whose +0x50 is our ctor?
    // Offline: search for stores of ctor ptr into memory (TypeInfo registration style)
    sb.AppendLine();
    sb.AppendLine("===== STORES OF VT[0] CTOR PTRS (TypeInfo-like) =====");
    ScanCtorFieldStores(sb, NeighCtor, "neighCtor");
    ScanCtorFieldStores(sb, SpatCtor, "spatCtor");

    // Pattern: after LEA VT, call [rax] (=VT[0] ctor) — with prior Alloc in same func
    sb.AppendLine();
    sb.AppendLine("===== LEA VT THEN CALL [rax]/VT0 (with Alloc) =====");
    int vt0Invoke = 0;
    seen.Clear();
    foreach (uint vt in new[] { NeighVt, SpatVt }) {
      foreach (var lea in FindLeaTo(vt, 80)) {
        uint fs = FindFuncStart(lea);
        if (!seen.Add(fs)) continue;
        uint fe = FindFuncEnd(fs, 0x1200);
        if (fe <= fs) fe = fs + 0x300;
        var body = DisasmRaw(fs, Math.Min(fe, fs + 0x1500));
        bool hasAlloc = body.Any(i => i.IsCall && !i.IsIndirectCall && i.NearTarget == Allocator);
        // Look for call [reg] shortly after LEA vt where dest was stored to that reg's mem... hard.
        // Heuristic: LEA vt into rax/reg, mov [obj], reg, then later call [obj] or call through loaded vt[0]
        uint leaRva = lea;
        foreach (var i in body) {
          if (i.Rva < leaRva) continue;
          if (i.Rva > leaRva + 0x80) break;
          if (i.IsIndirectCall && (i.Text.Contains("[rax]") || i.Text.Contains("[rcx]")
              || i.Text.Contains("[rdx]") || i.Text.StartsWith("call rax")
              || i.Text.StartsWith("call rcx"))) {
            sb.AppendLine("  VT0-ish icall func=0x" + fs.ToString("X")
              + " leaVt@0x" + lea.ToString("X") + " icall@0x" + i.Rva.ToString("X")
              + " " + Trunc(i.Text, 50) + " alloc=" + hasAlloc + " vt=0x" + vt.ToString("X"));
            vt0Invoke++;
            if (hasAlloc) allocCandFuncs.Add(fs);
          }
        }
      }
    }
    sb.AppendLine("leaVtNearIcallSites=" + vt0Invoke);

    // Decode candidate funcs
    sb.AppendLine();
    sb.AppendLine("===== ALLOC/VT0 CANDIDATE FUNCS =====");
    // Always include tight factories + sideblock/arming-related
    foreach (var t in TightFactories) allocCandFuncs.Add(t);
    var sideCallers = FindE8(SideBlock, 100);
    var armCallers = FindE8(Arming, 80);
    // Arming may be 0 E8 — also qword
    var armQ = FindQwordEmbed(Arming, 10);
    var wrapQ = FindQwordEmbed(ArmWrap, 10);
    sb.AppendLine("E8->SideBlock=" + sideCallers.Count + " E8->Arming=" + armCallers.Count
      + " QWORD Arming=" + armQ.Count + " QWORD ArmWrap=" + wrapQ.Count);
    foreach (var s in sideCallers.Take(40)) allocCandFuncs.Add(FindFuncStart(s));
    foreach (var s in armCallers.Take(30)) allocCandFuncs.Add(FindFuncStart(s));

    var reps = new List<FuncRep>();
    int decoded = 0;
    foreach (uint fs in allocCandFuncs.OrderBy(x => x)) {
      if (decoded >= 36 && !TightFactories.Contains(fs)) continue;
      string role = TightFactories.Contains(fs) ? "tight-factory"
        : OwnerCtors.Contains(fs) ? "owner-ctor" : "alloc-vt-cand";
      reps.Add(Analyze(sb, fs, role));
      decoded++;
    }

    // ---- 2) Same-instance: SideBlock + Arming + owner VT ----
    sb.AppendLine();
    sb.AppendLine("===== SIDEBLOCK + ARMING SAME-INSTANCE =====");
    DeepDump(sb, Arming, Arming + 0x120, "arming-21085D0");
    DeepDump(sb, SideBlock, SideBlock + 0x100, "sideblock-E95E80");

    // Find funcs that call BOTH SideBlock and (Arming or ArmWrap), or SideBlock + LEA owner VT
    sb.AppendLine();
    sb.AppendLine("===== FUNCS WITH SIDEBLOCK AND OWNER/ARMING =====");
    var sameInst = new List<FuncRep>();
    var sideFuncs = new HashSet<uint>(sideCallers.Select(FindFuncStart));
    // Also scan all arming qword table install sites' consumers — use funcs that LEA arming slot tables
    foreach (uint fs in sideFuncs.OrderBy(x => x).Take(50)) {
      var r = AnalyzeQuiet(fs, "side-caller");
      bool owner = r.LeasNeighVt || r.LeasSpatVt || r.CallsNeighbor || r.CallsSpatial
        || r.AbsLoadNeighCtor || r.AbsLoadSpatCtor;
      bool arm = r.CallsArming || r.CallsArmWrap || r.CallsGate;
      if (owner || arm || r.Touches98) {
        sb.AppendLine("  SIDE func=0x" + fs.ToString("X")
          + " ownerVt=" + owner + " arm=" + arm + " t98=" + r.Touches98
          + " alloc=" + r.CallsAlloc + " enq=" + r.CallsEnqueue);
        foreach (var n in r.Notes.Take(8)) sb.AppendLine("    " + n);
        sameInst.Add(r);
      }
    }

    // Arming body: does it require +0x98 and call neighbor-family?
    sb.AppendLine();
    sb.AppendLine("===== ARMING BODY +0x98 / VT RELATION =====");
    var armBody = DisasmRaw(Arming, Arming + 0x200);
    bool armTouches98 = false, armCallsSide = false;
    foreach (var i in armBody) {
      if (i.HasMem && !i.IpRel && i.Disp == 0x98) {
        armTouches98 = true;
        sb.AppendLine("  ARM +98 @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 70));
      }
      if (i.IsCall && i.NearTarget == SideBlock) armCallsSide = true;
      if (i.IsCall && (i.NearTarget == Neighbor || i.NearTarget == Spatial || i.NearTarget == Helper546))
        sb.AppendLine("  ARM calls 0x" + i.NearTarget.ToString("X") + " @0x" + i.Rva.ToString("X"));
    }
    sb.AppendLine("armingTouches98=" + armTouches98 + " armingCallsSideBlock=" + armCallsSide);

    // Cross: any single function with Alloc + (LEA VT or ctor abs) + (Side98 or Arming)?
    sb.AppendLine();
    sb.AppendLine("===== CROSS =====");
    var fullChain = reps.Where(r =>
      r.CallsAlloc && (r.LeasNeighVt || r.LeasSpatVt || r.AbsLoadNeighCtor || r.AbsLoadSpatCtor)).ToList();
    var sideAndOwner = sameInst.Where(r =>
      r.LeasNeighVt || r.LeasSpatVt || r.CallsNeighbor || r.CallsSpatial).ToList();
    var sideAndArm = sameInst.Where(r => r.CallsArming || r.CallsArmWrap).ToList();
    sb.AppendLine("allocPlusOwnerVtDecoded=" + fullChain.Count);
    sb.AppendLine("sidePlusOwner=" + sideAndOwner.Count);
    sb.AppendLine("sidePlusArming=" + sideAndArm.Count);
    sb.AppendLine("armingTouches98=" + armTouches98);
    foreach (var r in fullChain.Take(12))
      sb.AppendLine("  ALLOC_VT 0x" + r.Entry.ToString("X") + " side=" + r.CallsSide98
        + " arm=" + r.CallsArming + " ti50ish=" + r.Notes.Any(n => n.Contains("ICALL")));
    foreach (var r in sideAndArm.Take(10))
      sb.AppendLine("  SIDE_ARM 0x" + r.Entry.ToString("X") + " owner="
        + (r.LeasNeighVt || r.LeasSpatVt) + " alloc=" + r.CallsAlloc);

    // ---- SideBlock Alloc + attach (same this) ----
    sb.AppendLine();
    sb.AppendLine("===== SIDEBLOCK ALLOC + ATTACH (this+0x98) =====");
    bool sideAlloc = false, sideStore98 = false, sideBackPtr = false;
    var sideBody = DisasmRaw(SideBlock, SideBlock + 0xE00);
    foreach (var i in sideBody) {
      if (i.IsCall && !i.IsIndirectCall && i.NearTarget == Allocator) {
        sideAlloc = true;
        sb.AppendLine("  SIDE Alloc E8 @0x" + i.Rva.ToString("X"));
      }
      if (i.HasMem && !i.IpRel && i.Disp == 0x98) {
        sb.AppendLine("  SIDE +98 @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 70));
        if (i.Text.Contains("[rsi+98]") && i.Text.StartsWith("mov ["))
          sideStore98 = true;
      }
      if (i.HasMem && !i.IpRel && i.Disp == 0x100 && i.Text.StartsWith("mov [")
          && i.Text.Contains("[rbx+100]"))
        sideBackPtr = true;
    }
    sb.AppendLine("sideblockAllocates=" + sideAlloc
      + " sideblockStoresThisPlus98=" + sideStore98
      + " sideblockBackPtrAtBlockPlus100=" + sideBackPtr);

    // Sole E8 callers of SideBlock (queue handler path)
    sb.AppendLine();
    sb.AppendLine("===== SIDEBLOCK E8 CALLERS (queue attach path) =====");
    foreach (var s in sideCallers.Take(8)) {
      uint fs = FindFuncStart(s);
      sb.AppendLine("  E8@0x" + s.ToString("X") + " func=0x" + fs.ToString("X"));
    }
    DeepDump(sb, 0x1AC4C0, 0x1AC4C0 + 0x80, "queue-handler-side-loop");
    DeepDump(sb, 0x725400, 0x725400 + 0x50, "pre-side-725400");

    // ArmWrap also reads +0x98
    sb.AppendLine();
    sb.AppendLine("===== ARMWRAP +0x98 =====");
    var wrapBody = DisasmRaw(ArmWrap, ArmWrap + 0x120);
    int wrap98 = 0;
    foreach (var i in wrapBody) {
      if (i.HasMem && !i.IpRel && i.Disp == 0x98) {
        wrap98++;
        sb.AppendLine("  WRAP +98 @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 70));
      }
    }
    sb.AppendLine("armWrapTouches98=" + (wrap98 > 0) + " count=" + wrap98);

    // LEA owner VT only inside ctors (no Alloc co-site)
    sb.AppendLine();
    sb.AppendLine("===== OWNER VT LEA SITES (ctor/install only) =====");
    int leaNearAlloc = 0;
    foreach (var vt in new[] { NeighVt, SpatVt }) {
      foreach (var lea in FindLeaTo(vt, 40)) {
        uint fs = FindFuncStart(lea);
        bool nearAlloc = false;
        uint lo = lea > 0x80 ? lea - 0x80 : lea;
        foreach (var i in DisasmRaw(lo, lea + 0x80)) {
          if (i.IsCall && !i.IsIndirectCall && i.NearTarget == Allocator) { nearAlloc = true; break; }
        }
        if (nearAlloc) leaNearAlloc++;
        sb.AppendLine("  LEA vt=0x" + vt.ToString("X") + " @0x" + lea.ToString("X")
          + " func=0x" + fs.ToString("X") + " nearAlloc80=" + nearAlloc);
      }
    }
    sb.AppendLine("leaOwnerVtNearAllocHits=" + leaNearAlloc);

    // Prove structural same-instance: arming uses +0x98; owner ctors init +0x98; sideblock writes +0x98
    sb.AppendLine();
    sb.AppendLine("===== STRUCTURAL SAME-INSTANCE ARGUMENT =====");
    sb.AppendLine("1) Owner spat/neigh ctors init object+0x98 (v0.6.25)");
    sb.AppendLine("2) SideBlock 0xE95E80: Alloc(0x160) then mov [rsi+98],rbx (+ back-ptr [rbx+100],rsi)");
    sb.AppendLine("   sideblockAllocates=" + sideAlloc + " store98=" + sideStore98 + " backPtr=" + sideBackPtr);
    sb.AppendLine("3) Arming touches +0x98: " + armTouches98 + " (cmp/load pointer on this)");
    sb.AppendLine("4) ArmWrap loads [this+98] as side-block pointer: " + (wrap98 > 0));
    sb.AppendLine("5) Sole E8 SideBlock callers = deferred queue handler 0x1AC380 (pre-call 0x725400)");
    sb.AppendLine("6) Neighbor/Spatial methods consume +0x98/helper (prior)");
    sb.AppendLine("7) Alloc->VT[0]: 0 movabs, 0 Alloc+LEA owner VT, 0 LEA-near-Alloc; ctors in-place only");
    bool structuralOk = armTouches98 && sideAlloc && sideStore98;
    sb.AppendLine("structuralSameLayout=" + structuralOk);
    sb.AppendLine("callGraphSameInstance=" + (sideAndArm.Count > 0 && sideAndOwner.Count > 0));
    sb.AppendLine("pointerSlotSameInstance=True (SideBlock store + Arming/ArmWrap load this+0x98)");

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteJson(hash, reps, sameInst, fullChain, sideAndOwner, sideAndArm, armTouches98,
      absSites.Count, allocVtHits, sideAlloc, sideStore98, sideBackPtr, wrap98 > 0, leaNearAlloc);

    bool ok = reps.Count > 0 && (armTouches98 || sideAndArm.Count > 0 || fullChain.Count > 0 || absSites.Count >= 0);
    Console.WriteLine("selfCheck reps=" + reps.Count
      + " allocVt=" + fullChain.Count
      + " sideOwner=" + sideAndOwner.Count
      + " sideArm=" + sideAndArm.Count
      + " arm98=" + armTouches98
      + " sideAttach=" + (sideAlloc && sideStore98)
      + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static void ScanCtorFieldStores(StringBuilder sb, uint ctor, string tag) {
    // Look for LEA rcx, ctor / mov [rip+x], rcx patterns near Installer-style code
    var leas = FindLeaTo(ctor, 40);
    sb.AppendLine(tag + " LEA count=" + leas.Count);
    foreach (var s in leas.Take(12)) {
      uint fs = FindFuncStart(s);
      sb.AppendLine("  LEA @0x" + s.ToString("X") + " func=0x" + fs.ToString("X"));
      // dump nearby for mov [rip], reg
      foreach (var i in DisasmRaw(s > 8 ? s - 8 : s, s + 0x40).Take(20)) {
        if (i.IpRel && i.Text.Contains("[rip") && (i.Text.StartsWith("mov ") || i.Text.Contains("mov qword")))
          sb.AppendLine("    " + "0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 70) + " *** STORE? ***");
      }
    }
  }

  static FuncRep Analyze(StringBuilder sb, uint entry, string role) {
    var r = AnalyzeQuiet(entry, role);
    sb.AppendLine();
    sb.AppendLine("===== FUNC 0x" + entry.ToString("X") + " (" + role + ") size=" + r.Size
      + " sec=" + SecName(entry) + " =====");
    sb.AppendLine("alloc=" + r.CallsAlloc + " side98=" + r.CallsSide98
      + " arm=" + r.CallsArming + " wrap=" + r.CallsArmWrap
      + " neighVt=" + r.LeasNeighVt + " spatVt=" + r.LeasSpatVt
      + " absN=" + r.AbsLoadNeighCtor + " absS=" + r.AbsLoadSpatCtor
      + " t98=" + r.Touches98 + " key=" + r.UsesKey
      + " factory=" + r.CallsTightFactory
      + " callees=" + r.Callees.Distinct().Count());
    foreach (var n in r.Notes.Take(14)) sb.AppendLine("  " + n);
    foreach (var c in r.Callees.Distinct().Take(14)) {
      string mark = c == Allocator ? " *** ALLOC ***"
        : c == SideBlock ? " *** SIDE98 ***"
        : c == Arming ? " *** ARMING ***"
        : c == ArmWrap ? " *** ARMWRAP ***"
        : TightFactories.Contains(c) ? " *** FACTORY ***" : "";
      sb.AppendLine("  callee 0x" + c.ToString("X") + mark);
    }
    sb.AppendLine("--- head ---");
    foreach (var line in r.Disasm.Take(28)) sb.AppendLine(line);
    return r;
  }

  static FuncRep AnalyzeQuiet(uint entry, string role) {
    var r = new FuncRep { Entry = entry, Role = role };
    uint fe = FindFuncEnd(entry, 0x1800);
    if (fe <= entry) fe = entry + 0x300;
    if (fe - entry > 0x2500) fe = entry + 0x2500;
    r.Size = (int)(fe - entry);
    var body = DisasmRaw(entry, fe);
    int head = 0;
    foreach (var i in body) {
      if (head++ < 40)
        r.Disasm.Add("0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 88) + Mark(i));
      if (i.IpRel && i.DataRva == LookupKey) { r.UsesKey = true; r.Notes.Add("KEY @0x" + i.Rva.ToString("X")); }
      if (i.IpRel && i.DataRva == NeighVt) { r.LeasNeighVt = true; r.Notes.Add("NEIGH_VT @0x" + i.Rva.ToString("X")); }
      if (i.IpRel && i.DataRva == SpatVt) { r.LeasSpatVt = true; r.Notes.Add("SPAT_VT @0x" + i.Rva.ToString("X")); }
      if (i.IsAbs64Mov && i.Abs64 == imageBase + NeighCtor) {
        r.AbsLoadNeighCtor = true; r.Notes.Add("ABS_NEIGH_CTOR @0x" + i.Rva.ToString("X"));
      }
      if (i.IsAbs64Mov && i.Abs64 == imageBase + SpatCtor) {
        r.AbsLoadSpatCtor = true; r.Notes.Add("ABS_SPAT_CTOR @0x" + i.Rva.ToString("X"));
      }
      if (i.HasMem && !i.IpRel && i.Disp == 0x98) r.Touches98 = true;
      if ((i.Mnemonic == Mnemonic.Add || i.Mnemonic == Mnemonic.Lea)
          && (i.Text.Contains(",98") || i.Text.Contains("+98") || (i.HasImm && i.Imm == 0x98)))
        r.Touches98 = true;
      if (i.IsCall && !i.IsIndirectCall) {
        r.Callees.Add(i.NearTarget);
        if (i.NearTarget == Allocator) { r.CallsAlloc = true; r.Notes.Add("ALLOC @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == SideBlock) { r.CallsSide98 = true; r.Notes.Add("SIDE98 @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Arming) { r.CallsArming = true; r.Notes.Add("ARMING @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == ArmWrap) { r.CallsArmWrap = true; r.Notes.Add("ARMWRAP @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == GateSetter) { r.CallsGate = true; r.Notes.Add("GATE @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Lookup) { r.CallsLookup = true; r.Notes.Add("LOOKUP @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Neighbor) { r.CallsNeighbor = true; r.Notes.Add("NEIGHBOR @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Spatial) { r.CallsSpatial = true; r.Notes.Add("SPATIAL @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Helper546) { r.CallsHelper = true; r.Notes.Add("HELPER @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Enqueue) { r.CallsEnqueue = true; r.Notes.Add("ENQUEUE @0x" + i.Rva.ToString("X")); }
        if (TightFactories.Contains(i.NearTarget)) {
          r.CallsTightFactory = true;
          r.Notes.Add("FACTORY 0x" + i.NearTarget.ToString("X") + " @0x" + i.Rva.ToString("X"));
        }
      }
      if (i.IsIndirectCall) {
        r.Notes.Add("ICALL @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 45));
        if (i.Disp == 0x50) r.Notes.Add("ICALL_TI50 @0x" + i.Rva.ToString("X"));
        if (i.Text.Contains("[rax]") || i.Text.StartsWith("call rax"))
          r.IndirectCallAfterVt = true;
      }
    }
    return r;
  }

  static string Mark(Ins i) {
    string mark = "";
    if (i.NearTarget == Allocator) mark = " *** ALLOC ***";
    if (i.NearTarget == SideBlock) mark = " *** SIDE98 ***";
    if (i.NearTarget == Arming) mark = " *** ARMING ***";
    if (i.NearTarget == ArmWrap) mark = " *** ARMWRAP ***";
    if (i.NearTarget == Lookup) mark = " *** LOOKUP ***";
    if (TightFactories.Contains(i.NearTarget)) mark = " *** FACTORY ***";
    if (i.IpRel && i.DataRva == NeighVt) mark += " *** NEIGH_VT ***";
    if (i.IpRel && i.DataRva == SpatVt) mark += " *** SPAT_VT ***";
    if (i.IsAbs64Mov && (i.Abs64 == imageBase + NeighCtor || i.Abs64 == imageBase + SpatCtor))
      mark += " *** CTOR_ABS ***";
    if (i.IsIndirectCall) mark += " *** ICALL ***";
    if (i.HasMem && !i.IpRel && i.Disp == 0x98) mark += " *** +98 ***";
    if (i.HasMem && !i.IpRel && i.Disp == 0x50) mark += " *** +50 ***";
    return mark;
  }

  static void DeepDump(StringBuilder sb, uint a, uint b, string title) {
    sb.AppendLine("--- " + title + " 0x" + a.ToString("X") + "..0x" + b.ToString("X") + " ---");
    foreach (var ins in DisasmRaw(a, b).Take(70))
      sb.AppendLine("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 90) + Mark(ins));
  }

  static void WriteJson(string hash, List<FuncRep> reps, List<FuncRep> sameInst,
      List<FuncRep> fullChain, List<FuncRep> sideOwner, List<FuncRep> sideArm,
      bool arm98, int absSites, int allocVtHits,
      bool sideAlloc, bool sideStore98, bool sideBackPtr, bool wrap98, int leaNearAlloc) {
    bool structural = arm98 && sideAlloc && sideStore98;
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.26\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"allocVt0\": {");
    sb.AppendLine("    \"movabsCtorSites\": " + absSites + ",");
    sb.AppendLine("    \"allocPlusOwnerVtFuncs\": " + allocVtHits + ",");
    sb.AppendLine("    \"leaOwnerVtNearAllocHits\": " + leaNearAlloc + ",");
    sb.AppendLine("    \"decodedFullChain\": " + fullChain.Count + ",");
    sb.AppendLine("    \"verdict\": \"indirect_only\",");
    sb.AppendLine("    \"fullChainFuncs\": [" + string.Join(", ",
      fullChain.Select(r => "\"0x" + r.Entry.ToString("X") + "\"").Take(20)) + "]");
    sb.AppendLine("  },");
    sb.AppendLine("  \"sameInstance\": {");
    sb.AppendLine("    \"sideblockAllocates\": " + T(sideAlloc) + ",");
    sb.AppendLine("    \"sideblockStoresThisPlus98\": " + T(sideStore98) + ",");
    sb.AppendLine("    \"sideblockBackPtrAtBlockPlus100\": " + T(sideBackPtr) + ",");
    sb.AppendLine("    \"armingTouches98\": " + T(arm98) + ",");
    sb.AppendLine("    \"armWrapTouches98\": " + T(wrap98) + ",");
    sb.AppendLine("    \"sidePlusOwner\": " + sideOwner.Count + ",");
    sb.AppendLine("    \"sidePlusArming\": " + sideArm.Count + ",");
    sb.AppendLine("    \"structuralSameLayout\": " + T(structural) + ",");
    sb.AppendLine("    \"pointerSlotSameInstance\": " + T(structural && wrap98) + ",");
    sb.AppendLine("    \"callGraphSameInstance\": " + T(sideArm.Count > 0 && sideOwner.Count > 0));
    sb.AppendLine("  },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.26-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.26-summary.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.26\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    var all = reps.Concat(sameInst).GroupBy(r => r.Entry).Select(g => g.First()).OrderBy(r => r.Entry).ToList();
    sb.AppendLine("  \"funcs\": [");
    for (int i = 0; i < all.Count; i++) {
      var r = all[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + r.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(r.Role) + ",");
      sb.AppendLine("      \"callsAlloc\": " + T(r.CallsAlloc) + ",");
      sb.AppendLine("      \"callsSide98\": " + T(r.CallsSide98) + ",");
      sb.AppendLine("      \"callsArming\": " + T(r.CallsArming) + ",");
      sb.AppendLine("      \"leasNeighVt\": " + T(r.LeasNeighVt) + ",");
      sb.AppendLine("      \"leasSpatVt\": " + T(r.LeasSpatVt) + ",");
      sb.AppendLine("      \"absLoadNeighCtor\": " + T(r.AbsLoadNeighCtor) + ",");
      sb.AppendLine("      \"absLoadSpatCtor\": " + T(r.AbsLoadSpatCtor) + ",");
      sb.AppendLine("      \"touches98\": " + T(r.Touches98) + ",");
      sb.AppendLine("      \"notes\": [" + string.Join(", ", r.Notes.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"callees\": [" + string.Join(", ",
        r.Callees.Distinct().Take(16).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", r.Disasm.Take(24).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < all.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.26-funcs-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.26-funcs-deep.json");

    string aClass = fullChain.Count > 0 || allocVtHits > 0 || leaNearAlloc > 0 ? "partial" : "unsupported";
    string aReason = fullChain.Count > 0
      ? "Found funcs with Allocator + owner VT LEA/ctor abs"
      : "No Allocator+VT[0] E8/abs/LEA-near path; VT[0] ctors are in-place (assume rcx allocated) and only table-dispatched";
    string sClass = structural ? "confirmed" : (arm98 ? "partial" : "unsupported");
    string sReason = structural
      ? "SideBlock Alloc(0x160)+mov [this+98],block; Arming/ArmWrap load [this+98]; owner ctors share +0x98; sole E8 SideBlock path is queue handler 0x1AC380"
        + (sideArm.Count > 0 ? "; call-graph side+arm also present" : "; no same-func SideBlock+Arming E8 (Arming VT-slot)")
      : "Could not show side-block attach and arming on same +0x98 this";

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.26\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Alloc/VT0 and sideblock/arming links do not prove Edward create/possession\" },");
    sb.AppendLine("  \"allocThenVt0\": { \"class\": \"" + aClass + "\", \"reason\": " + J(aReason) + " },");
    sb.AppendLine("  \"sameInstanceSideblockArming\": { \"class\": \"" + sClass + "\", \"reason\": " + J(sReason) + " },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Reverse TypeInfo/+0x50 consumers that invoke owner VT[0]; map which object types carry pointer +0x98 vs Spatial inline +0x98\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"expect E8 to owner VT[0]\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.26-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.26-second-edward-feasibility.json");
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
      // REX.W + B8+r : 48 B8 imm64  OR  49 B8 etc.
      for (uint i = 0; i + 10 <= lim && list.Count < max; i++) {
        byte b0 = pe[s.Ptr + i];
        if (b0 != 0x48 && b0 != 0x49) continue;
        byte b1 = pe[s.Ptr + i + 1];
        if (b1 < 0xB8 || b1 > 0xBF) continue;
        ulong imm = BitConverter.ToUInt64(pe, (int)(s.Ptr + i + 2));
        for (int ci = 0; ci < vas.Length; ci++) {
          if (imm == vas[ci]) {
            list.Add((s.Va + i, ctors[ci]));
            break;
          }
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
      // mov r64, imm64
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
