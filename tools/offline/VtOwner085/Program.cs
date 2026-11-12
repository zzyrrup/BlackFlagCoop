// v0.6.25 — Offline: who constructs objects receiving vtables 0x976B2D0 / 0x9236E00
// (installers 0x13612B0, 0x5563CF0/0x6CF34A0); relate to enrollment / +0x98 / arming.
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
  const uint NeighInst = 0x13612B0;
  const uint SpatInstA = 0x5563CF0;
  const uint SpatInstB = 0x6CF34A0;
  const uint SpatInstHelper = 0x5563D30; // called by SpatInstA

  // Enrollment / +0x98 / arming anchors (prior milestones)
  const uint Enqueue = 0x2E97B60;
  const uint Wrapper = 0x2E97FC0;
  const uint SideBlockAlloc = 0xE95E80; // alloc 0x160 -> +0x98
  const uint Arming = 0x21085D0;
  const uint ArmWrap = 0x2108620;
  const uint GateSetter = 0x53F31A0;
  const uint Lookup = 0x429F9E0;
  const uint Allocator = 0x426EE50;
  const uint LookupKey = 0xB2898C8;
  const uint Helper546 = 0x546D150;
  const uint Neighbor = 0x2335140;
  const uint Spatial = 0x1D25E20;
  const uint OuterCtor = 0x59D9660;

  static readonly uint[] Installers = { NeighInst, SpatInstA, SpatInstB, SpatInstHelper };
  static readonly uint[] EnrollAnchors = {
    Enqueue, Wrapper, SideBlockAlloc, Arming, ArmWrap, GateSetter, Helper546, Neighbor, Spatial
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
  }
  sealed class FuncRep {
    public uint Entry; public string Role;
    public bool UsesKey, CallsLookup, CallsAlloc, CallsEnqueue, CallsWrapper;
    public bool CallsSide98, CallsArming, CallsArmWrap, CallsGate, CallsHelper;
    public bool CallsNeighInst, CallsSpatInst, Touches98, Touches61, Vcall2B0;
    public bool LeasNeighVt, LeasSpatVt, CallsInstaller;
    public List<uint> Callees = new List<uint>();
    public List<string> Notes = new List<string>();
    public List<string> Disasm = new List<string>();
    public List<string> Strings = new List<string>();
    public int Size;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v085-raw");
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
    sb.AppendLine("===== v0.6.25 VT OWNER CTORS + ENROLLMENT LINK =====");
    sb.AppendLine("exeSha256=" + hash);

    // ---- 1) Installer callers / constructors ----
    sb.AppendLine();
    sb.AppendLine("===== INSTALLER CALLERS =====");
    var ctorFuncs = new HashSet<uint>();
    foreach (uint inst in Installers) {
      var e8 = FindE8(inst, 120);
      var lea = FindLeaTo(inst, 40);
      sb.AppendLine("installer 0x" + inst.ToString("X") + " E8=" + e8.Count + " LEA=" + lea.Count);
      foreach (var s in e8.Take(20)) {
        uint fs = FindFuncStart(s);
        ctorFuncs.Add(fs);
        sb.AppendLine("  E8 @0x" + s.ToString("X") + " func=0x" + fs.ToString("X"));
      }
      foreach (var s in lea.Take(10)) {
        uint fs = FindFuncStart(s);
        ctorFuncs.Add(fs);
        sb.AppendLine("  LEA @0x" + s.ToString("X") + " func=0x" + fs.ToString("X"));
      }
    }

    // Also: funcs that LEA the vtable bases (may be installers themselves or wrappers)
    sb.AppendLine();
    sb.AppendLine("===== VT BASE LEA SITES =====");
    foreach (uint vt in new[] { NeighVt, SpatVt }) {
      var leas = FindLeaTo(vt, 40);
      sb.AppendLine("LEA -> 0x" + vt.ToString("X") + " count=" + leas.Count);
      foreach (var s in leas) {
        uint fs = FindFuncStart(s);
        ctorFuncs.Add(fs);
        sb.AppendLine("  @0x" + s.ToString("X") + " func=0x" + fs.ToString("X"));
      }
    }

    // Qword embeds of installers (vtable of ctors?)
    sb.AppendLine();
    sb.AppendLine("===== INSTALLER QWORD EMBEDS =====");
    foreach (uint inst in Installers) {
      var q = FindQwordEmbed(inst, 20);
      sb.AppendLine("QWORD 0x" + inst.ToString("X") + " embeds=" + q.Count);
      foreach (var s in q) {
        sb.AppendLine("  slot @0x" + s.ToString("X") + " sec=" + SecName(s));
        // nearby LEA to slot / table base around slot
      }
    }

    // Seed installers themselves
    ctorFuncs.Add(NeighInst);
    ctorFuncs.Add(SpatInstA);
    ctorFuncs.Add(SpatInstB);

    sb.AppendLine();
    sb.AppendLine("===== DEEP INSTALLERS =====");
    DeepDump(sb, NeighInst, NeighInst + 0x80, "neigh-inst");
    DeepDump(sb, SpatInstA, SpatInstA + 0x40, "spat-inst-A");
    DeepDump(sb, SpatInstB, SpatInstB + 0x40, "spat-inst-B");
    DeepDump(sb, SpatInstHelper, SpatInstHelper + 0xA0, "spat-inst-helper");

    // Analyze constructor/caller funcs
    sb.AppendLine();
    sb.AppendLine("===== CONSTRUCTOR / CALLER FUNCS =====");
    var reps = new List<FuncRep>();
    int decoded = 0;
    foreach (uint fs in ctorFuncs.OrderBy(x => x)) {
      bool isInst = Installers.Contains(fs);
      if (decoded >= 28 && !isInst) {
        sb.AppendLine("  (skip remaining 0x" + fs.ToString("X") + ")");
        continue;
      }
      string role = isInst ? "installer" : "ctor-or-caller";
      var rep = Analyze(sb, fs, role);
      reps.Add(rep);
      if (!isInst) decoded++;
    }

    // Pre-call windows for installer E8 sites (alloc? size?)
    sb.AppendLine();
    sb.AppendLine("===== PRE-INSTALLER CALL WINDOWS =====");
    foreach (uint inst in new[] { NeighInst, SpatInstA, SpatInstB }) {
      foreach (var site in FindE8(inst, 16).Take(8)) {
        uint start = site > 0x50 ? site - 0x50 : site;
        sb.AppendLine("--- before call 0x" + inst.ToString("X") + " @0x" + site.ToString("X")
          + " func=0x" + FindFuncStart(site).ToString("X") + " ---");
        foreach (var ins in DisasmRaw(start, site + 5).Take(40)) {
          string mark = Mark(ins);
          if (ins.Text.Contains("mov rcx") || ins.Text.Contains("lea rcx")
              || ins.Text.Contains("mov edx") || ins.Text.Contains("mov r8"))
            mark += " *** ARG ***";
          if (ins.HasMem && !ins.IpRel && (ins.Disp == 0x98 || ins.Disp == 0x61))
            mark += " *** FIELD ***";
          sb.AppendLine("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 88) + mark);
        }
      }
    }

    // ---- 2) Enrollment / +0x98 / arming relation ----
    sb.AppendLine();
    sb.AppendLine("===== ENROLLMENT / +0x98 / ARMING RELATION =====");
    // Which ctor reps touch enroll anchors?
    var linked = reps.Where(r =>
      r.CallsEnqueue || r.CallsWrapper || r.CallsSide98 || r.CallsArming || r.CallsArmWrap
      || r.CallsGate || r.Touches98 || r.Touches61 || r.CallsHelper || r.UsesKey).ToList();
    sb.AppendLine("ctorReps=" + reps.Count + " enrollLinked=" + linked.Count);
    foreach (var r in linked)
      sb.AppendLine("  LINK 0x" + r.Entry.ToString("X") + " role=" + r.Role
        + " key=" + r.UsesKey
        + " enq=" + r.CallsEnqueue + " wrap=" + r.CallsWrapper
        + " side98=" + r.CallsSide98 + " arm=" + r.CallsArming
        + " wrapArm=" + r.CallsArmWrap + " gate=" + r.CallsGate
        + " t98=" + r.Touches98 + " t61=" + r.Touches61
        + " helper=" + r.CallsHelper);

    // Reverse: who among enroll-anchor callers also calls installers / LEAs VTs?
    sb.AppendLine();
    sb.AppendLine("===== ENROLL ANCHOR FUNCS THAT TOUCH OWNER VTS =====");
    var enrollTouch = new List<FuncRep>();
    foreach (uint anchor in EnrollAnchors) {
      var sites = FindE8(anchor, 60);
      var funcs = new HashSet<uint>(sites.Select(FindFuncStart));
      int hit = 0;
      foreach (uint fs in funcs.OrderBy(x => x)) {
        if (hit >= 8) break;
        // Quick scan for VT LEA or installer call
        uint fe = FindFuncEnd(fs, 0x1000);
        if (fe <= fs) fe = fs + 0x300;
        if (fe - fs > 0x1800) fe = fs + 0x1800;
        var body = DisasmRaw(fs, fe);
        bool touchVt = false, touchInst = false, t98 = false;
        foreach (var i in body) {
          if (i.IpRel && (i.DataRva == NeighVt || i.DataRva == SpatVt)) touchVt = true;
          if (i.IsCall && !i.IsIndirectCall && Installers.Contains(i.NearTarget)) touchInst = true;
          if (i.HasMem && !i.IpRel && i.Disp == 0x98) t98 = true;
        }
        if (touchVt || touchInst) {
          sb.AppendLine("  anchor=0x" + anchor.ToString("X") + " func=0x" + fs.ToString("X")
            + " vt=" + touchVt + " inst=" + touchInst + " t98=" + t98);
          var rep = Analyze(sb, fs, "enroll-touches-owner");
          enrollTouch.Add(rep);
          hit++;
        }
      }
    }

    // Cross: SideBlockAlloc (+0x98) callers vs spatial installers
    sb.AppendLine();
    sb.AppendLine("===== +0x98 SIDEBLOCK vs SPATIAL INSTALLERS =====");
    var sideCallers = FindE8(SideBlockAlloc, 80);
    sb.AppendLine("E8->SideBlockAlloc(0xE95E80)=" + sideCallers.Count);
    var sideFuncs = new HashSet<uint>(sideCallers.Select(FindFuncStart));
    // Spatial installers call into +0x98 init — already known. Check if side callers also LEA spat VT
    int sideVt = 0;
    foreach (uint fs in sideFuncs.Take(40)) {
      uint fe = FindFuncEnd(fs, 0x800);
      if (fe <= fs) fe = fs + 0x200;
      foreach (var i in DisasmRaw(fs, Math.Min(fe, fs + 0x600))) {
        if (i.IpRel && (i.DataRva == SpatVt || i.DataRva == NeighVt)) {
          sb.AppendLine("  sideCaller 0x" + fs.ToString("X") + " LEA vt 0x" + i.DataRva.ToString("X"));
          sideVt++;
          break;
        }
        if (i.IsCall && Installers.Contains(i.NearTarget)) {
          sb.AppendLine("  sideCaller 0x" + fs.ToString("X") + " CALL inst 0x" + i.NearTarget.ToString("X"));
          sideVt++;
          break;
        }
      }
    }
    sb.AppendLine("sideCallersTouchingOwnerVtOrInst=" + sideVt);

    // Arming relation: do arming/wrap funcs appear in ctor call graphs?
    sb.AppendLine();
    sb.AppendLine("===== ARMING CROSS =====");
    foreach (uint a in new[] { Arming, ArmWrap, GateSetter }) {
      bool inCtorCallees = reps.Any(r => r.Callees.Contains(a));
      bool inEnrollTouch = enrollTouch.Any(r => r.Callees.Contains(a) || r.Entry == a);
      sb.AppendLine("  0x" + a.ToString("X") + " inCtorCallees=" + inCtorCallees
        + " inEnrollTouchSet=" + inEnrollTouch
        + " E8count=" + FindE8(a, 40).Count);
    }

    // Summary cross
    sb.AppendLine();
    sb.AppendLine("===== CROSS =====");
    bool haveCtorCallers = reps.Any(r => r.Role == "ctor-or-caller");
    bool spatTouches98 = reps.Any(r =>
      (r.Entry == SpatInstA || r.Entry == SpatInstB || r.CallsSpatInst) && (r.Touches98 || r.CallsSide98));
    // Spatial installers themselves touch +0x98 in body
    bool spatInst98 = reps.Any(r => Installers.Contains(r.Entry) && r.Entry != NeighInst && r.Touches98);
    sb.AppendLine("haveCtorCallers=" + haveCtorCallers);
    sb.AppendLine("spatInstallerTouches98=" + spatInst98);
    sb.AppendLine("enrollLinkedCtorReps=" + linked.Count);
    sb.AppendLine("enrollFuncsTouchingOwnerVt=" + enrollTouch.Count);
    sb.AppendLine("neighInstCallers=" + FindE8(NeighInst, 80).Count);
    sb.AppendLine("spatInstACallers=" + FindE8(SpatInstA, 80).Count);
    sb.AppendLine("spatInstBCallers=" + FindE8(SpatInstB, 80).Count);

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteJson(hash, reps, linked, enrollTouch, spatInst98);

    bool ok = reps.Count > 0 && (FindE8(NeighInst, 20).Count + FindE8(SpatInstA, 20).Count
      + FindE8(SpatInstB, 20).Count + FindLeaTo(NeighVt, 10).Count + FindLeaTo(SpatVt, 10).Count) > 0;
    Console.WriteLine("selfCheck reps=" + reps.Count
      + " linked=" + linked.Count
      + " enrollTouch=" + enrollTouch.Count
      + " spat98=" + spatInst98
      + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static FuncRep Analyze(StringBuilder sb, uint entry, string role) {
    var r = new FuncRep { Entry = entry, Role = role };
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
      if (head++ < 48)
        r.Disasm.Add("0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 88) + Mark(i));
      if (i.IpRel && i.DataRva == LookupKey) { r.UsesKey = true; r.Notes.Add("KEY @0x" + i.Rva.ToString("X")); }
      if (i.IpRel && i.DataRva == NeighVt) { r.LeasNeighVt = true; r.Notes.Add("NEIGH_VT @0x" + i.Rva.ToString("X")); }
      if (i.IpRel && i.DataRva == SpatVt) { r.LeasSpatVt = true; r.Notes.Add("SPAT_VT @0x" + i.Rva.ToString("X")); }
      if (i.HasMem && !i.IpRel) {
        if (i.Disp == 0x98) r.Touches98 = true;
        if (i.Disp == 0x61) r.Touches61 = true;
        if (i.Disp == 0x2B0) r.Vcall2B0 = true;
      }
      // add/lea reg, 0x98 — spatial installers init side-block via pointer advance
      if ((i.Mnemonic == Mnemonic.Add || i.Mnemonic == Mnemonic.Lea)
          && (i.Text.Contains(",98") || i.Text.Contains("+98") || i.Text.Contains("+0x98")
              || i.Text.EndsWith("98h") || i.HasImm && i.Imm == 0x98)) {
        r.Touches98 = true;
        r.Notes.Add("ADD_OR_LEA_98 @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 40));
      }
      if (i.IsIndirectCall && (i.Disp == 0x2B0 || i.Text.Contains("+2B0"))) r.Vcall2B0 = true;
      if (i.IsCall && !i.IsIndirectCall) {
        r.Callees.Add(i.NearTarget);
        if (i.NearTarget == Lookup) { r.CallsLookup = true; r.Notes.Add("LOOKUP @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Allocator) { r.CallsAlloc = true; r.Notes.Add("ALLOC @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Enqueue) { r.CallsEnqueue = true; r.Notes.Add("ENQUEUE @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Wrapper) { r.CallsWrapper = true; r.Notes.Add("WRAPPER @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == SideBlockAlloc) { r.CallsSide98 = true; r.Notes.Add("SIDE98 @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Arming) { r.CallsArming = true; r.Notes.Add("ARMING @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == ArmWrap) { r.CallsArmWrap = true; r.Notes.Add("ARMWRAP @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == GateSetter) { r.CallsGate = true; r.Notes.Add("GATE @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Helper546) { r.CallsHelper = true; r.Notes.Add("HELPER @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == NeighInst) { r.CallsNeighInst = true; r.CallsInstaller = true; r.Notes.Add("NEIGH_INST @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == SpatInstA || i.NearTarget == SpatInstB || i.NearTarget == SpatInstHelper) {
          r.CallsSpatInst = true; r.CallsInstaller = true;
          r.Notes.Add("SPAT_INST 0x" + i.NearTarget.ToString("X") + " @0x" + i.Rva.ToString("X"));
        }
      }
      if (i.IpRel) {
        string s = ReadAscii(i.DataRva, 48);
        if (IsString(s) && s.Length >= 5 && !r.Strings.Contains(s)) r.Strings.Add(s);
      }
    }
    sb.AppendLine("key=" + r.UsesKey + " alloc=" + r.CallsAlloc + " lookup=" + r.CallsLookup
      + " enq=" + r.CallsEnqueue + " wrap=" + r.CallsWrapper
      + " side98=" + r.CallsSide98 + " arm=" + r.CallsArming + " armWrap=" + r.CallsArmWrap
      + " gate=" + r.CallsGate + " t98=" + r.Touches98 + " t61=" + r.Touches61
      + " neighVt=" + r.LeasNeighVt + " spatVt=" + r.LeasSpatVt
      + " inst=" + r.CallsInstaller
      + " callees=" + r.Callees.Distinct().Count());
    foreach (var n in r.Notes.Take(16)) sb.AppendLine("  " + n);
    foreach (var s in r.Strings.Take(5)) sb.AppendLine("  str \"" + Trunc(s, 55) + "\"");
    foreach (var c in r.Callees.Distinct().Take(16)) {
      string mark = "";
      if (c == Allocator) mark = " *** ALLOC ***";
      if (c == Enqueue) mark = " *** ENQUEUE ***";
      if (c == SideBlockAlloc) mark = " *** SIDE98 ***";
      if (c == Arming) mark = " *** ARMING ***";
      if (c == ArmWrap) mark = " *** ARMWRAP ***";
      if (Installers.Contains(c)) mark = " *** INSTALLER ***";
      sb.AppendLine("  callee 0x" + c.ToString("X") + mark);
    }
    sb.AppendLine("--- head ---");
    foreach (var line in r.Disasm.Take(32)) sb.AppendLine(line);
    return r;
  }

  static string Mark(Ins i) {
    string mark = "";
    if (i.NearTarget == Allocator) mark = " *** ALLOC ***";
    if (i.NearTarget == Lookup) mark = " *** LOOKUP ***";
    if (i.NearTarget == Enqueue) mark = " *** ENQUEUE ***";
    if (i.NearTarget == Wrapper) mark = " *** WRAPPER ***";
    if (i.NearTarget == SideBlockAlloc) mark = " *** SIDE98 ***";
    if (i.NearTarget == Arming) mark = " *** ARMING ***";
    if (i.NearTarget == ArmWrap) mark = " *** ARMWRAP ***";
    if (i.NearTarget == GateSetter) mark = " *** GATE ***";
    if (i.NearTarget == Helper546) mark = " *** HELPER ***";
    if (Installers.Contains(i.NearTarget)) mark = " *** INSTALLER ***";
    if (i.IpRel && i.DataRva == NeighVt) mark += " *** NEIGH_VT ***";
    if (i.IpRel && i.DataRva == SpatVt) mark += " *** SPAT_VT ***";
    if (i.IpRel && i.DataRva == LookupKey) mark += " *** KEY ***";
    if (i.HasMem && !i.IpRel && i.Disp == 0x98) mark += " *** +98 ***";
    if (i.HasMem && !i.IpRel && i.Disp == 0x61) mark += " *** +61 ***";
    if (i.IsIndirectCall) mark += " *** ICALL ***";
    return mark;
  }

  static void DeepDump(StringBuilder sb, uint a, uint b, string title) {
    sb.AppendLine("--- " + title + " 0x" + a.ToString("X") + "..0x" + b.ToString("X") + " ---");
    foreach (var ins in DisasmRaw(a, b).Take(60))
      sb.AppendLine("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 90) + Mark(ins));
  }

  static void WriteJson(string hash, List<FuncRep> reps, List<FuncRep> linked,
      List<FuncRep> enrollTouch, bool spat98) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.25\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"vtOwners\": {");
    sb.AppendLine("    \"neighVt\": \"0x976B2D0\",");
    sb.AppendLine("    \"spatVt\": \"0x9236E00\",");
    sb.AppendLine("    \"neighInstCallers\": " + FindE8(NeighInst, 80).Count + ",");
    sb.AppendLine("    \"spatInstACallers\": " + FindE8(SpatInstA, 80).Count + ",");
    sb.AppendLine("    \"spatInstBCallers\": " + FindE8(SpatInstB, 80).Count + ",");
    sb.AppendLine("    \"funcsDecoded\": " + reps.Count + ",");
    sb.AppendLine("    \"ctorOrCallerFuncs\": [" + string.Join(", ",
      reps.Where(r => r.Role == "ctor-or-caller").Select(r => "\"0x" + r.Entry.ToString("X") + "\"").Take(30)) + "]");
    sb.AppendLine("  },");
    sb.AppendLine("  \"enrollmentLink\": {");
    sb.AppendLine("    \"spatInstallerTouches98\": " + T(spat98) + ",");
    sb.AppendLine("    \"enrollLinkedCtorReps\": " + linked.Count + ",");
    sb.AppendLine("    \"enrollFuncsTouchingOwnerVt\": " + enrollTouch.Count + ",");
    sb.AppendLine("    \"linkedFuncs\": [" + string.Join(", ",
      linked.Select(r => "\"0x" + r.Entry.ToString("X") + "\"").Take(20)) + "]");
    sb.AppendLine("  },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.25-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.25-summary.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.25\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"funcs\": [");
    var all = reps.Concat(enrollTouch)
      .GroupBy(r => r.Entry).Select(g => g.First()).OrderBy(r => r.Entry).ToList();
    for (int i = 0; i < all.Count; i++) {
      var r = all[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + r.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(r.Role) + ",");
      sb.AppendLine("      \"size\": " + r.Size + ",");
      sb.AppendLine("      \"usesKey\": " + T(r.UsesKey) + ",");
      sb.AppendLine("      \"callsAlloc\": " + T(r.CallsAlloc) + ",");
      sb.AppendLine("      \"callsEnqueue\": " + T(r.CallsEnqueue) + ",");
      sb.AppendLine("      \"callsSide98\": " + T(r.CallsSide98) + ",");
      sb.AppendLine("      \"callsArming\": " + T(r.CallsArming) + ",");
      sb.AppendLine("      \"callsArmWrap\": " + T(r.CallsArmWrap) + ",");
      sb.AppendLine("      \"touches98\": " + T(r.Touches98) + ",");
      sb.AppendLine("      \"touches61\": " + T(r.Touches61) + ",");
      sb.AppendLine("      \"leasNeighVt\": " + T(r.LeasNeighVt) + ",");
      sb.AppendLine("      \"leasSpatVt\": " + T(r.LeasSpatVt) + ",");
      sb.AppendLine("      \"notes\": [" + string.Join(", ", r.Notes.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"callees\": [" + string.Join(", ",
        r.Callees.Distinct().Take(18).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", r.Disasm.Take(28).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < all.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.25-funcs-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.25-funcs-deep.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.25\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Owner VT constructors and enrollment links do not prove Edward create/possession\" },");
    string oClass = reps.Any(r => r.Role == "ctor-or-caller" && (r.CallsInstaller || r.LeasNeighVt || r.LeasSpatVt))
      ? "partial" : "unsupported";
    sb.AppendLine("  \"ownerObjectConstruction\": { \"class\": \"" + oClass + "\", \"reason\": "
      + J("Mapped installer callers / VT LEA sites for 0x976B2D0 and 0x9236E00; see funcs-deep") + " },");
    string eClass = (spat98 || linked.Count > 0 || enrollTouch.Count > 0) ? "partial" : "unsupported";
    sb.AppendLine("  \"enrollmentRelation\": { \"class\": \"" + eClass + "\", \"reason\": "
      + J("spatInstallerTouches98=" + spat98 + " enrollLinked=" + linked.Count
        + " enrollTouchVt=" + enrollTouch.Count) + " },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Deep-decode strongest owner constructors that Alloc+install VT; prove shared object with enrollment +0x98/arming\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"expect E8 to Outer ctor\", \"treat helper position extract as possession\", \"+0x61-only ranking\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.25-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.25-second-edward-feasibility.json");
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
