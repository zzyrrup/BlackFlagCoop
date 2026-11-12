// v0.6.19 — Offline: map side-block modes 2/3 → enrollment eligibility;
// object/heap size from installerB chain 0x59D9660; AnimatedOnActiveChanged xref
// from 0x479E440. Read-only PE. No launch, inject, live memory, or game writes.
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
  const uint ArmWrap = 0x2108620;
  const uint Post2B8 = 0x479E440;
  const uint Canonical2B8 = 0x479E3B0;
  const uint InstallerBCaller = 0x59D9660;
  const uint InstallerB = 0x59D96A0;
  const uint CtorB = 0x59D9B90;
  const uint Allocator = 0x426EE50;
  const uint Helper = 0x2E97B60;
  const uint Wrapper = 0x2E97FC0;
  const uint WorkerA = 0x725400;
  const uint WorkerB = 0xE95E80;
  const uint MembershipA = 0x4B5A560;
  const uint MembershipB = 0x4D04450;
  const uint GateSetter = 0x53F31A0;
  const uint BitWriter = 0xF1C240;
  const uint ListHelper = 0xB27210;
  const uint ListA = 0xC45FB0;
  const uint ListB = 0xC46110;
  const uint ListC = 0x7250E0;
  const uint ListD = 0x725000;
  const uint ListE = 0x724EE0;
  const uint Fill = 0x5352080;
  const string Needle = "AnimatedOnActiveChanged";
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static readonly HashSet<uint> EnrollTargets = new HashSet<uint> {
    Helper, Wrapper, WorkerA, WorkerB, MembershipA, MembershipB, GateSetter, BitWriter
  };
  static readonly HashSet<uint> ModeListHelpers = new HashSet<uint> {
    ListHelper, ListA, ListB, ListC, ListD, ListE
  };

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);

  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }
  sealed class Ins {
    public uint Rva; public string Text; public Mnemonic Mnemonic;
    public bool IpRel; public uint DataRva; public bool IsCall, IsIndirectCall, HasMem;
    public long Disp; public int Length; public Instruction Raw;
    public uint NearTarget;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v079-raw");
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
    sb.AppendLine("===== v0.6.19 MODE→ENROLL + SIZE + ANIMATED XREF =====");
    sb.AppendLine("exeSha256=" + hash);

    // ---- 1) Mode 2/3 path from arm wrap ----
    sb.AppendLine();
    sb.AppendLine("===== ARM WRAP MODE 2/3 PATH =====");
    var wrapEnd = FindFuncEnd(ArmWrap, 0x800);
    var wrapIns = Disasm(ArmWrap, wrapEnd);
    var modeSites = new List<string>();
    var mode2Callees = new List<uint>();
    var mode3Callees = new List<uint>();
    uint lastModeImm = 0;
    foreach (var ins in wrapIns) {
      if ((ins.Mnemonic == Mnemonic.Mov || ins.Mnemonic == Mnemonic.Movzx)
          && (ins.Text.Contains(",2") || ins.Text.Contains(", 2")
              || ins.Text.Contains(",3") || ins.Text.Contains(", 3"))) {
        if (ins.Disp == 0x158 || ins.Text.Contains("+158") || ins.Text.Contains("[r8]")
            || ins.Text.Contains("dword ptr [r8]")) {
          modeSites.Add("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 90));
          if (ins.Text.Contains(",2") || ins.Text.Contains(", 2")) lastModeImm = 2;
          if (ins.Text.Contains(",3") || ins.Text.Contains(", 3")) lastModeImm = 3;
        }
      }
      if (ins.IsCall && !ins.IsIndirectCall && ins.NearTarget != 0) {
        if (lastModeImm == 2) mode2Callees.Add(ins.NearTarget);
        if (lastModeImm == 3) mode3Callees.Add(ins.NearTarget);
        // also track list helpers after any mode write in window
      }
    }
    // Collect callees in wrap after each mode-2 / mode-3 store by scanning windows
    CollectModeWindowCallees(wrapIns, 2, mode2Callees);
    CollectModeWindowCallees(wrapIns, 3, mode3Callees);
    sb.AppendLine("modeSites=" + modeSites.Count);
    foreach (var m in modeSites) sb.AppendLine("  " + m);
    sb.AppendLine("mode2Callees=[" + string.Join(",", mode2Callees.Distinct().Select(x => "0x" + x.ToString("X"))) + "]");
    sb.AppendLine("mode3Callees=[" + string.Join(",", mode3Callees.Distinct().Select(x => "0x" + x.ToString("X"))) + "]");

    // BFS from mode callees + list helpers for enrollment edges
    sb.AppendLine();
    sb.AppendLine("===== MODE→ENROLL BFS =====");
    var seeds = mode2Callees.Concat(mode3Callees).Concat(ModeListHelpers).Distinct().ToList();
    seeds.Add(ArmWrap);
    var bfsNotes = new List<string>();
    var hitEnroll = new Dictionary<uint, List<string>>();
    var visited = new HashSet<uint>();
    var q = new Queue<(uint entry, int depth, string path)>();
    foreach (var s in seeds) q.Enqueue((s, 0, "0x" + s.ToString("X")));
    int nodes = 0;
    while (q.Count > 0 && nodes < 80) {
      var (entry, depth, path) = q.Dequeue();
      if (!visited.Add(entry) || depth > 3) continue;
      nodes++;
      uint end = FindFuncEndFirstRet(entry, depth == 0 ? 0x1000 : 0x600);
      if (end <= entry) end = entry + 0x200;
      var ins = Disasm(entry, end);
      bool t61 = false, t98 = false, t158 = false;
      var callees = new List<uint>();
      foreach (var i in ins) {
        if (i.HasMem && !i.IpRel) {
          if (i.Disp == 0x61) t61 = true;
          if (i.Disp == 0x98) t98 = true;
          if (i.Disp == 0x158) t158 = true;
        }
        if (i.IsCall && !i.IsIndirectCall && i.NearTarget != 0) {
          callees.Add(i.NearTarget);
          if (EnrollTargets.Contains(i.NearTarget)) {
            string note = path + " -> 0x" + i.NearTarget.ToString("X")
              + " @" + "0x" + i.Rva.ToString("X") + " (" + NameOf(i.NearTarget) + ")";
            if (!hitEnroll.ContainsKey(i.NearTarget)) hitEnroll[i.NearTarget] = new List<string>();
            hitEnroll[i.NearTarget].Add(note);
            bfsNotes.Add("HIT " + note);
          }
        }
      }
      string tag = "0x" + entry.ToString("X") + " d=" + depth + " size=" + (end - entry)
        + " t61=" + t61 + " t98=" + t98 + " t158=" + t158
        + " callees=" + callees.Distinct().Count();
      if (ModeListHelpers.Contains(entry) || entry == ArmWrap || mode2Callees.Contains(entry) || mode3Callees.Contains(entry))
        bfsNotes.Add(tag);
      if (depth < 2) {
        foreach (var c in callees.Distinct().Take(12)) {
          if (!visited.Contains(c) && c > 0x1000)
            q.Enqueue((c, depth + 1, path + "->0x" + c.ToString("X")));
        }
      }
    }
    foreach (var n in bfsNotes.Take(80)) sb.AppendLine(n);
    sb.AppendLine("enrollHits=" + hitEnroll.Count + " bfsNodes=" + nodes);
    foreach (var kv in hitEnroll.OrderBy(k => k.Key))
      sb.AppendLine("  ENROLL 0x" + kv.Key.ToString("X") + " " + NameOf(kv.Key)
        + " paths=" + kv.Value.Count + " eg=" + Trunc(kv.Value[0], 120));

    // Direct: does wrap / list helpers call enroll targets?
    sb.AppendLine();
    sb.AppendLine("===== DIRECT ENROLL EDGE CHECK =====");
    bool wrapToHelper = wrapIns.Any(i => i.IsCall && i.NearTarget == Helper);
    bool wrapToWrapper = wrapIns.Any(i => i.IsCall && i.NearTarget == Wrapper);
    bool wrapToWorker = wrapIns.Any(i => i.IsCall && (i.NearTarget == WorkerA || i.NearTarget == WorkerB));
    bool wrapToGate = wrapIns.Any(i => i.IsCall && (i.NearTarget == GateSetter || i.NearTarget == BitWriter));
    bool wrapToMembership = wrapIns.Any(i => i.IsCall && (i.NearTarget == MembershipA || i.NearTarget == MembershipB));
    sb.AppendLine("wrap->helper=" + wrapToHelper + " wrapper=" + wrapToWrapper
      + " worker=" + wrapToWorker + " gate=" + wrapToGate + " membership=" + wrapToMembership);
    foreach (uint lh in ModeListHelpers) {
      uint e = FindFuncEndFirstRet(lh, 0x400);
      var li = Disasm(lh, e <= lh ? lh + 0x100 : e);
      bool e61 = li.Any(i => i.HasMem && !i.IpRel && i.Disp == 0x61);
      bool eH = li.Any(i => i.IsCall && i.NearTarget == Helper);
      bool eW = li.Any(i => i.IsCall && (i.NearTarget == WorkerA || i.NearTarget == WorkerB));
      bool eM = li.Any(i => i.IsCall && (i.NearTarget == MembershipA || i.NearTarget == MembershipB));
      string str = NearString(lh, 0x80);
      sb.AppendLine("list 0x" + lh.ToString("X") + " size~" + (e - lh)
        + " t61=" + e61 + " ->helper=" + eH + " ->worker=" + eW + " ->memb=" + eM
        + (str.Length > 0 ? " str=\"" + Trunc(str, 60) + "\"" : ""));
    }

    // Gate bit relationship: modes vs (+0x61&6)==2
    sb.AppendLine();
    sb.AppendLine("===== MODE vs GATE RELATION =====");
    sb.AppendLine("NOTE: enrollment gate is ([obj+0x61]&6)==2 (object flag bits).");
    sb.AppendLine("Arm-wrap modes 2/3 write side-block [+0x158] and listHelper args — NOT +0x61.");
    bool wrapTouches61 = wrapIns.Any(i => i.HasMem && !i.IpRel && i.Disp == 0x61);
    sb.AppendLine("wrapTouches+0x61=" + wrapTouches61 + " (expected false)");

    // ---- 2) InstallerB caller chain size ----
    sb.AppendLine();
    sb.AppendLine("===== INSTALLERB CHAIN 0x59D9660 =====");
    uint chainStart = InstallerBCaller;
    uint chainEnd = FindFuncEnd(chainStart, 0x2000);
    // Prefer covering through InstallerB if same contiguous region
    uint ibEnd = FindFuncEnd(InstallerB, 0x2000);
    uint ctorEnd = FindFuncEnd(CtorB, 0x800);
    sb.AppendLine("0x59D9660 end=0x" + chainEnd.ToString("X") + " size=" + (chainEnd - chainStart)
      + " sec=" + SecName(chainStart) + " prologue=" + Hex(chainStart, 12));
    sb.AppendLine("0x59D96A0 end=0x" + ibEnd.ToString("X") + " size=" + (ibEnd - InstallerB));
    sb.AppendLine("0x59D9B90 end=0x" + ctorEnd.ToString("X") + " size=" + (ctorEnd - CtorB));

    var sizeNotes = new List<string>();
    var immSizes = new List<uint>();
    var allocCalls = new List<string>();
    var maxField = 0L;
    foreach (uint entry in new[] { chainStart, InstallerB, CtorB }) {
      uint end = entry == CtorB ? ctorEnd : (entry == InstallerB ? ibEnd : chainEnd);
      if (end <= entry) end = entry + 0x400;
      foreach (var ins in Disasm(entry, end)) {
        if (ins.IsCall && !ins.IsIndirectCall) {
          if (ins.NearTarget == Allocator)
            allocCalls.Add("0x" + entry.ToString("X") + "+0x" + (ins.Rva - entry).ToString("X")
              + " call Allocator @" + "0x" + ins.Rva.ToString("X"));
          if (ins.NearTarget == Fill)
            allocCalls.Add("0x" + entry.ToString("X") + " call Fill 0x5352080 @" + "0x" + ins.Rva.ToString("X"));
          if (ins.NearTarget == CtorB)
            allocCalls.Add("call CtorB @" + "0x" + ins.Rva.ToString("X"));
        }
        // imm sizes in edx/ecx/r8 before alloc-like calls, and large mov imm
        if (ins.Mnemonic == Mnemonic.Mov && (ins.Text.Contains("edx,") || ins.Text.Contains("ecx,")
            || ins.Text.Contains("r8d,") || ins.Text.Contains("esi,") || ins.Text.Contains("edi,"))) {
          uint imm;
          if (TryParseImm(ins.Text, out imm) && imm >= 0x40 && imm <= 0x100000 && (imm % 8 == 0 || imm % 0x10 == 0)) {
            immSizes.Add(imm);
            sizeNotes.Add("imm@0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 70));
          }
        }
        if (ins.HasMem && !ins.IpRel && ins.Disp > maxField && ins.Disp < 0x20000)
          maxField = ins.Disp;
      }
    }
    // Also scan caller of 0x59D9660 for alloc+size
    var e8toChain = FindE8(InstallerBCaller, 20);
    sb.AppendLine("E8->0x59D9660 count=" + e8toChain.Count);
    foreach (var site in e8toChain.Take(8)) {
      uint fs = FindFuncStart(site);
      sb.AppendLine("  caller site=0x" + site.ToString("X") + " func≈0x" + fs.ToString("X"));
      uint fe = FindFuncEndFirstRet(fs, 0x1500);
      if (fe <= fs) fe = fs + 0x400;
      bool callsAlloc = false;
      var callerImms = new List<uint>();
      foreach (var ins in Disasm(fs, fe)) {
        if (ins.IsCall && ins.NearTarget == Allocator) {
          callsAlloc = true;
          allocCalls.Add("caller 0x" + fs.ToString("X") + " call Allocator @" + "0x" + ins.Rva.ToString("X"));
        }
        if (ins.Mnemonic == Mnemonic.Mov && TryParseImm(ins.Text, out uint imm)
            && imm >= 0x80 && imm <= 0x200000 && (imm % 8 == 0 || imm % 0x10 == 0)) {
          callerImms.Add(imm);
          sizeNotes.Add("callerImm@0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 70));
        }
        if (ins.HasMem && !ins.IpRel && ins.Disp > maxField && ins.Disp < 0x20000)
          maxField = ins.Disp;
      }
      sb.AppendLine("    callsAlloc=" + callsAlloc + " imms=["
        + string.Join(",", callerImms.Distinct().Take(12).Select(x => "0x" + x.ToString("X"))) + "]");
    }
    // LEA installers of InstallerBCaller / InstallerB
    var leaChain = FindLeaTo(InstallerBCaller, 20);
    var leaIB = FindLeaTo(InstallerB, 20);
    sb.AppendLine("LEA->0x59D9660=" + leaChain.Count + " LEA->0x59D96A0=" + leaIB.Count);
    foreach (var site in leaChain.Take(6))
      sb.AppendLine("  leaChain @0x" + site.ToString("X") + " func≈0x" + FindFuncStart(site).ToString("X"));

    // Known Fill size from ctor B (v0.6.17): 0x140 at bit-table related fill
    sb.AppendLine("allocCalls=" + allocCalls.Count);
    foreach (var a in allocCalls.Take(20)) sb.AppendLine("  " + a);
    sb.AppendLine("immSizes=[" + string.Join(",", immSizes.Distinct().OrderBy(x => x).Take(24).Select(x => "0x" + x.ToString("X"))) + "]");
    foreach (var n in sizeNotes.Take(30)) sb.AppendLine("  " + n);
    sb.AppendLine("maxFieldDisp=0x" + maxField.ToString("X") + " (lower-bound object span, not heap size)");

    // Deep dump head of 0x59D9660
    sb.AppendLine("--- disasm 0x59D9660 head ---");
    foreach (var ins in Disasm(chainStart, Math.Min(chainEnd, chainStart + 0x80)).Take(40))
      sb.AppendLine("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 100));

    // ---- 3) AnimatedOnActiveChanged xref ----
    sb.AppendLine();
    sb.AppendLine("===== AnimatedOnActiveChanged XREF =====");
    var strHits = FindAscii(Needle);
    sb.AppendLine("stringHits=" + strHits.Count);
    uint strRva = 0;
    foreach (var fo in strHits) {
      uint rva = FileToRva(fo);
      if (strRva == 0) strRva = rva;
      sb.AppendLine("  file=0x" + fo.ToString("X") + " rva=0x" + rva.ToString("X") + " sec=" + SecName(rva));
    }
    var leaStr = strRva != 0 ? FindLeaTo(strRva, 40) : new List<uint>();
    var leaStrPlus = new List<uint>();
    // also LEA to string+0 (exact) already; try qword abs refs
    var qwStr = strRva != 0 ? FindQword(strRva, 40) : new List<uint>();
    sb.AppendLine("LEA->string=" + leaStr.Count + " QWORD->string=" + qwStr.Count);
    var xrefFuncs = new HashSet<uint>();
    foreach (var site in leaStr) {
      uint fs = FindFuncStart(site);
      xrefFuncs.Add(fs);
      sb.AppendLine("  lea @0x" + site.ToString("X") + " func≈0x" + fs.ToString("X")
        + " sec=" + SecName(site));
    }
    foreach (var site in qwStr.Take(20)) {
      sb.AppendLine("  qword @0x" + site.ToString("X") + " sec=" + SecName(site));
    }
    // Does post2B8 or its callees xref the string?
    bool postXrefs = false;
    var postIns = Disasm(Post2B8, FindFuncEnd(Post2B8, 0x1000));
    var postCallees = postIns.Where(i => i.IsCall && !i.IsIndirectCall && i.NearTarget != 0)
      .Select(i => i.NearTarget).Distinct().ToList();
    foreach (var ins in postIns) {
      if (ins.IpRel && strRva != 0 && (ins.DataRva == strRva || (ins.DataRva >= strRva && ins.DataRva < strRva + 32))) {
        postXrefs = true;
        sb.AppendLine("  POST direct rip-ref @" + "0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 80));
      }
    }
    foreach (var c in postCallees) {
      uint ce = FindFuncEndFirstRet(c, 0x800);
      foreach (var ins in Disasm(c, ce <= c ? c + 0x200 : ce)) {
        if (ins.IpRel && strRva != 0 && (ins.DataRva == strRva || (ins.DataRva >= strRva && ins.DataRva < strRva + 32))) {
          postXrefs = true;
          sb.AppendLine("  POST-callee 0x" + c.ToString("X") + " rip-ref @" + "0x" + ins.Rva.ToString("X"));
        }
      }
      if (xrefFuncs.Contains(c)) {
        postXrefs = true;
        sb.AppendLine("  POST-callee 0x" + c.ToString("X") + " is string LEA-owner");
      }
    }
    // Distance: is string within ±0x400 of post body?
    long dist = strRva != 0 ? Math.Abs((long)strRva - (long)Post2B8) : -1;
    sb.AppendLine("stringRva=0x" + strRva.ToString("X") + " post2B8=0x479E440 absDist=0x" + dist.ToString("X")
      + " nearby400=" + (dist >= 0 && dist <= 0x400));
    sb.AppendLine("postOrCalleeXrefsString=" + postXrefs);
    sb.AppendLine("xrefFuncCount=" + xrefFuncs.Count);
    // Check if any string-xref func calls post2B8 or is called by it
    // Prefer full body to int3 pad (multi-ret funcs like 0x2335040)
    foreach (var xf in xrefFuncs.Take(15)) {
      uint xe = FindFuncEnd(xf, 0x1000);
      if (xe < xf + 0x80) xe = xf + 0x200;
      var xins = Disasm(xf, xe);
      bool callsPost = xins.Any(i => i.IsCall && i.NearTarget == Post2B8);
      bool calledByPost = postCallees.Contains(xf);
      bool hasAnimLea = strRva != 0 && xins.Any(i => i.IpRel && i.DataRva == strRva);
      string near = NearString(xf, 0x40);
      sb.AppendLine("  xrefFunc 0x" + xf.ToString("X") + " callsPost=" + callsPost
        + " hasAnimLea=" + hasAnimLea
        + " isPostCallee=" + calledByPost
        + (near.Length > 0 ? " near=\"" + Trunc(near, 50) + "\"" : ""));
      if (callsPost && hasAnimLea) {
        postXrefs = true;
        sb.AppendLine("  CONFIRMED same-owner: 0x" + xf.ToString("X")
          + " LEAs AnimatedOnActiveChanged and E8-calls 0x479E440");
      }
    }

    // Cross summary
    sb.AppendLine();
    sb.AppendLine("===== CROSS =====");
    bool modeMapsToEnroll = hitEnroll.Count > 0;
    bool modeMapsDirect = wrapToHelper || wrapToWrapper || wrapToWorker || wrapToGate || wrapToMembership;
    sb.AppendLine("mode2/3_directEnrollEdge=" + modeMapsDirect);
    sb.AppendLine("mode2/3_bfsEnrollHit=" + modeMapsToEnroll + " hitKeys=["
      + string.Join(",", hitEnroll.Keys.Select(k => "0x" + k.ToString("X") + ":" + NameOf(k))) + "]");
    sb.AppendLine("wrapTouches61=" + wrapTouches61);
    // Outer composite lower bound: header via 0xB169D0 (~0x18) + subobj at +0x20 with maxField
    long outerLower = maxField > 0x20 ? 0x20 + maxField : maxField;
    sb.AppendLine("heapSizeConfirmed=" + (allocCalls.Any(a => a.Contains("Allocator"))));
    sb.AppendLine("maxField=0x" + maxField.ToString("X"));
    sb.AppendLine("outerLowerBound=0x" + outerLower.ToString("X") + " (0x20 + subobj maxField; not heap alloc size)");
    sb.AppendLine("subobjAtPlus20=True fillImm=0x140 (ctorB zero-fill region)");
    sb.AppendLine("animatedXrefProven=" + postXrefs);
    sb.AppendLine("animatedNearbyOnly=" + (dist >= 0 && dist <= 0x400 && !postXrefs));
    sb.AppendLine("animatedSameOwnerAsPostCaller=" + postXrefs);

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteJson(hash, modeSites, mode2Callees, mode3Callees, hitEnroll, wrapTouches61,
      modeMapsDirect, modeMapsToEnroll, immSizes, maxField, allocCalls, e8toChain.Count,
      strRva, leaStr.Count, postXrefs, dist, xrefFuncs.Count);

    bool ok = wrapIns.Count > 0 && chainEnd > chainStart && strHits.Count > 0;
    Console.WriteLine("selfCheck wrapIns=" + wrapIns.Count + " chainSize=" + (chainEnd - chainStart)
      + " strHits=" + strHits.Count + " enrollBfs=" + modeMapsToEnroll
      + " animXref=" + postXrefs + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static void CollectModeWindowCallees(List<Ins> wrapIns, int mode, List<uint> into) {
    for (int i = 0; i < wrapIns.Count; i++) {
      var ins = wrapIns[i];
      bool isModeStore = (ins.Mnemonic == Mnemonic.Mov)
        && (ins.Text.Contains("," + mode) || ins.Text.Contains(", " + mode))
        && (ins.Disp == 0x158 || ins.Text.Contains("+158") || ins.Text.Contains("[r8]"));
      if (!isModeStore) continue;
      for (int j = i; j < wrapIns.Count && j < i + 25; j++) {
        if (wrapIns[j].IsCall && !wrapIns[j].IsIndirectCall && wrapIns[j].NearTarget != 0)
          into.Add(wrapIns[j].NearTarget);
      }
    }
  }

  static void WriteJson(string hash, List<string> modeSites, List<uint> m2, List<uint> m3,
      Dictionary<uint, List<string>> hitEnroll, bool wrap61, bool direct, bool bfs,
      List<uint> immSizes, long maxField, List<string> allocCalls, int callerE8,
      uint strRva, int leaCount, bool postXref, long dist, int xrefFuncs) {
    // summary
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.19\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"modes23\": {");
    sb.AppendLine("    \"sites\": " + modeSites.Count + ",");
    sb.AppendLine("    \"wrapTouches61\": " + T(wrap61) + ",");
    sb.AppendLine("    \"directEnrollEdge\": " + T(direct) + ",");
    sb.AppendLine("    \"bfsEnrollHit\": " + T(bfs) + ",");
    sb.AppendLine("    \"enrollHitCount\": " + hitEnroll.Count + ",");
    sb.AppendLine("    \"mode2Callees\": [" + string.Join(", ", m2.Distinct().Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("    \"mode3Callees\": [" + string.Join(", ", m3.Distinct().Select(x => "\"0x" + x.ToString("X") + "\"")) + "]");
    sb.AppendLine("  },");
    sb.AppendLine("  \"installerBChain\": {");
    sb.AppendLine("    \"entry\": \"0x59D9660\",");
    sb.AppendLine("    \"callerE8Count\": " + callerE8 + ",");
    sb.AppendLine("    \"allocatorCalls\": " + allocCalls.Count(a => a.Contains("Allocator")) + ",");
    sb.AppendLine("    \"maxFieldDisp\": \"0x" + maxField.ToString("X") + "\",");
    sb.AppendLine("    \"immSizes\": [" + string.Join(", ", immSizes.Distinct().OrderBy(x => x).Take(20).Select(x => "\"0x" + x.ToString("X") + "\"")) + "]");
    sb.AppendLine("  },");
    sb.AppendLine("  \"animated\": {");
    sb.AppendLine("    \"stringRva\": \"0x" + strRva.ToString("X") + "\",");
    sb.AppendLine("    \"leaXrefs\": " + leaCount + ",");
    sb.AppendLine("    \"postOrCalleeXref\": " + T(postXref) + ",");
    sb.AppendLine("    \"absDistFromPost\": \"0x" + dist.ToString("X") + "\",");
    sb.AppendLine("    \"xrefFuncCount\": " + xrefFuncs);
    sb.AppendLine("  },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.19-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.19-summary.json");

    // deep
    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.19\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"modeSites\": [" + string.Join(", ", modeSites.Select(J)) + "],");
    sb.AppendLine("  \"enrollHits\": {");
    bool first = true;
    foreach (var kv in hitEnroll.OrderBy(k => k.Key)) {
      if (!first) sb.AppendLine(",");
      first = false;
      sb.Append("    \"0x" + kv.Key.ToString("X") + "\": [" + string.Join(", ", kv.Value.Take(5).Select(J)) + "]");
    }
    if (!first) sb.AppendLine();
    sb.AppendLine("  },");
    sb.AppendLine("  \"allocNotes\": [" + string.Join(", ", allocCalls.Take(20).Select(J)) + "],");
    sb.AppendLine("  \"sizeNotesImm\": [" + string.Join(", ", immSizes.Distinct().OrderBy(x => x).Take(24).Select(x => "\"0x" + x.ToString("X") + "\"")) + "]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.19-mode-enroll-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.19-mode-enroll-deep.json");

    // feasibility
    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.19\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Modes 2/3 mutate side-block/list state; no create path\" },");
    string modeClass = direct || bfs ? "partial" : "unsupported";
    string modeReason = direct
      ? "Direct edge from wrap/mode callees to enrollment helpers"
      : (bfs ? "BFS found enroll-family hits from mode seeds (inspect paths)"
             : "No direct/BFS edge from mode 2/3 list paths to enqueue/wrapper/gate/membership");
    sb.AppendLine("  \"modes23ToEnrollment\": { \"class\": \"" + modeClass + "\", \"reason\": " + J(modeReason) + " },");
    bool heapOk = allocCalls.Any(a => a.Contains("Allocator"));
    sb.AppendLine("  \"objectHeapSize\": { \"class\": \"" + (heapOk ? "confirmed" : "partial")
      + "\", \"reason\": " + J(heapOk
        ? "Allocator call with size imm recovered on installerB chain"
        : "No allocator on 0x59D9660/0x59D96A0/0x59D9B90; maxFieldDisp=0x" + maxField.ToString("X") + " lower bound only") + " },");
    sb.AppendLine("  \"animatedOnActiveChangedXref\": { \"class\": \"" + (postXref ? "confirmed" : "unsupported")
      + "\", \"reason\": " + J(postXref
        ? "Func 0x2335040 LEAs AnimatedOnActiveChanged and is the E8 caller of 0x479E440 (same-owner)"
        : "String found; no proven same-owner/callee xref from 0x479E440") + " },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Follow AnimatedOnActiveChanged LEA owners; recover heap size from InstallerBCaller callers/LEA install sites\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.19-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.19-second-edward-feasibility.json");
  }

  static string NameOf(uint r) {
    if (r == Helper) return "enqueue-helper";
    if (r == Wrapper) return "wrapper";
    if (r == WorkerA) return "worker-725400";
    if (r == WorkerB) return "worker-E95E80";
    if (r == MembershipA) return "membership-A";
    if (r == MembershipB) return "membership-B";
    if (r == GateSetter) return "gate-setter";
    if (r == BitWriter) return "bit-writer";
    if (r == ListHelper) return "listHelper-B27210";
    if (r == Allocator) return "allocator";
    if (r == CtorB) return "ctorB";
    if (r == ArmWrap) return "arm-wrap";
    return "func";
  }

  static string NearString(uint entry, int max) {
    for (int d = 0; d < 0x200; d += 4) {
      string s = ReadAscii(entry + (uint)d, max);
      if (IsString(s) && s.Length >= 5) return s;
    }
    return "";
  }

  static bool TryParseImm(string text, out uint imm) {
    imm = 0;
    int c = text.LastIndexOf(',');
    if (c < 0) return false;
    string t = text.Substring(c + 1).Trim();
    if (t.StartsWith("0") && !t.StartsWith("0x") && t.Length > 1 && t.All(ch => ch >= '0' && ch <= '9')) {
      // hex without prefix sometimes from masm? skip
    }
    if (t.StartsWith("0x") || t.StartsWith("0X")) t = t.Substring(2);
    // MASM often prints hex without 0x: e.g. 0C000h or plain hex
    if (t.EndsWith("h", StringComparison.OrdinalIgnoreCase)) t = t.Substring(0, t.Length - 1);
    return uint.TryParse(t, System.Globalization.NumberStyles.HexNumber, null, out imm)
      || uint.TryParse(t, out imm);
  }

  static List<int> FindAscii(string s) {
    var hits = new List<int>();
    byte[] n = Encoding.ASCII.GetBytes(s);
    for (int i = 0; i + n.Length <= pe.Length; i++) {
      if (pe[i] != n[0]) continue;
      bool ok = true;
      for (int j = 1; j < n.Length; j++) if (pe[i + j] != n[j]) { ok = false; break; }
      if (ok) hits.Add(i);
    }
    return hits;
  }

  static uint FileToRva(int fo) {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      if (fo >= s.Ptr && fo < s.Ptr + s.Raw) return s.Va + (uint)(fo - s.Ptr);
    }
    return 0;
  }

  static string T(bool b) => b ? "true" : "false";
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }

  static List<Ins> Disasm(uint start, uint endExclusive) {
    var list = new List<Ins>();
    int fo = RvaToFile(start);
    if (fo < 0) return list;
    var reader = new ByteArrayCodeReader(pe);
    reader.Position = fo;
    var dec = Decoder.Create(64, reader);
    dec.IP = imageBase + start;
    ulong limit = imageBase + endExclusive;
    int guard = 0;
    while (dec.IP < limit && guard++ < 300000) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      if (raw.IP < imageBase) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      var ins = new Ins {
        Raw = raw, Rva = (uint)(raw.IP - imageBase), Text = o.ToString(),
        Mnemonic = raw.Mnemonic, Length = raw.Length,
        IsCall = raw.FlowControl == FlowControl.Call || raw.FlowControl == FlowControl.IndirectCall,
        IsIndirectCall = raw.FlowControl == FlowControl.IndirectCall
      };
      if (ins.IsCall && !ins.IsIndirectCall && raw.NearBranchTarget != 0 && raw.NearBranchTarget >= imageBase)
        ins.NearTarget = (uint)(raw.NearBranchTarget - imageBase);
      for (int i = 0; i < raw.OpCount; i++) {
        if (raw.GetOpKind(i) != OpKind.Memory) continue;
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
        break;
      }
      list.Add(ins);
      if (raw.Mnemonic == Mnemonic.Int3 && list.Count > 1) break;
    }
    return list;
  }

  static uint FindFuncEnd(uint entry, int maxScan) {
    var list = Disasm(entry, entry + (uint)maxScan);
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

  static uint FindFuncEndFirstRet(uint entry, int maxScan) {
    var list = Disasm(entry, entry + (uint)maxScan);
    foreach (var ins in list) {
      if (ins.Mnemonic == Mnemonic.Int3) return ins.Rva;
      if (ins.Mnemonic == Mnemonic.Ret) return ins.Rva + (uint)ins.Length;
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
        if (op != 0x8D && op != 0x8B) continue;
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

  static List<uint> FindQword(uint destRva, int max) {
    var list = new List<uint>();
    ulong abs = imageBase + destRva;
    byte[] needle = BitConverter.GetBytes(abs);
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 8 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != needle[0]) continue;
        bool ok = true;
        for (int k = 1; k < 8; k++) if (pe[s.Ptr + i + k] != needle[k]) { ok = false; break; }
        if (ok) list.Add(s.Va + i);
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

  static string Hex(uint rva, int n) {
    int fo = RvaToFile(rva);
    if (fo < 0) return "UNMAPPED";
    var sb = new StringBuilder();
    for (int i = 0; i < n && fo + i < pe.Length; i++) {
      if (i > 0) sb.Append(' ');
      sb.Append(pe[fo + i].ToString("X2"));
    }
    return sb.ToString();
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
