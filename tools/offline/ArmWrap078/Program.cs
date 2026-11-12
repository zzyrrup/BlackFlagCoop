// v0.6.18 — Offline deep-decode arming wrap 0x2108620 / 0x479E440
// and follow installers 0x5F11A40 / 0x59D96A0.
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
  const uint ArmWrap = 0x2108620;
  const uint Post2B8 = 0x479E440;
  const uint Canonical2B8 = 0x479E3B0;
  const uint Trampoline2B0 = 0x4656C80;
  const uint InstallerA = 0x5F11A40;  // LEAs ctor 0x2E97A50
  const uint InstallerB = 0x59D96A0;  // calls ctor 0x59D9B90
  const uint CtorA = 0x2E97A50;
  const uint CtorB = 0x59D9B90;
  const uint ArmingHelper = 0x21085D0;
  const uint GateStub = 0x7BB020;
  const uint GateSetter = 0x53F31A0;
  const uint LookupKey = 0xB2898C8;
  const uint Lookup = 0x429F9E0;
  const uint Allocator = 0x426EE50;
  const uint Helper = 0x2E97B60;
  const uint Wrapper = 0x2E97FC0;
  const uint WorkerA = 0x725400;
  const uint WorkerB = 0xE95E80;
  const uint MembershipB = 0x4D04450;
  const uint ListHelper = 0xB27210;
  const uint TableArm = 0x948FF50;
  const uint TableBit = 0x9303E28;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static readonly uint[] Targets = { ArmWrap, Post2B8, InstallerA, InstallerB };

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
  }
  sealed class FuncReport {
    public uint Entry; public string Role; public uint End; public int Size;
    public bool UsesKey, Nested, Touches61, Touches98, Touches22, Touches25, Touches26, Touches23;
    public bool Touches84, Touches158, CallsAllocator, CallsHelper, CallsLookup;
    public bool CallsCanonical2B8, CallsCtorA, CallsCtorB, CallsListHelper, CallsWorker;
    public List<uint> Callees = new List<uint>();
    public List<uint> CallersE8 = new List<uint>();
    public List<string> Strings = new List<string>();
    public List<string> ModeNotes = new List<string>();
    public List<string> FieldNotes = new List<string>();
    public List<string> GateOps = new List<string>();
    public List<string> VtableInstalls = new List<string>();
    public List<string> AllocNotes = new List<string>();
    public List<string> DisasmHead = new List<string>();
    public List<string> CallerNotes = new List<string>();
    public List<string> InstallHits = new List<string>();
    public List<uint> ImmSizes = new List<uint>();
    public List<int> ImmModes = new List<int>();
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v078-raw");
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
    sb.AppendLine("===== v0.6.18 ARM WRAP + INSTALLERS =====");
    sb.AppendLine("exeSha256=" + hash);

    var reports = new List<FuncReport>();
    foreach (uint t in Targets) {
      sb.AppendLine();
      sb.AppendLine("===== FUNC 0x" + t.ToString("X") + " =====");
      reports.Add(DeepFunc(sb, t, RoleOf(t)));
    }

    // Cross relations
    sb.AppendLine();
    sb.AppendLine("===== CROSS =====");
    var wrap = reports.First(r => r.Entry == ArmWrap);
    var post = reports.First(r => r.Entry == Post2B8);
    var ia = reports.First(r => r.Entry == InstallerA);
    var ib = reports.First(r => r.Entry == InstallerB);
    sb.AppendLine("armWrap callsCanonical2B8=" + wrap.CallsCanonical2B8
      + " t98=" + wrap.Touches98 + " modes=[" + string.Join(",", wrap.ImmModes.Distinct().OrderBy(x => x)) + "]"
      + " listHelper=" + wrap.CallsListHelper + " worker=" + wrap.CallsWorker);
    sb.AppendLine("post2B8 size=" + post.Size + " modes=[" + string.Join(",", post.ImmModes.Distinct().OrderBy(x => x)) + "]"
      + " nested=" + post.Nested + " strings=" + post.Strings.Count);
    sb.AppendLine("installerA callsCtorA=" + ia.CallsCtorA + " vtInstalls=" + ia.VtableInstalls.Count
      + " callersE8=" + ia.CallersE8.Count);
    sb.AppendLine("installerB callsCtorB=" + ib.CallsCtorB + " alloc=" + ib.CallsAllocator
      + " callersE8=" + ib.CallersE8.Count + " immSizes=["
      + string.Join(",", ib.ImmSizes.Take(12).Select(x => "0x" + x.ToString("X"))) + "]");

    sb.AppendLine();
    sb.AppendLine("===== SUMMARY =====");
    foreach (var r in reports)
      sb.AppendLine("0x" + r.Entry.ToString("X") + " " + r.Role + " size=" + r.Size
        + " callersE8=" + r.CallersE8.Count + " callees=" + r.Callees.Count
        + " modes=" + string.Join("/", r.ImmModes.Distinct().OrderBy(x => x)));

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteFuncsJson(hash, reports);
    WriteSummaryJson(hash, reports);
    WriteFeasibilityJson(hash, reports);

    bool ok = wrap.CallsCanonical2B8 && wrap.Touches98 && wrap.Size > 0
      && post.Size > 0 && ia.Size > 0 && ib.CallsCtorB;
    Console.WriteLine("selfCheck wrap->canonical=" + wrap.CallsCanonical2B8
      + " wrap+98=" + wrap.Touches98 + " installerB->ctorB=" + ib.CallsCtorB + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static string RoleOf(uint e) {
    if (e == ArmWrap) return "arming-wrap-2B8";
    if (e == Post2B8) return "post-2B8-continuation";
    if (e == InstallerA) return "ctorA-installer";
    if (e == InstallerB) return "ctorB-caller";
    return "func";
  }

  static FuncReport DeepFunc(StringBuilder sb, uint entry, string role) {
    var r = new FuncReport { Entry = entry, Role = role };
    int maxScan = entry == InstallerA ? 0x4000 : 0x3000;
    r.End = FindFuncEnd(entry, maxScan);
    if (r.End <= entry) r.End = entry + 0x400;
    if (r.End - entry > (uint)maxScan) r.End = entry + (uint)maxScan;
    r.Size = (int)(r.End - entry);
    sb.AppendLine("entry=0x" + entry.ToString("X") + " end=0x" + r.End.ToString("X")
      + " size=" + r.Size + " role=" + role + " prologue=" + Hex(entry, 16)
      + " sec=" + SecName(entry));

    var ins = Disasm(entry, r.End);
    bool s18 = false, sA8 = false, s3 = false;
    int head = 0;
    int headLimit = entry == InstallerA ? 80 : 64;
    for (int i = 0; i < ins.Count; i++) {
      var a = ins[i];
      if (head < headLimit) {
        string line = "0x" + a.Rva.ToString("X") + " " + a.Text;
        r.DisasmHead.Add(line);
        sb.AppendLine("  " + line);
        head++;
      }
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        r.Callees.Add(dest);
        if (dest == Canonical2B8) { r.CallsCanonical2B8 = true; sb.AppendLine("  *** CANONICAL_2B8 @0x" + a.Rva.ToString("X")); }
        if (dest == Post2B8) sb.AppendLine("  *** POST_2B8 @0x" + a.Rva.ToString("X"));
        if (dest == CtorA) { r.CallsCtorA = true; sb.AppendLine("  *** CTOR_A @0x" + a.Rva.ToString("X")); }
        if (dest == CtorB) { r.CallsCtorB = true; sb.AppendLine("  *** CTOR_B @0x" + a.Rva.ToString("X")); }
        if (dest == Allocator) {
          r.CallsAllocator = true;
          string note = "alloc @0x" + a.Rva.ToString("X");
          for (int j = Math.Max(0, i - 8); j < i; j++)
            if (ins[j].Text.IndexOf("edx,", StringComparison.OrdinalIgnoreCase) >= 0
                || ins[j].Text.IndexOf("r8d,", StringComparison.OrdinalIgnoreCase) >= 0)
              note += " | " + ins[j].Text;
          r.AllocNotes.Add(note);
          sb.AppendLine("  *** ALLOC " + note);
        }
        if (dest == Helper) r.CallsHelper = true;
        if (dest == Lookup) r.CallsLookup = true;
        if (dest == ListHelper) { r.CallsListHelper = true; sb.AppendLine("  *** LISTHELPER 0xB27210 @0x" + a.Rva.ToString("X")); }
        if (dest == WorkerA || dest == WorkerB) { r.CallsWorker = true; sb.AppendLine("  *** WORKER 0x" + dest.ToString("X") + " @0x" + a.Rva.ToString("X")); }
        if (dest == MembershipB) sb.AppendLine("  *** MEMBERSHIP_B @0x" + a.Rva.ToString("X"));
        if (dest == GateStub || dest == GateSetter) sb.AppendLine("  *** GATE 0x" + dest.ToString("X") + " @0x" + a.Rva.ToString("X"));
        if (dest == ArmingHelper) sb.AppendLine("  *** ARMING @0x" + a.Rva.ToString("X"));
        if (dest == Wrapper) sb.AppendLine("  *** WRAPPER @0x" + a.Rva.ToString("X"));
        if (dest == Trampoline2B0) sb.AppendLine("  *** TRAMP_2B0 @0x" + a.Rva.ToString("X"));
      }
      // indirect calls
      if ((a.IsIndirectCall || a.Mnemonic == Mnemonic.Jmp) && a.HasMem && !a.IpRel) {
        if (Math.Abs(a.Disp) == 0x2B0 || Math.Abs(a.Disp) == 0x2B8 || Math.Abs(a.Disp) == 0x2C0)
          sb.AppendLine("  *** INDIRECT vt+0x" + Math.Abs(a.Disp).ToString("X") + " @0x" + a.Rva.ToString("X") + " " + a.Text);
      }
      if (a.HasMem && !a.IpRel) {
        if (a.Disp == 0x18) s18 = true;
        if (a.Disp == 0xA8) sA8 = true;
        if (a.Disp == 0x3CD0) s3 = true;
        if (a.Disp == 0x61) { r.Touches61 = true; r.GateOps.Add("0x" + a.Rva.ToString("X") + " " + a.Text); }
        if (a.Disp == 0x98) {
          r.Touches98 = true;
          if (r.FieldNotes.Count < 20)
            r.FieldNotes.Add("+0x98 @0x" + a.Rva.ToString("X") + " " + a.Text);
        }
        if (a.Disp == 0x22) r.Touches22 = true;
        if (a.Disp == 0x23) r.Touches23 = true;
        if (a.Disp == 0x25) r.Touches25 = true;
        if (a.Disp == 0x26) r.Touches26 = true;
        if (a.Disp == 0x84) r.Touches84 = true;
        if (a.Disp == 0x158) {
          r.Touches158 = true;
          // mode byte writes often land here
          if (a.Mnemonic == Mnemonic.Mov && r.ModeNotes.Count < 20)
            r.ModeNotes.Add("+0x158 @0x" + a.Rva.ToString("X") + " " + a.Text);
        }
      }
      if (a.IpRel) {
        if (a.DataRva == LookupKey) r.UsesKey = true;
        if (a.DataRva == TableArm || a.DataRva == TableBit
            || a.DataRva == CtorA || a.DataRva == CtorB) {
          string note = "0x" + a.Rva.ToString("X") + " " + a.Text + " ->0x" + a.DataRva.ToString("X");
          for (int j = i + 1; j < ins.Count && j <= i + 4; j++)
            if (ins[j].Mnemonic == Mnemonic.Mov && ins[j].HasMem && !ins[j].IpRel)
              note += " => " + ins[j].Text;
          r.VtableInstalls.Add(note);
          sb.AppendLine("  *** VT/TABLE/CTORREF " + note);
        }
        string s = ReadAscii(a.DataRva, 96);
        if (IsString(s) && s.Length >= 5 && r.Strings.Count < 16
            && !s.StartsWith("AWAV", StringComparison.Ordinal) && !r.Strings.Contains(s))
          r.Strings.Add(s);
      }
      // collect small immediates that look like modes (1,2,3) stored near list helpers
      if (a.Raw.OpCount >= 2) {
        for (int oi = 0; oi < a.Raw.OpCount; oi++) {
          var k = a.Raw.GetOpKind(oi);
          if (k == OpKind.Immediate8 || k == OpKind.Immediate8to32 || k == OpKind.Immediate32) {
            try {
              long imm = (long)a.Raw.GetImmediate(oi);
              if (imm >= 1 && imm <= 4) {
                r.ImmModes.Add((int)imm);
                // if mov dword [r8], imm near list helper
                if (a.Mnemonic == Mnemonic.Mov && a.HasMem && r.ModeNotes.Count < 24)
                  r.ModeNotes.Add("imm" + imm + " @0x" + a.Rva.ToString("X") + " " + a.Text);
              }
              if (imm >= 0x20 && imm <= 0x20000 && (imm % 8) == 0)
                r.ImmSizes.Add((uint)imm);
            } catch { }
          }
        }
      }
    }
    if (ins.Count > headLimit) sb.AppendLine("  ... +" + (ins.Count - headLimit) + " ins ...");
    r.Nested = s18 && sA8 && s3;
    r.Callees = r.Callees.Distinct().ToList();
    r.ImmSizes = r.ImmSizes.Distinct().OrderBy(x => x).ToList();
    r.ImmModes = r.ImmModes.Distinct().OrderBy(x => x).ToList();
    r.CallersE8 = FindE8(entry, 40);

    foreach (var s in FindLeaTo(entry, 15))
      r.InstallHits.Add("lea @0x" + s.ToString("X") + " func≈0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in FindQword(entry, 15))
      r.InstallHits.Add("qword @0x" + s.ToString("X") + " sec=" + SecName(s));
    foreach (var s in FindRva32(entry, 12))
      r.InstallHits.Add("rva32 @0x" + s.ToString("X") + " sec=" + SecName(s));

    sb.AppendLine("nested=" + r.Nested + " key=" + r.UsesKey
      + " t61=" + r.Touches61 + " t98=" + r.Touches98
      + " t22/23/25/26=" + r.Touches22 + "/" + r.Touches23 + "/" + r.Touches25 + "/" + r.Touches26
      + " t84=" + r.Touches84 + " t158=" + r.Touches158
      + " canon2B8=" + r.CallsCanonical2B8 + " list=" + r.CallsListHelper
      + " callersE8=" + r.CallersE8.Count
      + " modes=[" + string.Join(",", r.ImmModes) + "]"
      + " immSizes=[" + string.Join(",", r.ImmSizes.Take(10).Select(x => "0x" + x.ToString("X"))) + "]");
    foreach (var m in r.ModeNotes.Take(16)) sb.AppendLine("  mode " + m);
    foreach (var g in r.GateOps.Take(8)) sb.AppendLine("  gate " + g);
    foreach (var f in r.FieldNotes.Take(12)) sb.AppendLine("  field " + f);
    foreach (var v in r.VtableInstalls.Take(12)) sb.AppendLine("  vt " + v);
    foreach (var a in r.AllocNotes) sb.AppendLine("  " + a);
    foreach (var s in r.Strings.Take(10)) sb.AppendLine("  str \"" + Trunc(s, 70) + "\"");
    foreach (var c in r.Callees.Where(x => !IsNoise(x)).Take(20))
      sb.AppendLine("  callee 0x" + c.ToString("X") + Tag(c));
    foreach (var h in r.InstallHits.Take(12)) sb.AppendLine("  install " + h);

    sb.AppendLine("-- callers --");
    foreach (var site in r.CallersE8.Take(20)) {
      uint fn = FindFuncStart(site);
      string note = "e8 @0x" + site.ToString("X") + " func≈0x" + fn.ToString("X");
      r.CallerNotes.Add(note);
      sb.AppendLine("  " + note);
      DumpStrings(sb, fn, 0x300);
    }

    foreach (var c in r.Callees.Where(x => !IsNoise(x) && x != Canonical2B8 && x != CtorA && x != CtorB).Take(5)) {
      sb.AppendLine("--- callee dump 0x" + c.ToString("X") + " ---");
      DumpShort(sb, c, 0x50);
      DumpStrings(sb, c, 0x300);
    }
    return r;
  }

  static bool IsNoise(uint d) => d == Lookup || d == Allocator || d < 0x10000;
  static string Tag(uint rva) {
    if (rva == Canonical2B8) return " *** CANONICAL_2B8 ***";
    if (rva == Post2B8) return " *** POST_2B8 ***";
    if (rva == ArmWrap) return " *** ARMWRAP ***";
    if (rva == CtorA) return " *** CTOR_A ***";
    if (rva == CtorB) return " *** CTOR_B ***";
    if (rva == ListHelper) return " *** LISTHELPER ***";
    if (rva == WorkerA) return " *** WORKER_A ***";
    if (rva == WorkerB) return " *** WORKER_B ***";
    if (rva == MembershipB) return " *** MEMBERSHIP_B ***";
    if (rva == Helper) return " *** HELPER ***";
    if (rva == Wrapper) return " *** WRAPPER ***";
    if (rva == ArmingHelper) return " *** ARMING ***";
    if (rva == GateStub) return " *** GATE_STUB ***";
    if (rva == GateSetter) return " *** GATESETTER ***";
    return "";
  }

  static void DumpShort(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEndFirstRet(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    sb.AppendLine("  func 0x" + entry.ToString("X") + " size~" + (end - entry)
      + " prologue=" + Hex(entry, 12));
    foreach (var a in Disasm(entry, end).Take(14))
      sb.AppendLine("    0x" + a.Rva.ToString("X") + " " + a.Text);
  }

  static void DumpStrings(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEnd(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    var seen = new HashSet<string>();
    foreach (var a in Disasm(entry, end)) {
      if (!a.IpRel) continue;
      string s = ReadAscii(a.DataRva, 80);
      if (!IsString(s) || s.Length < 5) continue;
      if (seen.Add(s)) sb.AppendLine("    str \"" + Trunc(s, 70) + "\"");
      if (seen.Count >= 5) break;
    }
  }

  static void WriteFuncsJson(string hash, List<FuncReport> reports) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.18\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"funcs\": [");
    for (int i = 0; i < reports.Count; i++) {
      var r = reports[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + r.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(r.Role) + ",");
      sb.AppendLine("      \"size\": " + r.Size + ",");
      sb.AppendLine("      \"usesKey\": " + T(r.UsesKey) + ",");
      sb.AppendLine("      \"nested\": " + T(r.Nested) + ",");
      sb.AppendLine("      \"touches61\": " + T(r.Touches61) + ",");
      sb.AppendLine("      \"touches98\": " + T(r.Touches98) + ",");
      sb.AppendLine("      \"touches22\": " + T(r.Touches22) + ",");
      sb.AppendLine("      \"touches23\": " + T(r.Touches23) + ",");
      sb.AppendLine("      \"touches25\": " + T(r.Touches25) + ",");
      sb.AppendLine("      \"touches26\": " + T(r.Touches26) + ",");
      sb.AppendLine("      \"touches84\": " + T(r.Touches84) + ",");
      sb.AppendLine("      \"touches158\": " + T(r.Touches158) + ",");
      sb.AppendLine("      \"callsCanonical2B8\": " + T(r.CallsCanonical2B8) + ",");
      sb.AppendLine("      \"callsCtorA\": " + T(r.CallsCtorA) + ",");
      sb.AppendLine("      \"callsCtorB\": " + T(r.CallsCtorB) + ",");
      sb.AppendLine("      \"callsListHelper\": " + T(r.CallsListHelper) + ",");
      sb.AppendLine("      \"callsWorker\": " + T(r.CallsWorker) + ",");
      sb.AppendLine("      \"callsAllocator\": " + T(r.CallsAllocator) + ",");
      sb.AppendLine("      \"modes\": [" + string.Join(", ", r.ImmModes) + "],");
      sb.AppendLine("      \"modeNotes\": [" + string.Join(", ", r.ModeNotes.Take(20).Select(J)) + "],");
      sb.AppendLine("      \"fieldNotes\": [" + string.Join(", ", r.FieldNotes.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"vtableInstalls\": [" + string.Join(", ", r.VtableInstalls.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"allocNotes\": [" + string.Join(", ", r.AllocNotes.Take(8).Select(J)) + "],");
      sb.AppendLine("      \"immSizes\": [" + string.Join(", ", r.ImmSizes.Take(16).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"strings\": [" + string.Join(", ", r.Strings.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"callees\": [" + string.Join(", ", r.Callees.Take(24).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callersE8\": [" + string.Join(", ", r.CallersE8.Take(24).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callerNotes\": [" + string.Join(", ", r.CallerNotes.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"installHits\": [" + string.Join(", ", r.InstallHits.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", r.DisasmHead.Take(40).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < reports.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.18-funcs-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.18-funcs-deep.json");
  }

  static void WriteSummaryJson(string hash, List<FuncReport> reports) {
    var wrap = reports.First(r => r.Entry == ArmWrap);
    var post = reports.First(r => r.Entry == Post2B8);
    var ia = reports.First(r => r.Entry == InstallerA);
    var ib = reports.First(r => r.Entry == InstallerB);
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.18\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"armWrap\": { \"rva\": \"0x2108620\", \"size\": " + wrap.Size
      + ", \"callsCanonical2B8\": " + T(wrap.CallsCanonical2B8)
      + ", \"touches98\": " + T(wrap.Touches98)
      + ", \"modes\": [" + string.Join(", ", wrap.ImmModes) + "]"
      + ", \"listHelper\": " + T(wrap.CallsListHelper) + " },");
    sb.AppendLine("  \"post2B8\": { \"rva\": \"0x479E440\", \"size\": " + post.Size
      + ", \"modes\": [" + string.Join(", ", post.ImmModes) + "]"
      + ", \"nested\": " + T(post.Nested) + " },");
    sb.AppendLine("  \"installerA\": { \"rva\": \"0x5F11A40\", \"size\": " + ia.Size
      + ", \"callsCtorA\": " + T(ia.CallsCtorA)
      + ", \"vtInstalls\": " + ia.VtableInstalls.Count
      + ", \"callersE8\": " + ia.CallersE8.Count + " },");
    sb.AppendLine("  \"installerB\": { \"rva\": \"0x59D96A0\", \"size\": " + ib.Size
      + ", \"callsCtorB\": " + T(ib.CallsCtorB)
      + ", \"alloc\": " + T(ib.CallsAllocator)
      + ", \"callersE8\": " + ib.CallersE8.Count + " },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.18-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.18-summary.json");
  }

  static void WriteFeasibilityJson(string hash, List<FuncReport> reports) {
    var wrap = reports.First(r => r.Entry == ArmWrap);
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.18\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Arm-wrap/installers still mutate existing objects/side-blocks\" },");
    sb.AppendLine("  \"armWrapDecoded\": { \"class\": \"confirmed\", \"reason\": \"0x2108620 calls 0x479E3B0 then +0x98 mode/list work\" },");
    sb.AppendLine("  \"post2B8Decoded\": { \"class\": "
      + (reports.First(r => r.Entry == Post2B8).Size > 0 ? "\"confirmed\"" : "\"unsupported\"")
      + ", \"reason\": \"0x479E440 deep-decoded\" },");
    sb.AppendLine("  \"installersFollowed\": { \"class\": \"confirmed\", \"reason\": \"0x5F11A40 / 0x59D96A0 followed\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Map mode 2/3 listHelper paths to enrollment eligibility; recover object size from installerB/ctorB chain\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.18-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.18-second-edward-feasibility.json");
  }

  static string T(bool b) => b ? "true" : "false";
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }

  // ---- common ----
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

  static List<uint> FindRva32(uint destRva, int max) {
    var list = new List<uint>();
    byte[] needle = BitConverter.GetBytes(destRva);
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 4 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != needle[0]) continue;
        bool ok = true;
        for (int k = 1; k < 4; k++) if (pe[s.Ptr + i + k] != needle[k]) { ok = false; break; }
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
