// v0.6.17 — Offline expected [vt+0x2B0]/[vt+0x2B8] from 0x43E7750
// and follow ctors 0x2E97A50 / 0x59D9B90.
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
  const uint Validator = 0x43E7750;
  const uint CtorA = 0x2E97A50;   // installs 0x948FF50
  const uint CtorB = 0x59D9B90;   // installs 0x9303E28 at +0x1D0
  const uint ArmingHelper = 0x21085D0;
  const uint GateStub = 0x7BB020;
  const uint GateSetter = 0x53F31A0;
  const uint BitWriter = 0xF1C240;
  const uint LookupKey = 0xB2898C8;
  const uint Lookup = 0x429F9E0;
  const uint Allocator = 0x426EE50;
  const uint Helper = 0x2E97B60;
  const uint Wrapper = 0x2E97FC0;
  const uint WorkerA = 0x725400;
  const uint WorkerB = 0xE95E80;
  const uint MembershipB = 0x4D04450;
  const uint TableArm = 0x948FF50;
  const uint TableBit = 0x9303E28;
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
    public long Disp; public int Length; public Instruction Raw;
  }
  sealed class ExpectedSlot {
    public uint VtOff; public uint CompareSite; public uint LeaSite; public uint ExpectedRva;
    public string Note = "";
  }
  sealed class FuncReport {
    public uint Entry; public string Role; public uint End; public int Size;
    public bool UsesKey, Nested, Touches61, Touches98, Touches2B0, Touches2B8;
    public bool CallsAllocator, CallsHelper, CallsLookup, CallsGateStub;
    public List<uint> Callees = new List<uint>();
    public List<uint> CallersE8 = new List<uint>();
    public List<string> Strings = new List<string>();
    public List<string> GateOps = new List<string>();
    public List<string> FieldNotes = new List<string>();
    public List<string> VtableInstalls = new List<string>();
    public List<string> AllocNotes = new List<string>();
    public List<string> DisasmHead = new List<string>();
    public List<string> CallerNotes = new List<string>();
    public List<uint> ImmSizes = new List<uint>();
    public List<string> InstallHits = new List<string>();
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v077-raw");
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
    sb.AppendLine("===== v0.6.17 VT +0x2B0/+0x2B8 + CTORS =====");
    sb.AppendLine("exeSha256=" + hash);

    // 1) Validator decode + extract expected callees
    sb.AppendLine();
    sb.AppendLine("===== VALIDATOR 0x43E7750 =====");
    var expected = ExtractExpected(sb);

    // 2) Deep-decode expected methods
    var expectedFuncs = new List<FuncReport>();
    foreach (var e in expected.Where(x => x.ExpectedRva != 0).GroupBy(x => x.ExpectedRva).Select(g => g.First())) {
      sb.AppendLine();
      sb.AppendLine("===== EXPECTED METHOD vt+0x" + e.VtOff.ToString("X")
        + " = 0x" + e.ExpectedRva.ToString("X") + " =====");
      expectedFuncs.Add(DeepFunc(sb, e.ExpectedRva, "vt+0x" + e.VtOff.ToString("X") + "-expected"));
    }

    // 3) Deep-decode ctors
    var ctors = new List<FuncReport>();
    foreach (var c in new[] { CtorA, CtorB }) {
      sb.AppendLine();
      sb.AppendLine("===== CTOR 0x" + c.ToString("X") + " =====");
      ctors.Add(DeepFunc(sb, c, c == CtorA ? "ctor-arm-table" : "ctor-bit-table"));
    }

    // 4) Cross-check: do expected methods appear in installed tables?
    sb.AppendLine();
    sb.AppendLine("===== TABLE SLOT CROSS-CHECK =====");
    foreach (var e in expected) {
      if (e.ExpectedRva == 0) continue;
      ScanTableFor(sb, TableArm, 0x200, e.ExpectedRva, "armTable");
      ScanTableFor(sb, TableBit, 0x100, e.ExpectedRva, "bitTable");
      // also search absolute qword of expected method
      var qw = FindQword(e.ExpectedRva, 20);
      sb.AppendLine("expected 0x" + e.ExpectedRva.ToString("X") + " qwordHits=" + qw.Count);
      foreach (var s in qw.Take(12))
        sb.AppendLine("  qw @0x" + s.ToString("X") + " sec=" + SecName(s)
          + " offFromArm=" + ((long)s - TableArm).ToString("X")
          + " offFromBit=" + ((long)s - TableBit).ToString("X"));
    }

    sb.AppendLine();
    sb.AppendLine("===== SUMMARY =====");
    foreach (var e in expected)
      sb.AppendLine("vt+0x" + e.VtOff.ToString("X") + " expected=0x" + e.ExpectedRva.ToString("X")
        + " lea@0x" + e.LeaSite.ToString("X"));
    foreach (var f in expectedFuncs.Concat(ctors))
      sb.AppendLine("0x" + f.Entry.ToString("X") + " " + f.Role + " size=" + f.Size
        + " alloc=" + f.CallsAllocator + " key=" + f.UsesKey
        + " t61=" + f.Touches61 + " callersE8=" + f.CallersE8.Count
        + " vtInstalls=" + f.VtableInstalls.Count);

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteExpectedJson(hash, expected, expectedFuncs);
    WriteCtorsJson(hash, ctors);
    WriteSummaryJson(hash, expected, expectedFuncs, ctors);
    WriteFeasibilityJson(hash, expected, expectedFuncs, ctors);

    bool ok = expected.Count >= 2
      && expected.All(e => e.ExpectedRva != 0)
      && ctors.All(c => c.Size > 0)
      && expectedFuncs.All(f => f.Size > 0);
    Console.WriteLine("selfCheck expected=" + expected.Count
      + " methods=" + expectedFuncs.Count + " ctors=" + ctors.Count + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static List<ExpectedSlot> ExtractExpected(StringBuilder sb) {
    var list = new List<ExpectedSlot>();
    uint end = FindFuncEnd(Validator, 0x400);
    if (end <= Validator) end = Validator + 0x100;
    sb.AppendLine("validator size=" + (end - Validator) + " prologue=" + Hex(Validator, 16));
    var ins = Disasm(Validator, end);
    for (int i = 0; i < ins.Count; i++) {
      sb.AppendLine("  0x" + ins[i].Rva.ToString("X") + " " + ins[i].Text);
      // look for mov rax,[reg+0x2B0/0x2B8] followed soon by lea r?,[rip+..] and cmp
      if (!ins[i].HasMem || ins[i].IpRel) continue;
      if (ins[i].Disp != 0x2B0 && ins[i].Disp != 0x2B8) continue;
      if (ins[i].Mnemonic != Mnemonic.Mov) continue;
      uint vtOff = (uint)ins[i].Disp;
      // find next LEA with IpRel within ~8 ins, then CMP
      for (int j = i + 1; j < ins.Count && j <= i + 8; j++) {
        if (ins[j].Mnemonic != Mnemonic.Lea || !ins[j].IpRel) continue;
        uint expected = ins[j].DataRva;
        var slot = new ExpectedSlot {
          VtOff = vtOff,
          CompareSite = ins[i].Rva,
          LeaSite = ins[j].Rva,
          ExpectedRva = expected,
          Note = "cmp against LEA target"
        };
        list.Add(slot);
        sb.AppendLine("  *** EXPECTED vt+0x" + vtOff.ToString("X")
          + " = 0x" + expected.ToString("X") + " sec=" + SecName(expected)
          + " prologue=" + Hex(expected, 16));
        break;
      }
    }
    // Also dump strings in validator
    DumpStrings(sb, Validator, 0x200);
    sb.AppendLine("expectedCount=" + list.Count);
    return list;
  }

  static void ScanTableFor(StringBuilder sb, uint baseRva, int span, uint needle, string tag) {
    int fo = RvaToFile(baseRva);
    if (fo < 0) return;
    for (int off = 0; off < span; off += 8) {
      if (fo + off + 8 > pe.Length) break;
      ulong q = BitConverter.ToUInt64(pe, fo + off);
      if (q == imageBase + needle) {
        sb.AppendLine("  " + tag + " HIT needle @ base+0x" + off.ToString("X")
          + " (slotRva=0x" + (baseRva + (uint)off).ToString("X") + ")");
      }
    }
  }

  static FuncReport DeepFunc(StringBuilder sb, uint entry, string role) {
    var r = new FuncReport { Entry = entry, Role = role };
    r.End = FindFuncEnd(entry, 0x3000);
    if (r.End <= entry) r.End = entry + 0x200;
    if (r.End - entry > 0x3000) r.End = entry + 0x3000;
    r.Size = (int)(r.End - entry);
    sb.AppendLine("entry=0x" + entry.ToString("X") + " end=0x" + r.End.ToString("X")
      + " size=" + r.Size + " role=" + role + " prologue=" + Hex(entry, 16)
      + " sec=" + SecName(entry));

    var ins = Disasm(entry, r.End);
    bool s18 = false, sA8 = false, s3 = false;
    int head = 0;
    for (int i = 0; i < ins.Count; i++) {
      var a = ins[i];
      if (head < 56) {
        string line = "0x" + a.Rva.ToString("X") + " " + a.Text;
        r.DisasmHead.Add(line);
        sb.AppendLine("  " + line);
        head++;
      }
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        r.Callees.Add(dest);
        if (dest == Allocator) {
          r.CallsAllocator = true;
          // look back for size imm in edx/r8
          string note = "alloc @0x" + a.Rva.ToString("X");
          for (int j = Math.Max(0, i - 10); j < i; j++) {
            if (ins[j].Text.IndexOf("edx,", StringComparison.OrdinalIgnoreCase) >= 0
                || ins[j].Text.IndexOf("r8d,", StringComparison.OrdinalIgnoreCase) >= 0
                || ins[j].Text.IndexOf("edx,", StringComparison.OrdinalIgnoreCase) >= 0)
              note += " | " + ins[j].Text;
          }
          r.AllocNotes.Add(note);
          sb.AppendLine("  *** ALLOC " + note);
        }
        if (dest == Helper) r.CallsHelper = true;
        if (dest == Lookup) r.CallsLookup = true;
        if (dest == GateStub) r.CallsGateStub = true;
        if (dest == GateSetter) sb.AppendLine("  *** GATESETTER @0x" + a.Rva.ToString("X"));
        if (dest == BitWriter) sb.AppendLine("  *** BITWRITER @0x" + a.Rva.ToString("X"));
        if (dest == WorkerA) sb.AppendLine("  *** WORKER_A @0x" + a.Rva.ToString("X"));
        if (dest == WorkerB) sb.AppendLine("  *** WORKER_B @0x" + a.Rva.ToString("X"));
        if (dest == Wrapper) sb.AppendLine("  *** WRAPPER @0x" + a.Rva.ToString("X"));
        if (dest == ArmingHelper) sb.AppendLine("  *** ARMING @0x" + a.Rva.ToString("X"));
        if (dest == MembershipB) sb.AppendLine("  *** MEMBERSHIP_B @0x" + a.Rva.ToString("X"));
      }
      if (a.HasMem && !a.IpRel) {
        if (a.Disp == 0x18) s18 = true;
        if (a.Disp == 0xA8) sA8 = true;
        if (a.Disp == 0x3CD0) s3 = true;
        if (a.Disp == 0x61) {
          r.Touches61 = true;
          r.GateOps.Add("0x" + a.Rva.ToString("X") + " " + a.Text);
        }
        if (a.Disp == 0x98) {
          r.Touches98 = true;
          if (r.FieldNotes.Count < 16)
            r.FieldNotes.Add("+0x98 @0x" + a.Rva.ToString("X") + " " + a.Text);
        }
        if (Math.Abs(a.Disp) == 0x2B0) r.Touches2B0 = true;
        if (Math.Abs(a.Disp) == 0x2B8) r.Touches2B8 = true;
      }
      if (a.IpRel) {
        if (a.DataRva == LookupKey) r.UsesKey = true;
        if (a.DataRva == TableArm || a.DataRva == TableBit
            || (a.DataRva >= 0x9300000 && a.DataRva < 0x9500000 && SecName(a.DataRva) == ".edata")) {
          // vtable/method-table install pattern: lea reg,[rip+edata]; mov [obj(+off)], reg
          string note = "0x" + a.Rva.ToString("X") + " " + a.Text + " ->0x" + a.DataRva.ToString("X");
          // peek next few for store
          for (int j = i + 1; j < ins.Count && j <= i + 4; j++) {
            if (ins[j].Mnemonic == Mnemonic.Mov && ins[j].HasMem && !ins[j].IpRel)
              note += " => " + ins[j].Text;
          }
          r.VtableInstalls.Add(note);
          sb.AppendLine("  *** VT/TABLE " + note);
        }
        string s = ReadAscii(a.DataRva, 96);
        if (IsString(s) && s.Length >= 5 && r.Strings.Count < 16
            && !s.StartsWith("AWAV", StringComparison.Ordinal) && !r.Strings.Contains(s))
          r.Strings.Add(s);
      }
      if (a.Raw.OpCount >= 2) {
        for (int oi = 0; oi < a.Raw.OpCount; oi++) {
          var k = a.Raw.GetOpKind(oi);
          if (k == OpKind.Immediate32 || k == OpKind.Immediate64) {
            ulong imm = a.Raw.GetImmediate(oi);
            if (imm >= 0x20 && imm <= 0x10000 && (imm % 8) == 0)
              r.ImmSizes.Add((uint)imm);
          }
        }
      }
    }
    if (ins.Count > 56) sb.AppendLine("  ... +" + (ins.Count - 56) + " ins ...");
    r.Nested = s18 && sA8 && s3;
    r.Callees = r.Callees.Distinct().ToList();
    r.ImmSizes = r.ImmSizes.Distinct().OrderBy(x => x).ToList();
    r.CallersE8 = FindE8(entry, 40);

    // install hits
    foreach (var s in FindLeaTo(entry, 15))
      r.InstallHits.Add("lea @0x" + s.ToString("X") + " func≈0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in FindQword(entry, 15))
      r.InstallHits.Add("qword @0x" + s.ToString("X") + " sec=" + SecName(s));
    foreach (var s in FindRva32(entry, 15))
      r.InstallHits.Add("rva32 @0x" + s.ToString("X") + " sec=" + SecName(s));

    sb.AppendLine("nested=" + r.Nested + " key=" + r.UsesKey + " alloc=" + r.CallsAllocator
      + " t61=" + r.Touches61 + " t98=" + r.Touches98
      + " t2B0=" + r.Touches2B0 + " t2B8=" + r.Touches2B8
      + " callersE8=" + r.CallersE8.Count
      + " immSizes=" + string.Join(",", r.ImmSizes.Take(12).Select(x => "0x" + x.ToString("X"))));
    foreach (var g in r.GateOps) sb.AppendLine("  gate " + g);
    foreach (var v in r.VtableInstalls) sb.AppendLine("  vt " + v);
    foreach (var a in r.AllocNotes) sb.AppendLine("  " + a);
    foreach (var f in r.FieldNotes.Take(10)) sb.AppendLine("  field " + f);
    foreach (var s in r.Strings.Take(10)) sb.AppendLine("  str \"" + Trunc(s, 70) + "\"");
    foreach (var c in r.Callees.Where(x => !IsNoise(x)).Take(16))
      sb.AppendLine("  callee 0x" + c.ToString("X") + Tag(c));
    foreach (var h in r.InstallHits.Take(12)) sb.AppendLine("  install " + h);

    sb.AppendLine("-- callers --");
    foreach (var site in r.CallersE8.Take(20)) {
      uint fn = FindFuncStart(site);
      string note = "e8 @0x" + site.ToString("X") + " func≈0x" + fn.ToString("X");
      bool ca = false, ck = false;
      uint end = FindFuncEnd(fn, 0x600);
      if (end <= fn) end = fn + 0x200;
      if (end - fn > 0x600) end = fn + 0x600;
      foreach (var a in Disasm(fn, end)) {
        if (a.IpRel && a.DataRva == LookupKey) ck = true;
        if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
          uint d = (uint)(a.Raw.NearBranchTarget - imageBase);
          if (d == Allocator) ca = true;
        }
      }
      note += " key=" + ck + " alloc=" + ca;
      r.CallerNotes.Add(note);
      sb.AppendLine("  " + note);
      DumpStrings(sb, fn, 0x300);
    }

    // sample interesting callees
    foreach (var c in r.Callees.Where(x => !IsNoise(x)).Take(4)) {
      sb.AppendLine("--- callee dump 0x" + c.ToString("X") + " ---");
      DumpShort(sb, c, 0x40);
      DumpStrings(sb, c, 0x300);
    }
    return r;
  }

  static bool IsNoise(uint d) => d == Lookup || d == Allocator || d < 0x10000;
  static string Tag(uint rva) {
    if (rva == Allocator) return " *** ALLOC ***";
    if (rva == Helper) return " *** HELPER ***";
    if (rva == Wrapper) return " *** WRAPPER ***";
    if (rva == GateStub) return " *** GATE_STUB ***";
    if (rva == GateSetter) return " *** GATESETTER ***";
    if (rva == WorkerA) return " *** WORKER_A ***";
    if (rva == WorkerB) return " *** WORKER_B ***";
    if (rva == ArmingHelper) return " *** ARMING ***";
    if (rva == MembershipB) return " *** MEMBERSHIP_B ***";
    if (rva == BitWriter) return " *** BITWRITER ***";
    return "";
  }

  static void DumpShort(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEndFirstRet(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    sb.AppendLine("  func 0x" + entry.ToString("X") + " size~" + (end - entry)
      + " prologue=" + Hex(entry, 12));
    foreach (var a in Disasm(entry, end).Take(12))
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

  // ---- writers ----
  static void WriteExpectedJson(string hash, List<ExpectedSlot> expected, List<FuncReport> funcs) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.17\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"validator\": \"0x43E7750\",");
    sb.AppendLine("  \"expected\": [");
    for (int i = 0; i < expected.Count; i++) {
      var e = expected[i];
      var f = funcs.FirstOrDefault(x => x.Entry == e.ExpectedRva);
      sb.AppendLine("    {");
      sb.AppendLine("      \"vtOff\": \"0x" + e.VtOff.ToString("X") + "\",");
      sb.AppendLine("      \"expectedRva\": \"0x" + e.ExpectedRva.ToString("X") + "\",");
      sb.AppendLine("      \"leaSite\": \"0x" + e.LeaSite.ToString("X") + "\",");
      sb.AppendLine("      \"compareSite\": \"0x" + e.CompareSite.ToString("X") + "\",");
      sb.AppendLine("      \"sec\": " + J(SecName(e.ExpectedRva)) + ",");
      sb.AppendLine("      \"size\": " + (f != null ? f.Size : 0) + ",");
      sb.AppendLine("      \"strings\": [" + string.Join(", ", (f != null ? f.Strings : new List<string>()).Take(8).Select(J)) + "],");
      sb.AppendLine("      \"callees\": [" + string.Join(", ", (f != null ? f.Callees : new List<uint>()).Take(16).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callersE8\": " + (f != null ? f.CallersE8.Count : 0) + ",");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", (f != null ? f.DisasmHead : new List<string>()).Take(24).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < expected.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.17-expected-vt-slots.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.17-expected-vt-slots.json");
  }

  static void WriteCtorsJson(string hash, List<FuncReport> ctors) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.17\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"ctors\": [");
    for (int i = 0; i < ctors.Count; i++) {
      var r = ctors[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + r.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(r.Role) + ",");
      sb.AppendLine("      \"size\": " + r.Size + ",");
      sb.AppendLine("      \"callsAllocator\": " + T(r.CallsAllocator) + ",");
      sb.AppendLine("      \"usesKey\": " + T(r.UsesKey) + ",");
      sb.AppendLine("      \"touches61\": " + T(r.Touches61) + ",");
      sb.AppendLine("      \"touches98\": " + T(r.Touches98) + ",");
      sb.AppendLine("      \"vtableInstalls\": [" + string.Join(", ", r.VtableInstalls.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"allocNotes\": [" + string.Join(", ", r.AllocNotes.Take(8).Select(J)) + "],");
      sb.AppendLine("      \"immSizes\": [" + string.Join(", ", r.ImmSizes.Take(16).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"strings\": [" + string.Join(", ", r.Strings.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"callees\": [" + string.Join(", ", r.Callees.Take(20).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callersE8\": [" + string.Join(", ", r.CallersE8.Take(20).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callerNotes\": [" + string.Join(", ", r.CallerNotes.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"installHits\": [" + string.Join(", ", r.InstallHits.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", r.DisasmHead.Take(32).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < ctors.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.17-ctors-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.17-ctors-deep.json");
  }

  static void WriteSummaryJson(string hash, List<ExpectedSlot> expected, List<FuncReport> methods, List<FuncReport> ctors) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.17\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"expectedSlots\": [");
    for (int i = 0; i < expected.Count; i++) {
      sb.Append("    { \"vtOff\": \"0x" + expected[i].VtOff.ToString("X")
        + "\", \"rva\": \"0x" + expected[i].ExpectedRva.ToString("X") + "\" }");
      sb.AppendLine(i + 1 < expected.Count ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"ctorA\": { \"rva\": \"0x2E97A50\", \"size\": "
      + ctors.First(c => c.Entry == CtorA).Size
      + ", \"vtInstalls\": " + ctors.First(c => c.Entry == CtorA).VtableInstalls.Count
      + ", \"callersE8\": " + ctors.First(c => c.Entry == CtorA).CallersE8.Count + " },");
    sb.AppendLine("  \"ctorB\": { \"rva\": \"0x59D9B90\", \"size\": "
      + ctors.First(c => c.Entry == CtorB).Size
      + ", \"vtInstalls\": " + ctors.First(c => c.Entry == CtorB).VtableInstalls.Count
      + ", \"callersE8\": " + ctors.First(c => c.Entry == CtorB).CallersE8.Count + " },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.17-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.17-summary.json");
  }

  static void WriteFeasibilityJson(string hash, List<ExpectedSlot> expected, List<FuncReport> methods, List<FuncReport> ctors) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.17\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Expected vt methods and ctors still not Edward factories\" },");
    sb.AppendLine("  \"expectedVtSlotsResolved\": { \"class\": "
      + (expected.Count >= 2 && expected.All(e => e.ExpectedRva != 0) ? "\"confirmed\"" : "\"unsupported\"")
      + ", \"reason\": \"count=" + expected.Count + "\" },");
    sb.AppendLine("  \"ctorsDecoded\": { \"class\": \"confirmed\", \"reason\": \"0x2E97A50 and 0x59D9B90 deep-decoded\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Deep-decode expected +0x2B0 method body semantics for edx=2; map ctor callers to object allocation size/type\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.17-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.17-second-edward-feasibility.json");
  }

  static string T(bool b) => b ? "true" : "false";
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }

  // ---- scanners / pe ----
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
    while (dec.IP < limit && guard++ < 200000) {
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
