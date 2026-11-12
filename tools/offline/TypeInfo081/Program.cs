// v0.6.21 — Offline: TypeInfo alloc consumer of 0xB2898E8 / 0xB289918 (size 0x20F0);
// deep-decode 0x546D150 / edx=3 arm-table callee.
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
  const uint SizeField = 0xB2898E8;
  const uint CtorField = 0xB289918;
  const uint LookupKey = 0xB2898C8;
  const uint OuterCtor = 0x59D9660;
  const uint RegSize = 0x20F0;
  const uint Helper546 = 0x546D150;
  const uint Neighbor = 0x2335140;
  const uint Allocator = 0x426EE50;
  const uint Lookup = 0x429F9E0;
  const uint ArmTable = 0x948FF50;
  const uint Trampoline2B0 = 0x4656C80;
  const uint ArmWrap = 0x2108620;
  const uint Canonical2B8 = 0x479E3B0;
  const uint Post2B8 = 0x479E440;
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
    public long Disp; public int Length; public Instruction Raw; public uint NearTarget;
  }
  sealed class FuncRep {
    public uint Entry, End; public int Size; public string Role;
    public bool Touches61, Touches98, Touches18, TouchesA8, Nested;
    public bool CallsAlloc, CallsLookup, CallsOuter, CallsArmWrap, UsesEdx3;
    public bool ReadsSizeField, ReadsCtorField, Imm20F0;
    public List<uint> Callees = new List<uint>();
    public List<uint> CallersE8 = new List<uint>();
    public List<string> Notes = new List<string>();
    public List<string> FieldNotes = new List<string>();
    public List<string> Disasm = new List<string>();
    public List<string> Strings = new List<string>();
    public List<uint> ImmSizes = new List<uint>();
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v081-raw");
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
    sb.AppendLine("===== v0.6.21 TYPEINFO ALLOC + EDX=3 =====");
    sb.AppendLine("exeSha256=" + hash);

    // ---- 1) RIP refs to size/ctor fields ----
    sb.AppendLine();
    sb.AppendLine("===== TYPEINFO FIELD XREFS =====");
    var sizeRefs = FindRipMemTo(SizeField, 80);
    var ctorRefs = FindRipMemTo(CtorField, 80);
    var keyRefs = FindRipMemTo(LookupKey, 40);
    sb.AppendLine("sizeField 0xB2898E8 refs=" + sizeRefs.Count);
    sb.AppendLine("ctorField 0xB289918 refs=" + ctorRefs.Count);
    sb.AppendLine("lookupKey 0xB2898C8 refs=" + keyRefs.Count);

    var consumerFuncs = new HashSet<uint>();
    foreach (var site in sizeRefs) {
      uint fs = FindFuncStart(site);
      consumerFuncs.Add(fs);
      sb.AppendLine("  SIZE @0x" + site.ToString("X") + " func≈0x" + fs.ToString("X")
        + " " + Trunc(InsnAt(site), 70) + " sec=" + SecName(site));
    }
    foreach (var site in ctorRefs) {
      uint fs = FindFuncStart(site);
      consumerFuncs.Add(fs);
      sb.AppendLine("  CTOR @0x" + site.ToString("X") + " func≈0x" + fs.ToString("X")
        + " " + Trunc(InsnAt(site), 70) + " sec=" + SecName(site));
    }

    // ---- 2) mov imm 0x20F0 near Allocator ----
    sb.AppendLine();
    sb.AppendLine("===== IMM 0x20F0 + ALLOCATOR =====");
    var imm20Sites = FindMovImm(RegSize, 80);
    sb.AppendLine("movImm0x20F0 sites=" + imm20Sites.Count);
    var allocWithSize = new List<string>();
    foreach (var site in imm20Sites) {
      uint fs = FindFuncStart(site);
      sb.AppendLine("  imm @0x" + site.ToString("X") + " func≈0x" + fs.ToString("X")
        + " " + Trunc(InsnAt(site), 70));
      // look forward ≤0x80 for call Allocator or call through reg after size load
      uint hi = site + 0xA0;
      bool sawAlloc = false;
      bool sawLookup = false;
      bool sawOuter = false;
      foreach (var ins in Disasm(site, hi)) {
        if (ins.IsCall && ins.NearTarget == Allocator) { sawAlloc = true; break; }
        if (ins.IsCall && ins.NearTarget == Lookup) sawLookup = true;
        if (ins.IsCall && (ins.NearTarget == OuterCtor || ins.NearTarget == 0x59D96A0)) sawOuter = true;
        if (ins.IpRel && (ins.DataRva == SizeField || ins.DataRva == CtorField)) { /* same record */ }
      }
      // also scan whole function for Allocator
      uint fe = FindFuncEnd(fs, 0x1500);
      foreach (var ins in Disasm(fs, Math.Min(fe, fs + 0x800))) {
        if (ins.IsCall && ins.NearTarget == Allocator) sawAlloc = true;
        if (ins.IsCall && ins.NearTarget == Lookup) sawLookup = true;
        if (ins.IsCall && ins.NearTarget == OuterCtor) sawOuter = true;
      }
      string note = "func 0x" + fs.ToString("X") + " imm20F0@0x" + site.ToString("X")
        + " alloc=" + sawAlloc + " lookup=" + sawLookup + " outer=" + sawOuter;
      if (sawAlloc || sawLookup || sawOuter || consumerFuncs.Contains(fs)) {
        allocWithSize.Add(note);
        sb.AppendLine("    " + note);
      }
      consumerFuncs.Add(fs);
    }

    // Deep-decode top consumer funcs (size/ctor readers + imm20F0+alloc)
    sb.AppendLine();
    sb.AppendLine("===== CONSUMER FUNC DECODES =====");
    var reps = new List<FuncRep>();
    var toDecode = consumerFuncs.OrderBy(x => x).Take(12).ToList();
    // Always include helper + known
    if (!toDecode.Contains(Helper546)) toDecode.Insert(0, Helper546);
    // Also include any func that both refs size and calls alloc
    foreach (uint entry in toDecode.Distinct().Take(15)) {
      string role = entry == Helper546 ? "helper-546D150"
        : (sizeRefs.Any(s => FindFuncStart(s) == entry) ? "size-field-reader"
        : (ctorRefs.Any(s => FindFuncStart(s) == entry) ? "ctor-field-reader" : "imm20F0-site"));
      // Skip giant InstallerA unless it is the only hit
      if (entry == 0x5F11A40) { sb.AppendLine("(skip InstallerA 0x5F11A40 writer — known)"); continue; }
      sb.AppendLine();
      sb.AppendLine("===== FUNC 0x" + entry.ToString("X") + " (" + role + ") =====");
      reps.Add(DeepFunc(sb, entry, role));
    }

    // Force deep-decode helper even if already done
    if (!reps.Any(r => r.Entry == Helper546)) {
      sb.AppendLine();
      sb.AppendLine("===== FUNC 0x546D150 (helper) =====");
      reps.Add(DeepFunc(sb, Helper546, "helper-546D150"));
    }

    // ---- 3) edx=3 arm-table path ----
    sb.AppendLine();
    sb.AppendLine("===== EDX=3 ARM-TABLE PATH =====");
    // Confirm arm table slots
    int fo = RvaToFile(ArmTable + 0x2B0);
    ulong q2b0 = fo >= 0 ? BitConverter.ToUInt64(pe, fo) : 0;
    fo = RvaToFile(ArmTable + 0x2B8);
    ulong q2b8 = fo >= 0 ? BitConverter.ToUInt64(pe, fo) : 0;
    uint r2b0 = q2b0 >= imageBase ? (uint)(q2b0 - imageBase) : 0;
    uint r2b8 = q2b8 >= imageBase ? (uint)(q2b8 - imageBase) : 0;
    sb.AppendLine("armTable+0x2B0=0x" + r2b0.ToString("X") + " +0x2B8=0x" + r2b8.ToString("X"));

    // Trampoline decode
    sb.AppendLine("--- trampoline 0x4656C80 ---");
    foreach (var ins in Disasm(Trampoline2B0, Trampoline2B0 + 0x20).Take(8))
      sb.AppendLine("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 90));

    // Does wrap / canonical read edx?
    sb.AppendLine("--- wrap edx use ---");
    bool wrapUsesEdx = false, canonUsesEdx = false;
    foreach (var ins in Disasm(ArmWrap, FindFuncEnd(ArmWrap, 0x800))) {
      if (ins.Text.Contains("edx") || ins.Text.Contains("rdx")) {
        // filter stack cookie noise roughly
        if (ins.Mnemonic == Mnemonic.Mov || ins.Mnemonic == Mnemonic.Test || ins.Mnemonic == Mnemonic.Cmp
            || ins.Mnemonic == Mnemonic.And || ins.Mnemonic == Mnemonic.Or) {
          wrapUsesEdx = true;
          sb.AppendLine("  wrap 0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 70));
        }
      }
    }
    foreach (var ins in Disasm(Canonical2B8, FindFuncEnd(Canonical2B8, 0x400))) {
      if ((ins.Text.Contains("edx") || ins.Text.Contains("rdx"))
          && (ins.Mnemonic == Mnemonic.Mov || ins.Mnemonic == Mnemonic.Test || ins.Mnemonic == Mnemonic.Cmp)) {
        canonUsesEdx = true;
        sb.AppendLine("  canon 0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 70));
      }
    }
    sb.AppendLine("wrapUsesEdx=" + wrapUsesEdx + " canonUsesEdx=" + canonUsesEdx);

    // Neighbor context already known; find other edx=3 ; call [vt+0x2B0] sites
    sb.AppendLine("--- other mov edx,3 near vcall +0x2B0 ---");
    var edx3Sites = FindMovImm(3, 200);
    int edx3Vcall = 0;
    foreach (var site in edx3Sites) {
      // look ahead 0x20 for call [reg+0x2B0]
      bool hit = false;
      foreach (var ins in Disasm(site, site + 0x30)) {
        if (ins.IsIndirectCall && (ins.Disp == 0x2B0 || ins.Text.Contains("+2B0"))) { hit = true; break; }
      }
      if (!hit) continue;
      edx3Vcall++;
      uint fs = FindFuncStart(site);
      sb.AppendLine("  edx3+vcall2B0 @0x" + site.ToString("X") + " func≈0x" + fs.ToString("X")
        + (fs == Neighbor ? " *** NEIGHBOR ***" : ""));
      if (edx3Vcall >= 15) break;
    }
    sb.AppendLine("edx3VcallSites=" + edx3Vcall);

    // Deep note on helper relation to neighbor
    var help = reps.FirstOrDefault(r => r.Entry == Helper546);
    sb.AppendLine();
    sb.AppendLine("===== CROSS =====");
    sb.AppendLine("sizeRefs=" + sizeRefs.Count + " ctorRefs=" + ctorRefs.Count
      + " imm20F0=" + imm20Sites.Count + " allocWithSizeNotes=" + allocWithSize.Count);
    bool foundAllocConsumer = reps.Any(r => r.CallsAlloc && (r.ReadsSizeField || r.Imm20F0 || r.ReadsCtorField));
    bool foundLookupConsumer = reps.Any(r => r.CallsLookup && (r.ReadsSizeField || r.ReadsCtorField));
    sb.AppendLine("foundAllocConsumer=" + foundAllocConsumer + " foundLookupConsumer=" + foundLookupConsumer);
    sb.AppendLine("helper size=" + (help != null ? help.Size : 0)
      + " callersE8=" + (help != null ? help.CallersE8.Count : 0)
      + " callees=" + (help != null ? help.Callees.Count : 0));
    sb.AppendLine("edx3->armPath trampoline=0x" + r2b0.ToString("X") + " wrap=0x" + r2b8.ToString("X")
      + " (same as edx=2 arming chain)");

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteJson(hash, reps, sizeRefs, ctorRefs, imm20Sites, allocWithSize, foundAllocConsumer,
      foundLookupConsumer, r2b0, r2b8, edx3Vcall, help);

    bool ok = help != null && help.Size > 0 && (sizeRefs.Count + ctorRefs.Count + imm20Sites.Count) > 0;
    Console.WriteLine("selfCheck helper=" + (help != null ? help.Size : 0)
      + " sizeRefs=" + sizeRefs.Count + " ctorRefs=" + ctorRefs.Count
      + " imm20=" + imm20Sites.Count + " allocConsumer=" + foundAllocConsumer + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static FuncRep DeepFunc(StringBuilder sb, uint entry, string role) {
    var r = new FuncRep { Entry = entry, Role = role };
    int maxScan = 0x2000;
    r.End = FindFuncEnd(entry, maxScan);
    if (r.End <= entry) r.End = entry + 0x200;
    // Cap enormous funcs
    if (r.End - entry > 0x3000) r.End = entry + 0x3000;
    r.Size = (int)(r.End - entry);
    sb.AppendLine("entry=0x" + entry.ToString("X") + " end=0x" + r.End.ToString("X")
      + " size=" + r.Size + " sec=" + SecName(entry) + " prologue=" + Hex(entry, 12));

    var ins = Disasm(entry, r.End);
    int head = 0;
    foreach (var i in ins) {
      if (head++ < 70) r.Disasm.Add("0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 100));
      if (i.HasMem && !i.IpRel) {
        if (i.Disp == 0x61) r.Touches61 = true;
        if (i.Disp == 0x98) r.Touches98 = true;
        if (i.Disp == 0x18) r.Touches18 = true;
        if (i.Disp == 0xA8) { r.TouchesA8 = true; r.Nested = true; }
        if (i.Disp >= 0x40 && i.Disp <= 0x100)
          r.FieldNotes.Add("+" + i.Disp.ToString("X") + " @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 50));
      }
      if (i.IpRel) {
        if (i.DataRva == SizeField) { r.ReadsSizeField = true; r.Notes.Add("SIZE_FIELD @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 60)); }
        if (i.DataRva == CtorField) { r.ReadsCtorField = true; r.Notes.Add("CTOR_FIELD @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 60)); }
        if (i.DataRva == LookupKey) r.Notes.Add("LOOKUP_KEY @0x" + i.Rva.ToString("X"));
        string s = ReadAscii(i.DataRva, 60);
        if (IsString(s) && s.Length >= 5 && !r.Strings.Contains(s)) r.Strings.Add(s);
      }
      if (i.IsCall && !i.IsIndirectCall && i.NearTarget != 0) {
        r.Callees.Add(i.NearTarget);
        if (i.NearTarget == Allocator) { r.CallsAlloc = true; r.Notes.Add("CALL_ALLOC @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Lookup) { r.CallsLookup = true; r.Notes.Add("CALL_LOOKUP @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == OuterCtor) { r.CallsOuter = true; r.Notes.Add("CALL_OUTER @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == ArmWrap) r.CallsArmWrap = true;
      }
      uint imm;
      if (i.Mnemonic == Mnemonic.Mov && TryParseImm(i.Text, out imm)) {
        if (imm == RegSize) { r.Imm20F0 = true; r.Notes.Add("IMM_20F0 @0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 50)); }
        if (imm == 3 && i.Text.Contains("edx")) r.UsesEdx3 = true;
        if (imm >= 0x40 && imm <= 0x100000 && (imm % 8 == 0 || imm % 0x10 == 0)) r.ImmSizes.Add(imm);
      }
    }
    r.CallersE8 = FindE8(entry, 40);
    sb.AppendLine("size=" + r.Size + " t61=" + r.Touches61 + " t98=" + r.Touches98
      + " alloc=" + r.CallsAlloc + " lookup=" + r.CallsLookup + " outer=" + r.CallsOuter
      + " sizeFld=" + r.ReadsSizeField + " ctorFld=" + r.ReadsCtorField + " imm20F0=" + r.Imm20F0
      + " callersE8=" + r.CallersE8.Count + " callees=" + r.Callees.Distinct().Count());
    foreach (var n in r.Notes) sb.AppendLine("  " + n);
    foreach (var s in r.Strings.Take(8)) sb.AppendLine("  str \"" + Trunc(s, 70) + "\"");
    foreach (var c in r.Callees.Distinct().Take(16)) {
      string mark = c == Allocator ? " *** ALLOC ***" : c == Lookup ? " *** LOOKUP ***"
        : c == OuterCtor ? " *** OUTER ***" : "";
      sb.AppendLine("  callee 0x" + c.ToString("X") + " size~" + (FindFuncEndFirstRet(c, 0x400) - c)
        + mark + " prologue=" + Hex(c, 8));
    }
    foreach (var site in r.CallersE8.Take(12))
      sb.AppendLine("  e8 @0x" + site.ToString("X") + " func≈0x" + FindFuncStart(site).ToString("X"));
    sb.AppendLine("--- disasm head ---");
    foreach (var line in r.Disasm.Take(50)) sb.AppendLine(line);
    return r;
  }

  static void WriteJson(string hash, List<FuncRep> reps, List<uint> sizeRefs, List<uint> ctorRefs,
      List<uint> imm20, List<string> allocNotes, bool foundAlloc, bool foundLookup,
      uint r2b0, uint r2b8, int edx3Vcall, FuncRep help) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.21\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"typeInfo\": {");
    sb.AppendLine("    \"sizeField\": \"0xB2898E8\",");
    sb.AppendLine("    \"ctorField\": \"0xB289918\",");
    sb.AppendLine("    \"registeredSize\": \"0x20F0\",");
    sb.AppendLine("    \"sizeRefs\": " + sizeRefs.Count + ",");
    sb.AppendLine("    \"ctorRefs\": " + ctorRefs.Count + ",");
    sb.AppendLine("    \"imm20F0Sites\": " + imm20.Count + ",");
    sb.AppendLine("    \"allocConsumerFound\": " + T(foundAlloc) + ",");
    sb.AppendLine("    \"lookupConsumerFound\": " + T(foundLookup));
    sb.AppendLine("  },");
    sb.AppendLine("  \"edx3\": {");
    sb.AppendLine("    \"helper\": \"0x546D150\",");
    sb.AppendLine("    \"helperSize\": " + (help != null ? help.Size : 0) + ",");
    sb.AppendLine("    \"helperCallersE8\": " + (help != null ? help.CallersE8.Count : 0) + ",");
    sb.AppendLine("    \"armTable2B0\": \"0x" + r2b0.ToString("X") + "\",");
    sb.AppendLine("    \"armTable2B8\": \"0x" + r2b8.ToString("X") + "\",");
    sb.AppendLine("    \"edx3VcallSites\": " + edx3Vcall);
    sb.AppendLine("  },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.21-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.21-summary.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.21\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"sizeRefSites\": [" + string.Join(", ", sizeRefs.Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("  \"ctorRefSites\": [" + string.Join(", ", ctorRefs.Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("  \"imm20F0Sites\": [" + string.Join(", ", imm20.Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("  \"allocNotes\": [" + string.Join(", ", allocNotes.Select(J)) + "],");
    sb.AppendLine("  \"funcs\": [");
    for (int i = 0; i < reps.Count; i++) {
      var r = reps[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + r.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(r.Role) + ",");
      sb.AppendLine("      \"size\": " + r.Size + ",");
      sb.AppendLine("      \"callsAlloc\": " + T(r.CallsAlloc) + ",");
      sb.AppendLine("      \"callsLookup\": " + T(r.CallsLookup) + ",");
      sb.AppendLine("      \"readsSizeField\": " + T(r.ReadsSizeField) + ",");
      sb.AppendLine("      \"readsCtorField\": " + T(r.ReadsCtorField) + ",");
      sb.AppendLine("      \"imm20F0\": " + T(r.Imm20F0) + ",");
      sb.AppendLine("      \"notes\": [" + string.Join(", ", r.Notes.Select(J)) + "],");
      sb.AppendLine("      \"strings\": [" + string.Join(", ", r.Strings.Select(J)) + "],");
      sb.AppendLine("      \"callees\": [" + string.Join(", ", r.Callees.Distinct().Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callersE8\": [" + string.Join(", ", r.CallersE8.Take(20).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", r.Disasm.Take(40).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < reps.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.21-funcs-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.21-funcs-deep.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.21\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"TypeInfo/edx=3 paths still operate on existing object graphs\" },");
    string allocClass = foundAlloc ? "confirmed" : (foundLookup ? "partial" : "unsupported");
    string allocReason = foundAlloc
      ? "Found function that reads TypeInfo size/ctor fields and calls Allocator"
      : (foundLookup
        ? "Found Lookup consumer of TypeInfo fields; Allocator call site still indirect"
        : "No direct size/ctor-field reader that calls Allocator in scanned refs");
    sb.AppendLine("  \"typeInfoAllocConsumer\": { \"class\": \"" + allocClass + "\", \"reason\": " + J(allocReason) + " },");
    sb.AppendLine("  \"helper546Decoded\": { \"class\": \"" + (help != null && help.Size > 0 ? "confirmed" : "unsupported")
      + "\", \"reason\": " + J(help != null ? "0x546D150 size=" + help.Size + " callersE8=" + help.CallersE8.Count : "missing") + " },");
    sb.AppendLine("  \"edx3ArmCallee\": { \"class\": \"confirmed\", \"reason\": \"edx=3 [vt+0x2B0] uses same arm-table trampoline 0x4656C80 -> wrap 0x2108620 as edx=2\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Follow TypeInfo Lookup->alloc factory; map 0x546D150 outputs into possession/control candidates\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\", \"conflating wrap modes with gate\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.21-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.21-second-edward-feasibility.json");
  }

  static string InsnAt(uint rva) {
    var list = Disasm(rva, rva + 0x10);
    return list.Count > 0 ? list[0].Text : "";
  }

  static List<uint> FindRipMemTo(uint target, int max) {
    var list = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim && list.Count < max; i++) {
        // Scan with iced would be slow; pattern: rex? + opcode + modrm=xx000101 + disp32
        int off = 0;
        byte b0 = pe[s.Ptr + i];
        if (b0 == 0x48 || b0 == 0x4C || b0 == 0x49 || b0 == 0x4D || b0 == 0x41 || b0 == 0x44 || b0 == 0x45 || b0 == 0x46 || b0 == 0x47)
          off = 1;
        // dual rex rare; also handle no rex
        byte op = pe[s.Ptr + i + off];
        // common: 8B/8D/3B/39/89/87 etc with modrm rip
        if (!(op == 0x8B || op == 0x8D || op == 0x3B || op == 0x39 || op == 0x89 || op == 0x87
              || op == 0x03 || op == 0x01 || op == 0x33 || op == 0x2B || op == 0x63
              || op == 0xFF || op == 0xF7 || op == 0x81 || op == 0x83 || op == 0xC7))
          continue;
        int modOff = off + 1;
        // group1 with imm may be longer — only handle modrm rip form (mod=00 rm=101)
        if (modOff >= lim) continue;
        byte modrm = pe[s.Ptr + i + modOff];
        if ((modrm & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + modOff + 1));
        uint site = s.Va + i;
        uint len = (uint)(modOff + 1 + 4);
        if (unchecked((uint)(site + len + disp)) == target) list.Add(site);
      }
    }
    return list;
  }

  static List<uint> FindMovImm(uint imm, int max) {
    var list = new List<uint>();
    // mov r32, imm32 = B8+rd ; mov r/m32, imm32 = C7 /0
    byte[] immBytes = BitConverter.GetBytes(imm);
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 5 <= lim && list.Count < max; i++) {
        // B8+rd imm32
        byte op = pe[s.Ptr + i];
        if (op >= 0xB8 && op <= 0xBF) {
          bool ok = true;
          for (int k = 0; k < 4; k++) if (pe[s.Ptr + i + 1 + k] != immBytes[k]) { ok = false; break; }
          if (ok) { list.Add(s.Va + i); continue; }
        }
        // REX.W B8+rd imm32 (10 bytes) — skip for 32-bit imm sizes
        // C7 /0 modrm imm32
        int off = 0;
        if (op == 0x48 || op == 0x41 || op == 0x49) { off = 1; op = pe[s.Ptr + i + off]; }
        if (op == 0xC7 && i + off + 6 <= lim) {
          byte modrm = pe[s.Ptr + i + off + 1];
          if ((modrm & 0x38) != 0) continue; // /0
          // modrm forms: mod=11 reg; or disp
          int immAt;
          byte mod = (byte)(modrm >> 6);
          if (mod == 3) immAt = off + 2;
          else if (mod == 0 && (modrm & 7) == 5) immAt = off + 2 + 4; // rip
          else if (mod == 0) immAt = off + 2;
          else if (mod == 1) immAt = off + 2 + 1;
          else immAt = off + 2 + 4;
          if (i + immAt + 4 > lim) continue;
          bool ok = true;
          for (int k = 0; k < 4; k++) if (pe[s.Ptr + i + immAt + k] != immBytes[k]) { ok = false; break; }
          if (ok) list.Add(s.Va + i);
        }
      }
    }
    return list;
  }

  static bool TryParseImm(string text, out uint imm) {
    imm = 0;
    int c = text.LastIndexOf(',');
    if (c < 0) return false;
    string t = text.Substring(c + 1).Trim();
    if (t.StartsWith("0x") || t.StartsWith("0X")) t = t.Substring(2);
    if (t.EndsWith("h", StringComparison.OrdinalIgnoreCase)) t = t.Substring(0, t.Length - 1);
    return uint.TryParse(t, System.Globalization.NumberStyles.HexNumber, null, out imm)
      || uint.TryParse(t, out imm);
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
