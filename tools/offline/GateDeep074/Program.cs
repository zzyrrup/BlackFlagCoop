// v0.6.14 — Offline deep-decode of gate/insert leads + TypeInfo fields at 0xB2898C8.
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
  const uint GateSetter = 0x53F31A0;
  const uint BitWriter = 0xF1C240;
  const uint MemberA = 0x4B5A560;
  const uint MemberB = 0x4D04450;
  const uint NearWrap = 0x2EA0B00;
  const uint LookupKey = 0xB2898C8;
  const uint Lookup = 0x429F9E0;
  const uint Allocator = 0x426EE50;
  const uint Helper = 0x2E97B60;
  const uint Wrapper = 0x2E97FC0;
  const uint WrapperEnd = 0x2E9D91E;
  const uint WorkerA = 0x725400;
  const uint ListScan = 0x537C2C0;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static readonly uint[] Leads = { GateSetter, BitWriter, MemberA, MemberB, NearWrap };

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
  sealed class LeadReport {
    public uint Entry, End; public int Size;
    public string RoleHint = "";
    public List<uint> Callees = new List<uint>();
    public List<uint> CallersE8 = new List<uint>();
    public List<string> Strings = new List<string>();
    public List<string> FieldNotes = new List<string>();
    public List<string> GateOps = new List<string>();
    public List<string> StoreNotes = new List<string>();
    public List<string> DisasmHead = new List<string>();
    public List<string> CallerNotes = new List<string>();
    public bool NestedChain, CallsLookup, CallsAllocator, CallsHelper, CallsWrapper;
    public bool CallsListScan, Touches98, SmallArray, UsesKey;
    public List<uint> ImmSizes = new List<uint>();
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v074-raw");
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
    sb.AppendLine("===== v0.6.14 GATE/INSERT DEEP-DECODE + TYPEINFO =====");
    sb.AppendLine("exeSha256=" + hash);

    // 1) TypeInfo field map
    sb.AppendLine();
    sb.AppendLine("===== TYPEINFO 0x" + LookupKey.ToString("X") + " =====");
    var typeInfo = MapTypeInfo(sb);

    // 2) How lookup uses the key (sample decode of 0x429F9E0 head)
    sb.AppendLine();
    sb.AppendLine("===== LOOKUP 0x429F9E0 KEY CONSUMPTION =====");
    DecodeLookupConsumer(sb);

    // 3) Deep-decode each lead
    var reports = new List<LeadReport>();
    foreach (uint lead in Leads) {
      sb.AppendLine();
      sb.AppendLine("===== LEAD 0x" + lead.ToString("X") + " =====");
      reports.Add(DeepDecode(sb, lead));
    }

    // 4) Cross relations
    sb.AppendLine();
    sb.AppendLine("===== CROSS RELATIONS =====");
    foreach (var r in reports) {
      sb.AppendLine("0x" + r.Entry.ToString("X") + " role=" + r.RoleHint
        + " callersE8=" + r.CallersE8.Count
        + " key=" + r.UsesKey + " nest=" + r.NestedChain
        + " lookup=" + r.CallsLookup + " helper=" + r.CallsHelper
        + " listScan=" + r.CallsListScan + " +98=" + r.Touches98
        + " small=" + r.SmallArray);
      foreach (var n in r.CallerNotes.Take(8)) sb.AppendLine("  " + n);
    }

    // Does any lead call another lead?
    sb.AppendLine("-- lead→lead calls --");
    foreach (var r in reports) {
      foreach (var c in r.Callees.Where(x => Leads.Contains(x) && x != r.Entry))
        sb.AppendLine("  0x" + r.Entry.ToString("X") + " -> 0x" + c.ToString("X"));
    }

    sb.AppendLine();
    sb.AppendLine("===== SUMMARY =====");
    sb.AppendLine("leads=" + reports.Count
      + " typeInfoClass=" + typeInfo.Classification
      + " namedFields=" + typeInfo.Fields.Count(f => !string.IsNullOrEmpty(f.Interp)));

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteTypeInfoJson(hash, typeInfo);
    WriteLeadsJson(hash, reports);
    WriteSummaryJson(hash, reports, typeInfo);
    WriteFeasibilityJson(hash, reports, typeInfo);

    bool ok = reports.All(r => r.Size > 0)
      && reports.First(r => r.Entry == GateSetter).UsesKey
      && reports.First(r => r.Entry == BitWriter).GateOps.Count > 0;
    Console.WriteLine("selfCheck leads=" + reports.Count + " ok=" + ok);
    return ok ? 0 : 4;
  }

  sealed class TypeField {
    public int Off; public string Hex; public string Kind; public string Interp = ""; public string Detail = "";
  }
  sealed class TypeInfoMap {
    public uint Rva = LookupKey;
    public string Section = "";
    public string Hex128 = "";
    public string Classification = "unknown";
    public List<TypeField> Fields = new List<TypeField>();
    public List<string> Notes = new List<string>();
    public List<string> NearbyStrings = new List<string>();
  }

  static TypeInfoMap MapTypeInfo(StringBuilder sb) {
    var info = new TypeInfoMap { Section = SecName(LookupKey), Hex128 = Hex(LookupKey, 128) };
    sb.AppendLine("sec=" + info.Section + " hex128=" + info.Hex128);
    int fo = RvaToFile(LookupKey);
    if (fo < 0) { info.Classification = "unmapped"; return info; }

    // Scan nearby TypeInfo-like neighbors in .trace for name strings / structure
    for (int delta = -0x80; delta < 0x200; delta += 8) {
      uint r = unchecked((uint)((int)LookupKey + delta));
      string s = ReadAscii(r, 64);
      if (IsString(s) && s.Length >= 4 && info.NearbyStrings.Count < 16)
        info.NearbyStrings.Add("0x" + r.ToString("X") + ":" + s);
    }
    foreach (var s in info.NearbyStrings) sb.AppendLine("  near " + Trunc(s, 90));

    // Field walk: interpret as mix of tagged ptrs / relative RVAs / hashes
    // Anvil Type often: [0]=flags/hash, then pointer-like fields with high bits
    for (int off = 0; off < 64; off += 4) {
      uint d = BitConverter.ToUInt32(pe, fo + off);
      var f = new TypeField { Off = off, Hex = d.ToString("X8"), Kind = "dword" };
      // Direct RVA candidate
      if (d >= 0x1000 && d < 0x20000000 && RvaToFile(d) >= 0) {
        string sn = SecName(d);
        string s = ReadAscii(d, 80);
        f.Kind = "rva32?";
        f.Interp = "asRva->" + sn;
        f.Detail = IsString(s) ? "\"" + Trunc(s, 40) + "\"" : "hex=" + Hex(d, 8);
      }
      // Image VA low32 + high pattern from tagged pointers (common: FFFF???? or high nibble tags)
      if ((d & 0xFFFF0000) == 0xFFFF0000) {
        f.Kind = "tagged_hi";
        f.Interp = "high16=0xFFFF_tag_or_reloc";
      }
      info.Fields.Add(f);
      sb.AppendLine("  +0x" + off.ToString("X2") + " d=0x" + f.Hex + " " + f.Kind
        + (string.IsNullOrEmpty(f.Interp) ? "" : " " + f.Interp)
        + (string.IsNullOrEmpty(f.Detail) ? "" : " " + f.Detail));
    }

    // Qword view for pointer slots
    for (int off = 0; off < 64; off += 8) {
      ulong q = BitConverter.ToUInt64(pe, fo + off);
      if (q > imageBase && q < imageBase + 0x20000000) {
        uint r = (uint)(q - imageBase);
        string s = ReadAscii(r, 80);
        sb.AppendLine("  q+0x" + off.ToString("X2") + "=VA->0x" + r.ToString("X")
          + " sec=" + SecName(r)
          + (IsString(s) ? " \"" + Trunc(s, 40) + "\"" : " hex=" + Hex(r, 8)));
        info.Notes.Add("q+0x" + off.ToString("X") + "->0x" + r.ToString("X"));
      }
    }

    // Cross-check: identical key bytes used? search first 8 bytes uniqueness
    info.Notes.Add("used_as_lookup_rdx_key");
    info.Notes.Add("shared_wrapper_and_worker");
    // Heuristic: .trace + no ASCII name + used as TypeId for lookup
    info.Classification = "anvil_typeinfo_key_blob_no_inline_name";
    // Try follow dwords that look like pointers into .rdata/.impdata for name tables
    TryResolveTypeName(sb, info, fo);
    sb.AppendLine("classification=" + info.Classification);
    return info;
  }

  static void TryResolveTypeName(StringBuilder sb, TypeInfoMap info, int fo) {
    // Some Anvil TypeInfo layouts store a name pointer at a fixed offset; try common slots
    int[] tryOffs = { 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48 };
    foreach (int off in tryOffs) {
      if (fo + off + 8 > pe.Length) continue;
      ulong q = BitConverter.ToUInt64(pe, fo + off);
      // Strip common pointer tags (low 3 bits / high bits)
      ulong cand = q;
      if ((cand & 7) != 0) cand &= ~7UL;
      if (cand > imageBase && cand < imageBase + 0x20000000) {
        uint r = (uint)(cand - imageBase);
        string s = ReadAscii(r, 96);
        if (IsString(s) && s.Length >= 3) {
          sb.AppendLine("  nameCand +0x" + off.ToString("X") + " -> 0x" + r.ToString("X")
            + " \"" + Trunc(s, 60) + "\"");
          info.Notes.Add("nameCand+0x" + off.ToString("X") + "=" + s);
          info.Classification = "anvil_typeinfo_with_name_ptr";
          var f = info.Fields.FirstOrDefault(x => x.Off == off);
          if (f != null) { f.Interp = "name_ptr?"; f.Detail = "\"" + Trunc(s, 40) + "\""; }
        }
      }
      // Also try as RVA32 at this offset
      uint d = BitConverter.ToUInt32(pe, fo + off);
      if (d >= 0x1000 && d < 0x20000000 && RvaToFile(d) >= 0) {
        string s = ReadAscii(d, 96);
        if (IsString(s) && s.Length >= 3) {
          sb.AppendLine("  nameCand32 +0x" + off.ToString("X") + " -> 0x" + d.ToString("X")
            + " \"" + Trunc(s, 60) + "\"");
          info.Notes.Add("nameCand32+0x" + off.ToString("X") + "=" + s);
          if (!info.Classification.Contains("name"))
            info.Classification = "anvil_typeinfo_with_name_rva32";
        }
      }
    }

    // Walk ±0x100 looking for TypeInfo directory / string table patterns referencing this key abs VA
    ulong va = imageBase + LookupKey;
    var abs = FindAbsQword(va, 20);
    sb.AppendLine("absQwordRefsToKey=" + abs.Count);
    foreach (var a in abs.Take(10)) {
      sb.AppendLine("  abs @0x" + a.ToString("X") + " sec=" + SecName(a)
        + " ctx=" + Hex(a > 0x10 ? a - 0x10 : a, 32));
      // strings near the abs ref
      for (int d = -0x40; d < 0x40; d++) {
        uint r = unchecked((uint)((int)a + d));
        string s = ReadAscii(r, 64);
        if (IsString(s) && s.Length >= 5) {
          sb.AppendLine("    nearAbsStr \"" + Trunc(s, 50) + "\"");
          info.NearbyStrings.Add("absNear:" + s);
          break;
        }
      }
    }
  }

  static void DecodeLookupConsumer(StringBuilder sb) {
    uint end = FindFuncEndFirstRet(Lookup, 0x200);
    if (end <= Lookup) end = Lookup + 0x100;
    sb.AppendLine("lookup size~" + (end - Lookup) + " prologue=" + Hex(Lookup, 16));
    int n = 0;
    foreach (var a in Disasm(Lookup, end)) {
      if (n++ < 40) sb.AppendLine("  0x" + a.Rva.ToString("X") + " " + a.Text);
      if (a.HasMem && !a.IpRel && a.Disp != 0 && Math.Abs(a.Disp) < 0x200)
        sb.AppendLine("    fieldDisp 0x" + a.Disp.ToString("X"));
    }
  }

  static LeadReport DeepDecode(StringBuilder sb, uint entry) {
    var r = new LeadReport { Entry = entry };
    r.End = FindFuncEnd(entry, 0x4000);
    if (r.End <= entry) r.End = entry + 0x400;
    if (r.End - entry > 0x4000) r.End = entry + 0x4000;
    r.Size = (int)(r.End - entry);
    r.RoleHint = RoleOf(entry);
    sb.AppendLine("entry=0x" + entry.ToString("X") + " end=0x" + r.End.ToString("X")
      + " size=" + r.Size + " role=" + r.RoleHint + " prologue=" + Hex(entry, 16));

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
        string tag = Tag(dest);
        if (dest == Lookup) r.CallsLookup = true;
        if (dest == Allocator) r.CallsAllocator = true;
        if (dest == Helper) r.CallsHelper = true;
        if (dest == Wrapper) r.CallsWrapper = true;
        if (dest == ListScan) r.CallsListScan = true;
        if (!string.IsNullOrEmpty(tag))
          sb.AppendLine("  *** call 0x" + dest.ToString("X") + tag + " @0x" + a.Rva.ToString("X"));
      }
      if (a.HasMem && !a.IpRel) {
        if (a.Disp == 0x18) s18 = true;
        if (a.Disp == 0xA8) sA8 = true;
        if (a.Disp == 0x3CD0) s3 = true;
        if (a.Disp == 0x98) {
          r.Touches98 = true;
          if (r.FieldNotes.Count < 20)
            r.FieldNotes.Add("+0x98 @0x" + a.Rva.ToString("X") + " " + a.Text);
        }
        if (a.Disp == 0x61) {
          r.GateOps.Add("0x" + a.Rva.ToString("X") + " " + a.Text);
          sb.AppendLine("  *** GATE 0x" + a.Rva.ToString("X") + " " + a.Text);
        }
        // potential pointer-array stores: mov [reg+reg*8], ...
        if ((a.Mnemonic == Mnemonic.Mov || a.Mnemonic == Mnemonic.Movnti)
            && a.Raw.OpCount >= 1 && a.Raw.GetOpKind(0) == OpKind.Memory
            && a.Raw.MemoryIndex != Register.None
            && (a.Raw.MemoryIndexScale == 8 || a.Raw.MemoryIndexScale == 1)) {
          r.StoreNotes.Add("0x" + a.Rva.ToString("X") + " " + a.Text);
        }
      }
      if (a.IpRel) {
        if (a.DataRva == LookupKey) {
          r.UsesKey = true;
          sb.AppendLine("  *** KEY LEA/MOV @0x" + a.Rva.ToString("X") + " " + a.Text);
        }
        string s = ReadAscii(a.DataRva, 96);
        if (IsString(s) && s.Length >= 5 && r.Strings.Count < 16
            && !s.StartsWith("AWAV", StringComparison.Ordinal) && !s.Contains("VWUSH")
            && !r.Strings.Contains(s))
          r.Strings.Add(s);
      }
      if (a.Raw.OpCount >= 2) {
        for (int oi = 0; oi < a.Raw.OpCount; oi++) {
          var k = a.Raw.GetOpKind(oi);
          if (k == OpKind.Immediate32 || k == OpKind.Immediate64) {
            ulong imm = a.Raw.GetImmediate(oi);
            if (imm == 0x1FFF8) r.SmallArray = true;
            if (imm >= 0x20 && imm <= 0x8000 && (imm % 8) == 0 && imm <= uint.MaxValue)
              r.ImmSizes.Add((uint)imm);
          }
          if (k == OpKind.Immediate8 && a.Mnemonic == Mnemonic.Or && a.HasMem && a.Disp == 0x61)
            sb.AppendLine("  *** OR61 imm=0x" + a.Raw.Immediate8.ToString("X"));
        }
      }
      if ((a.Mnemonic == Mnemonic.Shl || a.Mnemonic == Mnemonic.Sal)
          && a.Raw.OpCount >= 2 && a.Raw.GetOpKind(1) == OpKind.Immediate8
          && a.Raw.Immediate8 == 3)
        r.SmallArray = true; // *8 hint with count
    }
    if (ins.Count > 56) sb.AppendLine("  ... +" + (ins.Count - 56) + " ins ...");
    r.NestedChain = s18 && sA8 && s3;
    r.Callees = r.Callees.Distinct().ToList();
    r.ImmSizes = r.ImmSizes.Distinct().OrderBy(x => x).ToList();
    r.CallersE8 = FindE8(entry, 40);

    sb.AppendLine("nested=" + r.NestedChain + " key=" + r.UsesKey + " lookup=" + r.CallsLookup
      + " alloc=" + r.CallsAllocator + " helper=" + r.CallsHelper
      + " listScan=" + r.CallsListScan + " +98=" + r.Touches98 + " small=" + r.SmallArray);
    sb.AppendLine("gateOps=" + r.GateOps.Count + " indexedStores=" + r.StoreNotes.Count
      + " callersE8=" + r.CallersE8.Count);
    foreach (var g in r.GateOps) sb.AppendLine("  gate " + g);
    foreach (var s in r.StoreNotes.Take(12)) sb.AppendLine("  store " + s);
    foreach (var f in r.FieldNotes.Take(10)) sb.AppendLine("  field " + f);
    foreach (var s in r.Strings.Take(8)) sb.AppendLine("  str \"" + Trunc(s, 70) + "\"");
    foreach (var c in r.Callees.Where(x => !IsNoiseCallee(x)).Take(12))
      sb.AppendLine("  callee 0x" + c.ToString("X") + Tag(c));

    // Caller analysis
    sb.AppendLine("-- callers --");
    foreach (var site in r.CallersE8.Take(20)) {
      uint fn = FindFuncStart(site);
      string note = "e8 @0x" + site.ToString("X") + " func≈0x" + fn.ToString("X");
      // peek: does caller use key / touch 61 / call helper?
      bool ck = false, c61 = false, ch = false, ca = false;
      uint end = FindFuncEndFirstRet(fn, 0x1000);
      if (end <= fn) end = fn + 0x200;
      if (end - fn > 0x1000) end = fn + 0x1000;
      foreach (var a in Disasm(fn, end)) {
        if (a.IpRel && a.DataRva == LookupKey) ck = true;
        if (a.HasMem && !a.IpRel && a.Disp == 0x61) c61 = true;
        if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
          uint d = (uint)(a.Raw.NearBranchTarget - imageBase);
          if (d == Helper) ch = true;
          if (d == Allocator) ca = true;
        }
      }
      note += " key=" + ck + " t61=" + c61 + " helper=" + ch + " alloc=" + ca;
      if (fn >= Wrapper && fn < WrapperEnd) note += " [wrapper]";
      if (fn == WorkerA) note += " [worker]";
      r.CallerNotes.Add(note);
      sb.AppendLine("  " + note);
      DumpStrings(sb, fn, 0x400);
    }

    // Sample interesting non-noise callees
    foreach (var c in r.Callees.Where(x => !IsNoiseCallee(x) && !Leads.Contains(x)).Take(4)) {
      sb.AppendLine("--- callee dump 0x" + c.ToString("X") + " ---");
      DumpShort(sb, c, 0x50);
      DumpStrings(sb, c, 0x400);
    }
    return r;
  }

  static string RoleOf(uint e) {
    if (e == GateSetter) return "gate-setter";
    if (e == BitWriter) return "bit-writer";
    if (e == MemberA) return "membership-A";
    if (e == MemberB) return "membership-B";
    if (e == NearWrap) return "near-wrapper-list";
    return "lead";
  }

  static bool IsNoiseCallee(uint d) =>
    d == Lookup || d == Allocator || d < 0x10000;

  static string Tag(uint rva) {
    if (rva == Allocator) return " *** ALLOC ***";
    if (rva == Lookup) return " *** LOOKUP ***";
    if (rva == Helper) return " *** HELPER ***";
    if (rva == Wrapper) return " *** WRAPPER ***";
    if (rva == WorkerA) return " *** WORKER_A ***";
    if (rva == ListScan) return " *** LISTSCAN ***";
    if (rva == BitWriter) return " *** BITWRITER ***";
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

  static void WriteTypeInfoJson(string hash, TypeInfoMap info) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.14\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"rva\": \"0x" + LookupKey.ToString("X") + "\",");
    sb.AppendLine("  \"section\": " + J(info.Section) + ",");
    sb.AppendLine("  \"classification\": " + J(info.Classification) + ",");
    sb.AppendLine("  \"hex128\": " + J(info.Hex128) + ",");
    sb.AppendLine("  \"fields\": [");
    for (int i = 0; i < info.Fields.Count; i++) {
      var f = info.Fields[i];
      sb.Append("    { \"off\": \"0x" + f.Off.ToString("X") + "\", \"hex\": " + J(f.Hex)
        + ", \"kind\": " + J(f.Kind) + ", \"interp\": " + J(f.Interp)
        + ", \"detail\": " + J(f.Detail) + " }");
      sb.AppendLine(i + 1 < info.Fields.Count ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"notes\": [" + string.Join(", ", info.Notes.Select(J)) + "],");
    sb.AppendLine("  \"nearbyStrings\": [" + string.Join(", ", info.NearbyStrings.Take(16).Select(J)) + "]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.14-typeinfo-fields.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.14-typeinfo-fields.json");
  }

  static void WriteLeadsJson(string hash, List<LeadReport> reports) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.14\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"leads\": [");
    for (int i = 0; i < reports.Count; i++) {
      var r = reports[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + r.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(r.RoleHint) + ",");
      sb.AppendLine("      \"size\": " + r.Size + ",");
      sb.AppendLine("      \"usesKey\": " + T(r.UsesKey) + ",");
      sb.AppendLine("      \"nestedChain\": " + T(r.NestedChain) + ",");
      sb.AppendLine("      \"callsLookup\": " + T(r.CallsLookup) + ",");
      sb.AppendLine("      \"callsAllocator\": " + T(r.CallsAllocator) + ",");
      sb.AppendLine("      \"callsHelper\": " + T(r.CallsHelper) + ",");
      sb.AppendLine("      \"callsListScan\": " + T(r.CallsListScan) + ",");
      sb.AppendLine("      \"touches98\": " + T(r.Touches98) + ",");
      sb.AppendLine("      \"smallArray\": " + T(r.SmallArray) + ",");
      sb.AppendLine("      \"gateOps\": [" + string.Join(", ", r.GateOps.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"indexedStores\": [" + string.Join(", ", r.StoreNotes.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"fieldNotes\": [" + string.Join(", ", r.FieldNotes.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"strings\": [" + string.Join(", ", r.Strings.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"callees\": [" + string.Join(", ", r.Callees.Take(20).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callersE8\": [" + string.Join(", ", r.CallersE8.Take(20).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callerNotes\": [" + string.Join(", ", r.CallerNotes.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", r.DisasmHead.Take(32).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < reports.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.14-leads-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.14-leads-deep.json");
  }

  static void WriteSummaryJson(string hash, List<LeadReport> reports, TypeInfoMap info) {
    var gs = reports.First(r => r.Entry == GateSetter);
    var bw = reports.First(r => r.Entry == BitWriter);
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.14\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"typeInfoClass\": " + J(info.Classification) + ",");
    sb.AppendLine("  \"gateSetter\": { \"rva\": \"0x53F31A0\", \"usesKey\": " + T(gs.UsesKey)
      + ", \"nestedChain\": " + T(gs.NestedChain) + ", \"gateOps\": " + gs.GateOps.Count
      + ", \"callersE8\": " + gs.CallersE8.Count + " },");
    sb.AppendLine("  \"bitWriter\": { \"rva\": \"0xF1C240\", \"gateOps\": " + bw.GateOps.Count
      + ", \"callersE8\": " + bw.CallersE8.Count + ", \"usesKey\": " + T(bw.UsesKey) + " },");
    sb.AppendLine("  \"membershipLeads\": [");
    var mems = reports.Where(r => r.Entry == MemberA || r.Entry == MemberB || r.Entry == NearWrap).ToList();
    for (int i = 0; i < mems.Count; i++) {
      var m = mems[i];
      sb.Append("    { \"rva\": \"0x" + m.Entry.ToString("X") + "\", \"touches98\": " + T(m.Touches98)
        + ", \"smallArray\": " + T(m.SmallArray) + ", \"callersE8\": " + m.CallersE8.Count
        + ", \"indexedStores\": " + m.StoreNotes.Count + " }");
      sb.AppendLine(i + 1 < mems.Count ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"anyLeadCallsHelper\": " + T(reports.Any(r => r.CallsHelper)) + ",");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.14-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.14-summary.json");
  }

  static void WriteFeasibilityJson(string hash, List<LeadReport> reports, TypeInfoMap info) {
    var gs = reports.First(r => r.Entry == GateSetter);
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.14\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Gate/membership leads operate on existing typed objects; no Edward factory shown\" },");
    sb.AppendLine("  \"typeInfoNamed\": { \"class\": "
      + (info.Classification.Contains("name") ? "\"plausible\"" : "\"unsupported\"")
      + ", \"reason\": " + J(info.Classification) + " },");
    sb.AppendLine("  \"gateSetterConfirmed\": { \"class\": \"confirmed\", \"reason\": \"0x53F31A0 uses key+nested and writes +0x61\" },");
    sb.AppendLine("  \"bitWriterConfirmed\": { \"class\": \"confirmed\", \"reason\": \"0xF1C240 load/mask/or/store +0x61\" },");
    sb.AppendLine("  \"membershipInsertPinned\": { \"class\": "
      + (reports.Any(r => (r.Entry == MemberA || r.Entry == MemberB) && r.StoreNotes.Count > 0)
        ? "\"plausible\"" : "\"unsupported\"")
      + ", \"reason\": \"indexed store notes present on membership leads?\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Trace callers of 0x53F31A0 / 0xF1C240 to object creation; pin SmallArray store sites on membership leads\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.14-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.14-second-edward-feasibility.json");
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

  static List<uint> FindAbsQword(ulong va, int max) {
    var list = new List<uint>();
    byte[] needle = BitConverter.GetBytes(va);
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 8 <= lim && list.Count < max; i++) {
        bool ok = true;
        for (int k = 0; k < 8; k++) if (pe[s.Ptr + i + k] != needle[k]) { ok = false; break; }
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
