// v0.6.13 — Offline: inserters into enrollment SmallArrays / +0x61 gate writers;
// decode shared lookup key 0xB2898C8.
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
  const uint LookupKey = 0xB2898C8;
  const uint Wrapper = 0x2E97FC0;
  const uint WrapperEnd = 0x2E9D91E;
  const uint Helper = 0x2E97B60;
  const uint Allocator = 0x426EE50;
  const uint Lookup = 0x429F9E0;
  const uint WorkerA = 0x725400;
  const uint ListScan = 0x537C2C0;
  const uint LodStub = 0x1A5A70;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);

  sealed class Sec {
    public string Name;
    public uint Va, VSize, Raw, Ptr, Char;
  }

  sealed class Ins {
    public uint Rva;
    public string Text;
    public Mnemonic Mnemonic;
    public bool IpRel;
    public uint DataRva;
    public bool IsCall;
    public bool IsIndirectCall;
    public bool HasMem;
    public long Disp;
    public int Length;
    public Instruction Raw;
    public bool Op0IsReg;
    public Register Op0Reg;
  }

  sealed class GateHit {
    public uint Site;
    public uint Func;
    public string Text;
    public string Kind; // or2|or4|or6|andFD|andFB|andOther|mov|other|key-user|bit1-set-seq
    public uint Imm;
    public bool InWrapper;
    public bool CallsAllocator;
    public bool CallsLookup;
    public bool CallsHelper;
    public bool CallsListScan;
    public bool NestedChain;
    public List<string> Strings = new List<string>();
    public List<uint> ImmSizes = new List<uint>();
    public List<string> Notes = new List<string>();
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v073-raw");
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
    sb.AppendLine("===== v0.6.13 ENROLL INSERT / GATE / LOOKUP KEY =====");
    sb.AppendLine("exeSha256=" + hash);

    // 1) Decode lookup key blob
    sb.AppendLine();
    sb.AppendLine("===== LOOKUP KEY 0x" + LookupKey.ToString("X") + " =====");
    var keyInfo = DecodeLookupKey(sb);

    // 2) LEA/MOV xrefs to key
    sb.AppendLine();
    sb.AppendLine("===== XREFS TO LOOKUP KEY =====");
    var keyXrefsRaw = FindLeaOrMovTo(LookupKey, 200);
    var keyXrefs = new List<uint>();
    foreach (var x in keyXrefsRaw) {
      var ins = DisasmOne(x);
      if (ins == null || ins.Rva != x) continue;
      if (!ins.IpRel || ins.DataRva != LookupKey) continue;
      if (ins.Mnemonic != Mnemonic.Lea && ins.Mnemonic != Mnemonic.Mov) continue;
      keyXrefs.Add(x);
    }
    sb.AppendLine("leaOrMovXrefsRaw=" + keyXrefsRaw.Count + " verified=" + keyXrefs.Count);
    var keyCallerFuncs = new HashSet<uint>();
    foreach (var x in keyXrefs) {
      uint fn = FindFuncStart(x);
      keyCallerFuncs.Add(fn);
      bool inWrap = x >= Wrapper && x < WrapperEnd;
      bool isWorker = fn == WorkerA;
      sb.AppendLine("  xref @0x" + x.ToString("X") + " " + DisasmOne(x).Text
        + " func≈0x" + fn.ToString("X")
        + (inWrap ? " [wrapper]" : "") + (isWorker ? " [workerA]" : ""));
    }
    sb.AppendLine("uniqueFuncsReferencingKey=" + keyCallerFuncs.Count);

    // Absolute qword refs
    var absRefs = FindAbsQword(LookupKey + imageBase, 40);
    sb.AppendLine("absQwordRefs=" + absRefs.Count);
    foreach (var r in absRefs.Take(20))
      sb.AppendLine("  abs @0x" + r.ToString("X") + " func≈0x" + FindFuncStart(r).ToString("X"));

    // 3) Imm +0x61 writers (or4 post-enqueue etc.) — note: bit1 rarely set via imm or2
    sb.AppendLine();
    sb.AppendLine("===== +0x61 IMM BYTE WRITERS =====");
    var gateHits = ScanGateWriters(sb);
    var or2 = gateHits.Where(h => h.Kind == "or2").ToList();
    var or4 = gateHits.Where(h => h.Kind == "or4").ToList();
    var andFd = gateHits.Where(h => h.Kind == "andFD").ToList();
    sb.AppendLine("note: enrollment gate bit1 is usually set via register-form RMW, not imm or2");
    sb.AppendLine("immOr2=" + or2.Count + " immOr4=" + or4.Count + " andFD=" + andFd.Count);
    foreach (var h in or4.Where(x => x.InWrapper))
      sb.AppendLine("  or4-wrapper 0x" + h.Site.ToString("X") + " " + h.Text);

    // 4) Classify every key-referencing function
    sb.AppendLine();
    sb.AppendLine("===== KEY-USER CLASSIFICATION =====");
    var keyUsers = new List<GateHit>();
    foreach (var fn in keyCallerFuncs.OrderBy(x => x)) {
      // skip obvious mid-insn FindFuncStart junk (odd addresses with no real prologue)
      if (fn > 0x10000000) continue;
      var h = new GateHit { Func = fn, Site = fn, Kind = "key-user" };
      EnrichFunc(h);
      bool touch61 = Touches61(fn, out bool or61, out bool and61, out bool mov61);
      h.Notes.Add(touch61 ? "touch61" : "no61");
      if (or61) h.Notes.Add("or61");
      if (and61) h.Notes.Add("and61");
      if (mov61) h.Notes.Add("mov61");
      if (HasSmallArrayTouch(fn)) h.Notes.Add("smallArray");
      if (fn == Wrapper || (fn >= Wrapper && fn < WrapperEnd)) { h.InWrapper = true; h.Notes.Add("wrapper"); }
      if (fn == WorkerA) h.Notes.Add("workerA");
      keyUsers.Add(h);
      sb.AppendLine("  0x" + fn.ToString("X")
        + " alloc=" + h.CallsAllocator + " lookup=" + h.CallsLookup + " helper=" + h.CallsHelper
        + " nest=" + h.NestedChain + " " + string.Join(",", h.Notes)
        + (h.Strings.Count > 0 ? " str=\"" + Trunc(h.Strings[0], 40) + "\"" : ""));
    }

    // 5) High-signal insert/gate leads = key-users that touch +0x61 (excl. wrapper-only or4 consumers)
    sb.AppendLine();
    sb.AppendLine("===== INSERT / GATE LEADS (key-user ∩ +0x61) =====");
    var insertLeads = keyUsers.Where(h =>
      h.Notes.Contains("touch61") && !h.Notes.Contains("wrapper")).ToList();
    // Also keep key-users with SmallArray + allocator even without 61 (possible inserters)
    foreach (var h in keyUsers.Where(x =>
        x.Notes.Contains("smallArray") && x.CallsAllocator && !x.Notes.Contains("wrapper")
        && !insertLeads.Any(y => y.Func == x.Func))) {
      h.Notes.Add("alloc+small-no61");
      insertLeads.Add(h);
    }
    foreach (var h in insertLeads.OrderBy(x => x.Func)) {
      sb.AppendLine("  LEAD 0x" + h.Func.ToString("X") + " " + string.Join("+", h.Notes)
        + " nest=" + h.NestedChain + " alloc=" + h.CallsAllocator);
      DumpShort(sb, h.Func, 0x50);
      // dump +0x61 ops
      foreach (var a in Disasm(h.Func, h.Func + 0x800).Where(x => x.HasMem && !x.IpRel && x.Disp == 0x61).Take(12))
        sb.AppendLine("    61op 0x" + a.Rva.ToString("X") + " " + a.Text);
      foreach (var a in Disasm(h.Func, h.Func + 0x800).Where(x => x.IpRel && x.DataRva == LookupKey).Take(4))
        sb.AppendLine("    key 0x" + a.Rva.ToString("X") + " " + a.Text);
      foreach (var t in h.Strings.Take(4))
        sb.AppendLine("    str \"" + Trunc(t, 70) + "\"");
    }

    // 6) ListScan callers
    sb.AppendLine();
    sb.AppendLine("===== LISTSCAN 0x537C2C0 CALLERS =====");
    var listCallers = FindE8(ListScan, 60);
    var listCallerFuncs = new HashSet<uint>();
    sb.AppendLine("e8Callers=" + listCallers.Count);
    foreach (var s in listCallers) {
      uint fn = FindFuncStart(s);
      listCallerFuncs.Add(fn);
      bool inWrap = s >= Wrapper && s < WrapperEnd;
      bool keyUser = keyCallerFuncs.Contains(fn);
      sb.AppendLine("  e8 @0x" + s.ToString("X") + " func≈0x" + fn.ToString("X")
        + (inWrap ? " [wrapper]" : "") + (keyUser ? " [keyUser]" : ""));
    }

    // 7) Worker + key (confirmed teardown path shares TypeInfo)
    sb.AppendLine();
    sb.AppendLine("===== WORKER 0x725400 + KEY =====");
    sb.AppendLine("workerReferencesLookupKey=" + keyCallerFuncs.Contains(WorkerA));
    DumpShort(sb, WorkerA, 0x60);
    foreach (var a in Disasm(WorkerA, WorkerA + 0x280)) {
      if (a.HasMem && !a.IpRel && a.Disp == 0x61)
        sb.AppendLine("  w61 0x" + a.Rva.ToString("X") + " " + a.Text);
      if (a.IpRel && a.DataRva == LookupKey)
        sb.AppendLine("  wkey 0x" + a.Rva.ToString("X") + " " + a.Text);
    }

    // 8) Bit1 setter sequences: or r8, 2  then store to +0x61 (within 10 ins)
    sb.AppendLine();
    sb.AppendLine("===== BIT1 SET SEQUENCES (or r*,2 → store +0x61) =====");
    var bit1Setters = FindBit1SetSequences(sb, 40);

    sb.AppendLine();
    sb.AppendLine("===== SUMMARY =====");
    sb.AppendLine("lookupKey=0x" + LookupKey.ToString("X")
      + " xrefs=" + keyXrefs.Count + " keyUsers=" + keyUsers.Count
      + " class=" + keyInfo.Classification);
    sb.AppendLine("immOr4=" + or4.Count + " insertLeads=" + insertLeads.Count
      + " bit1SetSeq=" + bit1Setters.Count
      + " listScanCallers=" + listCallerFuncs.Count
      + " workerUsesKey=" + keyCallerFuncs.Contains(WorkerA));

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteKeyJson(hash, keyInfo, keyXrefs, absRefs, keyCallerFuncs);
    WriteGateJson(hash, gateHits, insertLeads, bit1Setters, keyUsers);
    WriteSummaryJson(hash, keyInfo, keyXrefs, or4, insertLeads, bit1Setters, listCallerFuncs, keyUsers);
    WriteFeasibilityJson(hash, keyInfo, insertLeads, bit1Setters);

    bool ok = keyXrefs.Count >= 2 && or4.Count(h => h.InWrapper) >= 2
      && keyCallerFuncs.Contains(WorkerA) && insertLeads.Count >= 1;
    Console.WriteLine("selfCheck keyXrefs=" + keyXrefs.Count + " or4wrap=" + or4.Count(h => h.InWrapper)
      + " insertLeads=" + insertLeads.Count + " bit1Seq=" + bit1Setters.Count + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static bool Touches61(uint entry, out bool or61, out bool and61, out bool mov61) {
    or61 = and61 = mov61 = false;
    bool any = false;
    uint end = FindFuncEndFirstRet(entry, 0x1800);
    if (end <= entry) end = entry + 0x400;
    if (end - entry > 0x1800) end = entry + 0x1800;
    foreach (var a in Disasm(entry, end)) {
      if (!a.HasMem || a.IpRel || a.Disp != 0x61) continue;
      any = true;
      if (a.Mnemonic == Mnemonic.Or) or61 = true;
      if (a.Mnemonic == Mnemonic.And) and61 = true;
      if (a.Mnemonic == Mnemonic.Mov && a.Raw.OpCount >= 1 && a.Raw.GetOpKind(0) == OpKind.Memory)
        mov61 = true;
    }
    return any;
  }

  static List<GateHit> FindBit1SetSequences(StringBuilder sb, int max) {
    var hits = new List<GateHit>();
    // Pattern: 80 C? 02 / 41 80 C? 02  (or r8/r8b/al/..., 2) then nearby store to +0x61
    foreach (var sec in CodeSecs()) {
      uint lim = Math.Min(sec.Raw, sec.VSize > 0 ? sec.VSize : sec.Raw);
      for (uint i = 0; i + 3 <= lim && hits.Count < max; i++) {
        int p = (int)(sec.Ptr + i);
        int rex = 0;
        byte b0 = pe[p];
        if (b0 >= 0x40 && b0 <= 0x4F) { rex = 1; if (i + 4 > lim) continue; b0 = pe[p + 1]; }
        // or r/m8, imm8 with register dest: 80 /1 with mod=11, imm=2
        if (b0 != 0x80 && b0 != 0x82) continue;
        byte modrm = pe[p + rex + 1];
        if ((modrm >> 6) != 3) continue; // register
        if (((modrm >> 3) & 7) != 1) continue; // OR
        if (pe[p + rex + 2] != 0x02) continue;
        uint site = sec.Va + i;
        // look ahead ≤ 0x30 bytes for store to +0x61
        var win = Disasm(site, site + 0x40);
        bool store61 = false;
        string storeTxt = "";
        foreach (var a in win) {
          if (a.Rva < site) continue;
          if (a.Mnemonic == Mnemonic.Mov && a.HasMem && !a.IpRel && a.Disp == 0x61
              && a.Raw.OpCount >= 1 && a.Raw.GetOpKind(0) == OpKind.Memory) {
            store61 = true; storeTxt = a.Text; break;
          }
          if (a.Mnemonic == Mnemonic.Or && a.HasMem && !a.IpRel && a.Disp == 0x61) {
            store61 = true; storeTxt = a.Text; break;
          }
        }
        if (!store61) continue;
        uint fn = FindFuncStart(site);
        var h = new GateHit {
          Site = site, Func = fn, Kind = "bit1-set-seq", Imm = 2,
          Text = win[0].Text + " ; " + storeTxt,
          InWrapper = site >= Wrapper && site < WrapperEnd
        };
        EnrichFunc(h);
        hits.Add(h);
        sb.AppendLine("  bit1 @0x" + site.ToString("X") + " func=0x" + fn.ToString("X")
          + " " + h.Text + " alloc=" + h.CallsAllocator + " nest=" + h.NestedChain
          + " keyUser=" + (fn == WorkerA || (fn >= Wrapper && fn < WrapperEnd)));
      }
    }
    sb.AppendLine("bit1SetSequences=" + hits.Count);
    return hits;
  }

  sealed class KeyInfo {
    public uint Rva = LookupKey;
    public string Hex64 = "";
    public List<string> Qwords = new List<string>();
    public List<string> NearbyStrings = new List<string>();
    public string Classification = "unknown";
    public List<string> Notes = new List<string>();
  }

  static KeyInfo DecodeLookupKey(StringBuilder sb) {
    var info = new KeyInfo();
    int fo = RvaToFile(LookupKey);
    if (fo < 0) {
      sb.AppendLine("UNMAPPED");
      info.Classification = "unmapped";
      return info;
    }
    info.Hex64 = Hex(LookupKey, 64);
    sb.AppendLine("sec=" + SecName(LookupKey) + " hex64=" + info.Hex64);
    // Dword view (Anvil TypeInfo often mixes 32-bit reloc fields)
    for (int i = 0; i < 16; i++) {
      uint d = BitConverter.ToUInt32(pe, fo + i * 4);
      string note = "d[" + i + "]=0x" + d.ToString("X");
      if (d > 0x1000 && d < 0x20000000) {
        string s = ReadAscii(d, 80);
        string sn = SecName(d);
        note += " asRva sec=" + sn;
        if (IsString(s)) note += " \"" + Trunc(s, 40) + "\"";
        else {
          // maybe pointer to another struct — show prologue hex
          note += " hex=" + Hex(d, 8);
        }
      }
      // image VA truncated low32?
      ulong maybe = imageBase + d;
      if (d > 0x1000 && d < 0x20000000) { /* already */ }
      info.Qwords.Add(note);
      sb.AppendLine("  " + note);
    }
    for (int i = 0; i < 4; i++) {
      ulong q = BitConverter.ToUInt64(pe, fo + i * 8);
      string note = "q[" + i + "]=0x" + q.ToString("X");
      if (q > imageBase && q < imageBase + 0x20000000) {
        uint r = (uint)(q - imageBase);
        string s = ReadAscii(r, 80);
        note += " ->rva 0x" + r.ToString("X") + (IsString(s) ? " \"" + Trunc(s, 40) + "\"" : "")
          + " sec=" + SecName(r);
      }
      sb.AppendLine("  " + note);
    }
    info.Notes.Add("section=.trace");

    // Nearby strings ±0x400
    var seen = new HashSet<string>();
    for (int delta = -0x400; delta < 0x800; delta++) {
      uint r = unchecked((uint)((int)LookupKey + delta));
      int p = RvaToFile(r);
      if (p < 0 || p >= pe.Length) continue;
      if (pe[p] < 32 || pe[p] >= 127) continue;
      if (delta > -0x400) {
        int prev = RvaToFile(unchecked((uint)((int)LookupKey + delta - 1)));
        if (prev >= 0 && pe[prev] >= 32 && pe[prev] < 127) continue;
      }
      string s = ReadAscii(r, 100);
      if (!IsString(s) || s.Length < 5) continue;
      if (seen.Add(s)) {
        info.NearbyStrings.Add("0x" + r.ToString("X") + ":" + s);
        sb.AppendLine("  nearStr 0x" + r.ToString("X") + " \"" + Trunc(s, 80) + "\"");
      }
      if (seen.Count >= 24) break;
    }

    // Heuristic classification from first qwords / usage
    // Prior dump showed: A2 C3 FF FF FF FF 06 C4 ... looks like tagged/compressed pointer + type meta
    byte b0 = pe[fo];
    // Anvil TypeInfo often starts with vtable or name pointer
    bool hasNameNearby = info.NearbyStrings.Any(x =>
      x.IndexOf("Actor", StringComparison.OrdinalIgnoreCase) >= 0
      || x.IndexOf("LOD", StringComparison.OrdinalIgnoreCase) >= 0
      || x.IndexOf("Entity", StringComparison.OrdinalIgnoreCase) >= 0
      || x.IndexOf("Component", StringComparison.OrdinalIgnoreCase) >= 0);
    info.Notes.Add("first8=" + Hex(LookupKey, 8));
    info.Notes.Add("usedAsLookupRdxKeyInEnrollmentSites");
    if (hasNameNearby) {
      info.Classification = "typeinfo_or_descriptor_near_named_strings";
    } else {
      info.Classification = "opaque_anvil_typeinfo_key_in_.trace";
    }
    info.Notes.Add("shared_by_UpdateActorLOD_wrapper_and_worker_0x725400");
    sb.AppendLine("classification=" + info.Classification);
    return info;
  }

  static List<GateHit> ScanGateWriters(StringBuilder sb) {
    var hits = new List<GateHit>();
    // Fast pattern: [REX?] 80 ModRM(+disp8 0x61) imm8
    // Group1: /0 ADD /1 OR /2 ADC /3 SBB /4 AND /5 SUB /6 XOR /7 CMP
    // OR  => ModRM = 0x48|rm ; AND => 0x60|rm
    // also 82 (alias), and C6 mov r/m8, imm8 with same disp
    foreach (var sec in CodeSecs()) {
      uint lim = Math.Min(sec.Raw, sec.VSize > 0 ? sec.VSize : sec.Raw);
      for (uint i = 0; i + 4 <= lim; i++) {
        int p = (int)(sec.Ptr + i);
        int rex = 0;
        byte b0 = pe[p];
        if (b0 >= 0x40 && b0 <= 0x4F) { rex = 1; if (i + 5 > lim) continue; b0 = pe[p + 1]; }
        if (b0 != 0x80 && b0 != 0x82 && b0 != 0xC6) continue;
        byte modrm = pe[p + rex + 1];
        byte mod = (byte)(modrm >> 6);
        byte reg = (byte)((modrm >> 3) & 7);
        if (mod != 1) continue; // disp8 only for this pass
        if (pe[p + rex + 2] != 0x61) continue;
        // OR=/1, AND=/4, MOV C6=/0; also keep XOR=/6 for completeness
        if (b0 == 0xC6 && reg != 0) continue;
        if ((b0 == 0x80 || b0 == 0x82) && reg != 1 && reg != 4 && reg != 6) continue;
        uint site = sec.Va + i;
        var ins = DisasmOne(site);
        if (ins == null || ins.Rva != site) continue;
        if (!ins.HasMem || ins.IpRel || ins.Disp != 0x61) continue;
        if (ins.Mnemonic != Mnemonic.Or && ins.Mnemonic != Mnemonic.And && ins.Mnemonic != Mnemonic.Mov)
          continue;
        uint imm = 0;
        bool hasImm = false;
        if (ins.Raw.OpCount >= 2 && (ins.Raw.GetOpKind(1) == OpKind.Immediate8
            || ins.Raw.GetOpKind(1) == OpKind.Immediate8to32
            || ins.Raw.GetOpKind(1) == OpKind.Immediate8to64)) {
          hasImm = true;
          imm = ins.Raw.Immediate8;
        }
        if (!hasImm) continue;
        string kind = ClassifyGate(ins.Mnemonic, imm, true);
        if (kind == "skip") continue;
        hits.Add(new GateHit {
          Site = site,
          Func = FindFuncStart(site),
          Text = ins.Text,
          Kind = kind,
          Imm = imm,
          InWrapper = site >= Wrapper && site < WrapperEnd
        });
      }
    }
    hits = hits.GroupBy(h => h.Site).Select(g => g.First()).OrderBy(h => h.Site).ToList();
    sb.AppendLine("rawVerifiedHits=" + hits.Count);
    foreach (var g in hits.GroupBy(h => h.Kind).OrderByDescending(g => g.Count()))
      sb.AppendLine("  kind=" + g.Key + " count=" + g.Count());
    foreach (var h in hits.Where(x => x.Kind == "or2").Take(50))
      sb.AppendLine("  or2 @0x" + h.Site.ToString("X") + " func≈0x" + h.Func.ToString("X") + " " + h.Text);
    return hits;
  }

  static string ClassifyGate(Mnemonic m, uint imm, bool hasImm) {
    if (m == Mnemonic.Or && hasImm) {
      if (imm == 2) return "or2";
      if (imm == 4) return "or4";
      if (imm == 6) return "or6";
      if (imm == 1 || imm == 8 || imm == 0x10 || imm == 0x20 || imm == 0x40 || imm == 0x80)
        return "orOther";
      return "orOther";
    }
    if (m == Mnemonic.And && hasImm) {
      if (imm == 0xFD) return "andFD"; // clear bit1
      if (imm == 0xFB) return "andFB"; // clear bit2
      if (imm == 0xF9) return "andF9"; // clear bit1+2
      return "andOther";
    }
    if (m == Mnemonic.Mov && hasImm) return "movImm";
    if (m == Mnemonic.Xor && hasImm && imm == 0) return "skip";
    return "skip";
  }

  static void EnrichFunc(GateHit h) {
    uint end = FindFuncEndFirstRet(h.Func, 0x2000);
    if (end <= h.Func) end = h.Func + 0x400;
    if (end - h.Func > 0x2000) end = h.Func + 0x2000;
    bool s18 = false, sA8 = false, s3 = false;
    foreach (var a in Disasm(h.Func, end)) {
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
        uint d = (uint)(a.Raw.NearBranchTarget - imageBase);
        if (d == Allocator) h.CallsAllocator = true;
        if (d == Lookup) h.CallsLookup = true;
        if (d == Helper) h.CallsHelper = true;
        if (d == ListScan) h.CallsListScan = true;
        if (d == Wrapper) { /* rare */ }
      }
      if (a.HasMem && !a.IpRel) {
        if (a.Disp == 0x18) s18 = true;
        if (a.Disp == 0xA8) sA8 = true;
        if (a.Disp == 0x3CD0) s3 = true;
      }
      if (a.Raw.OpCount >= 2 && a.Raw.GetOpKind(1) == OpKind.Immediate32) {
        uint imm = a.Raw.Immediate32;
        if (imm >= 0x20 && imm <= 0x8000 && (imm % 8) == 0) h.ImmSizes.Add(imm);
      }
      if (a.IpRel) {
        string s = ReadAscii(a.DataRva, 80);
        if (IsString(s) && s.Length >= 5 && h.Strings.Count < 8
            && !s.StartsWith("AWAV", StringComparison.Ordinal) && !s.Contains("VWUSH")
            && !h.Strings.Contains(s))
          h.Strings.Add(s);
      }
    }
    h.NestedChain = s18 && sA8 && s3;
    h.ImmSizes = h.ImmSizes.Distinct().OrderBy(x => x).ToList();
    if (h.Func >= Wrapper && h.Func < WrapperEnd) h.InWrapper = true;
  }

  static bool HasSmallArrayTouch(uint entry) {
    uint end = FindFuncEndFirstRet(entry, 0x1200);
    if (end <= entry) end = entry + 0x300;
    if (end - entry > 0x1200) end = entry + 0x1200;
    bool saw1fff8 = false, sawShift3 = false, sawCount8 = false;
    foreach (var a in Disasm(entry, end)) {
      if (a.Raw.OpCount >= 2) {
        for (int i = 0; i < a.Raw.OpCount; i++) {
          var k = a.Raw.GetOpKind(i);
          if (k == OpKind.Immediate32 || k == OpKind.Immediate8to32 || k == OpKind.Immediate64) {
            ulong imm = a.Raw.GetImmediate(i);
            if (imm == 0x1FFF8) saw1fff8 = true;
          }
        }
      }
      if (a.Mnemonic == Mnemonic.Shl || a.Mnemonic == Mnemonic.Sal) {
        // shl x,3 often for *8
        if (a.Raw.OpCount >= 2 && a.Raw.GetOpKind(1) == OpKind.Immediate8 && a.Raw.Immediate8 == 3)
          sawShift3 = true;
      }
      if (a.HasMem && !a.IpRel && a.Disp == 8) sawCount8 = true;
    }
    return saw1fff8 || (sawShift3 && sawCount8);
  }

  static string LeadReason(GateHit h, HashSet<uint> keyFuncs) {
    var parts = new List<string>();
    if (h.CallsAllocator) parts.Add("alloc");
    if (h.CallsLookup) parts.Add("lookup");
    if (h.NestedChain) parts.Add("nest");
    if (h.CallsListScan) parts.Add("listScan");
    if (h.CallsHelper) parts.Add("helper");
    if (keyFuncs.Contains(h.Func)) parts.Add("keyXref");
    if (HasSmallArrayTouch(h.Func)) parts.Add("smallArray");
    return string.Join("+", parts);
  }

  static Ins DisasmOne(uint rva) {
    var list = Disasm(rva, rva + 0x10);
    return list.Count > 0 && list[0].Rva == rva ? list[0] : (list.Count > 0 ? list[0] : null);
  }

  static void DumpShort(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEndFirstRet(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    sb.AppendLine("  func 0x" + entry.ToString("X") + " size~" + (end - entry)
      + " prologue=" + Hex(entry, 12));
    foreach (var a in Disasm(entry, end).Take(16))
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
      if (seen.Count >= 6) break;
    }
  }

  static bool Reach(uint entry, HashSet<uint> targets, int maxDepth, out string path) {
    path = "";
    var seen = new HashSet<uint>();
    var q = new Queue<(uint e, int d, string p)>();
    q.Enqueue((entry, 0, "0x" + entry.ToString("X")));
    while (q.Count > 0) {
      var (e, d, p) = q.Dequeue();
      if (!seen.Add(e) || d > maxDepth) continue;
      if (d > 0 && targets.Contains(e)) { path = p; return true; }
      uint end = FindFuncEndFirstRet(e, 0x800);
      if (end <= e) end = e + 0x120;
      if (end - e > 0x800) end = e + 0x800;
      foreach (var a in Disasm(e, end)) {
        if (!a.IsCall || a.IsIndirectCall || a.Raw.NearBranchTarget == 0) continue;
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        q.Enqueue((dest, d + 1, p + " -> 0x" + dest.ToString("X")));
      }
    }
    return false;
  }

  static void WriteKeyJson(string hash, KeyInfo key, List<uint> xrefs, List<uint> abs,
      HashSet<uint> funcs) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.13\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"lookupKey\": {");
    sb.AppendLine("    \"rva\": \"0x" + LookupKey.ToString("X") + "\",");
    sb.AppendLine("    \"section\": " + J(SecName(LookupKey)) + ",");
    sb.AppendLine("    \"hex64\": " + J(key.Hex64) + ",");
    sb.AppendLine("    \"classification\": " + J(key.Classification) + ",");
    sb.AppendLine("    \"qwords\": [" + string.Join(", ", key.Qwords.Select(J)) + "],");
    sb.AppendLine("    \"nearbyStrings\": [" + string.Join(", ", key.NearbyStrings.Take(20).Select(J)) + "],");
    sb.AppendLine("    \"notes\": [" + string.Join(", ", key.Notes.Select(J)) + "]");
    sb.AppendLine("  },");
    sb.AppendLine("  \"leaOrMovXrefs\": [" + string.Join(", ", xrefs.Take(60).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("  \"absQwordRefs\": [" + string.Join(", ", abs.Take(40).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("  \"referencingFuncs\": [" + string.Join(", ", funcs.OrderBy(x => x).Take(40).Select(x => "\"0x" + x.ToString("X") + "\"")) + "]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.13-lookup-key.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.13-lookup-key.json");
  }

  static void WriteGateJson(string hash, List<GateHit> all, List<GateHit> leads,
      List<GateHit> bit1, List<GateHit> keyUsers) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.13\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"immKindCounts\": {");
    var kinds = all.GroupBy(h => h.Kind).OrderByDescending(g => g.Count()).ToList();
    for (int i = 0; i < kinds.Count; i++) {
      sb.Append("    \"" + kinds[i].Key + "\": " + kinds[i].Count());
      sb.AppendLine(i + 1 < kinds.Count ? "," : "");
    }
    sb.AppendLine("  },");
    sb.AppendLine("  \"or4InWrapper\": [" + string.Join(", ",
      all.Where(h => h.Kind == "or4" && h.InWrapper).Select(h => "\"0x" + h.Site.ToString("X") + "\"")) + "],");
    sb.AppendLine("  \"bit1SetSequences\": [" + string.Join(", ", bit1.Take(30).Select(h =>
      "{ \"site\": \"0x" + h.Site.ToString("X") + "\", \"func\": \"0x" + h.Func.ToString("X")
      + "\", \"text\": " + J(h.Text) + " }")) + "],");
    sb.AppendLine("  \"insertLeads\": [");
    for (int i = 0; i < leads.Count; i++) {
      var h = leads[i];
      sb.Append("    { \"func\": \"0x" + h.Func.ToString("X")
        + "\", \"notes\": [" + string.Join(", ", h.Notes.Select(J)) + "]"
        + ", \"callsAllocator\": " + T(h.CallsAllocator)
        + ", \"callsLookup\": " + T(h.CallsLookup)
        + ", \"nestedChain\": " + T(h.NestedChain)
        + ", \"strings\": [" + string.Join(", ", h.Strings.Take(5).Select(J)) + "] }");
      sb.AppendLine(i + 1 < leads.Count ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"keyUsersTouch61\": [" + string.Join(", ",
      keyUsers.Where(h => h.Notes.Contains("touch61")).Select(h => "\"0x" + h.Func.ToString("X") + "\"")) + "]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.13-gate-writers.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.13-gate-writers.json");
  }

  static void WriteSummaryJson(string hash, KeyInfo key, List<uint> xrefs,
      List<GateHit> or4, List<GateHit> leads, List<GateHit> bit1,
      HashSet<uint> listCallers, List<GateHit> keyUsers) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.13\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"lookupKeyRva\": \"0x" + LookupKey.ToString("X") + "\",");
    sb.AppendLine("  \"lookupKeyClass\": " + J(key.Classification) + ",");
    sb.AppendLine("  \"lookupKeySection\": " + J(SecName(LookupKey)) + ",");
    sb.AppendLine("  \"lookupKeyXrefs\": " + xrefs.Count + ",");
    sb.AppendLine("  \"keyUserCount\": " + keyUsers.Count + ",");
    sb.AppendLine("  \"keyUsersTouch61\": " + keyUsers.Count(h => h.Notes.Contains("touch61")) + ",");
    sb.AppendLine("  \"or4SiteCount\": " + or4.Count + ",");
    sb.AppendLine("  \"or4InWrapper\": " + or4.Count(h => h.InWrapper) + ",");
    sb.AppendLine("  \"insertLeadCount\": " + leads.Count + ",");
    sb.AppendLine("  \"bit1SetSequenceCount\": " + bit1.Count + ",");
    sb.AppendLine("  \"listScanCallerCount\": " + listCallers.Count + ",");
    sb.AppendLine("  \"workerReferencesLookupKey\": true,");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.13-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.13-summary.json");
  }

  static void WriteFeasibilityJson(string hash, KeyInfo key, List<GateHit> leads, List<GateHit> bit1) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.13\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Insert/gate leads share TypeInfo key but do not prove Edward factory\" },");
    sb.AppendLine("  \"lookupKeyIdentifiesSubjectType\": { \"class\": \"plausible\", \"reason\": " + J(key.Classification + "; used by wrapper+workerA") + " },");
    sb.AppendLine("  \"insertLeads\": { \"class\": " + (leads.Count > 0 ? "\"plausible\"" : "\"unsupported\"")
      + ", \"reason\": \"count=" + leads.Count + "\" },");
    sb.AppendLine("  \"bit1SetSequences\": { \"class\": " + (bit1.Count > 0 ? "\"plausible\"" : "\"unsupported\"")
      + ", \"reason\": \"count=" + bit1.Count + "\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Deep-decode insert leads 0x53F31A0 / 0xF1C240 / 0x2EA0B00 / 0x4D04450 and TypeInfo fields at 0xB2898C8\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking without list evidence\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.13-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.13-second-edward-feasibility.json");
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
        Raw = raw,
        Rva = (uint)(raw.IP - imageBase),
        Text = o.ToString(),
        Mnemonic = raw.Mnemonic,
        Length = raw.Length,
        IsCall = raw.FlowControl == FlowControl.Call || raw.FlowControl == FlowControl.IndirectCall,
        IsIndirectCall = raw.FlowControl == FlowControl.IndirectCall
      };
      if (raw.OpCount >= 1 && raw.GetOpKind(0) == OpKind.Register) {
        ins.Op0IsReg = true;
        ins.Op0Reg = raw.GetOpRegister(0);
      }
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

  static List<uint> FindLeaOrMovTo(uint target, int max) {
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
