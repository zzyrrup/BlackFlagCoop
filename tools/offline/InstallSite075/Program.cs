// v0.6.15 — Offline recover indirect install sites for 0x53F31A0 / 0xF1C240
// and deep-decode allocator/call-source 0xE2C8A0.
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
  const uint AllocSrc = 0xE2C8A0;
  const uint NearWrap = 0x2EA0B00;
  const uint LookupKey = 0xB2898C8;
  const uint Lookup = 0x429F9E0;
  const uint Allocator = 0x426EE50;
  const uint Helper = 0x2E97B60;
  const uint Wrapper = 0x2E97FC0;
  const uint WorkerA = 0x725400;
  const uint ListScan = 0x537C2C0;
  const uint Registrar = 0x5CBDFB0;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static readonly uint[] InstallTargets = { GateSetter, BitWriter };

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
  sealed class XrefHit {
    public string Kind; public uint Site; public uint Func; public string Sec; public string Note = "";
  }
  sealed class InstallReport {
    public uint Target;
    public string Role;
    public List<XrefHit> Hits = new List<XrefHit>();
    public List<uint> StubEntries = new List<uint>();
    public List<string> Notes = new List<string>();
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v075-raw");
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
    sb.AppendLine("===== v0.6.15 INSTALL SITES + 0xE2C8A0 =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("imageBase=0x" + imageBase.ToString("X"));

    // Control: wrapper should still show stub/LEA path pattern class (known from v0.6.7)
    sb.AppendLine();
    sb.AppendLine("===== CONTROL XREFS WRAPPER 0x2E97FC0 =====");
    DumpAllXrefs(sb, Wrapper, "wrapper");

    var installs = new List<InstallReport>();
    foreach (uint t in InstallTargets) {
      sb.AppendLine();
      sb.AppendLine("===== INSTALL TARGET 0x" + t.ToString("X") + " =====");
      installs.Add(RecoverInstall(sb, t, RoleOf(t)));
    }

    // Two-hop: find stubs that JMP/E9 to target, then xref those stubs
    foreach (var rep in installs) {
      sb.AppendLine();
      sb.AppendLine("===== STUB FOLLOW 0x" + rep.Target.ToString("X") + " =====");
      FollowStubs(sb, rep);
    }

    // TypeInfo / table neighborhood: look for target RVA near key or in .edata tables
    sb.AppendLine();
    sb.AppendLine("===== TABLE / TYPEINFO NEIGHBORHOOD =====");
    ScanTablesNearKey(sb);
    foreach (uint t in InstallTargets)
      ScanRva32Pairs(sb, t);

    // Deep-decode 0xE2C8A0
    sb.AppendLine();
    sb.AppendLine("===== DEEP 0xE2C8A0 =====");
    var alloc = DeepE2C8A0(sb);

    sb.AppendLine();
    sb.AppendLine("===== SUMMARY =====");
    foreach (var r in installs) {
      sb.AppendLine("0x" + r.Target.ToString("X") + " " + r.Role
        + " hits=" + r.Hits.Count + " stubs=" + r.StubEntries.Count);
      foreach (var h in r.Hits.Take(20))
        sb.AppendLine("  " + h.Kind + " @0x" + h.Site.ToString("X")
          + " func≈0x" + h.Func.ToString("X") + " sec=" + h.Sec
          + (string.IsNullOrEmpty(h.Note) ? "" : " " + h.Note));
    }
    sb.AppendLine("e2c8a0 size=" + alloc.Size + " callsNearWrap=" + alloc.CallsNearWrap
      + " callsAlloc=" + alloc.CallsAllocator + " usesKey=" + alloc.UsesKey
      + " callersE8=" + alloc.CallersE8.Count);

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteInstallJson(hash, installs);
    WriteE2Json(hash, alloc);
    WriteSummaryJson(hash, installs, alloc);
    WriteFeasibilityJson(hash, installs, alloc);

    bool ok = installs.All(r => r.Target != 0) && alloc.Size > 0 && alloc.CallsNearWrap;
    Console.WriteLine("selfCheck installs=" + installs.Count
      + " totalHits=" + installs.Sum(r => r.Hits.Count)
      + " e2callsNearWrap=" + alloc.CallsNearWrap + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static string RoleOf(uint t) =>
    t == GateSetter ? "gate-setter" : t == BitWriter ? "bit-writer" : "target";

  static InstallReport RecoverInstall(StringBuilder sb, uint target, string role) {
    var rep = new InstallReport { Target = target, Role = role };
    void add(string kind, uint site, string note = "") {
      rep.Hits.Add(new XrefHit {
        Kind = kind, Site = site, Func = FindFuncStart(site),
        Sec = SecName(site), Note = note
      });
      sb.AppendLine("  " + kind + " @0x" + site.ToString("X")
        + " sec=" + SecName(site) + " func≈0x" + FindFuncStart(site).ToString("X")
        + (string.IsNullOrEmpty(note) ? "" : " " + note));
    }

    sb.AppendLine("target=0x" + target.ToString("X") + " role=" + role
      + " prologue=" + Hex(target, 16));

    foreach (var s in FindE8(target, 40)) add("e8", s);
    foreach (var s in FindLeaTo(target, 40)) add("lea", s);
    foreach (var s in FindLeaNear(target, 0x20, 40)) add("leaNear", s, "nearEntry");
    foreach (var s in FindQword(target, 40)) add("qword", s);
    foreach (var s in FindRva32(target, 60)) add("rva32", s);
    foreach (var s in FindE9(target, 40)) {
      add("e9", s);
      rep.StubEntries.Add(FindFuncStart(s));
    }
    foreach (var s in FindFf25To(target, 20)) add("ff25", s, "jmp[rip]");
    foreach (var s in FindMovImm64(target, 20)) add("movImm64", s);
    foreach (var s in FindCallIndirectRipLoad(target, 20)) add("callRipQword", s);

    // Relative-from-site style rarely used but check
    foreach (var s in FindRel32SitePlus(target, 20)) add("rel32site", s);

    sb.AppendLine("hitCount=" + rep.Hits.Count + " byKind="
      + string.Join(",", rep.Hits.GroupBy(h => h.Kind).Select(g => g.Key + ":" + g.Count())));
    return rep;
  }

  static void FollowStubs(StringBuilder sb, InstallReport rep) {
    var stubs = new HashSet<uint>(rep.StubEntries);
    // Also consider functions that contain E9/FF25 to target as stubs
    foreach (var h in rep.Hits.Where(x => x.Kind == "e9" || x.Kind == "ff25"))
      stubs.Add(h.Func == 0 ? h.Site : h.Func);
    // Probe ±0x40 for short JMP thunks into target
    for (int d = -0x40; d < 0x40; d++) {
      uint cand = unchecked((uint)((int)rep.Target + d));
      if (cand == rep.Target) continue;
      int fo = RvaToFile(cand);
      if (fo < 0) continue;
      // E9 to target
      if (fo + 5 <= pe.Length && pe[fo] == 0xE9) {
        int rel = BitConverter.ToInt32(pe, fo + 1);
        if ((long)cand + 5 + rel == rep.Target) stubs.Add(cand);
      }
      // EB short
      if (fo + 2 <= pe.Length && pe[fo] == 0xEB) {
        sbyte rel = unchecked((sbyte)pe[fo + 1]);
        if ((long)cand + 2 + rel == rep.Target) stubs.Add(cand);
      }
    }
    rep.StubEntries = stubs.OrderBy(x => x).ToList();
    sb.AppendLine("stubCandidates=" + rep.StubEntries.Count);
    foreach (uint stub in rep.StubEntries.Take(16)) {
      sb.AppendLine("  stub 0x" + stub.ToString("X") + " " + Hex(stub, 12));
      DumpShort(sb, stub, 0x30);
      // Xrefs to stub
      foreach (var s in FindE8(stub, 12)) {
        var h = new XrefHit {
          Kind = "stubE8", Site = s, Func = FindFuncStart(s), Sec = SecName(s),
          Note = "stub=0x" + stub.ToString("X")
        };
        rep.Hits.Add(h);
        sb.AppendLine("    stubE8 @0x" + s.ToString("X") + " func≈0x" + h.Func.ToString("X"));
      }
      foreach (var s in FindLeaTo(stub, 12)) {
        var h = new XrefHit {
          Kind = "stubLea", Site = s, Func = FindFuncStart(s), Sec = SecName(s),
          Note = "stub=0x" + stub.ToString("X")
        };
        rep.Hits.Add(h);
        sb.AppendLine("    stubLea @0x" + s.ToString("X") + " func≈0x" + h.Func.ToString("X"));
        // Dump installer context
        DumpInstallerContext(sb, h.Func, stub, rep.Target);
      }
      foreach (var s in FindQword(stub, 12)) {
        var h = new XrefHit {
          Kind = "stubQword", Site = s, Func = 0, Sec = SecName(s),
          Note = "stub=0x" + stub.ToString("X")
        };
        rep.Hits.Add(h);
        sb.AppendLine("    stubQword @0x" + s.ToString("X") + " sec=" + h.Sec);
        DumpQwordNeighbor(sb, s);
      }
      foreach (var s in FindRva32(stub, 20)) {
        var h = new XrefHit {
          Kind = "stubRva32", Site = s, Func = 0, Sec = SecName(s),
          Note = "stub=0x" + stub.ToString("X")
        };
        rep.Hits.Add(h);
        sb.AppendLine("    stubRva32 @0x" + s.ToString("X") + " sec=" + h.Sec);
      }
    }
    if (rep.Hits.Count == 0)
      rep.Notes.Add("no_direct_or_stub_install_found");
  }

  static void DumpInstallerContext(StringBuilder sb, uint func, uint stub, uint target) {
    if (func == 0) return;
    uint end = FindFuncEnd(func, 0x800);
    if (end <= func) end = func + 0x200;
    if (end - func > 0x800) end = func + 0x800;
    sb.AppendLine("    -- installer ≈0x" + func.ToString("X") + " --");
    bool key = false;
    var strs = new List<string>();
    foreach (var a in Disasm(func, end)) {
      if (a.IpRel && a.DataRva == LookupKey) key = true;
      if (a.IpRel) {
        string s = ReadAscii(a.DataRva, 80);
        if (IsString(s) && s.Length >= 5 && strs.Count < 8 && !strs.Contains(s))
          strs.Add(s);
      }
      if (a.Mnemonic == Mnemonic.Lea && a.IpRel && (a.DataRva == stub || a.DataRva == target))
        sb.AppendLine("      0x" + a.Rva.ToString("X") + " " + a.Text);
      // stores of register after LEA often indicate install
      if ((a.Mnemonic == Mnemonic.Mov || a.Mnemonic == Mnemonic.Movnti) && a.HasMem && !a.IpRel
          && Math.Abs(a.Disp) < 0x400)
        sb.AppendLine("      store? 0x" + a.Rva.ToString("X") + " " + a.Text);
    }
    sb.AppendLine("      usesKey=" + key);
    foreach (var s in strs) sb.AppendLine("      str \"" + Trunc(s, 70) + "\"");
  }

  static void DumpQwordNeighbor(StringBuilder sb, uint site) {
    // dump ±4 qwords; classify if they look like code VAs
    for (int i = -4; i <= 4; i++) {
      uint r = unchecked((uint)((int)site + i * 8));
      int fo = RvaToFile(r);
      if (fo < 0 || fo + 8 > pe.Length) continue;
      ulong q = BitConverter.ToUInt64(pe, fo);
      string note = "";
      if (q > imageBase && q < imageBase + 0x20000000) {
        uint rr = (uint)(q - imageBase);
        note = " ->0x" + rr.ToString("X") + " sec=" + SecName(rr)
          + (LooksLikeCode(rr) ? " CODE" : "");
      }
      sb.AppendLine("      q[" + i + "] @0x" + r.ToString("X") + "=0x" + q.ToString("X") + note);
    }
  }

  static void ScanTablesNearKey(StringBuilder sb) {
    // From v0.6.14: abs qword of key at 0x9491000 in .edata — dump surrounding function-like VAs
    var absKey = FindQword(LookupKey, 8);
    sb.AppendLine("absKeyHits=" + absKey.Count);
    foreach (var site in absKey) {
      sb.AppendLine("  keyAbs @0x" + site.ToString("X") + " sec=" + SecName(site));
      DumpQwordNeighbor(sb, site);
      // scan a wider window for gate/bitwriter VAs
      for (int off = -0x200; off < 0x200; off += 8) {
        uint r = unchecked((uint)((int)site + off));
        int fo = RvaToFile(r);
        if (fo < 0 || fo + 8 > pe.Length) continue;
        ulong q = BitConverter.ToUInt64(pe, fo);
        if (q == imageBase + GateSetter)
          sb.AppendLine("  *** GATESETTER VA in table @0x" + r.ToString("X") + " (keyAbs" + off + ")");
        if (q == imageBase + BitWriter)
          sb.AppendLine("  *** BITWRITER VA in table @0x" + r.ToString("X") + " (keyAbs" + off + ")");
        if (q == imageBase + NearWrap)
          sb.AppendLine("  *** NEARWRAP VA in table @0x" + r.ToString("X") + " (keyAbs" + off + ")");
      }
    }
  }

  static void ScanRva32Pairs(StringBuilder sb, uint target) {
    // Look for [start,end] bounds pairs like v0.6.7 .vmp4 table
    var hits = FindRva32(target, 40);
    sb.AppendLine("rva32 of 0x" + target.ToString("X") + " count=" + hits.Count);
    foreach (var s in hits.Take(20)) {
      int fo = RvaToFile(s);
      uint next = fo >= 0 && fo + 8 <= pe.Length ? BitConverter.ToUInt32(pe, fo + 4) : 0;
      sb.AppendLine("  @0x" + s.ToString("X") + " sec=" + SecName(s)
        + " nextDword=0x" + next.ToString("X")
        + (next > target && next - target < 0x10000 ? " BOUNDS?" : ""));
    }
  }

  sealed class E2Report {
    public uint Entry = AllocSrc;
    public uint End;
    public int Size;
    public bool CallsNearWrap, CallsAllocator, CallsHelper, CallsLookup, UsesKey, Nested;
    public bool Touches61, Touches98;
    public List<uint> Callees = new List<uint>();
    public List<uint> CallersE8 = new List<uint>();
    public List<string> Strings = new List<string>();
    public List<string> GateOps = new List<string>();
    public List<string> StoreNotes = new List<string>();
    public List<string> FieldNotes = new List<string>();
    public List<string> DisasmHead = new List<string>();
    public List<string> CallerNotes = new List<string>();
    public List<string> NearWrapSites = new List<string>();
    public List<uint> ImmSizes = new List<uint>();
  }

  static E2Report DeepE2C8A0(StringBuilder sb) {
    var r = new E2Report();
    r.End = FindFuncEnd(AllocSrc, 0x6000);
    if (r.End <= AllocSrc) r.End = AllocSrc + 0x800;
    if (r.End - AllocSrc > 0x6000) r.End = AllocSrc + 0x6000;
    r.Size = (int)(r.End - AllocSrc);
    sb.AppendLine("entry=0x" + AllocSrc.ToString("X") + " end=0x" + r.End.ToString("X")
      + " size=" + r.Size + " prologue=" + Hex(AllocSrc, 16));

    var ins = Disasm(AllocSrc, r.End);
    bool s18 = false, sA8 = false, s3 = false;
    int head = 0;
    for (int i = 0; i < ins.Count; i++) {
      var a = ins[i];
      if (head < 64) {
        string line = "0x" + a.Rva.ToString("X") + " " + a.Text;
        r.DisasmHead.Add(line);
        sb.AppendLine("  " + line);
        head++;
      }
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        r.Callees.Add(dest);
        if (dest == NearWrap) {
          r.CallsNearWrap = true;
          r.NearWrapSites.Add("0x" + a.Rva.ToString("X"));
          sb.AppendLine("  *** call NEARWRAP 0x2EA0B00 @0x" + a.Rva.ToString("X"));
          // dump arg setup lookback
          for (int j = Math.Max(0, i - 12); j < i; j++)
            sb.AppendLine("    pre 0x" + ins[j].Rva.ToString("X") + " " + ins[j].Text);
        }
        if (dest == Allocator) { r.CallsAllocator = true; sb.AppendLine("  *** ALLOC @0x" + a.Rva.ToString("X")); }
        if (dest == Helper) r.CallsHelper = true;
        if (dest == Lookup) r.CallsLookup = true;
        if (dest == GateSetter) sb.AppendLine("  *** GATESETTER call @0x" + a.Rva.ToString("X"));
        if (dest == BitWriter) sb.AppendLine("  *** BITWRITER call @0x" + a.Rva.ToString("X"));
        if (dest == WorkerA) sb.AppendLine("  *** WORKER call @0x" + a.Rva.ToString("X"));
        if (dest == ListScan) sb.AppendLine("  *** LISTSCAN @0x" + a.Rva.ToString("X"));
        if (dest == Wrapper) sb.AppendLine("  *** WRAPPER @0x" + a.Rva.ToString("X"));
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
          if (r.FieldNotes.Count < 20)
            r.FieldNotes.Add("+0x98 @0x" + a.Rva.ToString("X") + " " + a.Text);
        }
        if ((a.Mnemonic == Mnemonic.Mov || a.Mnemonic == Mnemonic.Movnti)
            && a.Raw.OpCount >= 1 && a.Raw.GetOpKind(0) == OpKind.Memory
            && a.Raw.MemoryIndex != Register.None
            && (a.Raw.MemoryIndexScale == 8 || a.Raw.MemoryIndexScale == 1)
            && r.StoreNotes.Count < 24)
          r.StoreNotes.Add("0x" + a.Rva.ToString("X") + " " + a.Text);
      }
      if (a.IpRel) {
        if (a.DataRva == LookupKey) r.UsesKey = true;
        string s = ReadAscii(a.DataRva, 96);
        if (IsString(s) && s.Length >= 5 && r.Strings.Count < 20
            && !s.StartsWith("AWAV", StringComparison.Ordinal) && !r.Strings.Contains(s))
          r.Strings.Add(s);
      }
      if (a.Raw.OpCount >= 2) {
        for (int oi = 0; oi < a.Raw.OpCount; oi++) {
          var k = a.Raw.GetOpKind(oi);
          if (k == OpKind.Immediate32 || k == OpKind.Immediate64) {
            ulong imm = a.Raw.GetImmediate(oi);
            if (imm >= 0x20 && imm <= 0x8000 && (imm % 8) == 0)
              r.ImmSizes.Add((uint)imm);
          }
        }
      }
    }
    if (ins.Count > 64) sb.AppendLine("  ... +" + (ins.Count - 64) + " ins ...");
    r.Nested = s18 && sA8 && s3;
    r.Callees = r.Callees.Distinct().ToList();
    r.ImmSizes = r.ImmSizes.Distinct().OrderBy(x => x).ToList();
    r.CallersE8 = FindE8(AllocSrc, 40);

    sb.AppendLine("nested=" + r.Nested + " key=" + r.UsesKey + " lookup=" + r.CallsLookup
      + " alloc=" + r.CallsAllocator + " helper=" + r.CallsHelper
      + " nearWrap=" + r.CallsNearWrap + " t61=" + r.Touches61 + " t98=" + r.Touches98);
    sb.AppendLine("nearWrapSites=" + string.Join(",", r.NearWrapSites));
    sb.AppendLine("gateOps=" + r.GateOps.Count + " indexedStores=" + r.StoreNotes.Count
      + " callersE8=" + r.CallersE8.Count + " immSizes=" + string.Join(",", r.ImmSizes.Take(12).Select(x => "0x" + x.ToString("X"))));
    foreach (var g in r.GateOps.Take(12)) sb.AppendLine("  gate " + g);
    foreach (var s in r.StoreNotes.Take(16)) sb.AppendLine("  store " + s);
    foreach (var f in r.FieldNotes.Take(12)) sb.AppendLine("  field " + f);
    foreach (var s in r.Strings.Take(12)) sb.AppendLine("  str \"" + Trunc(s, 70) + "\"");
    foreach (var c in r.Callees.Where(x => !IsNoise(x)).Take(20))
      sb.AppendLine("  callee 0x" + c.ToString("X") + Tag(c));

    sb.AppendLine("-- callers of 0xE2C8A0 --");
    foreach (var site in r.CallersE8.Take(24)) {
      uint fn = FindFuncStart(site);
      string note = "e8 @0x" + site.ToString("X") + " func≈0x" + fn.ToString("X");
      bool ck = false, ca = false, ch = false;
      uint end = FindFuncEndFirstRet(fn, 0x800);
      if (end <= fn) end = fn + 0x200;
      if (end - fn > 0x800) end = fn + 0x800;
      foreach (var a in Disasm(fn, end)) {
        if (a.IpRel && a.DataRva == LookupKey) ck = true;
        if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
          uint d = (uint)(a.Raw.NearBranchTarget - imageBase);
          if (d == Allocator) ca = true;
          if (d == Helper) ch = true;
        }
      }
      note += " key=" + ck + " alloc=" + ca + " helper=" + ch;
      r.CallerNotes.Add(note);
      sb.AppendLine("  " + note);
      DumpStrings(sb, fn, 0x400);
    }

    // Sample interesting callees
    foreach (var c in r.Callees.Where(x => !IsNoise(x) && x != NearWrap).Take(6)) {
      sb.AppendLine("--- callee dump 0x" + c.ToString("X") + " ---");
      DumpShort(sb, c, 0x40);
      DumpStrings(sb, c, 0x400);
    }

    // Also LEA xrefs to E2C8A0
    sb.AppendLine("-- LEA/QWORD/RVA32 of 0xE2C8A0 --");
    DumpAllXrefs(sb, AllocSrc, "e2c8a0");
    return r;
  }

  static void DumpAllXrefs(StringBuilder sb, uint target, string name) {
    var e8 = FindE8(target, 20);
    var lea = FindLeaTo(target, 20);
    var qw = FindQword(target, 20);
    var r32 = FindRva32(target, 20);
    var e9 = FindE9(target, 20);
    var imm = FindMovImm64(target, 10);
    sb.AppendLine(name + " E8=" + e8.Count + " LEA=" + lea.Count + " QWORD=" + qw.Count
      + " RVA32=" + r32.Count + " E9=" + e9.Count + " imm64=" + imm.Count);
    foreach (var s in e8.Take(8)) sb.AppendLine("  e8 0x" + s.ToString("X") + " func≈0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in lea.Take(8)) sb.AppendLine("  lea 0x" + s.ToString("X") + " func≈0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in qw.Take(8)) sb.AppendLine("  qw 0x" + s.ToString("X") + " sec=" + SecName(s));
    foreach (var s in r32.Take(8)) sb.AppendLine("  r32 0x" + s.ToString("X") + " sec=" + SecName(s));
    foreach (var s in e9.Take(8)) sb.AppendLine("  e9 0x" + s.ToString("X") + " func≈0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in imm.Take(8)) sb.AppendLine("  imm64 0x" + s.ToString("X"));
  }

  static bool IsNoise(uint d) => d == Lookup || d == Allocator || d < 0x10000;
  static string Tag(uint rva) {
    if (rva == Allocator) return " *** ALLOC ***";
    if (rva == Lookup) return " *** LOOKUP ***";
    if (rva == Helper) return " *** HELPER ***";
    if (rva == Wrapper) return " *** WRAPPER ***";
    if (rva == WorkerA) return " *** WORKER ***";
    if (rva == NearWrap) return " *** NEARWRAP ***";
    if (rva == GateSetter) return " *** GATESETTER ***";
    if (rva == BitWriter) return " *** BITWRITER ***";
    if (rva == ListScan) return " *** LISTSCAN ***";
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
  static void WriteInstallJson(string hash, List<InstallReport> installs) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.15\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"targets\": [");
    for (int i = 0; i < installs.Count; i++) {
      var r = installs[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"rva\": \"0x" + r.Target.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(r.Role) + ",");
      sb.AppendLine("      \"stubs\": [" + string.Join(", ", r.StubEntries.Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"notes\": [" + string.Join(", ", r.Notes.Select(J)) + "],");
      sb.AppendLine("      \"hits\": [");
      for (int j = 0; j < Math.Min(r.Hits.Count, 40); j++) {
        var h = r.Hits[j];
        sb.Append("        { \"kind\": " + J(h.Kind) + ", \"site\": \"0x" + h.Site.ToString("X")
          + "\", \"func\": \"0x" + h.Func.ToString("X") + "\", \"sec\": " + J(h.Sec)
          + ", \"note\": " + J(h.Note) + " }");
        sb.AppendLine(j + 1 < Math.Min(r.Hits.Count, 40) ? "," : "");
      }
      sb.AppendLine("      ]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < installs.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.15-install-sites.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.15-install-sites.json");
  }

  static void WriteE2Json(string hash, E2Report r) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.15\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"entry\": \"0xE2C8A0\",");
    sb.AppendLine("  \"size\": " + r.Size + ",");
    sb.AppendLine("  \"callsNearWrap\": " + T(r.CallsNearWrap) + ",");
    sb.AppendLine("  \"callsAllocator\": " + T(r.CallsAllocator) + ",");
    sb.AppendLine("  \"callsHelper\": " + T(r.CallsHelper) + ",");
    sb.AppendLine("  \"callsLookup\": " + T(r.CallsLookup) + ",");
    sb.AppendLine("  \"usesKey\": " + T(r.UsesKey) + ",");
    sb.AppendLine("  \"nestedChain\": " + T(r.Nested) + ",");
    sb.AppendLine("  \"touches61\": " + T(r.Touches61) + ",");
    sb.AppendLine("  \"touches98\": " + T(r.Touches98) + ",");
    sb.AppendLine("  \"nearWrapSites\": [" + string.Join(", ", r.NearWrapSites.Select(J)) + "],");
    sb.AppendLine("  \"gateOps\": [" + string.Join(", ", r.GateOps.Take(16).Select(J)) + "],");
    sb.AppendLine("  \"indexedStores\": [" + string.Join(", ", r.StoreNotes.Take(16).Select(J)) + "],");
    sb.AppendLine("  \"fieldNotes\": [" + string.Join(", ", r.FieldNotes.Take(12).Select(J)) + "],");
    sb.AppendLine("  \"strings\": [" + string.Join(", ", r.Strings.Take(16).Select(J)) + "],");
    sb.AppendLine("  \"callees\": [" + string.Join(", ", r.Callees.Take(30).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("  \"callersE8\": [" + string.Join(", ", r.CallersE8.Take(24).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("  \"callerNotes\": [" + string.Join(", ", r.CallerNotes.Take(16).Select(J)) + "],");
    sb.AppendLine("  \"disasmHead\": [" + string.Join(", ", r.DisasmHead.Take(40).Select(J)) + "]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.15-e2c8a0-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.15-e2c8a0-deep.json");
  }

  static void WriteSummaryJson(string hash, List<InstallReport> installs, E2Report e2) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.15\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"gateSetterHits\": " + installs.First(r => r.Target == GateSetter).Hits.Count + ",");
    sb.AppendLine("  \"bitWriterHits\": " + installs.First(r => r.Target == BitWriter).Hits.Count + ",");
    sb.AppendLine("  \"e2c8a0\": { \"size\": " + e2.Size + ", \"callsNearWrap\": " + T(e2.CallsNearWrap)
      + ", \"callsAllocator\": " + T(e2.CallsAllocator) + ", \"usesKey\": " + T(e2.UsesKey)
      + ", \"callersE8\": " + e2.CallersE8.Count + " },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.15-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.15-summary.json");
  }

  static void WriteFeasibilityJson(string hash, List<InstallReport> installs, E2Report e2) {
    int total = installs.Sum(r => r.Hits.Count);
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.15\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Install/list helpers still do not show Edward factory\" },");
    sb.AppendLine("  \"installSitesRecovered\": { \"class\": "
      + (total > 0 ? "\"plausible\"" : "\"unsupported\"")
      + ", \"reason\": \"totalHits=" + total + "\" },");
    sb.AppendLine("  \"e2c8a0FeedsNearWrap\": { \"class\": "
      + (e2.CallsNearWrap ? "\"confirmed\"" : "\"unsupported\"")
      + ", \"reason\": \"calls 0x2EA0B00\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"If install hits found, deep-decode installers; else probe TypeInfo method-slot tables / VMP relative encodings; continue E2C8A0 upstream\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.15-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.15-second-edward-feasibility.json");
  }

  static string T(bool b) => b ? "true" : "false";
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }

  // ---- scanners ----
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

  static List<uint> FindE9(uint dest, int max) {
    var list = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 5 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xE9) continue;
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

  static List<uint> FindLeaNear(uint target, int radius, int max) {
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
        uint dest = unchecked((uint)(site + len + disp));
        if (dest == target) continue; // exact handled elsewhere
        if (Math.Abs((long)dest - target) <= radius && LooksLikeCode(dest))
          list.Add(site);
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
      // fast scan
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
      // skip pure executable? keep all — bounds tables live in data/vmp
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

  static List<uint> FindMovImm64(uint destRva, int max) {
    var list = new List<uint>();
    ulong abs = imageBase + destRva;
    byte[] imm = BitConverter.GetBytes(abs);
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 10 <= lim && list.Count < max; i++) {
        // REX.W + B8+r : 48 B8+r imm64
        byte b0 = pe[s.Ptr + i];
        if (b0 != 0x48 && b0 != 0x49) continue;
        byte b1 = pe[s.Ptr + i + 1];
        if (b1 < 0xB8 || b1 > 0xBF) continue;
        bool ok = true;
        for (int k = 0; k < 8; k++) if (pe[s.Ptr + i + 2 + k] != imm[k]) { ok = false; break; }
        if (ok) list.Add(s.Va + i);
      }
    }
    return list;
  }

  static List<uint> FindFf25To(uint dest, int max) {
    // FF 25 disp32  => jmp qword ptr [rip+disp]; then check qword target
    var list = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 6 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xFF || pe[s.Ptr + i + 1] != 0x25) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 2));
        uint site = s.Va + i;
        uint slot = unchecked((uint)(site + 6 + disp));
        int fo = RvaToFile(slot);
        if (fo < 0 || fo + 8 > pe.Length) continue;
        ulong q = BitConverter.ToUInt64(pe, fo);
        if (q == imageBase + dest) list.Add(site);
      }
    }
    return list;
  }

  static List<uint> FindCallIndirectRipLoad(uint dest, int max) {
    // FF 15 disp32 => call [rip+disp] where qword == dest
    var list = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 6 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xFF || pe[s.Ptr + i + 1] != 0x15) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 2));
        uint site = s.Va + i;
        uint slot = unchecked((uint)(site + 6 + disp));
        int fo = RvaToFile(slot);
        if (fo < 0 || fo + 8 > pe.Length) continue;
        ulong q = BitConverter.ToUInt64(pe, fo);
        if (q == imageBase + dest) list.Add(site);
      }
    }
    return list;
  }

  static List<uint> FindRel32SitePlus(uint dest, int max) {
    // E8/E9 already covered; this looks for raw rel32 such that site+4+rel==dest in data (unusual)
    return new List<uint>();
  }

  static bool LooksLikeCode(uint rva) {
    int fo = RvaToFile(rva);
    if (fo < 0 || fo + 4 > pe.Length) return false;
    // Heuristic: in executable section
    foreach (var s in secs) {
      if (rva >= s.Va && rva < s.Va + Math.Max(s.VSize, s.Raw))
        return (s.Char & 0x20000000) != 0
          || s.Name.IndexOf("impdata", StringComparison.OrdinalIgnoreCase) >= 0
          || s.Name.IndexOf("code", StringComparison.OrdinalIgnoreCase) >= 0;
    }
    return false;
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
