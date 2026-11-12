// v0.6.8 — Offline subject constructor/vtable fingerprint match + LOD sibling 0x67BDB30 decode.
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
  const uint LodSibling = 0x67BDB30;
  const uint LodStub = 0x1A5A70;
  const uint LodTail = 0x1A5A00;
  const uint EnqueueWrapper = 0x2E97FC0;
  const uint WorkerA = 0x725400;
  const uint WorkerB = 0xE95E80;
  const uint Lookup = 0x429F9E0;
  const uint OpaqueKey = 0xB2898C8;
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
    public Register MemBase;
    public long Disp;
    public int Length;
    public Instruction Raw;
    public Register Op0Reg;
    public bool Op0IsReg;
    public bool WritesMem;
  }

  sealed class FuncScore {
    public uint Entry;
    public int Hits61;
    public int Hits98;
    public int Hits18;
    public int HitsA8;
    public int Hits3CD0;
    public int VtableInstalls;
    public int NestedChainHits;
    public List<uint> Vtables = new List<uint>();
    public List<string> Rtti = new List<string>();
    public List<string> Notes = new List<string>();
    public int Score => Hits61 * 3 + Hits98 * 4 + Hits3CD0 * 5 + NestedChainHits * 8
      + VtableInstalls * 2 + (Hits18 > 0 && HitsA8 > 0 ? 2 : 0);
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v068-raw");
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
    sb.AppendLine("===== v0.6.8 SUBJECT CTOR / LOD SIBLING =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("imageBase=0x" + imageBase.ToString("X"));

    // --- A: decode LOD sibling ---
    sb.AppendLine();
    sb.AppendLine("===== DECODE LOD SIBLING 0x67BDB30 =====");
    DecodeLodSibling(sb);

    sb.AppendLine();
    sb.AppendLine("===== DECODE LOD TAIL 0x1A5A00 (bundle +0xE30) =====");
    DecodeShortFunc(sb, LodTail, 0x80);

    sb.AppendLine();
    sb.AppendLine("===== XREFS TO 0x67BDB30 =====");
    DumpXrefs(sb, LodSibling, "lodSibling");

    // --- B: fingerprint field-use scan ---
    sb.AppendLine();
    sb.AppendLine("===== FINGERPRINT FIELD USE (+0x61 / +0x98 / +0x3CD0) =====");
    var scores = ScoreFingerprintFunctions(sb);

    // --- C: nested chain sites ---
    sb.AppendLine();
    sb.AppendLine("===== NESTED CHAIN +0x18 -> +0xA8 -> +0x3CD0 =====");
    var chainSites = FindNestedChainSites(sb);

    // Apply nested-chain membership from site list onto function scores.
    var chainFuncs = new HashSet<uint>(chainSites.Select(FindFuncStart));
    foreach (var f in scores) {
      if (chainFuncs.Contains(f.Entry)) f.NestedChainHits = Math.Max(f.NestedChainHits, 1);
    }

    // --- D: vtable install candidates near fingerprint functions ---
    sb.AppendLine();
    sb.AppendLine("===== TOP FINGERPRINT FUNCTIONS / VTABLE RTTI =====");
    var top = scores.OrderByDescending(x => x.Score).Take(40).ToList();
    foreach (var f in top) {
      EnrichVtables(f);
      sb.AppendLine("FUNC 0x" + f.Entry.ToString("X")
        + " score=" + f.Score
        + " +61=" + f.Hits61
        + " +98=" + f.Hits98
        + " +18=" + f.Hits18
        + " +A8=" + f.HitsA8
        + " +3CD0=" + f.Hits3CD0
        + " nest=" + f.NestedChainHits
        + " vtInstall=" + f.VtableInstalls
        + " sec=" + SecName(f.Entry));
      foreach (var vt in f.Vtables.Distinct().Take(8)) {
        string rtti = TryRttiName(vt);
        sb.AppendLine("  vtable 0x" + vt.ToString("X")
          + (rtti != null ? " RTTI=" + rtti : " RTTI=(none)"));
        if (rtti != null) f.Rtti.Add(rtti);
      }
      foreach (var n in f.Notes.Take(6)) sb.AppendLine("  note " + n);
    }

    // --- E: or [reg+0x61],4 writers (enqueue flag) ---
    sb.AppendLine();
    sb.AppendLine("===== OR [reg+0x61], 4 SITES =====");
    var or61 = FindOr61Bit2(sb);

    // --- F: RTTI on known workers again (control) + opaque key strings ---
    sb.AppendLine();
    sb.AppendLine("===== CONTROL: WORKER/WRAPPER RTTI + KEY =====");
    ProbeRttiInFunc(sb, WorkerB, 0x2000);
    ProbeRttiInFunc(sb, EnqueueWrapper, 0x6000);
    sb.AppendLine("opaqueKey@0xB2898C8 hex=" + Hex(OpaqueKey, 32));

    // --- G: actor-related strings near high-score funcs ---
    sb.AppendLine();
    sb.AppendLine("===== STRINGS IN TOP FUNCS =====");
    foreach (var f in top.Take(15)) DumpFuncStrings(sb, f.Entry, 0x1800);

    // --- H: MSVC type descriptor string scan (Actor/Entity/Character/Edward) ---
    sb.AppendLine();
    sb.AppendLine("===== MSVC .?AV* TYPE STRINGS (Actor/Entity/Character/Edward/Player) =====");
    ScanTypeDescriptors(sb);

    // --- I: intersection — +0x61 writers that also use nested chain or +0x98 ---
    sb.AppendLine();
    sb.AppendLine("===== STRONG CTOR-LIKE CANDIDATES (+61 write & +98/nest) =====");
    var strong = scores
      .Where(x => x.Hits61 > 0 && (x.Hits98 > 0 || x.NestedChainHits > 0 || x.Hits3CD0 > 0))
      .OrderByDescending(x => x.Score)
      .Take(20)
      .ToList();
    foreach (var f in strong) {
      EnrichVtables(f);
      sb.AppendLine("STRONG 0x" + f.Entry.ToString("X")
        + " score=" + f.Score
        + " +61=" + f.Hits61 + " +98=" + f.Hits98
        + " +3CD0=" + f.Hits3CD0 + " nest=" + f.NestedChainHits
        + " vt=" + f.VtableInstalls);
      DumpFuncStrings(sb, f.Entry, 0x1000);
      foreach (var vt in f.Vtables.Where(v => (v & 7) == 0).Distinct().Take(8)) {
        string rtti = TryRttiName(vt);
        sb.AppendLine("  alignedVt 0x" + vt.ToString("X") + (rtti != null ? " " + rtti : " (no RTTI)"));
      }
    }
    if (strong.Count == 0) sb.AppendLine("  (none with combined +61 and +98/nest/3CD0)");

    // Mark known control functions
    sb.AppendLine();
    sb.AppendLine("===== CONTROL FUNCS PRESENT IN CANDIDATES =====");
    foreach (uint known in new uint[] { WorkerA, WorkerB, EnqueueWrapper, 0x2E97B60 }) {
      bool hit = scores.Any(x => x.Entry == known) || chainSites.Any(s => FindFuncStart(s) == known);
      sb.AppendLine("  known 0x" + known.ToString("X") + " inFingerprintSet=" + hit);
    }

    string path = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path + " chars=" + sb.Length);

    WriteLodJson(hash, scores, chainSites, or61, top);
    WriteCtorJson(hash, top, chainSites, or61);
    WriteSummaryJson(hash, top, chainSites, or61);
    WriteFeasibilityJson(hash, top);

    // Self-checks
    bool lodDecoded = LooksLikeCode(LodSibling);
    bool fingerprintHits = scores.Count > 0 && scores.Any(x => x.Hits61 > 0);
    Console.WriteLine("selfCheck lodDecoded=" + lodDecoded + " fingerprintHits=" + fingerprintHits
      + " topScore=" + (top.Count > 0 ? top[0].Score.ToString() : "0"));
    if (!lodDecoded || !fingerprintHits) {
      Console.Error.WriteLine("Self-test failed.");
      return 4;
    }
    return 0;
  }

  static void DecodeLodSibling(StringBuilder sb) {
    // First ret ends the comparator; adjacent 0x67BDB50 is a separate helper (no CC pad).
    uint end = FindFuncEndFirstRet(LodSibling, 0x80);
    if (end <= LodSibling) end = LodSibling + 0x20;
    sb.AppendLine("entry=0x" + LodSibling.ToString("X")
      + " end=0x" + end.ToString("X")
      + " size=" + (end - LodSibling)
      + " sec=" + SecName(LodSibling)
      + " prologue=" + Hex(LodSibling, 16));
    sb.AppendLine("roleHypothesis=comparator: load [rcx+8]/[rdx+8], return 0 if equal else +/-1");
    var ins = Disasm(LodSibling, end);
    var callees = new List<uint>();
    var vcalls = new List<string>();
    foreach (var a in ins) {
      sb.AppendLine("  " + HexRva(a.Rva) + " " + a.Text);
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0)
        callees.Add((uint)(a.Raw.NearBranchTarget - imageBase));
      if (a.IsIndirectCall) vcalls.Add("0x" + a.Rva.ToString("X") + " " + a.Text);
    }
    sb.AppendLine("directCallees(comparator)=" + (callees.Count == 0 ? "(none)" :
      string.Join(", ", callees.Distinct().Select(x => "0x" + x.ToString("X")))));
    foreach (var v in vcalls.Take(20)) sb.AppendLine("  vcall " + v);

    sb.AppendLine("--- adjacent function 0x67BDB50 (NOT the LOD bundle entry) ---");
    DecodeShortFunc(sb, 0x67BDB50, 0x100);
    var adjIns = Disasm(0x67BDB50, FindFuncEnd(0x67BDB50, 0x200));
    foreach (var a in adjIns) {
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0)
        callees.Add((uint)(a.Raw.NearBranchTarget - imageBase));
    }
    foreach (var c in callees.Distinct().Take(6)) {
      sb.AppendLine("--- adjacent-callee 0x" + c.ToString("X") + " ---");
      DecodeShortFunc(sb, c, 0x100);
      DumpFuncStrings(sb, c, 0x400);
    }
  }

  static void DecodeShortFunc(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEnd(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    sb.AppendLine("func 0x" + entry.ToString("X") + " end=0x" + end.ToString("X")
      + " size=" + (end - entry) + " sec=" + SecName(entry)
      + " prologue=" + Hex(entry, 12));
    var ins = Disasm(entry, end);
    int n = 0;
    foreach (var a in ins) {
      sb.AppendLine("  " + HexRva(a.Rva) + " " + a.Text);
      if (++n >= 48) break;
    }
  }

  static void DumpXrefs(StringBuilder sb, uint target, string name) {
    var e8 = FindE8(target, 40);
    var lea = FindLeaTo(target, 40);
    var qw = FindQword(target, 40);
    var rva32 = FindRvaDword(target, 40);
    sb.AppendLine(name + " E8=" + e8.Count + " LEA=" + lea.Count
      + " QWORD=" + qw.Count + " RVA32=" + rva32.Count);
    foreach (var s in e8) sb.AppendLine("  e8 0x" + s.ToString("X")
      + " sec=" + SecName(s) + " func≈0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in lea) sb.AppendLine("  lea 0x" + s.ToString("X")
      + " sec=" + SecName(s) + " func≈0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in qw) sb.AppendLine("  qw 0x" + s.ToString("X") + " sec=" + SecName(s));
    foreach (var s in rva32) sb.AppendLine("  rva32 0x" + s.ToString("X") + " sec=" + SecName(s));
  }

  static List<FuncScore> ScoreFingerprintFunctions(StringBuilder sb) {
    var map = new Dictionary<uint, FuncScore>();
    // Byte-scan for distinctive displacements, then confirm with iced in a small window.
    var seeds = new List<(uint rva, long disp)>();
    foreach (var sec in CodeSecs()) {
      uint lim = Math.Min(sec.Raw, sec.VSize > 0 ? sec.VSize : sec.Raw);
      for (uint i = 0; i + 5 < lim; i++) {
        // modrm disp8: ... XX 61 / 98 / 18 / A8  (mod=01)
        byte modrm = pe[sec.Ptr + i];
        if ((modrm & 0xC0) == 0x40) {
          byte d8 = pe[sec.Ptr + i + 1];
          if (d8 == 0x61 || d8 == 0x98 || d8 == 0x18 || d8 == 0xA8)
            seeds.Add((sec.Va + i, d8));
        }
        // modrm disp32 little-endian 0x00003CD0
        if ((modrm & 0xC0) == 0x80 && i + 5 < lim) {
          uint d32 = BitConverter.ToUInt32(pe, (int)(sec.Ptr + i + 1));
          if (d32 == 0x3CD0) seeds.Add((sec.Va + i, 0x3CD0));
        }
        if (seeds.Count > 20000) break;
      }
      if (seeds.Count > 20000) break;
    }
    sb.AppendLine("dispSeedSites=" + seeds.Count);

    foreach (var seed in seeds) {
      uint winStart = seed.rva > 8 ? seed.rva - 8 : seed.rva;
      var ins = Disasm(winStart, seed.rva + 0x20);
      foreach (var a in ins) {
        if (!a.HasMem || a.IpRel) continue;
        long d = a.Disp;
        if (d != 0x61 && d != 0x98 && d != 0x18 && d != 0xA8 && d != 0x3CD0) continue;
        // Prefer hits near the seed
        if (a.Rva + 8 < seed.rva || a.Rva > seed.rva + 8) continue;
        uint entry = FindFuncStart(a.Rva);
        if (!map.TryGetValue(entry, out var fs)) {
          fs = new FuncScore { Entry = entry };
          map[entry] = fs;
        }
        if (d == 0x61) {
          fs.Hits61++;
          if (fs.Notes.Count < 12) fs.Notes.Add("+0x61 @0x" + a.Rva.ToString("X") + " " + a.Text);
        } else if (d == 0x98) {
          fs.Hits98++;
          if (fs.Notes.Count < 12) fs.Notes.Add("+0x98 @0x" + a.Rva.ToString("X") + " " + a.Text);
        } else if (d == 0x18) fs.Hits18++;
        else if (d == 0xA8) fs.HitsA8++;
        else if (d == 0x3CD0) {
          fs.Hits3CD0++;
          if (fs.Notes.Count < 12) fs.Notes.Add("+0x3CD0 @0x" + a.Rva.ToString("X") + " " + a.Text);
        }
      }
    }

    // Keep functions that touch the distinctive fields (not every +0x18 alone).
    var filtered = map.Values
      .Where(x => x.Hits61 > 0 || x.Hits98 > 0 || x.Hits3CD0 > 0)
      .ToList();
    sb.AppendLine("candidateFuncs=" + filtered.Count
      + " with+61=" + filtered.Count(x => x.Hits61 > 0)
      + " with+98=" + filtered.Count(x => x.Hits98 > 0)
      + " with+3CD0=" + filtered.Count(x => x.Hits3CD0 > 0));
    return filtered;
  }

  static List<uint> FindNestedChainSites(StringBuilder sb) {
    var sites = new List<uint>();
    // Seed on +0x3CD0 disp32, then verify nearby +0x18/+0xA8 in the same function window.
    var seeds = new List<uint>();
    foreach (var sec in CodeSecs()) {
      uint lim = Math.Min(sec.Raw, sec.VSize > 0 ? sec.VSize : sec.Raw);
      for (uint i = 0; i + 5 < lim; i++) {
        byte modrm = pe[sec.Ptr + i];
        if ((modrm & 0xC0) != 0x80) continue;
        if (BitConverter.ToUInt32(pe, (int)(sec.Ptr + i + 1)) != 0x3CD0) continue;
        seeds.Add(sec.Va + i);
        if (seeds.Count >= 400) break;
      }
      if (seeds.Count >= 400) break;
    }
    sb.AppendLine("disp3CD0Seeds=" + seeds.Count);
    foreach (var seed in seeds) {
      uint entry = FindFuncStart(seed);
      uint end = FindFuncEnd(entry, 0x1800);
      if (end <= entry) end = entry + 0x400;
      // Cap window around the seed
      uint start = seed > 0x80 ? seed - 0x80 : entry;
      if (start < entry) start = entry;
      uint stop = Math.Min(end, seed + 0x40);
      var ins = Disasm(start, stop + 0x20);
      bool saw18 = false, sawA8 = false, saw3 = false;
      uint site18 = 0;
      foreach (var a in ins) {
        if (!a.HasMem || a.IpRel) continue;
        if (a.Disp == 0x18) { saw18 = true; if (site18 == 0) site18 = a.Rva; }
        if (a.Disp == 0xA8) sawA8 = true;
        if (a.Disp == 0x3CD0) saw3 = true;
      }
      if (saw18 && sawA8 && saw3) {
        uint site = site18 != 0 ? site18 : seed;
        if (sites.Contains(site)) continue;
        sites.Add(site);
        sb.AppendLine("  chain @0x" + site.ToString("X")
          + " func≈0x" + entry.ToString("X")
          + " seed3CD0=0x" + seed.ToString("X"));
        if (sites.Count >= 60) break;
      }
    }
    sb.AppendLine("nestedChainSites=" + sites.Count);
    return sites;
  }

  static void ScanTypeDescriptors(StringBuilder sb) {
    string[] needles = {
      ".?AV", "Actor", "Edward", "Character", "Entity", "Player", "LOD"
    };
    // Find .?AV names containing interesting substrings
    var hits = new List<(uint rva, string name)>();
    byte[] prefix = Encoding.ASCII.GetBytes(".?AV");
    foreach (var sec in secs) {
      if (sec.Ptr == 0) continue;
      uint lim = Math.Min(sec.Raw, sec.VSize > 0 ? sec.VSize : sec.Raw);
      for (uint i = 0; i + 8 < lim && hits.Count < 80; i++) {
        bool ok = true;
        for (int k = 0; k < prefix.Length; k++) if (pe[sec.Ptr + i + k] != prefix[k]) { ok = false; break; }
        if (!ok) continue;
        string name = ReadAscii(sec.Va + i, 96);
        if (name.Length < 8) continue;
        string low = name.ToLowerInvariant();
        if (!(low.Contains("actor") || low.Contains("edward") || low.Contains("character")
              || low.Contains("entity") || low.Contains("player") || low.Contains("lod")))
          continue;
        hits.Add((sec.Va + i, name));
      }
    }
    sb.AppendLine("interestingTypeDescriptors=" + hits.Count);
    foreach (var h in hits.Take(40)) {
      sb.AppendLine("  td 0x" + h.rva.ToString("X") + " " + Trunc(h.name, 80) + " sec=" + SecName(h.rva));
      // LEA to type descriptor / nearby COL rarely direct; still record LEA xrefs to the string
      foreach (var lea in FindLeaTo(h.rva, 4))
        sb.AppendLine("    lea 0x" + lea.ToString("X") + " func≈0x" + FindFuncStart(lea).ToString("X"));
    }
  }

  static void EnrichVtables(FuncScore f) {
    f.Vtables.Clear();
    f.VtableInstalls = 0;
    f.NestedChainHits = 0;
    uint end = FindFuncEnd(f.Entry, 0x2000);
    if (end <= f.Entry) end = f.Entry + 0x800;
    var ins = Disasm(f.Entry, end);
    // Detect lea reg,[rip+vt]; mov [reg], reg  (vtable install)
    for (int i = 0; i < ins.Count; i++) {
      var a = ins[i];
      if (a.Mnemonic != Mnemonic.Lea || !a.IpRel) continue;
      if (a.DataRva == 0 || (a.DataRva & 7) != 0) continue; // require 8-aligned
      // Heuristic: vtable-like if followed by store to [reg+0]
      bool stored = false;
      for (int j = i + 1; j < ins.Count && j <= i + 6; j++) {
        var b = ins[j];
        if (b.Mnemonic == Mnemonic.Mov && b.HasMem && !b.IpRel && b.Disp == 0)
          stored = true;
      }
      if (!stored) continue;
      f.VtableInstalls++;
      f.Vtables.Add(a.DataRva);
      if (f.Notes.Count < 16)
        f.Notes.Add("vtInstall lea@0x" + a.Rva.ToString("X") + " -> 0x" + a.DataRva.ToString("X"));
    }
    // Nested chain inside this function
    for (int i = 0; i < ins.Count; i++) {
      if (!ins[i].HasMem || ins[i].IpRel || ins[i].Disp != 0x18) continue;
      bool a8 = false, c3 = false;
      for (int j = i + 1; j < ins.Count && j <= i + 24; j++) {
        if (!ins[j].HasMem || ins[j].IpRel) continue;
        if (ins[j].Disp == 0xA8) a8 = true;
        if (ins[j].Disp == 0x3CD0) c3 = true;
      }
      if (a8 && c3) f.NestedChainHits++;
    }
  }

  static List<uint> FindOr61Bit2(StringBuilder sb) {
    var sites = new List<uint>();
    // Common encodings: 80 4X 61 04 / 80 48 61 04 / 83 ... less common for byte or
    foreach (var sec in CodeSecs()) {
      uint lim = Math.Min(sec.Raw, sec.VSize > 0 ? sec.VSize : sec.Raw);
      for (uint i = 0; i + 4 < lim && sites.Count < 40; i++) {
        // 80 /r ib with modrm disp8=0x61 imm=0x04
        if (pe[sec.Ptr + i] == 0x80) {
          byte modrm = pe[sec.Ptr + i + 1];
          // /1 = OR, mod=01 (disp8)
          if ((modrm & 0x38) != 0x08) continue;
          if ((modrm & 0xC0) != 0x40) continue;
          if (pe[sec.Ptr + i + 2] != 0x61) continue;
          if (pe[sec.Ptr + i + 3] != 0x04) continue;
          uint rva = sec.Va + i;
          var ins = Disasm(rva, rva + 8);
          if (ins.Count == 0 || ins[0].Mnemonic != Mnemonic.Or) continue;
          sites.Add(rva);
          sb.AppendLine("  or61bit2 @0x" + rva.ToString("X")
            + " func≈0x" + FindFuncStart(rva).ToString("X")
            + " " + ins[0].Text);
          continue;
        }
        // REX.W variant unlikely for byte OR; also check 80 with REX (40..4F) prefix
        if (pe[sec.Ptr + i] >= 0x40 && pe[sec.Ptr + i] <= 0x4F
            && i + 5 < lim && pe[sec.Ptr + i + 1] == 0x80) {
          byte modrm = pe[sec.Ptr + i + 2];
          if ((modrm & 0x38) != 0x08) continue;
          if ((modrm & 0xC0) != 0x40) continue;
          if (pe[sec.Ptr + i + 3] != 0x61) continue;
          if (pe[sec.Ptr + i + 4] != 0x04) continue;
          uint rva = sec.Va + i;
          var ins = Disasm(rva, rva + 8);
          if (ins.Count == 0 || ins[0].Mnemonic != Mnemonic.Or) continue;
          sites.Add(rva);
          sb.AppendLine("  or61bit2 @0x" + rva.ToString("X")
            + " func≈0x" + FindFuncStart(rva).ToString("X")
            + " " + ins[0].Text);
        }
      }
    }
    sb.AppendLine("or61bit2Sites=" + sites.Count);
    return sites;
  }

  static void WriteLodJson(string hash, List<FuncScore> scores, List<uint> chain, List<uint> or61, List<FuncScore> top) {
    uint end = FindFuncEndFirstRet(LodSibling, 0x80);
    var ins = Disasm(LodSibling, end <= LodSibling ? LodSibling + 0x20 : end);
    var lines = new List<string>();
    var callees = new List<string>();
    foreach (var a in ins.Take(60)) {
      lines.Add("0x" + a.Rva.ToString("X") + " " + a.Text);
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0)
        callees.Add("0x" + ((uint)(a.Raw.NearBranchTarget - imageBase)).ToString("X"));
    }
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.8\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"lodSibling\": \"0x67BDB30\",");
    sb.AppendLine("  \"end\": \"0x" + end.ToString("X") + "\",");
    sb.AppendLine("  \"size\": " + (end > LodSibling ? end - LodSibling : 0) + ",");
    sb.AppendLine("  \"section\": " + J(SecName(LodSibling)) + ",");
    sb.AppendLine("  \"prologue\": " + J(Hex(LodSibling, 16)) + ",");
    sb.AppendLine("  \"confirmedRole\": \"pointer comparator on [arg+8]; returns 0 if equal else +/-1\",");
    sb.AppendLine("  \"adjacentFunction\": \"0x67BDB50 (separate; allocator/refcount helper — not the LOD entry)\",");
    sb.AppendLine("  \"bundleRole\": \"stored at UpdateActorLOD coord+0xE28 (v0.6.7)\",");
    sb.AppendLine("  \"bundleSiblingThunk\": \"0x1A5A00 at +0xE30: mov rax,rcx; mov rcx,rdx; jmp [rax+8]\",");
    sb.AppendLine("  \"directCallees\": [" + string.Join(", ", callees.Distinct().Select(J)) + "],");
    sb.AppendLine("  \"disasmSample\": [");
    for (int i = 0; i < lines.Count; i++) {
      sb.Append("    " + J(lines[i]));
      sb.AppendLine(i + 1 < lines.Count ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"xrefs\": {");
    sb.AppendLine("    \"e8\": " + FindE8(LodSibling, 40).Count + ",");
    sb.AppendLine("    \"lea\": " + FindLeaTo(LodSibling, 40).Count + ",");
    sb.AppendLine("    \"qword\": " + FindQword(LodSibling, 40).Count + ",");
    sb.AppendLine("    \"rva32\": " + FindRvaDword(LodSibling, 40).Count);
    sb.AppendLine("  }");
    sb.AppendLine("}");
    string path = Path.Combine(ReportsRoot, "v0.6.8-lod-sibling-decode.json");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static void WriteCtorJson(string hash, List<FuncScore> top, List<uint> chain, List<uint> or61) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.8\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"fingerprint\": {");
    sb.AppendLine("    \"+0x61\": \"flag byte bit2 enqueue\",");
    sb.AppendLine("    \"+0x98\": \"0x160 side block\",");
    sb.AppendLine("    \"nested\": \"+0x18 -> +0xA8 -> +0x3CD0\"");
    sb.AppendLine("  },");
    sb.AppendLine("  \"nestedChainSiteCount\": " + chain.Count + ",");
    sb.AppendLine("  \"or61Bit2SiteCount\": " + or61.Count + ",");
    sb.AppendLine("  \"or61Bit2Sites\": [" + string.Join(", ", or61.Take(20).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("  \"topFunctions\": [");
    for (int i = 0; i < Math.Min(25, top.Count); i++) {
      var f = top[i];
      sb.Append("    { \"entry\": \"0x" + f.Entry.ToString("X")
        + "\", \"score\": " + f.Score
        + ", \"hits61\": " + f.Hits61
        + ", \"hits98\": " + f.Hits98
        + ", \"hits3CD0\": " + f.Hits3CD0
        + ", \"nestedChainHits\": " + f.NestedChainHits
        + ", \"vtableInstalls\": " + f.VtableInstalls
        + ", \"vtables\": [" + string.Join(", ", f.Vtables.Distinct().Take(6).Select(v => "\"0x" + v.ToString("X") + "\"")) + "]"
        + ", \"rtti\": [" + string.Join(", ", f.Rtti.Distinct().Take(6).Select(J)) + "]"
        + " }");
      sb.AppendLine(i + 1 < Math.Min(25, top.Count) ? "," : "");
    }
    sb.AppendLine("  ],");
    bool named = top.Any(t => t.Rtti.Count > 0);
    sb.AppendLine("  \"msvcRttiNameRecovered\": " + (named ? "true" : "false"));
    sb.AppendLine("}");
    string path = Path.Combine(ReportsRoot, "v0.6.8-subject-ctor-candidates.json");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static void WriteSummaryJson(string hash, List<FuncScore> top, List<uint> chain, List<uint> or61) {
    var named = top.SelectMany(t => t.Rtti).Distinct().ToList();
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.8\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"lodSiblingDecoded\": true,");
    sb.AppendLine("  \"lodSibling\": \"0x67BDB30\",");
    sb.AppendLine("  \"fingerprintCandidateCount\": " + top.Count + ",");
    sb.AppendLine("  \"nestedChainSites\": " + chain.Count + ",");
    sb.AppendLine("  \"or61Bit2Sites\": " + or61.Count + ",");
    sb.AppendLine("  \"rttiNames\": [" + string.Join(", ", named.Take(20).Select(J)) + "],");
    sb.AppendLine("  \"topEntry\": " + (top.Count > 0 ? "\"0x" + top[0].Entry.ToString("X") + "\"" : "null") + ",");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    string path = Path.Combine(ReportsRoot, "v0.6.8-fingerprint-summary.json");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static void WriteFeasibilityJson(string hash, List<FuncScore> top) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.8\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"No constructor proven to create Edward; fingerprint leads only\" },");
    sb.AppendLine("  \"identifySubjectType\": { \"class\": " + (top.Any(t => t.Rtti.Count > 0) ? "\"plausible\"" : "\"unsupported\"")
      + ", \"reason\": \"Offline RTTI on fingerprint-matching ctors\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized this milestone\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Deep-decode highest-score ctor/vtable candidates; confirm whether LOD sibling unwraps actor components\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    string path = Path.Combine(ReportsRoot, "v0.6.8-second-edward-feasibility.json");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static void DumpFuncStrings(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEnd(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    var ins = Disasm(entry, end);
    var seen = new HashSet<string>();
    foreach (var a in ins) {
      if (!a.IpRel) continue;
      string s = ReadAscii(a.DataRva, 80);
      if (!IsString(s) || s.Length < 5) continue;
      string line = "0x" + a.Rva.ToString("X") + " \"" + Trunc(s, 70) + "\"";
      if (seen.Add(line)) sb.AppendLine("  str func0x" + entry.ToString("X") + " " + line);
      if (seen.Count >= 12) break;
    }
  }

  static void ProbeRttiInFunc(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEnd(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    var ins = Disasm(entry, end);
    int hits = 0;
    foreach (var a in ins) {
      if (!a.IpRel) continue;
      string rtti = TryRttiName(a.DataRva);
      if (rtti == null) continue;
      sb.AppendLine("  rtti 0x" + a.Rva.ToString("X") + " lea 0x" + a.DataRva.ToString("X") + " -> " + rtti);
      if (++hits >= 15) break;
    }
    if (hits == 0) sb.AppendLine("  (no MSVC RTTI in 0x" + entry.ToString("X") + ")");
  }

  static string TryRttiName(uint maybeVtable) {
    if (maybeVtable < 8) return null;
    int fo = RvaToFile(maybeVtable - 8);
    if (fo < 0 || fo + 8 > pe.Length) return null;
    ulong colVa = BitConverter.ToUInt64(pe, fo);
    if (colVa < imageBase) return null;
    uint col = (uint)(colVa - imageBase);
    int cfo = RvaToFile(col);
    if (cfo < 0 || cfo + 0x18 > pe.Length) return null;
    uint sig = BitConverter.ToUInt32(pe, cfo);
    if (sig != 1) return null;
    uint self = BitConverter.ToUInt32(pe, cfo + 0x14);
    if (self != col) return null;
    uint td = BitConverter.ToUInt32(pe, cfo + 0x0C);
    string name = ReadAscii(td + 0x10, 96);
    if (name.Length < 6 || !name.StartsWith(".?A", StringComparison.Ordinal)) return null;
    return Demangle(name) + " [" + name + "]";
  }

  static string Demangle(string n) {
    string s = n;
    if (s.StartsWith(".?AV", StringComparison.Ordinal) || s.StartsWith(".?AU", StringComparison.Ordinal))
      s = s.Substring(4);
    int at = s.IndexOf("@@", StringComparison.Ordinal);
    if (at >= 0) s = s.Substring(0, at);
    return s;
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
    while (dec.IP < limit && guard++ < 100000) {
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
        IsIndirectCall = raw.FlowControl == FlowControl.IndirectCall,
        WritesMem = raw.Op0Kind == OpKind.Memory
      };
      if (raw.Op0Kind == OpKind.Register) {
        ins.Op0IsReg = true;
        ins.Op0Reg = raw.Op0Register;
      }
      for (int i = 0; i < raw.OpCount; i++) {
        if (raw.GetOpKind(i) != OpKind.Memory) continue;
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

  static bool LooksLikeCode(uint rva) {
    int fo = RvaToFile(rva);
    if (fo < 0 || fo + 4 > pe.Length) return false;
    string sec = SecName(rva);
    if (sec.IndexOf("impdata", StringComparison.OrdinalIgnoreCase) < 0
        && sec.IndexOf("code", StringComparison.OrdinalIgnoreCase) < 0
        && sec.IndexOf("text", StringComparison.OrdinalIgnoreCase) < 0)
      return false;
    byte b0 = pe[fo];
    if (b0 >= 0x40 && b0 <= 0x4F) return true;
    if (b0 >= 0x50 && b0 <= 0x57) return true;
    if (b0 == 0x48 || b0 == 0x55 || b0 == 0x53 || b0 == 0x56 || b0 == 0x57) return true;
    if (b0 == 0xE9 || b0 == 0xEB || b0 == 0xE8) return true;
    return true;
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
      if (s.Ptr == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 8 <= lim && list.Count < max; i++) {
        bool ok = true;
        for (int k = 0; k < 8; k++) if (pe[s.Ptr + i + k] != needle[k]) { ok = false; break; }
        if (ok) list.Add(s.Va + i);
      }
    }
    return list;
  }

  static List<uint> FindRvaDword(uint target, int max) {
    var list = new List<uint>();
    byte[] needle = BitConverter.GetBytes(target);
    foreach (var s in secs) {
      if (s.Ptr == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 4 <= lim && list.Count < max; i++) {
        bool ok = true;
        for (int k = 0; k < 4; k++) if (pe[s.Ptr + i + k] != needle[k]) { ok = false; break; }
        if (!ok) continue;
        uint site = s.Va + i;
        if (site >= target && site < target + 0x20) continue;
        list.Add(site);
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

  static string HexRva(uint rva) { return "0x" + rva.ToString("X"); }
  static string Trunc(string s, int n) { return s == null ? "" : (s.Length <= n ? s : s.Substring(0, n)); }
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }

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
