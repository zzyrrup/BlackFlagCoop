// v0.6.20 — Offline deep-decode 0x2335040 / 0x8CD620 / neighbor 0x2335140;
// recover heap size from 0x59D9660 registration consumers.
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
  const uint ActivOwner = 0x2335040;
  const uint Notify = 0x8CD620;
  const uint Neighbor = 0x2335140;
  const uint Post2B8 = 0x479E440;
  const uint AnimStr = 0xA179A9F;
  const uint OuterCtor = 0x59D9660;
  const uint InstallerB = 0x59D96A0;
  const uint HeaderInit = 0xB169D0;
  const uint InstallerA = 0x5F11A40;
  const uint Allocator = 0x426EE50;
  const uint Fill = 0x5352080;
  const uint ArmWrap = 0x2108620;
  const uint Trampoline2B0 = 0x4656C80;
  const uint Canonical2B8 = 0x479E3B0;
  const uint Helper = 0x2E97B60;
  const uint Wrapper = 0x2E97FC0;
  const uint WorkerA = 0x725400;
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
    public bool Touches22, Touches25, Touches26, Touches34, Touches61, Touches98, TouchesA0;
    public bool Touches18, TouchesA8, Nested;
    public bool CallsPost, CallsNotify, CallsAlloc, CallsHelper, CallsWrapper;
    public bool UsesAnimStr, Vcall2B0, Vcall2C0;
    public List<uint> Callees = new List<uint>();
    public List<uint> CallersE8 = new List<uint>();
    public List<string> Notes = new List<string>();
    public List<string> ModeNotes = new List<string>();
    public List<string> FieldNotes = new List<string>();
    public List<string> Disasm = new List<string>();
    public List<string> Strings = new List<string>();
    public List<uint> ImmSizes = new List<uint>();
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v080-raw");
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
    sb.AppendLine("===== v0.6.20 ACTIV PATH + HEAP SIZE =====");
    sb.AppendLine("exeSha256=" + hash);

    var reps = new List<FuncRep>();
    foreach (var t in new[] {
      (ActivOwner, "activ-owner-2335040"),
      (Notify, "notify-8CD620"),
      (Neighbor, "neighbor-2335140")
    }) {
      sb.AppendLine();
      sb.AppendLine("===== FUNC 0x" + t.Item1.ToString("X") + " (" + t.Item2 + ") =====");
      reps.Add(DeepFunc(sb, t.Item1, t.Item2));
    }

    // ---- Registration consumers of 0x59D9660 ----
    sb.AppendLine();
    sb.AppendLine("===== 0x59D9660 REGISTRATION CONSUMERS =====");
    var leaSites = FindLeaTo(OuterCtor, 40);
    var qwSites = FindQword(OuterCtor, 40);
    var e8Sites = FindE8(OuterCtor, 20);
    sb.AppendLine("LEA=" + leaSites.Count + " QWORD=" + qwSites.Count + " E8=" + e8Sites.Count);
    var regStoreTargets = new List<uint>();
    var sizeCandidates = new List<uint>();
    var heapNotes = new List<string>();

    foreach (var site in leaSites) {
      uint fs = FindFuncStart(site);
      sb.AppendLine("  lea @0x" + site.ToString("X") + " func≈0x" + fs.ToString("X") + " sec=" + SecName(site));
      // Window around LEA: look for mov [rip+disp], rax (store of ctor ptr) and nearby size imms
      uint winLo = site > 0x80 ? site - 0x80 : site;
      uint winHi = site + 0xC0;
      var win = Disasm(winLo, winHi);
      uint storeRva = 0;
      foreach (var ins in win) {
        if (ins.Rva <= site) continue;
        // store of rax/rcx/etc to rip-relative = registration slot
        if (ins.IpRel && (ins.Mnemonic == Mnemonic.Mov || ins.Mnemonic == Mnemonic.Movaps || ins.Mnemonic == Mnemonic.Movups)
            && (ins.Text.StartsWith("mov [rip") || ins.Text.Contains("mov qword ptr [rip"))) {
          storeRva = ins.DataRva;
          regStoreTargets.Add(storeRva);
          sb.AppendLine("    storeSlot @0x" + ins.Rva.ToString("X") + " ->0x" + storeRva.ToString("X")
            + " " + Trunc(ins.Text, 70));
          break;
        }
      }
      // nearby size-like imms in ±0x100 of LEA
      foreach (var ins in win) {
        if (ins.Mnemonic != Mnemonic.Mov) continue;
        uint imm;
        if (!TryParseImm(ins.Text, out imm)) continue;
        if (imm >= 0x100 && imm <= 0x100000 && (imm % 8 == 0 || imm % 0x10 == 0)) {
          sizeCandidates.Add(imm);
          heapNotes.Add("nearLeaImm@0x" + ins.Rva.ToString("X") + " 0x" + imm.ToString("X") + " " + Trunc(ins.Text, 60));
        }
      }
      // Also scan larger window in InstallerA around known site 0x5F14901 for size field writes to same record
      if (fs == InstallerA || (site >= 0x5F14800 && site <= 0x5F14A00)) {
        DecodeRegRecord(sb, site, storeRva, sizeCandidates, heapNotes);
      }
    }

    foreach (var site in qwSites.Take(10))
      sb.AppendLine("  qword @0x" + site.ToString("X") + " sec=" + SecName(site));

    // Search code that: calls Allocator with size, then eventually uses OuterCtor / store slot
    sb.AppendLine();
    sb.AppendLine("===== ALLOC + OUTER CTOR PROXIMITY =====");
    // Find E8 to Allocator, look at preceding imm in edx/r8d within 16 ins, record if size ~0x20E0±
    var allocSites = FindE8(Allocator, 200);
    sb.AppendLine("E8->Allocator sampleCap=" + allocSites.Count);
    var interestingAllocs = new List<string>();
    uint[] interestingSizes = { 0x20E0, 0x20C0, 0x2100, 0x2200, 0x2000, 0x1800, 0x1000, 0x140, 0xE0, 0x50 };
    int matched = 0;
    foreach (var site in allocSites) {
      uint fs = FindFuncStart(site);
      uint fe = FindFuncEnd(fs, 0x800);
      if (fe < site + 0x20) fe = site + 0x100;
      // look back 30 ins from call for size imm
      uint lo = site > 0x60 ? site - 0x60 : fs;
      var pre = Disasm(lo, site + 5);
      uint sizeImm = 0;
      foreach (var ins in pre) {
        if (ins.Rva >= site) break;
        uint imm;
        if (ins.Mnemonic == Mnemonic.Mov && TryParseImm(ins.Text, out imm)
            && (ins.Text.Contains("edx,") || ins.Text.Contains("r8d,") || ins.Text.Contains("ecx,")
                || ins.Text.Contains("esi,") || ins.Text.Contains("edi,"))) {
          if (imm >= 0x40 && imm <= 0x200000) sizeImm = imm;
        }
      }
      bool sizeHit = sizeImm != 0 && interestingSizes.Any(s => s == sizeImm || (sizeImm >= 0x20C0 && sizeImm <= 0x2200));
      // also check if function references OuterCtor or InstallerB or store slots
      bool refsOuter = false;
      var body = Disasm(fs, Math.Min(fe, fs + 0x400));
      foreach (var ins in body) {
        if (ins.IsCall && (ins.NearTarget == OuterCtor || ins.NearTarget == InstallerB || ins.NearTarget == HeaderInit))
          refsOuter = true;
        if (ins.IpRel && regStoreTargets.Contains(ins.DataRva)) refsOuter = true;
      }
      if (sizeHit || refsOuter) {
        matched++;
        string note = "alloc@0x" + site.ToString("X") + " func≈0x" + fs.ToString("X")
          + " sizeImm=0x" + sizeImm.ToString("X") + " refsOuter=" + refsOuter;
        interestingAllocs.Add(note);
        heapNotes.Add(note);
        if (matched <= 30) sb.AppendLine("  " + note);
      }
    }
    sb.AppendLine("interestingAllocHits=" + matched);

    // Decode registration record bytes at store slots
    sb.AppendLine();
    sb.AppendLine("===== REG RECORD PEEK =====");
    foreach (var slot in regStoreTargets.Distinct().Take(8)) {
      PeekRegRecord(sb, slot, sizeCandidates);
    }

    // Also: scan InstallerA around 0x5F14901 for dword/qword size fields written into the same struct
    sb.AppendLine();
    sb.AppendLine("===== INSTALLERA WINDOW @0x5F148C0 =====");
    var iaWin = Disasm(0x5F148C0, 0x5F14980);
    foreach (var ins in iaWin) {
      string mark = "";
      if (ins.IpRel && leaSites.Any(s => Math.Abs((long)s - ins.Rva) < 0x20) && ins.Mnemonic == Mnemonic.Lea)
        mark = " *** LEA OUTER ***";
      if (ins.NearTarget == OuterCtor) mark += " *** OUTER ***";
      uint imm;
      if (ins.Mnemonic == Mnemonic.Mov && TryParseImm(ins.Text, out imm) && imm >= 0x100 && imm <= 0x100000)
        mark += " imm=0x" + imm.ToString("X");
      sb.AppendLine("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 90) + mark);
    }

    // Cross
    var activ = reps.First(r => r.Entry == ActivOwner);
    var notify = reps.First(r => r.Entry == Notify);
    var neigh = reps.First(r => r.Entry == Neighbor);
    sb.AppendLine();
    sb.AppendLine("===== CROSS =====");
    sb.AppendLine("activ callsPost=" + activ.CallsPost + " usesAnim=" + activ.UsesAnimStr
      + " callsNotify=" + activ.CallsNotify + " t26=" + activ.Touches26 + " vcall2C0=" + activ.Vcall2C0);
    sb.AppendLine("notify size=" + notify.Size + " strings=" + notify.Strings.Count
      + " callees=" + notify.Callees.Count + " callersE8=" + notify.CallersE8.Count);
    sb.AppendLine("neighbor vcall2B0=" + neigh.Vcall2B0 + " modes=[" + string.Join(",", neigh.ModeNotes.Take(6)) + "]"
      + " t61=" + neigh.Touches61);
    sb.AppendLine("regSlots=" + regStoreTargets.Distinct().Count()
      + " sizeCandidates=[" + string.Join(",", sizeCandidates.Distinct().OrderBy(x => x).Take(16).Select(x => "0x" + x.ToString("X"))) + "]");
    sb.AppendLine("heapNotes=" + heapNotes.Count);

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteJson(hash, reps, regStoreTargets, sizeCandidates, heapNotes, interestingAllocs);

    bool ok = activ.CallsPost && activ.UsesAnimStr && notify.Size > 0 && neigh.Size > 0;
    Console.WriteLine("selfCheck activ->post=" + activ.CallsPost + " anim=" + activ.UsesAnimStr
      + " notify=" + notify.Size + " neigh2B0=" + neigh.Vcall2B0 + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static void DecodeRegRecord(StringBuilder sb, uint leaSite, uint storeRva,
      List<uint> sizeCandidates, List<string> heapNotes) {
    // Walk ±0x40 stores to rip-relative; collect a cluster of field stores that form the type record
    uint lo = leaSite > 0x100 ? leaSite - 0x100 : leaSite;
    uint hi = leaSite + 0x100;
    var stores = new List<(uint site, uint slot, string text, uint imm)>();
    foreach (var ins in Disasm(lo, hi)) {
      uint imm = 0;
      TryParseImm(ins.Text, out imm);
      if (ins.IpRel && ins.Mnemonic == Mnemonic.Mov) {
        stores.Add((ins.Rva, ins.DataRva, Trunc(ins.Text, 80), imm));
      }
      if (ins.Mnemonic == Mnemonic.Mov && imm >= 0x100 && imm <= 0x100000
          && (ins.Text.Contains("dword") || ins.Text.Contains("eax,") || ins.Text.Contains("ecx,")
              || ins.Text.Contains("edx,") || ins.Text.Contains("r8d,") || ins.Text.Contains("esi,"))) {
        // mov reg, imm then likely store — track
        sizeCandidates.Add(imm);
      }
    }
    sb.AppendLine("    regWindowStores=" + stores.Count);
    foreach (var s in stores.Take(20)) {
      sb.AppendLine("      @0x" + s.site.ToString("X") + " slot=0x" + s.slot.ToString("X")
        + " imm=0x" + s.imm.ToString("X") + " " + s.text);
      if (s.imm >= 0x100 && s.imm <= 0x100000) {
        sizeCandidates.Add(s.imm);
        heapNotes.Add("regStoreImm slot=0x" + s.slot.ToString("X") + " imm=0x" + s.imm.ToString("X"));
      }
    }
  }

  static void PeekRegRecord(StringBuilder sb, uint slot, List<uint> sizeCandidates) {
    // Read 0x40 bytes at slot as potential record; also look ±0x40 for size-looking dwords
    int fo = RvaToFile(slot);
    if (fo < 0) { sb.AppendLine("  slot 0x" + slot.ToString("X") + " UNMAPPED"); return; }
    sb.AppendLine("  slot 0x" + slot.ToString("X") + " sec=" + SecName(slot) + " hex40=" + Hex(slot, 40));
    // Interpret as qword ptr (should be imageBase+OuterCtor if this is the ctor slot)
    if (fo + 8 <= pe.Length) {
      ulong q = BitConverter.ToUInt64(pe, fo);
      if (q >= imageBase) {
        uint r = (uint)(q - imageBase);
        sb.AppendLine("    qword0=0x" + q.ToString("X") + " rva=0x" + r.ToString("X")
          + (r == OuterCtor ? " *** OUTER_CTOR ***" : ""));
      }
    }
    // Scan nearby dwords for size-like values
    for (int off = -0x40; off <= 0x40; off += 4) {
      int p = fo + off;
      if (p < 0 || p + 4 > pe.Length) continue;
      uint d = BitConverter.ToUInt32(pe, p);
      if (d >= 0x100 && d <= 0x100000 && (d % 8 == 0 || d % 0x10 == 0)) {
        uint rva = slot + (uint)off;
        sb.AppendLine("    nearDword off=" + off + " @0x" + rva.ToString("X") + " =0x" + d.ToString("X"));
        if (d >= 0x1000) sizeCandidates.Add(d);
      }
    }
  }

  static FuncRep DeepFunc(StringBuilder sb, uint entry, string role) {
    var r = new FuncRep { Entry = entry, Role = role };
    int maxScan = entry == Notify ? 0x2000 : 0x800;
    r.End = FindFuncEnd(entry, maxScan);
    if (r.End <= entry) r.End = entry + 0x200;
    r.Size = (int)(r.End - entry);
    sb.AppendLine("entry=0x" + entry.ToString("X") + " end=0x" + r.End.ToString("X")
      + " size=" + r.Size + " sec=" + SecName(entry) + " prologue=" + Hex(entry, 12));

    var ins = Disasm(entry, r.End);
    int head = 0;
    foreach (var i in ins) {
      if (head++ < 80) r.Disasm.Add("0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 100));
      if (i.HasMem && !i.IpRel) {
        if (i.Disp == 0x22) r.Touches22 = true;
        if (i.Disp == 0x25) r.Touches25 = true;
        if (i.Disp == 0x26) { r.Touches26 = true; r.FieldNotes.Add("+0x26 @" + "0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 60)); }
        if (i.Disp == 0x34) { r.Touches34 = true; r.FieldNotes.Add("+0x34 @" + "0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 60)); }
        if (i.Disp == 0x61) r.Touches61 = true;
        if (i.Disp == 0x98) r.Touches98 = true;
        if (i.Disp == 0xA0) r.TouchesA0 = true;
        if (i.Disp == 0x18) r.Touches18 = true;
        if (i.Disp == 0xA8) { r.TouchesA8 = true; r.Nested = true; }
        if (i.Disp == 0x2B0 || i.Text.Contains("+2B0")) r.Vcall2B0 = true;
        if (i.Disp == 0x2C0 || i.Text.Contains("+2C0")) r.Vcall2C0 = true;
      }
      if (i.IsIndirectCall && (i.Disp == 0x2B0 || i.Text.Contains("+2B0"))) r.Vcall2B0 = true;
      if (i.IsIndirectCall && (i.Disp == 0x2C0 || i.Text.Contains("+2C0"))) r.Vcall2C0 = true;
      if (i.IpRel && i.DataRva == AnimStr) {
        r.UsesAnimStr = true;
        r.Notes.Add("ANIM_STR @" + "0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 70));
      }
      if (i.IsCall && !i.IsIndirectCall && i.NearTarget != 0) {
        r.Callees.Add(i.NearTarget);
        if (i.NearTarget == Post2B8) { r.CallsPost = true; r.Notes.Add("CALL_POST @" + "0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Notify) { r.CallsNotify = true; r.Notes.Add("CALL_NOTIFY @" + "0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Allocator) r.CallsAlloc = true;
        if (i.NearTarget == Helper) r.CallsHelper = true;
        if (i.NearTarget == Wrapper) r.CallsWrapper = true;
      }
      // edx mode immediates
      if (i.Mnemonic == Mnemonic.Mov && (i.Text.Contains("edx,") || i.Text.Contains("r8d,") || i.Text.Contains("r8b,"))) {
        uint imm;
        if (TryParseImm(i.Text, out imm) && imm <= 8)
          r.ModeNotes.Add("0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 50));
      }
      if (i.Mnemonic == Mnemonic.Mov && TryParseImm(i.Text, out uint sz)
          && sz >= 0x40 && sz <= 0x100000 && (sz % 8 == 0 || sz % 0x10 == 0))
        r.ImmSizes.Add(sz);
      // test edx, ~2 pattern
      if (i.Text.Contains("0FFFFFFFD") || i.Text.Contains("FFFFFFFD"))
        r.ModeNotes.Add("test~2 @" + "0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 50));
    }

    r.CallersE8 = FindE8(entry, 30);
    sb.AppendLine("nested=" + r.Nested + " t22/25/26/34=" + r.Touches22 + "/" + r.Touches25 + "/" + r.Touches26 + "/" + r.Touches34
      + " t61=" + r.Touches61 + " t98=" + r.Touches98 + " tA0=" + r.TouchesA0
      + " post=" + r.CallsPost + " notify=" + r.CallsNotify + " anim=" + r.UsesAnimStr
      + " v2B0=" + r.Vcall2B0 + " v2C0=" + r.Vcall2C0
      + " callersE8=" + r.CallersE8.Count + " callees=" + r.Callees.Distinct().Count());
    foreach (var n in r.Notes) sb.AppendLine("  " + n);
    foreach (var n in r.FieldNotes) sb.AppendLine("  field " + n);
    foreach (var n in r.ModeNotes) sb.AppendLine("  mode " + n);
    foreach (var c in r.Callees.Distinct().Take(20)) {
      uint ce = FindFuncEndFirstRet(c, 0x400);
      string str = NearString(c, 0x60);
      sb.AppendLine("  callee 0x" + c.ToString("X") + " size~" + (ce > c ? ce - c : 0)
        + " prologue=" + Hex(c, 8)
        + (c == Post2B8 ? " *** POST ***" : "")
        + (c == Notify ? " *** NOTIFY ***" : "")
        + (c == Allocator ? " *** ALLOC ***" : "")
        + (str.Length > 0 ? " \"" + Trunc(str, 50) + "\"" : ""));
    }
    foreach (var site in r.CallersE8.Take(12))
      sb.AppendLine("  e8 @0x" + site.ToString("X") + " func≈0x" + FindFuncStart(site).ToString("X"));

    // strings near / rip-ref
    foreach (var i in ins) {
      if (!i.IpRel || i.DataRva == 0) continue;
      string s = ReadAscii(i.DataRva, 80);
      if (IsString(s) && s.Length >= 5 && !r.Strings.Contains(s)) {
        r.Strings.Add(s);
        sb.AppendLine("  str @0x" + i.DataRva.ToString("X") + " \"" + Trunc(s, 70) + "\"");
      }
    }

    sb.AppendLine("--- disasm head ---");
    foreach (var line in r.Disasm.Take(60)) sb.AppendLine(line);
    return r;
  }

  static void WriteJson(string hash, List<FuncRep> reps, List<uint> regSlots,
      List<uint> sizeCandidates, List<string> heapNotes, List<string> interestingAllocs) {
    var activ = reps.First(r => r.Entry == ActivOwner);
    var notify = reps.First(r => r.Entry == Notify);
    var neigh = reps.First(r => r.Entry == Neighbor);
    var sizes = sizeCandidates.Distinct().OrderBy(x => x).ToList();
    // Prefer sizes near outer lower bound
    uint best = 0;
    foreach (var s in sizes)
      if (s >= 0x20C0 && s <= 0x2400) { best = s; break; }

    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.20\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"activOwner\": { \"rva\": \"0x2335040\", \"size\": " + activ.Size
      + ", \"callsPost\": " + T(activ.CallsPost)
      + ", \"usesAnim\": " + T(activ.UsesAnimStr)
      + ", \"callsNotify\": " + T(activ.CallsNotify)
      + ", \"touches26\": " + T(activ.Touches26)
      + ", \"vcall2C0\": " + T(activ.Vcall2C0) + " },");
    sb.AppendLine("  \"notify\": { \"rva\": \"0x8CD620\", \"size\": " + notify.Size
      + ", \"callersE8\": " + notify.CallersE8.Count
      + ", \"strings\": [" + string.Join(", ", notify.Strings.Take(8).Select(J)) + "] },");
    sb.AppendLine("  \"neighbor\": { \"rva\": \"0x2335140\", \"size\": " + neigh.Size
      + ", \"vcall2B0\": " + T(neigh.Vcall2B0)
      + ", \"touches61\": " + T(neigh.Touches61) + " },");
    sb.AppendLine("  \"heap\": {");
    sb.AppendLine("    \"regSlots\": [" + string.Join(", ", regSlots.Distinct().Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("    \"sizeCandidates\": [" + string.Join(", ", sizes.Take(24).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("    \"bestNear20E0\": " + (best != 0 ? "\"0x" + best.ToString("X") + "\"" : "null") + ",");
    sb.AppendLine("    \"interestingAllocs\": " + interestingAllocs.Count);
    sb.AppendLine("  },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.20-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.20-summary.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.20\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"funcs\": [");
    for (int i = 0; i < reps.Count; i++) {
      var r = reps[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + r.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(r.Role) + ",");
      sb.AppendLine("      \"size\": " + r.Size + ",");
      sb.AppendLine("      \"callsPost\": " + T(r.CallsPost) + ",");
      sb.AppendLine("      \"callsNotify\": " + T(r.CallsNotify) + ",");
      sb.AppendLine("      \"usesAnimStr\": " + T(r.UsesAnimStr) + ",");
      sb.AppendLine("      \"vcall2B0\": " + T(r.Vcall2B0) + ",");
      sb.AppendLine("      \"vcall2C0\": " + T(r.Vcall2C0) + ",");
      sb.AppendLine("      \"touches26\": " + T(r.Touches26) + ",");
      sb.AppendLine("      \"touches34\": " + T(r.Touches34) + ",");
      sb.AppendLine("      \"notes\": [" + string.Join(", ", r.Notes.Select(J)) + "],");
      sb.AppendLine("      \"modeNotes\": [" + string.Join(", ", r.ModeNotes.Select(J)) + "],");
      sb.AppendLine("      \"fieldNotes\": [" + string.Join(", ", r.FieldNotes.Select(J)) + "],");
      sb.AppendLine("      \"strings\": [" + string.Join(", ", r.Strings.Select(J)) + "],");
      sb.AppendLine("      \"callees\": [" + string.Join(", ", r.Callees.Distinct().Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callersE8\": [" + string.Join(", ", r.CallersE8.Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", r.Disasm.Take(40).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < reps.Count ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"heapNotes\": [" + string.Join(", ", heapNotes.Take(40).Select(J)) + "]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.20-funcs-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.20-funcs-deep.json");

    bool heapConfirmed = best != 0 && interestingAllocs.Any(a => a.Contains("refsOuter=True") || a.Contains("sizeImm=0x" + best.ToString("X")));
    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.20\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Activation/notify path mutates existing objects\" },");
    sb.AppendLine("  \"activPathDecoded\": { \"class\": \"confirmed\", \"reason\": \"0x2335040 sets +0x26, calls 0x479E440 and 0x8CD620 with AnimatedOnActiveChanged\" },");
    sb.AppendLine("  \"notifyDecoded\": { \"class\": " + (notify.Size > 0 ? "\"confirmed\"" : "\"unsupported\"")
      + ", \"reason\": " + J("0x8CD620 size=" + notify.Size + " strings=" + notify.Strings.Count) + " },");
    sb.AppendLine("  \"neighborDecoded\": { \"class\": " + (neigh.Vcall2B0 ? "\"confirmed\"" : "\"partial\"")
      + ", \"reason\": " + J("0x2335140 vcall2B0=" + neigh.Vcall2B0 + " size=" + neigh.Size) + " },");
    sb.AppendLine("  \"heapSize\": { \"class\": \"" + (heapConfirmed ? "confirmed" : (best != 0 ? "partial" : "unsupported"))
      + "\", \"reason\": " + J(best != 0
        ? "Best size candidate near 0x20E0 bound: 0x" + best.ToString("X") + "; allocHits=" + interestingAllocs.Count
        : "No size candidate near outer lower bound 0x20E0") + " },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Follow notify 0x8CD620 consumers; confirm heap alloc site for registered 0x59D9660 type\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\", \"conflating wrap modes with gate\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.20-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.20-second-edward-feasibility.json");
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
