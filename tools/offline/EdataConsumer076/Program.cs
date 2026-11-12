// v0.6.16 — Offline consumers of .edata slots + arming neighbors + vcall +0x2B0.
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
  const uint SlotArming = 0x9490078;      // .edata -> 0x21085D0
  const uint SlotBit0 = 0x9303E30;         // .edata -> 0x210A9F0
  const uint SlotBit1 = 0x9303E38;         // .edata -> 0xF1C230
  const uint ArmingHelper = 0x21085D0;
  const uint NeighborA = 0x2108530;
  const uint NeighborB = 0x2108830;
  const uint GateStub = 0x7BB020;
  const uint GateSetter = 0x53F31A0;
  const uint BitWriter = 0xF1C240;
  const uint BitThunk0 = 0x210A9F0;
  const uint BitThunk1 = 0xF1C230;
  const uint WorkerB = 0xE95E80;
  const uint LookupKey = 0xB2898C8;
  const uint Lookup = 0x429F9E0;
  const uint Allocator = 0x426EE50;
  const uint Helper = 0x2E97B60;
  const uint Wrapper = 0x2E97FC0;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static readonly uint[] EdataSlots = { SlotArming, SlotBit0, SlotBit1 };
  static readonly uint[] Neighbors = { NeighborA, NeighborB, ArmingHelper };

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
  sealed class Hit {
    public string Kind; public uint Site; public uint Func; public string Sec; public string Note = "";
  }
  sealed class SlotReport {
    public uint Slot; public uint PointsTo; public string Role;
    public List<Hit> Hits = new List<Hit>();
    public List<string> NeighborQwords = new List<string>();
    public List<string> Notes = new List<string>();
  }
  sealed class FuncReport {
    public uint Entry; public string Role; public uint End; public int Size;
    public bool UsesKey, Nested, Touches61, Touches98, Touches2B0;
    public bool CallsGateStub, CallsAllocator, CallsHelper, CallsLookup;
    public List<string> GateOps = new List<string>();
    public List<string> VcallNotes = new List<string>();
    public List<string> FieldNotes = new List<string>();
    public List<string> Strings = new List<string>();
    public List<uint> Callees = new List<uint>();
    public List<uint> CallersE8 = new List<uint>();
    public List<string> CallerNotes = new List<string>();
    public List<string> DisasmHead = new List<string>();
    public List<Hit> InstallHits = new List<Hit>();
  }
  sealed class Vcall2B0Hit {
    public uint Site; public uint Func; public bool Edx2Nearby; public string Context = "";
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v076-raw");
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
    sb.AppendLine("===== v0.6.16 EDATA CONSUMERS + ARMING + VCALL +0x2B0 =====");
    sb.AppendLine("exeSha256=" + hash);

    // 1) Map slot contents + neighborhood
    var slots = new List<SlotReport>();
    foreach (uint slot in EdataSlots) {
      sb.AppendLine();
      sb.AppendLine("===== SLOT 0x" + slot.ToString("X") + " =====");
      slots.Add(AnalyzeSlot(sb, slot));
    }

    // 2) Also probe LEA to nearby table bases (aligned down)
    sb.AppendLine();
    sb.AppendLine("===== TABLE BASE PROBES =====");
    foreach (uint slot in EdataSlots) {
      foreach (uint baseCand in new[] {
        slot & unchecked((uint)~0xFFu),
        slot & unchecked((uint)~0x7Fu),
        slot & unchecked((uint)~0x3Fu),
        slot - (slot % 0x10)
      }.Distinct()) {
        var leas = FindLeaTo(baseCand, 8);
        if (leas.Count == 0) continue;
        sb.AppendLine("baseCand 0x" + baseCand.ToString("X") + " (from slot 0x" + slot.ToString("X")
          + ") lea=" + leas.Count);
        foreach (var s in leas.Take(8))
          sb.AppendLine("  lea @0x" + s.ToString("X") + " func≈0x" + FindFuncStart(s).ToString("X"));
      }
    }

    // 3) Deep-decode neighbors + arming helper
    var funcs = new List<FuncReport>();
    foreach (uint f in Neighbors) {
      sb.AppendLine();
      sb.AppendLine("===== FUNC 0x" + f.ToString("X") + " =====");
      funcs.Add(DeepFunc(sb, f, RoleOf(f)));
    }

    // 4) Global scan for vcall +0x2B0
    sb.AppendLine();
    sb.AppendLine("===== VCALL +0x2B0 SITES =====");
    var vcalls = ScanVcall2B0(sb);

    // 5) Cross: which vcall sites are in arming helper / neighbors
    sb.AppendLine();
    sb.AppendLine("===== SUMMARY =====");
    foreach (var s in slots) {
      sb.AppendLine("slot 0x" + s.Slot.ToString("X") + " ->0x" + s.PointsTo.ToString("X")
        + " " + s.Role + " hits=" + s.Hits.Count);
      foreach (var h in s.Hits.Take(12))
        sb.AppendLine("  " + h.Kind + " @0x" + h.Site.ToString("X")
          + " func≈0x" + h.Func.ToString("X") + " " + h.Note);
    }
    foreach (var f in funcs) {
      sb.AppendLine("func 0x" + f.Entry.ToString("X") + " " + f.Role
        + " size=" + f.Size + " t61=" + f.Touches61 + " t98=" + f.Touches98
        + " t2B0=" + f.Touches2B0 + " gateStub=" + f.CallsGateStub
        + " callersE8=" + f.CallersE8.Count + " installHits=" + f.InstallHits.Count);
    }
    sb.AppendLine("vcall2B0Sites=" + vcalls.Count
      + " withEdx2=" + vcalls.Count(v => v.Edx2Nearby));

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteSlotsJson(hash, slots);
    WriteFuncsJson(hash, funcs);
    WriteVcallJson(hash, vcalls);
    WriteSummaryJson(hash, slots, funcs, vcalls);
    WriteFeasibilityJson(hash, slots, funcs, vcalls);

    bool ok = funcs.All(f => f.Size > 0)
      && funcs.Any(f => f.Entry == ArmingHelper && f.Touches2B0)
      && slots.All(s => s.PointsTo != 0);
    Console.WriteLine("selfCheck slots=" + slots.Count + " funcs=" + funcs.Count
      + " vcalls=" + vcalls.Count + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static string RoleOf(uint e) {
    if (e == ArmingHelper) return "arming-helper";
    if (e == NeighborA) return "arming-neighbor-A";
    if (e == NeighborB) return "arming-neighbor-B";
    return "func";
  }

  static string SlotRole(uint slot) {
    if (slot == SlotArming) return "arming-helper-slot";
    if (slot == SlotBit0) return "bit-thunk0-slot";
    if (slot == SlotBit1) return "bit-thunk1-slot";
    return "edata-slot";
  }

  static SlotReport AnalyzeSlot(StringBuilder sb, uint slot) {
    var r = new SlotReport { Slot = slot, Role = SlotRole(slot) };
    int fo = RvaToFile(slot);
    if (fo < 0 || fo + 8 > pe.Length) {
      r.Notes.Add("unmapped");
      sb.AppendLine("UNMAPPED");
      return r;
    }
    ulong q = BitConverter.ToUInt64(pe, fo);
    if (q > imageBase && q < imageBase + 0x20000000)
      r.PointsTo = (uint)(q - imageBase);
    sb.AppendLine("sec=" + SecName(slot) + " qword=0x" + q.ToString("X")
      + " ->0x" + r.PointsTo.ToString("X") + " role=" + r.Role);

    // Neighbor window
    for (int i = -6; i <= 6; i++) {
      uint rr = unchecked((uint)((int)slot + i * 8));
      int f2 = RvaToFile(rr);
      if (f2 < 0 || f2 + 8 > pe.Length) continue;
      ulong qq = BitConverter.ToUInt64(pe, f2);
      string note = "q[" + i + "] @0x" + rr.ToString("X") + "=0x" + qq.ToString("X");
      if (qq > imageBase && qq < imageBase + 0x20000000) {
        uint dest = (uint)(qq - imageBase);
        note += " ->0x" + dest.ToString("X") + " " + SecName(dest)
          + (LooksLikeCode(dest) ? " CODE" : "");
      }
      r.NeighborQwords.Add(note);
      sb.AppendLine("  " + note);
    }

    void add(string kind, uint site, string note = "") {
      r.Hits.Add(new Hit {
        Kind = kind, Site = site, Func = FindFuncStart(site),
        Sec = SecName(site), Note = note
      });
      sb.AppendLine("  " + kind + " @0x" + site.ToString("X")
        + " sec=" + SecName(site) + " func≈0x" + FindFuncStart(site).ToString("X")
        + (string.IsNullOrEmpty(note) ? "" : " " + note));
    }

    // Direct xrefs to the slot address (LEA/load of the pointer slot itself)
    foreach (var s in FindLeaTo(slot, 30)) add("leaSlot", s);
    foreach (var s in FindMovFromRip(slot, 30)) add("movRipSlot", s, "load qword from slot");
    foreach (var s in FindQwordAbs(slot, 20)) add("qwordOfSlotAddr", s, "pointer-to-slot");
    foreach (var s in FindRva32(slot, 20)) add("rva32Slot", s);

    // Also LEA/load of the function the slot points to (already known, but capture installers)
    if (r.PointsTo != 0) {
      foreach (var s in FindLeaTo(r.PointsTo, 20)) add("leaTarget", s, "target=0x" + r.PointsTo.ToString("X"));
      foreach (var s in FindE8(r.PointsTo, 20)) add("e8Target", s, "target=0x" + r.PointsTo.ToString("X"));
      foreach (var s in FindQwordAbs(r.PointsTo, 20)) add("qwordTarget", s, "target=0x" + r.PointsTo.ToString("X"));
    }

    // Search for scaled-index or displacement loads that could index into the table
    // by finding LEAs to nearby aligned bases that later add a constant offset == slot-base
    ProbeIndexedConsumers(sb, r);

    sb.AppendLine("hitCount=" + r.Hits.Count + " byKind="
      + string.Join(",", r.Hits.GroupBy(h => h.Kind).Select(g => g.Key + ":" + g.Count())));
    return r;
  }

  static void ProbeIndexedConsumers(StringBuilder sb, SlotReport r) {
    // For each LEA to addresses within ±0x200 of slot, check if consumer uses disp matching offset
    var nearBases = new HashSet<uint>();
    for (int off = -0x200; off <= 0x200; off += 8) {
      uint cand = unchecked((uint)((int)r.Slot + off));
      if ((cand & 7) != 0) continue;
      foreach (var s in FindLeaTo(cand, 4)) {
        nearBases.Add(cand);
        int delta = (int)r.Slot - (int)cand;
        sb.AppendLine("  nearBaseLea base=0x" + cand.ToString("X") + " lea@0x" + s.ToString("X")
          + " func≈0x" + FindFuncStart(s).ToString("X") + " deltaToSlot=" + delta
          + " (0x" + delta.ToString("X") + ")");
        r.Hits.Add(new Hit {
          Kind = "nearBaseLea", Site = s, Func = FindFuncStart(s), Sec = SecName(s),
          Note = "base=0x" + cand.ToString("X") + " delta=0x" + delta.ToString("X")
        });
        // Dump a bit of the consumer for displacement use
        DumpConsumerDisp(sb, FindFuncStart(s), cand, r.Slot);
      }
    }
  }

  static void DumpConsumerDisp(StringBuilder sb, uint func, uint baseAddr, uint slot) {
    if (func == 0) return;
    uint end = FindFuncEnd(func, 0x600);
    if (end <= func) end = func + 0x200;
    if (end - func > 0x600) end = func + 0x600;
    int delta = (int)slot - (int)baseAddr;
    int n = 0;
    foreach (var a in Disasm(func, end)) {
      if (a.IpRel && a.DataRva == baseAddr)
        sb.AppendLine("    0x" + a.Rva.ToString("X") + " " + a.Text + " [BASE]");
      if (a.HasMem && !a.IpRel && a.Disp == delta)
        sb.AppendLine("    0x" + a.Rva.ToString("X") + " " + a.Text + " [DISP==slotDelta]");
      if (a.HasMem && !a.IpRel && Math.Abs(a.Disp) == 0x2B0)
        sb.AppendLine("    0x" + a.Rva.ToString("X") + " " + a.Text + " [+0x2B0]");
      if (a.IpRel) {
        string s = ReadAscii(a.DataRva, 64);
        if (IsString(s) && s.Length >= 5 && n < 4) {
          sb.AppendLine("    str \"" + Trunc(s, 60) + "\"");
          n++;
        }
      }
    }
  }

  static FuncReport DeepFunc(StringBuilder sb, uint entry, string role) {
    var r = new FuncReport { Entry = entry, Role = role };
    r.End = FindFuncEnd(entry, 0x2000);
    if (r.End <= entry) r.End = entry + 0x200;
    if (r.End - entry > 0x2000) r.End = entry + 0x2000;
    r.Size = (int)(r.End - entry);
    sb.AppendLine("entry=0x" + entry.ToString("X") + " end=0x" + r.End.ToString("X")
      + " size=" + r.Size + " role=" + role + " prologue=" + Hex(entry, 16));

    var ins = Disasm(entry, r.End);
    bool s18 = false, sA8 = false, s3 = false;
    int head = 0;
    for (int i = 0; i < ins.Count; i++) {
      var a = ins[i];
      if (head < 48) {
        string line = "0x" + a.Rva.ToString("X") + " " + a.Text;
        r.DisasmHead.Add(line);
        sb.AppendLine("  " + line);
        head++;
      }
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        r.Callees.Add(dest);
        if (dest == GateStub) { r.CallsGateStub = true; sb.AppendLine("  *** GATE STUB @0x" + a.Rva.ToString("X")); }
        if (dest == GateSetter) sb.AppendLine("  *** GATESETTER @0x" + a.Rva.ToString("X"));
        if (dest == Allocator) { r.CallsAllocator = true; sb.AppendLine("  *** ALLOC @0x" + a.Rva.ToString("X")); }
        if (dest == Helper) r.CallsHelper = true;
        if (dest == Lookup) r.CallsLookup = true;
        if (dest == WorkerB) sb.AppendLine("  *** WORKER_B @0x" + a.Rva.ToString("X"));
        if (dest == BitWriter || dest == BitThunk0 || dest == BitThunk1)
          sb.AppendLine("  *** BIT path 0x" + dest.ToString("X") + " @0x" + a.Rva.ToString("X"));
      }
      // indirect call/jmp
      if (a.IsIndirectCall || a.Mnemonic == Mnemonic.Jmp) {
        if (a.HasMem && !a.IpRel && Math.Abs(a.Disp) == 0x2B0) {
          r.Touches2B0 = true;
          bool edx2 = Edx2Nearby(ins, i);
          string note = "0x" + a.Rva.ToString("X") + " " + a.Text + " edx2=" + edx2;
          r.VcallNotes.Add(note);
          sb.AppendLine("  *** VCALL/JMP +0x2B0 " + note);
        }
        // pattern: mov rax,[rax+0x2B0]; call/jmp rax
        if (i > 0) {
          var prev = ins[i - 1];
          if (prev.HasMem && !prev.IpRel && Math.Abs(prev.Disp) == 0x2B0
              && (prev.Mnemonic == Mnemonic.Mov || prev.Mnemonic == Mnemonic.Movzx)) {
            r.Touches2B0 = true;
            bool edx2 = Edx2Nearby(ins, i);
            string note = "0x" + prev.Rva.ToString("X") + "/" + a.Rva.ToString("X")
              + " load+0x2B0 then " + a.Mnemonic + " edx2=" + edx2;
            r.VcallNotes.Add(note);
            sb.AppendLine("  *** VCALL pattern " + note);
          }
        }
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
        if (Math.Abs(a.Disp) == 0x2B0) {
          r.Touches2B0 = true;
          if (r.VcallNotes.Count < 16)
            r.VcallNotes.Add("mem 0x" + a.Rva.ToString("X") + " " + a.Text);
        }
      }
      if (a.IpRel) {
        if (a.DataRva == LookupKey) r.UsesKey = true;
        string s = ReadAscii(a.DataRva, 96);
        if (IsString(s) && s.Length >= 5 && r.Strings.Count < 12
            && !s.StartsWith("AWAV", StringComparison.Ordinal) && !r.Strings.Contains(s))
          r.Strings.Add(s);
      }
    }
    if (ins.Count > 48) sb.AppendLine("  ... +" + (ins.Count - 48) + " ins ...");
    r.Nested = s18 && sA8 && s3;
    r.Callees = r.Callees.Distinct().ToList();
    r.CallersE8 = FindE8(entry, 30);

    // Install hits for this function
    foreach (var s in FindLeaTo(entry, 15))
      r.InstallHits.Add(new Hit { Kind = "lea", Site = s, Func = FindFuncStart(s), Sec = SecName(s) });
    foreach (var s in FindQwordAbs(entry, 15))
      r.InstallHits.Add(new Hit { Kind = "qword", Site = s, Func = 0, Sec = SecName(s) });
    foreach (var s in FindRva32(entry, 15))
      r.InstallHits.Add(new Hit { Kind = "rva32", Site = s, Func = 0, Sec = SecName(s) });

    sb.AppendLine("nested=" + r.Nested + " key=" + r.UsesKey + " t61=" + r.Touches61
      + " t98=" + r.Touches98 + " t2B0=" + r.Touches2B0 + " gateStub=" + r.CallsGateStub
      + " callersE8=" + r.CallersE8.Count + " installHits=" + r.InstallHits.Count);
    foreach (var g in r.GateOps) sb.AppendLine("  gate " + g);
    foreach (var v in r.VcallNotes) sb.AppendLine("  vcall " + v);
    foreach (var f in r.FieldNotes.Take(10)) sb.AppendLine("  field " + f);
    foreach (var s in r.Strings.Take(8)) sb.AppendLine("  str \"" + Trunc(s, 70) + "\"");
    foreach (var c in r.Callees.Where(x => !IsNoise(x)).Take(12))
      sb.AppendLine("  callee 0x" + c.ToString("X") + Tag(c));
    foreach (var h in r.InstallHits.Take(12))
      sb.AppendLine("  install " + h.Kind + " @0x" + h.Site.ToString("X") + " sec=" + h.Sec);

    sb.AppendLine("-- callers --");
    foreach (var site in r.CallersE8.Take(16)) {
      uint fn = FindFuncStart(site);
      string note = "e8 @0x" + site.ToString("X") + " func≈0x" + fn.ToString("X");
      r.CallerNotes.Add(note);
      sb.AppendLine("  " + note);
      DumpStrings(sb, fn, 0x300);
    }
    return r;
  }

  static bool Edx2Nearby(List<Ins> ins, int idx) {
    int lo = Math.Max(0, idx - 8), hi = Math.Min(ins.Count - 1, idx + 2);
    for (int i = lo; i <= hi; i++) {
      var a = ins[i];
      // mov edx, 2 / mov r8d,2 etc — check imm
      for (int oi = 0; oi < a.Raw.OpCount; oi++) {
        var k = a.Raw.GetOpKind(oi);
        if (k == OpKind.Immediate8 || k == OpKind.Immediate8to32 || k == OpKind.Immediate8to64
            || k == OpKind.Immediate32 || k == OpKind.Immediate64) {
          try {
            if (a.Raw.GetImmediate(oi) == 2) {
              // prefer if destination looks like edx/r8d (edx is 2nd arg)
              if (a.Text.IndexOf("edx", StringComparison.OrdinalIgnoreCase) >= 0
                  || a.Text.IndexOf("r8d", StringComparison.OrdinalIgnoreCase) >= 0
                  || a.Text.IndexOf("dx,", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
            }
          } catch { }
        }
      }
      if (a.Text.IndexOf("edx,2", StringComparison.OrdinalIgnoreCase) >= 0
          || a.Text.IndexOf("edx, 2", StringComparison.OrdinalIgnoreCase) >= 0)
        return true;
    }
    return false;
  }

  static List<Vcall2B0Hit> ScanVcall2B0(StringBuilder sb) {
    var hits = new List<Vcall2B0Hit>();
    // Scan code for displacement 0x2B0 used with call/jmp/mov patterns via Iced on chunks is expensive.
    // Byte-level: look for 83 /disp8=0xB0 unlikely; 0x2B0 as disp32 in ModRM forms.
    // Better: walk known interesting funcs + broad opcode scan for [reg+0x2B0].
    // Pattern bytes common: 48 8B 80/88/90/98 B0 02 00 00  (mov r64, [r64+0x2B0])
    // Also FF 90 B0 02 00 00 (call [rax+0x2B0]), FF A0 B0 02 00 00 (jmp [rax+0x2B0])
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 6 <= lim && hits.Count < 80; i++) {
        // call/jmp [reg+0x2B0]: FF /2 or /4 with modrm and disp32
        if (pe[s.Ptr + i] == 0xFF) {
          byte modrm = pe[s.Ptr + i + 1];
          int reg = (modrm >> 3) & 7;
          int mod = (modrm >> 6) & 3;
          if ((reg == 2 || reg == 4) && mod == 2 && i + 6 <= lim) {
            int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 2));
            if (disp == 0x2B0 || disp == -0x2B0) {
              uint site = s.Va + i;
              var h = MakeVcallHit(site);
              hits.Add(h);
              sb.AppendLine("  ff " + (reg == 2 ? "call" : "jmp") + " [reg+0x2B0] @0x"
                + site.ToString("X") + " func≈0x" + h.Func.ToString("X")
                + " edx2=" + h.Edx2Nearby);
            }
          }
        }
        // REX.W mov r64,[r64+0x2B0]: 48 8B modrm disp32
        if (i + 7 <= lim && pe[s.Ptr + i] == 0x48 && pe[s.Ptr + i + 1] == 0x8B) {
          byte modrm = pe[s.Ptr + i + 2];
          int mod = (modrm >> 6) & 3;
          if (mod == 2) {
            int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 3));
            if (disp == 0x2B0 || disp == -0x2B0) {
              uint site = s.Va + i;
              // only keep if followed soon by call/jmp rax-ish — always record, classify later
              var h = MakeVcallHit(site);
              // avoid dup if already have nearby
              if (!hits.Any(x => Math.Abs((long)x.Site - site) < 4)) {
                hits.Add(h);
                sb.AppendLine("  mov [reg+0x2B0] @0x" + site.ToString("X")
                  + " func≈0x" + h.Func.ToString("X") + " edx2=" + h.Edx2Nearby
                  + " " + Trunc(h.Context, 80));
              }
            }
          }
        }
      }
    }
    // Highlight arming-related
    foreach (var h in hits.Where(x =>
        x.Func == ArmingHelper || x.Func == NeighborA || x.Func == NeighborB || x.Edx2Nearby).Take(30))
      sb.AppendLine("  HIGHLIGHT @0x" + h.Site.ToString("X") + " func≈0x" + h.Func.ToString("X")
        + " edx2=" + h.Edx2Nearby);
    return hits;
  }

  static Vcall2B0Hit MakeVcallHit(uint site) {
    uint fn = FindFuncStart(site);
    var h = new Vcall2B0Hit { Site = site, Func = fn };
    // disasm small window for edx,2 and context
    uint start = site > 0x20 ? site - 0x20 : site;
    uint end = site + 0x30;
    var ins = Disasm(start, end);
    var sb = new StringBuilder();
    for (int i = 0; i < ins.Count; i++) {
      sb.Append(ins[i].Text).Append(" | ");
      if (ins[i].Rva <= site && (i + 1 >= ins.Count || ins[i + 1].Rva > site))
        h.Edx2Nearby = Edx2Nearby(ins, i);
    }
    // also check textually
    if (!h.Edx2Nearby && sb.ToString().IndexOf("edx,2", StringComparison.OrdinalIgnoreCase) >= 0)
      h.Edx2Nearby = true;
    h.Context = sb.ToString();
    return h;
  }

  // ---- writers ----
  static void WriteSlotsJson(string hash, List<SlotReport> slots) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.16\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"slots\": [");
    for (int i = 0; i < slots.Count; i++) {
      var s = slots[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"slot\": \"0x" + s.Slot.ToString("X") + "\",");
      sb.AppendLine("      \"pointsTo\": \"0x" + s.PointsTo.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(s.Role) + ",");
      sb.AppendLine("      \"notes\": [" + string.Join(", ", s.Notes.Select(J)) + "],");
      sb.AppendLine("      \"neighborQwords\": [" + string.Join(", ", s.NeighborQwords.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"hits\": [");
      for (int j = 0; j < Math.Min(s.Hits.Count, 40); j++) {
        var h = s.Hits[j];
        sb.Append("        { \"kind\": " + J(h.Kind) + ", \"site\": \"0x" + h.Site.ToString("X")
          + "\", \"func\": \"0x" + h.Func.ToString("X") + "\", \"sec\": " + J(h.Sec)
          + ", \"note\": " + J(h.Note) + " }");
        sb.AppendLine(j + 1 < Math.Min(s.Hits.Count, 40) ? "," : "");
      }
      sb.AppendLine("      ]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < slots.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.16-edata-consumers.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.16-edata-consumers.json");
  }

  static void WriteFuncsJson(string hash, List<FuncReport> funcs) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.16\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"funcs\": [");
    for (int i = 0; i < funcs.Count; i++) {
      var r = funcs[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + r.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(r.Role) + ",");
      sb.AppendLine("      \"size\": " + r.Size + ",");
      sb.AppendLine("      \"usesKey\": " + T(r.UsesKey) + ",");
      sb.AppendLine("      \"nested\": " + T(r.Nested) + ",");
      sb.AppendLine("      \"touches61\": " + T(r.Touches61) + ",");
      sb.AppendLine("      \"touches98\": " + T(r.Touches98) + ",");
      sb.AppendLine("      \"touches2B0\": " + T(r.Touches2B0) + ",");
      sb.AppendLine("      \"callsGateStub\": " + T(r.CallsGateStub) + ",");
      sb.AppendLine("      \"gateOps\": [" + string.Join(", ", r.GateOps.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"vcallNotes\": [" + string.Join(", ", r.VcallNotes.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"fieldNotes\": [" + string.Join(", ", r.FieldNotes.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"strings\": [" + string.Join(", ", r.Strings.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"callees\": [" + string.Join(", ", r.Callees.Take(20).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callersE8\": [" + string.Join(", ", r.CallersE8.Take(20).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"installHits\": [" + string.Join(", ", r.InstallHits.Take(16).Select(h =>
        "{ \"kind\": " + J(h.Kind) + ", \"site\": \"0x" + h.Site.ToString("X") + "\", \"sec\": " + J(h.Sec) + " }")) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", r.DisasmHead.Take(32).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < funcs.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.16-arming-neighbors.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.16-arming-neighbors.json");
  }

  static void WriteVcallJson(string hash, List<Vcall2B0Hit> vcalls) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.16\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"count\": " + vcalls.Count + ",");
    sb.AppendLine("  \"withEdx2\": " + vcalls.Count(v => v.Edx2Nearby) + ",");
    sb.AppendLine("  \"sites\": [");
    for (int i = 0; i < Math.Min(vcalls.Count, 60); i++) {
      var v = vcalls[i];
      sb.Append("    { \"site\": \"0x" + v.Site.ToString("X") + "\", \"func\": \"0x"
        + v.Func.ToString("X") + "\", \"edx2\": " + T(v.Edx2Nearby)
        + ", \"context\": " + J(Trunc(v.Context, 160)) + " }");
      sb.AppendLine(i + 1 < Math.Min(vcalls.Count, 60) ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.16-vcall-2b0.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.16-vcall-2b0.json");
  }

  static void WriteSummaryJson(string hash, List<SlotReport> slots, List<FuncReport> funcs, List<Vcall2B0Hit> vcalls) {
    var arm = funcs.First(f => f.Entry == ArmingHelper);
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.16\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"slotHitTotals\": {");
    for (int i = 0; i < slots.Count; i++) {
      sb.Append("    \"0x" + slots[i].Slot.ToString("X") + "\": " + slots[i].Hits.Count);
      sb.AppendLine(i + 1 < slots.Count ? "," : "");
    }
    sb.AppendLine("  },");
    sb.AppendLine("  \"armingHelperTouches2B0\": " + T(arm.Touches2B0) + ",");
    sb.AppendLine("  \"armingHelperCallsGateStub\": " + T(arm.CallsGateStub) + ",");
    sb.AppendLine("  \"vcall2B0Count\": " + vcalls.Count + ",");
    sb.AppendLine("  \"vcall2B0WithEdx2\": " + vcalls.Count(v => v.Edx2Nearby) + ",");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.16-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.16-summary.json");
  }

  static void WriteFeasibilityJson(string hash, List<SlotReport> slots, List<FuncReport> funcs, List<Vcall2B0Hit> vcalls) {
    int consumerHits = slots.Sum(s => s.Hits.Count(h =>
      h.Kind == "leaSlot" || h.Kind == "movRipSlot" || h.Kind == "nearBaseLea"));
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.16\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Still flag/arming/list helpers; no Edward factory\" },");
    sb.AppendLine("  \"edataConsumersFound\": { \"class\": "
      + (consumerHits > 0 ? "\"plausible\"" : "\"unsupported\"")
      + ", \"reason\": \"consumerHits=" + consumerHits + "\" },");
    sb.AppendLine("  \"vcall2B0Mapped\": { \"class\": "
      + (vcalls.Any(v => v.Edx2Nearby) ? "\"confirmed\"" : "\"plausible\"")
      + ", \"reason\": \"sites=" + vcalls.Count + " edx2=" + vcalls.Count(v => v.Edx2Nearby) + "\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Deep-decode hottest .edata consumers and edx=2 +0x2B0 call sites for subject type/vtable origin\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.16-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.16-second-edward-feasibility.json");
  }

  static string T(bool b) => b ? "true" : "false";
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }
  static bool IsNoise(uint d) => d == Lookup || d == Allocator || d < 0x10000;
  static string Tag(uint rva) {
    if (rva == GateStub) return " *** GATE_STUB ***";
    if (rva == GateSetter) return " *** GATESETTER ***";
    if (rva == WorkerB) return " *** WORKER_B ***";
    if (rva == BitWriter) return " *** BITWRITER ***";
    if (rva == Helper) return " *** HELPER ***";
    if (rva == Wrapper) return " *** WRAPPER ***";
    return "";
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

  static List<uint> FindMovFromRip(uint target, int max) {
    // specifically 8B / rip-relative that loads FROM target (same encoding as FindLeaTo for 8B)
    return FindLeaTo(target, max).Where(s => {
      int fo = RvaToFile(s);
      if (fo < 0) return false;
      // check opcode is 8B not 8D
      int off = 0;
      byte b0 = pe[fo];
      if (b0 == 0x48 || b0 == 0x4C || b0 == 0x49 || b0 == 0x4D) off = 1;
      return pe[fo + off] == 0x8B;
    }).ToList();
  }

  static List<uint> FindQwordAbs(uint destRva, int max) {
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

  static bool LooksLikeCode(uint rva) {
    foreach (var s in secs) {
      if (rva >= s.Va && rva < s.Va + Math.Max(s.VSize, s.Raw))
        return (s.Char & 0x20000000) != 0
          || s.Name.IndexOf("impdata", StringComparison.OrdinalIgnoreCase) >= 0
          || s.Name.IndexOf("code", StringComparison.OrdinalIgnoreCase) >= 0;
    }
    return false;
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

  static void DumpStrings(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEnd(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    var seen = new HashSet<string>();
    foreach (var a in Disasm(entry, end)) {
      if (!a.IpRel) continue;
      string s = ReadAscii(a.DataRva, 80);
      if (!IsString(s) || s.Length < 5) continue;
      if (seen.Add(s)) sb.AppendLine("    str \"" + Trunc(s, 70) + "\"");
      if (seen.Count >= 4) break;
    }
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
