// v0.8.0 — Offline: vtable written for the objects returned by
// 0x34730 (edx=0x1528) and 0x3DE6300 (edx=0x1530).
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
  const uint Allocator = 0x426EE50;
  const uint SchemaRegister = 0x4572C60;
  const uint NpcHash = 0x94D05600;
  const uint CopyHelper = 0x5E3DB0;

  static readonly uint[] AllocSites = { 0x34730, 0x3DE6300 };

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);

  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }
  sealed class Ins {
    public uint Rva; public string Text; public Mnemonic Mnemonic; public int Length;
    public bool IpRel; public uint DataRva; public bool IsCall, IsRet;
    public uint NearTarget; public bool HasImm; public ulong Imm;
    public string DestReg = ""; public string SrcReg = "";
    public string BaseReg = ""; public long Disp; public bool HasMem;
    public bool IsLea;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha256Hex(pe);
    Console.WriteLine("exeSha256=" + hash);
    if (!hash.Equals(ExpectedExeSha, StringComparison.OrdinalIgnoreCase)) {
      Console.Error.WriteLine("REFUSING: EXE hash mismatch.");
      return 2;
    }
    ParsePe();
    string rawDir = Path.Combine(root, "reports", "v080-vptr-raw");
    Directory.CreateDirectory(rawDir);

    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 ALLOC VPTR =====");
    sb.AppendLine("exeSha256=" + hash);
    var rows = new List<string>();
    foreach (uint site in AllocSites) {
      sb.AppendLine();
      sb.AppendLine("===== FUNC 0x" + site.ToString("X") + " =====");
      var insns = Disasm(site, site + 0x900);
      uint end = insns.Count == 0 ? site : insns[insns.Count - 1].Rva;
      sb.AppendLine("insns=" + insns.Count + " end=0x" + end.ToString("X"));
      var e8 = FindE8(site, 16);
      sb.AppendLine("directE8Callers=" + e8.Count);
      foreach (uint c in e8) {
        uint fs = FindFuncStart(c);
        sb.AppendLine("  callerSite=0x" + c.ToString("X") + " func=0x" + fs.ToString("X"));
        DumpWindow(sb, Disasm(c > 0x20 ? c - 0x20 : c, c + 0x40), "caller-window");
      }
      Trace(sb, rows, site, insns);
    }

    sb.AppendLine();
    sb.AppendLine("===== SPAWNNPC HASH 0x94D05600 =====");
    var hashSites = FindImm32(NpcHash, 24);
    sb.AppendLine("immSites=" + hashSites.Count);
    foreach (uint site in hashSites) {
      uint fs = FindFuncStart(site);
      sb.AppendLine("  imm=0x" + site.ToString("X") + " func=0x" + fs.ToString("X"));
      var body = Disasm(fs, fs + 0x180);
      foreach (var ins in body.Where(i => i.IpRel && i.DataRva != 0).Take(8)) {
        string s = ReadAscii(ins.DataRva, 80);
        if (IsString(s)) sb.AppendLine("    str 0x" + ins.Rva.ToString("X") + " " + Trunc(s, 72));
      }
      foreach (var ins in body.Where(i => i.IsCall && i.NearTarget != 0).Take(8))
        sb.AppendLine("    call 0x" + ins.NearTarget.ToString("X") + " @0x" + ins.Rva.ToString("X"));
    }

    sb.AppendLine();
    sb.AppendLine("===== SLOT METHODS =====");
    foreach (uint fn in new uint[] { 0x67C6A70, 0x8DFFB50, 0xCF5CC0, 0x8E00440, 0x671C1A0, 0x8E00400, 0xB0EFA0 }) {
      sb.AppendLine("-- 0x" + fn.ToString("X") + " --");
      var body = Disasm(fn, fn + 0x90);
      foreach (var ins in body.Take(16))
        sb.AppendLine("  0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 100));
      foreach (var ins in body.Where(i => i.IpRel && i.DataRva != 0)) {
        string s = ReadAscii(ins.DataRva, 80);
        if (IsString(s)) sb.AppendLine("  STR " + Trunc(s, 72));
      }
      foreach (var ins in body.Where(i => i.IsCall && i.NearTarget != 0).Take(6))
        sb.AppendLine("  CALL 0x" + ins.NearTarget.ToString("X"));
    }

    sb.AppendLine();
    sb.AppendLine("===== TYPE KEY BLOBS =====");
    foreach (uint blob in new uint[] { 0xC059DE0, 0xC05CF10, 0xC05AA10 })
      DumpBlob(sb, blob);
    sb.AppendLine("-- dtor body 0xCF5CF0 --");
    foreach (var ins in Disasm(0xCF5CF0, 0xCF5CF0 + 0x80).Take(20)) {
      sb.AppendLine("  0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 100));
      if (ins.IpRel && ins.DataRva != 0) {
        string s = ReadAscii(ins.DataRva, 72);
        if (IsString(s)) sb.AppendLine("  STR " + Trunc(s, 72));
      }
    }

    sb.AppendLine();
    sb.AppendLine("===== COPY HELPER 0x5E3DB0 =====");
    DecodeHelper(sb, CopyHelper);

    string text = sb.ToString();
    File.WriteAllText(Path.Combine(rawDir, "evidence.txt"), text);
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-alloc-vtables.txt"),
      string.Join(Environment.NewLine, rows) + Environment.NewLine);
    Console.WriteLine(text);
    Console.WriteLine("ROWS");
    foreach (string row in rows) Console.WriteLine(row);
    return rows.Count >= 2 ? 0 : 3;
  }

  static void Trace(StringBuilder sb, List<string> rows, uint site, List<Ins> insns) {
    int allocAt = insns.FindIndex(i => i.IsCall && i.NearTarget == Allocator);
    if (allocAt < 0) {
      sb.AppendLine("NO allocator call");
      rows.Add(site.ToString("X") + " | no-alloc-call | | | | | | low");
      return;
    }
    var sizeIns = insns.Take(allocAt).Reverse().FirstOrDefault(i =>
      i.Mnemonic == Mnemonic.Mov && i.HasImm && i.DestReg == "EDX");
    uint size = sizeIns == null ? 0 : (uint)sizeIns.Imm;
    sb.AppendLine("allocCall=0x" + insns[allocAt].Rva.ToString("X") + " edx=0x" + size.ToString("X"));

    var alias = new Dictionary<string, string>(StringComparer.Ordinal);
    alias["RCX"] = "this";
    var vptrs = new List<string>();
    uint vptrRva = 0;
    uint vptrStore = 0;
    string vptrBase = "";
    long vptrDisp = 0;
    uint embeddedStore = 0;
    long embeddedDisp = 0;
    string embeddedBase = "";
    var ctorCalls = new List<uint>();

    for (int i = 0; i < insns.Count; i++) {
      var ins = insns[i];
      if (i == allocAt) {
        alias["RAX"] = "alloc";
        foreach (string vol in new[] { "RCX", "RDX", "R8", "R9", "R10", "R11" })
          alias.Remove(vol);
        continue;
      }
      if (ins.Mnemonic == Mnemonic.Mov && ins.DestReg.Length > 0 && ins.SrcReg.Length > 0 && !ins.HasMem) {
        alias[ins.DestReg] = alias.TryGetValue(ins.SrcReg, out string src) ? src : "unk";
      } else if (ins.IsLea && ins.IpRel && ins.DestReg.Length > 0) {
        alias[ins.DestReg] = "ptr:" + ins.DataRva.ToString("X");
      } else if (ins.Mnemonic == Mnemonic.Mov && ins.HasMem && ins.DestReg.Length == 0 && ins.SrcReg.Length > 0) {
        string src = alias.TryGetValue(ins.SrcReg, out string s) ? s : "";
        string dst = alias.TryGetValue(ins.BaseReg, out string d) ? d : ins.BaseReg;
        if (src.StartsWith("ptr:", StringComparison.Ordinal) && (dst == "alloc" || dst == "this")
            && !IsCode(ParsePtr(src))) {
          uint vt = ParsePtr(src);
          vptrs.Add("0x" + ins.Rva.ToString("X") + " base=" + dst + "+0x" + ins.Disp.ToString("X")
            + " vt=0x" + vt.ToString("X"));
          vptrRva = vt;
          vptrStore = ins.Rva;
          vptrBase = dst;
          vptrDisp = ins.Disp;
          sb.AppendLine("VPTR write @0x" + ins.Rva.ToString("X")
            + " base=" + dst + " disp=0x" + ins.Disp.ToString("X")
            + " vt=0x" + vt.ToString("X")
            + " src=" + ins.Text);
        }
        if (src == "alloc" && dst == "this") {
          embeddedStore = ins.Rva;
          embeddedDisp = ins.Disp;
          embeddedBase = dst;
          sb.AppendLine("ALLOC stored into this @0x" + ins.Rva.ToString("X")
            + " disp=0x" + ins.Disp.ToString("X") + " " + ins.Text);
        }
      } else if (ins.IsCall && ins.NearTarget != 0 && i > allocAt) {
        string rcx = alias.TryGetValue("RCX", out string c) ? c : "";
        if (rcx == "alloc" || rcx.StartsWith("ptr:", StringComparison.Ordinal)) {
          ctorCalls.Add(ins.NearTarget);
          sb.AppendLine("CALL on " + rcx + " -> 0x" + ins.NearTarget.ToString("X") + " @0x" + ins.Rva.ToString("X"));
        }
        foreach (string vol in new[] { "RAX", "RCX", "RDX", "R8", "R9", "R10", "R11" })
          alias.Remove(vol);
      }
      if (i >= allocAt && i <= allocAt + 80)
        sb.AppendLine("  0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 100));
    }

    if (vptrRva == 0) {
      foreach (uint ctor in ctorCalls.Take(3)) {
        sb.AppendLine("-- follow ctor 0x" + ctor.ToString("X") + " --");
        var inner = Disasm(ctor, ctor + 0x200);
        DumpWindow(sb, inner.Take(40).ToList(), "ctor");
        var hit = FirstVptr(inner);
        if (hit != null && vptrRva == 0) {
          vptrRva = hit.Value.vt;
          vptrStore = hit.Value.at;
          vptrBase = "ctor-rcx";
          vptrDisp = hit.Value.disp;
          sb.AppendLine("CTOR VPTR vt=0x" + vptrRva.ToString("X") + " @0x" + vptrStore.ToString("X"));
        }
      }
    }

    sb.AppendLine("VPTR sequence: " + (vptrs.Count == 0 ? "none" : string.Join(" ; ", vptrs)));
    sb.AppendLine("-- embedded +0x20 ctor 0xB0EFA0 --");
    var emb = Disasm(0xB0EFA0, 0xB0EFA0 + 0x80);
    var embHit = FirstVptr(emb);
    if (embHit != null)
      sb.AppendLine("embedded vptr @0x" + embHit.Value.at.ToString("X")
        + " disp=0x" + embHit.Value.disp.ToString("X")
        + " vt=0x" + embHit.Value.vt.ToString("X"));
    else
      sb.AppendLine("embedded vptr not in head");
    foreach (var ins in emb.Take(18))
      sb.AppendLine("  0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 100));

    string rtti = "none";
    string typeName = "";
    var slotNotes = new List<string>();
    var seen = new HashSet<uint>();
    foreach (string item in vptrs) {
      int mark = item.LastIndexOf("vt=0x", StringComparison.Ordinal);
      if (mark < 0) continue;
      uint vt = uint.Parse(item.Substring(mark + 5), System.Globalization.NumberStyles.HexNumber);
      if (!seen.Add(vt)) continue;
      rtti = ReadRtti(sb, vt, out typeName);
      DescribeSlots(sb, vt, slotNotes);
    }
    if (embHit != null && seen.Add(embHit.Value.vt)) {
      sb.AppendLine("-- embedded table --");
      rtti = ReadRtti(sb, embHit.Value.vt, out typeName);
      DescribeSlots(sb, embHit.Value.vt, slotNotes);
    }
    bool character = IsCharacterName(typeName) || slotNotes.Any(n => n.StartsWith("IDENTITY", StringComparison.Ordinal));
    string klass = vptrRva == 0 ? "vptr-not-found" : (character ? "character-or-actor" : "not-character");
    string owner = vptrBase == "alloc" && vptrDisp == 0 ? "allocation-owns-vptr"
      : vptrBase == "this" ? "outer-object-owns-vptr"
      : vptrDisp != 0 ? "embedded-disp-0x" + vptrDisp.ToString("X")
      : vptrBase.Length == 0 ? "unknown" : vptrBase;
    if (embeddedStore != 0 && vptrBase != "alloc")
      owner += "; alloc-stored-at-this+0x" + embeddedDisp.ToString("X");
    sb.AppendLine("CLASS " + klass + " owner=" + owner + " rtti=" + rtti + " name=" + typeName);

    rows.Add(string.Join(" | ", new[] {
      "0x" + site.ToString("X") + " edx=0x" + size.ToString("X"),
      embeddedStore != 0 ? "stored this+0x" + embeddedDisp.ToString("X") : "return/local",
      vptrStore == 0 ? "none" : "0x" + vptrStore.ToString("X") + " " + owner,
      vptrRva == 0 ? "none" : "0x" + vptrRva.ToString("X") + " rtti=" + rtti,
      typeName.Length == 0 ? klass : typeName,
      ctorCalls.Count == 0 ? "none" : string.Join(",", ctorCalls.Take(4).Select(c => "0x" + c.ToString("X"))),
      character ? "confirmed-character" : "not-a-character"
    }));
  }

  static (uint vt, uint at, long disp)? FirstVptr(List<Ins> insns) {
    var alias = new Dictionary<string, string>(StringComparer.Ordinal);
    alias["RCX"] = "this";
    foreach (var ins in insns) {
      if (ins.IsLea && ins.IpRel && ins.DestReg.Length > 0)
        alias[ins.DestReg] = "ptr:" + ins.DataRva.ToString("X");
      else if (ins.Mnemonic == Mnemonic.Mov && ins.DestReg.Length > 0 && ins.SrcReg.Length > 0 && !ins.HasMem)
        alias[ins.DestReg] = alias.TryGetValue(ins.SrcReg, out string src) ? src : "unk";
      else if (ins.Mnemonic == Mnemonic.Mov && ins.HasMem && ins.SrcReg.Length > 0) {
        string src = alias.TryGetValue(ins.SrcReg, out string s) ? s : "";
        if (src.StartsWith("ptr:", StringComparison.Ordinal) && !IsCode(ParsePtr(src)) && ins.Disp >= 0 && ins.Disp < 0x40)
          return (ParsePtr(src), ins.Rva, ins.Disp);
      }
    }
    return null;
  }

  static void DescribeSlots(StringBuilder sb, uint vt, List<string> notes) {
    sb.AppendLine("SLOTS vt=0x" + vt.ToString("X"));
    for (int i = 0; i < 16; i++) {
      uint ptr = ReadQwordRva(vt + (uint)(i * 8));
      if (!IsCode(ptr)) {
        sb.AppendLine("  [" + i + "] 0x" + ptr.ToString("X") + " not-code");
        break;
      }
      var head = Disasm(ptr, ptr + 0x80);
      var strings = new List<string>();
      foreach (var ins in head) {
        if (!ins.IpRel || ins.DataRva == 0) continue;
        string s = ReadAscii(ins.DataRva, 72);
        if (IsString(s)) strings.Add(s);
      }
      string flag = "";
      foreach (string s in strings) {
        if (IsCharacterName(s)) {
          flag = " IDENTITY " + Trunc(s, 48);
          notes.Add("IDENTITY slot" + i + " " + s);
          break;
        }
      }
      bool schema = head.Any(h => h.IsCall && h.NearTarget == SchemaRegister);
      sb.AppendLine("  [" + i + "] 0x" + ptr.ToString("X")
        + (schema ? " schema" : "")
        + (strings.Count == 0 ? "" : " str=" + Trunc(strings[0], 48))
        + flag);
    }
  }

  static string ReadRtti(StringBuilder sb, uint vt, out string name) {
    name = "";
    int rawFo = RvaToFile(vt - 8);
    ulong rawQ = rawFo >= 0 && rawFo + 8 <= pe.Length ? BitConverter.ToUInt64(pe, rawFo) : 0;
    sb.AppendLine("vt-8 raw=0x" + rawQ.ToString("X") + " sec=" + SecName(vt));
    uint colCandidate = ReadQwordRva(vt - 8);
    if (colCandidate == 0) return "no-col";
    int fo = RvaToFile(colCandidate);
    if (fo < 0 || fo + 0x18 > pe.Length) return "col-unreadable";
    uint sig = BitConverter.ToUInt32(pe, fo);
    sb.AppendLine("colSig=" + sig);
    if (sig != 1 && sig != 0) return "not-msvc-col";
    uint typeRva = BitConverter.ToUInt32(pe, fo + 0x0C);
    int tfo = RvaToFile(typeRva);
    if (tfo < 0) return "type-unreadable";
    name = ReadAscii((uint)(typeRva + 0x10), 96);
    if (!name.StartsWith(".?A", StringComparison.Ordinal)) {
      name = ReadAscii((uint)(typeRva + 0x14), 96);
    }
    sb.AppendLine("rttiName=" + name);
    if (!name.StartsWith(".?A", StringComparison.Ordinal)) {
      name = "";
      return "col-without-name";
    }
    return "msvc";
  }

  static void DumpBlob(StringBuilder sb, uint rva) {
    sb.AppendLine("-- blob 0x" + rva.ToString("X") + " sec=" + SecName(rva) + " --");
    int fo = RvaToFile(rva);
    if (fo < 0) { sb.AppendLine("  unreadable"); return; }
    for (int i = 0; i < 8; i++) {
      if (fo + i * 8 + 8 > pe.Length) break;
      ulong q = BitConverter.ToUInt64(pe, fo + i * 8);
      string extra = "";
      if (q >= imageBase) {
        uint rr = (uint)(q - imageBase);
        string s = ReadAscii(rr, 64);
        if (IsString(s)) extra = " str=" + Trunc(s, 60);
        else extra = " rva=0x" + rr.ToString("X") + " sec=" + SecName(rr);
      }
      sb.AppendLine("  +" + (i * 8).ToString("X") + " 0x" + q.ToString("X") + extra);
    }
    string inline = ReadAscii(rva, 48);
    if (IsString(inline)) sb.AppendLine("  inline=" + Trunc(inline, 48));
  }

  static void DecodeHelper(StringBuilder sb, uint entry) {
    var insns = Disasm(entry, entry + 0x120);
    sb.AppendLine("insns=" + insns.Count);
    foreach (var ins in insns.Take(40))
      sb.AppendLine("  0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 100));
    var calls = insns.Where(i => i.IsCall && i.NearTarget != 0).Select(i => i.NearTarget).Distinct().ToList();
    sb.AppendLine("callees=" + string.Join(",", calls.Select(c => "0x" + c.ToString("X"))));
    var e8 = FindE8(entry, 12);
    sb.AppendLine("directE8=" + e8.Count);
    foreach (uint site in e8.Take(8))
      sb.AppendLine("  site=0x" + site.ToString("X") + " func=0x" + FindFuncStart(site).ToString("X"));
    var q = FindQword(entry, 8);
    sb.AppendLine("qwordEmbeds=" + q.Count);
    foreach (uint slot in q)
      sb.AppendLine("  slot=0x" + slot.ToString("X") + " sec=" + SecName(slot));
    sb.AppendLine("-- 0x5E3DF0 --");
    foreach (var ins in Disasm(0x5E3DF0, 0x5E3DF0 + 0x60).Take(24))
      sb.AppendLine("  0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 100));
  }

  static List<uint> FindQword(uint rva, int max) {
    var list = new List<uint>();
    ulong va = imageBase + rva;
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0 || (s.Char & 0x20000000) != 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 8 <= lim && list.Count < max; i += 8) {
        if (BitConverter.ToUInt64(pe, (int)(s.Ptr + i)) == va) list.Add(s.Va + i);
      }
    }
    return list;
  }

  static void DumpWindow(StringBuilder sb, List<Ins> insns, string tag) {
    sb.AppendLine("-- " + tag + " --");
    foreach (var ins in insns.Take(24))
      sb.AppendLine("  0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 100));
  }

  static bool IsCharacterName(string s) {
    if (string.IsNullOrEmpty(s)) return false;
    string[] keys = { "Character", "Actor", "Edward", "NPC", "SpawnNPC", "Player" };
    foreach (string k in keys)
      if (s.IndexOf(k, StringComparison.Ordinal) >= 0) return true;
    return false;
  }

  static uint ParsePtr(string src) {
    int c = src.IndexOf(':');
    if (c < 0) return 0;
    return uint.Parse(src.Substring(c + 1), System.Globalization.NumberStyles.HexNumber);
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
    while (dec.IP < limit && guard++ < 2500) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      if (raw.IP < imageBase) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      var ins = new Ins {
        Rva = (uint)(raw.IP - imageBase), Text = o.ToString(),
        Mnemonic = raw.Mnemonic, Length = raw.Length,
        IsCall = raw.FlowControl == FlowControl.Call,
        IsRet = raw.Mnemonic == Mnemonic.Ret,
        IsLea = raw.Mnemonic == Mnemonic.Lea
      };
      if (ins.IsCall && raw.NearBranchTarget >= imageBase)
        ins.NearTarget = (uint)(raw.NearBranchTarget - imageBase);
      if (raw.OpCount > 0 && raw.GetOpKind(0) == OpKind.Register)
        ins.DestReg = raw.GetOpRegister(0).ToString().ToUpperInvariant();
      if (raw.OpCount > 1 && raw.GetOpKind(1) == OpKind.Register)
        ins.SrcReg = raw.GetOpRegister(1).ToString().ToUpperInvariant();
      for (int oi = 0; oi < raw.OpCount; oi++) {
        var kind = raw.GetOpKind(oi);
        if (kind == OpKind.Immediate8 || kind == OpKind.Immediate8to32 || kind == OpKind.Immediate32
            || kind == OpKind.Immediate32to64 || kind == OpKind.Immediate64 || kind == OpKind.Immediate8to64
            || kind == OpKind.Immediate16 || kind == OpKind.Immediate8to16) {
          ins.HasImm = true;
          try { ins.Imm = raw.GetImmediate(oi); } catch { }
        }
        if (kind != OpKind.Memory) continue;
        ins.HasMem = true;
        ins.BaseReg = raw.MemoryBase.ToString().ToUpperInvariant();
        int sz = raw.MemoryDisplSize;
        if (sz == 1) ins.Disp = unchecked((sbyte)raw.MemoryDisplacement32);
        else if (sz == 2) ins.Disp = unchecked((short)raw.MemoryDisplacement32);
        else if (sz == 4) ins.Disp = unchecked((int)raw.MemoryDisplacement32);
        else if (sz == 8) ins.Disp = unchecked((long)raw.MemoryDisplacement64);
        if (raw.IsIPRelativeMemoryOperand) {
          ins.IpRel = true;
          ulong va = raw.IPRelativeMemoryAddress;
          if (va >= imageBase) ins.DataRva = (uint)(va - imageBase);
        }
      }
      list.Add(ins);
      if (ins.Mnemonic == Mnemonic.Int3) break;
      if (ins.IsRet) {
        uint next = ins.Rva + (uint)ins.Length;
        int nfo = RvaToFile(next);
        if (nfo >= 0 && nfo < pe.Length && pe[nfo] == 0xCC) break;
      }
    }
    return list;
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

  static List<uint> FindImm32(uint imm, int max) {
    var list = new List<uint>();
    byte[] pat = BitConverter.GetBytes(imm);
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      int from = (int)s.Ptr;
      int end = from + (int)lim;
      int guard = 0;
      while (from < end && list.Count < max && guard++ < 32) {
        int at = pe.AsSpan(from, end - from).IndexOf(pat);
        if (at < 0) break;
        list.Add(s.Va + (uint)(from - s.Ptr + at));
        from = from + at + 4;
      }
    }
    return list;
  }

  static uint FindFuncStart(uint site) {
    int fo = RvaToFile(site);
    if (fo < 0) return 0;
    int back = Math.Min(fo, 0x4000);
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

  static string SecName(uint rva) {
    foreach (var s in secs)
      if (rva >= s.Va && rva < s.Va + Math.Max(s.VSize, s.Raw)) return s.Name;
    return "?";
  }

  static bool IsCode(uint rva) {
    if (rva < 0x10000) return false;
    foreach (var s in CodeSecs()) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva >= s.Va && rva < s.Va + span) return true;
    }
    return false;
  }

  static IEnumerable<Sec> CodeSecs() {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      if ((s.Char & 0x20000000) != 0) yield return s;
    }
  }

  static uint ReadQwordRva(uint rva) {
    int fo = RvaToFile(rva);
    if (fo < 0 || fo + 8 > pe.Length) return 0;
    ulong va = BitConverter.ToUInt64(pe, fo);
    if (va < imageBase) return 0;
    ulong r = va - imageBase;
    return r > uint.MaxValue ? 0 : (uint)r;
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

  static string Trunc(string s, int n) => s == null ? "" : (s.Length <= n ? s : s.Substring(0, n));

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
    if (BitConverter.ToUInt16(pe, e + 24) != 0x20B) throw new InvalidOperationException("Expected PE32+");
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
