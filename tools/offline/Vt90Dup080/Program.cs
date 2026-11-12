// v0.8.0 — Focus call [reg+0x90] with last-def (0,0); require unbroken
// mov RET,rax ... mov r8,RET (no intervening write to RET) before Build(lea rdx).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;

internal static class Program {
  const string Expected = "19920F34BB2FAC814023EE3C27F0CECA1872E80A2AAFB37C092C419FFF77CC0D";
  const int VtOff = 0x90;
  static byte[] pe; static ulong ib; static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(new FormatterOptions { RipRelativeAddresses = true }, null, null);
  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }
  sealed class Hit {
    public uint dup, build, buildCal, begin, end, func; public string retReg; public bool begin10, endFree;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha(pe);
    if (!hash.Equals(Expected, StringComparison.OrdinalIgnoreCase)) { Console.Error.WriteLine("hash mismatch"); return 2; }
    Parse();
    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 vt+0x90 Dup → unbroken r8 → Build =====");
    sb.AppendLine("exeSha256=" + hash);

    Console.WriteLine("Scanning call [reg+0x90] with Dup(0,0)...");
    int vt90 = 0, withRet = 0;
    var hits = new List<Hit>();
    var samples = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      uint i = 0;
      while (i + 8 < lim) {
        int fo = (int)(s.Ptr + i);
        var reader = new ByteArrayCodeReader(pe); reader.Position = fo;
        var dec = Decoder.Create(64, reader); dec.IP = ib + s.Va + i;
        var raw = dec.Decode();
        if (raw.Length == 0 || raw.Code == Code.INVALID) { i++; continue; }
        uint site = (uint)(raw.IP - ib);
        if (raw.Mnemonic == Mnemonic.Call && raw.IsCallNearIndirect) {
          int off = MemDisp(raw);
          if (off == VtOff && LastDefDup00(site)) {
            vt90++;
            if (samples.Count < 12) samples.Add(site);
            var h = FollowStrict(site);
            if (h != null) {
              withRet++;
              hits.Add(h);
            }
          }
        }
        i += (uint)Math.Max(1, raw.Length);
      }
    }
    sb.AppendLine("vt90Dup00=" + vt90);
    sb.AppendLine("unbrokenRetToBuild=" + hits.Count);

    sb.AppendLine();
    sb.AppendLine("===== SAMPLE vt+0x90 (0,0) SITES =====");
    foreach (var site in samples) {
      sb.AppendLine("site=0x" + site.ToString("X") + " func=0x" + FuncStart(site).ToString("X"));
      Dump(sb, site, 0x20, 0x60, "sample");
    }

    sb.AppendLine();
    sb.AppendLine("===== UNBROKEN RET→BUILD HITS =====");
    foreach (var h in hits.Take(30)) {
      sb.AppendLine("func=0x" + h.func.ToString("X") + " dup=0x" + h.dup.ToString("X")
        + " ret=" + h.retReg + " build=0x" + h.build.ToString("X") + "->0x" + h.buildCal.ToString("X")
        + " begin=" + Hx(h.begin) + " end=" + Hx(h.end)
        + " begin10=" + h.begin10 + " endFree=" + h.endFree);
      Dump(sb, h.dup, 0x40, 0xA0, "hit");
    }

    int withB = hits.Count(h => h.begin10);
    int full = hits.Count(h => h.begin10 && h.endFree);
    sb.AppendLine("withBegin10=" + withB + " withBeginEnd=" + full);

    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    sb.AppendLine("c2Proven=false");
    sb.AppendLine("callEngine=off");
    if (full > 0) {
      sb.AppendLine("decision=vt+0x90 Duplicate→Build with Begin/End — triad candidates unproven");
      sb.AppendLine("next=Identify Begin/End/Build callees; prove selector/builder; C1 cache.");
    } else if (hits.Count > 0) {
      sb.AppendLine("decision=vt+0x90 unbroken return→Build exists; Begin/End not freestanding-(1,0)");
      sb.AppendLine("next=At hits, find scope arm (TLS/Begin) another way; confirm Build is EntityBuilder.");
    } else if (vt90 > 0) {
      sb.AppendLine("decision=vt+0x90 (0,0) sites exist but no unbroken rax→r8→Build chain");
      sb.AppendLine("next=Allow ret in rcx passed differently; or Build uses [rsp] out without r8=dup.");
    } else {
      sb.AppendLine("decision=no vt+0x90 with Dup(0,0) under last-def filter");
      sb.AppendLine("next=Widen disp match; check [rax+90h] encoding variants.");
    }

    string dir = Path.Combine(root, "reports", "v080-vt90-raw");
    Directory.CreateDirectory(dir);
    File.WriteAllText(Path.Combine(dir, "evidence.txt"), sb.ToString());
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-vt90-dup.json"),
      "{\n  \"schemaVersion\": 1,\n  \"vt90Dup00\": " + vt90 + ",\n  \"unbrokenRetToBuild\": " + hits.Count + ",\n" +
      "  \"withBegin10\": " + withB + ",\n  \"withBeginEnd\": " + full + ",\n" +
      "  \"c2Proven\": false,\n  \"callEngine\": false\n}\n");
    Console.WriteLine(string.Join("\n", sb.ToString().Split('\n').Take(45)));
    Console.WriteLine("WROTE reports/v080-vt90-raw/evidence.txt");
    return 0;
  }

  static Hit FollowStrict(uint dupSite) {
    // Find first mov RET,rax (allow test/jcc before)
    string ret = null;
    uint build = 0, buildCal = 0;
    var after = Disasm(dupSite + 2, dupSite + 0xC0);
    int idx = 0;
    for (; idx < after.Count; idx++) {
      var ins = after[idx];
      string t = Norm(ins.text);
      if (ret == null) {
        if (IsMovFromRax(t, out ret)) continue;
        if (t.StartsWith("testrax") || t.StartsWith("orrax,rax") || t.StartsWith("je") || t.StartsWith("jne")
            || t.StartsWith("jz") || t.StartsWith("jnz") || t.StartsWith("nop") || t.StartsWith("movzx")
            || t.StartsWith("sete") || t.StartsWith("setne")) continue;
        if (ins.isCall || ins.mnem == Mnemonic.Ret) return null;
        // unknown — abort
        if (t.StartsWith("mov") && t.Contains(",rax")) { IsMovFromRax(t, out ret); if (ret != null) continue; }
        return null;
      }
      break;
    }
    if (ret == null) return null;

    // From capture point, track last def of ret; find Build where last def of r8 is ret and lea rdx
    string lastR8 = null;
    bool retKilled = false;
    for (; idx < after.Count; idx++) {
      var ins = after[idx];
      string t = Norm(ins.text);
      // kill ret if written (except mov ret,rax again)
      if (IsWriteTo(t, ret) && !IsMovFromRaxTo(t, ret)) { retKilled = true; }
      if (t.StartsWith("movr8,") || t.StartsWith("movr8d,") || t.StartsWith("lear8,")) lastR8 = t;
      if (ins.isCall) {
        if (!retKilled && lastR8 != null && (lastR8 == "movr8," + ret || lastR8 == "movr8d," + ret)
            && LooksBuildLea(ins.rva)) {
          build = ins.rva; buildCal = ins.target; break;
        }
        // calls may clobber — if call before build match, conservative kill unless leaf
        if (build == 0 && ins.rva > dupSite + 8) {
          // don't immediately fail; only fail if ret written
        }
      }
      if (ins.mnem == Mnemonic.Ret || ins.mnem == Mnemonic.Int3) break;
    }
    if (build == 0) return null;

    var h = new Hit { dup = dupSite, build = build, buildCal = buildCal, retReg = ret, func = FuncStart(dupSite) };
    var back = Disasm(dupSite > 0x80 ? dupSite - 0x80 : 0, dupSite);
    for (int i = back.Count - 1; i >= 0; i--) {
      if (!back[i].isCall) continue;
      if (LastDefIs(back[i].rva, "ecx", 1) && LastDefIs(back[i].rva, "edx", 0) && !LastRcxThis(back[i].rva)) {
        h.begin = back[i].rva; h.begin10 = true; break;
      }
    }
    foreach (var ins in Disasm(dupSite + 5, build + 0x40)) {
      if (!ins.isCall || ins.rva == build) continue;
      if (LooksEnd(ins.rva)) { h.end = ins.rva; h.endFree = true; break; }
    }
    return h;
  }

  static bool IsMovFromRax(string t, out string dest) {
    dest = null;
    // movREG,rax
    string[] regs = { "rcx","rbx","rsi","rdi","rbp","r8","r9","r10","r11","r12","r13","r14","r15","eax","rax" };
    foreach (var r in regs) {
      if (t == "mov" + r + ",rax") { dest = r == "eax" ? "rax" : r; return true; }
    }
    return false;
  }
  static bool IsMovFromRaxTo(string t, string ret) => t == "mov" + ret + ",rax";
  static bool IsWriteTo(string t, string reg) {
    // crude: starts with movREG, or leaREG, or xorREG,REG
    if (t.StartsWith("mov" + reg + ",") || t.StartsWith("lea" + reg + ",") || t.StartsWith("xor" + reg + ",")
        || t.StartsWith("or" + reg + ",") || t.StartsWith("and" + reg + ",") || t.StartsWith("add" + reg + ",")
        || t.StartsWith("sub" + reg + ",") || t.StartsWith("pop" + reg)) return true;
    return false;
  }
  static bool LooksBuildLea(uint callSite) {
    bool lea = false, rcx = false;
    foreach (var ins in Disasm(callSite > 0x40 ? callSite - 0x40 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("leardx,[rsp") || t.StartsWith("leardx,[rbp")) lea = true;
      if (t.StartsWith("movrcx,")) rcx = true;
    }
    return lea && rcx;
  }

  static int MemDisp(Instruction raw) {
    try {
      if (raw.MemoryBase != Register.None || raw.MemoryIndex != Register.None)
        return (int)raw.MemoryDisplacement64;
    } catch { }
    // text fallback
    string t = "";
    var o = new StringOutput(); Fmt.Format(raw, o); t = o.ToString().ToLowerInvariant();
    int p = t.IndexOf("+90h]"); if (p > 0) return 0x90;
    p = t.IndexOf("+90]"); if (p > 0) return 0x90;
    return -1;
  }

  static bool LastDefDup00(uint callSite) {
    string lastEdx = null, lastR8 = null; bool hasRcx = false;
    foreach (var ins in Disasm(callSite > 0x30 ? callSite - 0x30 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("movedx,") || t.StartsWith("movdl,") || t.StartsWith("xoredx,edx") || t.StartsWith("movrdx,") || t.StartsWith("xorrdx,rdx")) lastEdx = t;
      if (t.StartsWith("movr8") || t.StartsWith("xorr8") || t.StartsWith("lear8")) lastR8 = t;
      if (t.StartsWith("movrcx,") || t.StartsWith("learcx,")) hasRcx = true;
    }
    if (!hasRcx || lastEdx == null || lastR8 == null) return false;
    if (lastEdx.Contains(",1") || lastR8.Contains(",1")) return false;
    return (lastEdx.Contains("xor") || lastEdx.EndsWith(",0")) && (lastR8.Contains("xor") || lastR8.EndsWith(",0"));
  }
  static bool LooksEnd(uint callSite) {
    foreach (var ins in Disasm(callSite > 0x14 ? callSite - 0x14 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("movrcx,") || t.StartsWith("movecx,") || t.StartsWith("movcl,") || t.StartsWith("learcx,")) return false;
      if (t.StartsWith("movedx,") || t.StartsWith("movr8")) return false;
    }
    return true;
  }
  static bool LastDefIs(uint callSite, string reg, int want) {
    string last = null;
    foreach (var ins in Disasm(callSite > 0x30 ? callSite - 0x30 : 0, callSite)) {
      string t = Norm(ins.text);
      if (reg == "ecx" && (t.StartsWith("movecx,") || t.StartsWith("movcl,") || t.StartsWith("xorecx,ecx") || t.StartsWith("movrcx,") || t.StartsWith("learcx,"))) last = t;
      if (reg == "edx" && (t.StartsWith("movedx,") || t.StartsWith("movdl,") || t.StartsWith("xoredx,edx") || t.StartsWith("movrdx,") || t.StartsWith("xorrdx,rdx"))) last = t;
    }
    if (last == null) return false;
    if (want == 0) return last.Contains("xor") || last.EndsWith(",0");
    return last.EndsWith(",1");
  }
  static bool LastRcxThis(uint callSite) {
    string last = null;
    foreach (var ins in Disasm(callSite > 0x28 ? callSite - 0x28 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("movrcx,") || t.StartsWith("learcx,") || t.StartsWith("movecx,") || t.StartsWith("movcl,")) last = t;
    }
    if (last == null) return false;
    return !(last == "movecx,1" || last == "movcl,1" || last == "movrcx,1");
  }

  static string Hx(uint v) => v == 0 ? "0" : "0x" + v.ToString("X");
  static string Norm(string s) => s.Replace(" ", "").Replace("ptr", "").ToLowerInvariant();
  struct Ins { public uint rva, target; public string text; public Mnemonic mnem; public bool isCall; }
  static List<Ins> Disasm(uint start, uint endEx) {
    var list = new List<Ins>();
    int fo = RvaToFile(start); if (fo < 0) return list;
    var reader = new ByteArrayCodeReader(pe); reader.Position = fo;
    var dec = Decoder.Create(64, reader); dec.IP = ib + start;
    ulong lim = ib + endEx; int g = 0;
    while (dec.IP < lim && g++ < 700) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      var o = new StringOutput(); Fmt.Format(raw, o);
      var ins = new Ins { rva = (uint)(raw.IP - ib), text = o.ToString(), mnem = raw.Mnemonic };
      if (raw.FlowControl == FlowControl.Call) {
        if (raw.NearBranchTarget != 0 && raw.NearBranchTarget >= ib) { ins.isCall = true; ins.target = (uint)(raw.NearBranchTarget - ib); }
        else if (raw.IsCallNearIndirect) ins.isCall = true;
      }
      list.Add(ins);
      if (ins.mnem == Mnemonic.Int3) break;
    }
    return list;
  }
  static void Dump(StringBuilder sb, uint center, int before, int after, string label) {
    uint start = center > (uint)before ? center - (uint)before : center;
    sb.AppendLine("--- " + label + " @0x" + center.ToString("X") + " ---");
    foreach (var ins in Disasm(start, center + (uint)after).Take(36)) {
      string ex = ins.isCall ? (ins.target != 0 ? "  ;call=0x" + ins.target.ToString("X") : "  ;call=mem") : "";
      sb.AppendLine("0x" + ins.rva.ToString("X") + " " + Trunc(ins.text, 100) + ex);
    }
  }
  static IEnumerable<Sec> CodeSecs() {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      if ((s.Char & 0x20000000) != 0 || s.Name.Contains("impdata") || s.Name.Contains("code")) yield return s;
    }
  }
  static uint FuncStart(uint site) {
    int fo = RvaToFile(site); if (fo < 0) return 0;
    int back = Math.Min(fo, 0x2000), pad = -1;
    for (int i = 1; i < back; i++) if (pe[fo - i] == 0xCC && i + 1 < back && pe[fo - i - 1] == 0xCC) { pad = i; break; }
    if (pad < 0) return site > 0x20 ? site - 0x20 : site;
    uint rva = site - (uint)pad; int p = RvaToFile(rva);
    while (p >= 0 && p < pe.Length && pe[p] == 0xCC) { rva++; p++; }
    return rva;
  }
  static string Trunc(string s, int n) => s.Length <= n ? s : s.Substring(0, n);
  static int RvaToFile(uint rva) {
    foreach (var s in secs) { uint sp = Math.Max(s.VSize, s.Raw); if (rva >= s.Va && rva < s.Va + sp && s.Ptr > 0) return (int)s.Ptr + (int)(rva - s.Va); }
    return -1;
  }
  static void Parse() {
    int e = BitConverter.ToInt32(pe, 0x3C); ib = BitConverter.ToUInt64(pe, e + 48);
    ushort n = BitConverter.ToUInt16(pe, e + 6), o = BitConverter.ToUInt16(pe, e + 20);
    int sec = e + 24 + o; secs = new List<Sec>();
    for (int i = 0; i < n; i++) {
      int p = sec + i * 40;
      secs.Add(new Sec {
        Name = Encoding.ASCII.GetString(pe, p, 8).TrimEnd('\0'),
        VSize = BitConverter.ToUInt32(pe, p + 8), Va = BitConverter.ToUInt32(pe, p + 12),
        Raw = BitConverter.ToUInt32(pe, p + 16), Ptr = BitConverter.ToUInt32(pe, p + 20),
        Char = BitConverter.ToUInt32(pe, p + 36)
      });
    }
  }
  static string Sha(byte[] d) { using (var s = SHA256.Create()) { var h = s.ComputeHash(d); var sb = new StringBuilder(); foreach (byte b in h) sb.Append(b.ToString("X2")); return sb.ToString(); } }
}
