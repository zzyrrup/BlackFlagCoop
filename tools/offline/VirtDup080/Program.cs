// v0.8.0 — Hunt Duplicate whose return feeds Build r8.
// Paths: (A) virtual call [reg+disp] with last-def (0,0);
//        (B) direct E8 with last-def (0,0) then mov r8,rax + lea rdx Build.
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
  static byte[] pe; static ulong ib; static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(new FormatterOptions { RipRelativeAddresses = true }, null, null);
  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }
  sealed class Hit {
    public uint dupSite, buildSite, buildCallee, beginSite, endSite, func;
    public int vtOff; public string kind; public bool begin10, endFree;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha(pe);
    if (!hash.Equals(Expected, StringComparison.OrdinalIgnoreCase)) { Console.Error.WriteLine("hash mismatch"); return 2; }
    Parse();
    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 VirtDup / return-to-Build =====");
    sb.AppendLine("exeSha256=" + hash);

    Console.WriteLine("Pass A: virtual call [reg+disp] Dup(0,0) → Build...");
    var virt = ScanVirtual(max: 4000);
    sb.AppendLine("virtDup00=" + virt.dup00);
    sb.AppendLine("virtRetToBuild=" + virt.hits.Count);
    foreach (var h in virt.hits.Take(40)) {
      sb.AppendLine(Format(h));
      Dump(sb, h.dupSite, 0x30, 0x90, "virt");
    }
    sb.AppendLine("virtVtOffTop=" + string.Join(",", virt.vtHist.OrderByDescending(kv => kv.Value).Take(12)
      .Select(kv => "0x" + kv.Key.ToString("X") + ":" + kv.Value)));

    Console.WriteLine("Pass B: direct E8 Dup(0,0) → mov r8,rax → Build...");
    var dir = ScanDirect(max: 4000);
    sb.AppendLine();
    sb.AppendLine("directDup00=" + dir.dup00);
    sb.AppendLine("directRetToBuild=" + dir.hits.Count);
    foreach (var h in dir.hits.Take(40)) {
      sb.AppendLine(Format(h));
      Dump(sb, h.dupSite, 0x30, 0x90, "direct");
    }
    sb.AppendLine("directCalleeTop=" + string.Join(",", dir.calHist.OrderByDescending(kv => kv.Value).Take(12)
      .Select(kv => "0x" + kv.Key.ToString("X") + ":" + kv.Value)));

    var withBegin = virt.hits.Concat(dir.hits).Where(h => h.begin10).ToList();
    var full = withBegin.Where(h => h.endFree).ToList();
    sb.AppendLine();
    sb.AppendLine("retToBuildWithBegin10=" + withBegin.Count);
    sb.AppendLine("retToBuildWithBeginAndEnd=" + full.Count);
    foreach (var h in full.Take(20)) { sb.AppendLine(Format(h)); Dump(sb, h.dupSite, 0x50, 0xA0, "FULLISH"); }

    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    sb.AppendLine("c2Proven=false");
    sb.AppendLine("callEngine=off");
    int total = virt.hits.Count + dir.hits.Count;
    if (full.Count > 0) {
      sb.AppendLine("decision=return-to-Build sites with Begin(1,0)+End — triad candidates, identity unproven");
      sb.AppendLine("next=Prove Begin/End/Dup/Build callees; selector/builder this; C1 cache backtrace.");
    } else if (total > 0) {
      sb.AppendLine("decision=return-to-Build Dup sites found; Begin/End link missing or different shape");
      sb.AppendLine("next=At top hits, widen Begin/End search; check scope via TLS rather than freestanding End.");
    } else {
      sb.AppendLine("decision=no return-to-Build Duplicate shape under current heuristics");
      sb.AppendLine("next=Allow r8 from mov r8,reg after mov reg,rax; Ask Agent1 Build arg order on x64.");
    }

    string outDir = Path.Combine(root, "reports", "v080-virtdup-raw");
    Directory.CreateDirectory(outDir);
    File.WriteAllText(Path.Combine(outDir, "evidence.txt"), sb.ToString());
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-virtdup.json"),
      "{\n  \"schemaVersion\": 1,\n  \"virtDup00\": " + virt.dup00 + ",\n  \"virtRetToBuild\": " + virt.hits.Count + ",\n" +
      "  \"directDup00\": " + dir.dup00 + ",\n  \"directRetToBuild\": " + dir.hits.Count + ",\n" +
      "  \"withBegin10\": " + withBegin.Count + ",\n  \"withBeginEnd\": " + full.Count + ",\n" +
      "  \"c2Proven\": false,\n  \"callEngine\": false\n}\n");
    Console.WriteLine(string.Join("\n", sb.ToString().Split('\n').Take(50)));
    Console.WriteLine("WROTE reports/v080-virtdup-raw/evidence.txt");
    return 0;
  }

  sealed class PassResult {
    public int dup00;
    public List<Hit> hits = new List<Hit>();
    public Dictionary<int, int> vtHist = new Dictionary<int, int>();
    public Dictionary<uint, int> calHist = new Dictionary<uint, int>();
  }

  static PassResult ScanVirtual(int max) {
    var r = new PassResult();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      uint i = 0;
      while (i + 8 < lim && r.dup00 < max) {
        int fo = (int)(s.Ptr + i);
        var reader = new ByteArrayCodeReader(pe); reader.Position = fo;
        var dec = Decoder.Create(64, reader); dec.IP = ib + s.Va + i;
        var raw = dec.Decode();
        if (raw.Length == 0 || raw.Code == Code.INVALID) { i++; continue; }
        uint site = (uint)(raw.IP - ib);
        if (raw.Mnemonic == Mnemonic.Call && raw.IsCallNearIndirect) {
          // call qword ptr [reg+disp]
          int off = VtOffset(raw);
          if (off >= 0 && LastDefDup00(site)) {
            r.dup00++;
            if (!r.vtHist.ContainsKey(off)) r.vtHist[off] = 0;
            r.vtHist[off]++;
            var hit = FollowRetToBuild(site, 0, "virt", off);
            if (hit != null) r.hits.Add(hit);
          }
        }
        i += (uint)Math.Max(1, raw.Length);
      }
    }
    return r;
  }

  static PassResult ScanDirect(int max) {
    var r = new PassResult();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0x30; i + 5 <= lim && r.dup00 < max; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        // cheap xor edx / xor r8d prefilter
        bool zEdx = false, zR8 = false;
        for (uint j = i - 0x28; j + 2 < i; j++) {
          byte a = pe[s.Ptr + j], b = pe[s.Ptr + j + 1];
          if ((a == 0x33 || a == 0x31) && b == 0xD2) zEdx = true;
          if (a == 0x45 && (b == 0x33 || b == 0x31) && pe[s.Ptr + j + 2] == 0xC0) zR8 = true;
        }
        if (!zEdx || !zR8) continue;
        uint site = s.Va + i;
        if (!LastDefDup00(site)) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        uint cal = unchecked((uint)(site + 5 + rel));
        r.dup00++;
        if (!r.calHist.ContainsKey(cal)) r.calHist[cal] = 0;
        r.calHist[cal]++;
        var hit = FollowRetToBuild(site, cal, "direct", -1);
        if (hit != null) r.hits.Add(hit);
      }
    }
    return r;
  }

  static Hit FollowRetToBuild(uint dupSite, uint dupCallee, string kind, int vtOff) {
    // After Dup: look for mov REG,rax then later Build with mov r8,REG and lea rdx,[rsp]
    string retReg = null;
    uint buildSite = 0, buildCal = 0;
    foreach (var ins in Disasm(dupSite + (uint)(kind == "virt" ? 2 : 5), dupSite + 0xA0)) {
      string t = Norm(ins.text);
      if (retReg == null) {
        if (t.StartsWith("movrcx,rax") || t.StartsWith("movrbx,rax") || t.StartsWith("movrsi,rax")
            || t.StartsWith("movrdi,rax") || t.StartsWith("movrbp,rax") || t.StartsWith("movr12,rax")
            || t.StartsWith("movr13,rax") || t.StartsWith("movr14,rax") || t.StartsWith("movr15,rax")
            || t.StartsWith("movr8,rax") || t.StartsWith("movr9,rax")) {
          // extract dest
          retReg = t.Substring(3, t.IndexOf(",rax") - 3);
        } else if (t.StartsWith("testrax,") || t.StartsWith("je") || t.StartsWith("jne") || t.StartsWith("jz") || t.StartsWith("jnz")
                   || t.StartsWith("nop") || t.StartsWith("moveax,")) {
          /* allow */ }
        else if (ins.isCall) break;
        continue;
      }
      if (ins.isCall && LooksBuildWithR8From(ins.rva, retReg)) {
        buildSite = ins.rva; buildCal = ins.target; break;
      }
      if (ins.mnem == Mnemonic.Ret || ins.mnem == Mnemonic.Int3) break;
    }
    if (buildSite == 0) return null;

    var h = new Hit {
      dupSite = dupSite, buildSite = buildSite, buildCallee = buildCal,
      func = FuncStart(dupSite), kind = kind, vtOff = vtOff
    };
    var back = Disasm(dupSite > 0x80 ? dupSite - 0x80 : 0, dupSite);
    for (int i = back.Count - 1; i >= 0; i--) {
      var ins = back[i];
      if (!ins.isCall) continue;
      if (LastDefIs(ins.rva, "ecx", 1) && LastDefIs(ins.rva, "edx", 0) && !LastRcxThis(ins.rva)) {
        h.beginSite = ins.rva; h.begin10 = true; break;
      }
    }
    foreach (var ins in Disasm(dupSite + 5, Math.Max(buildSite + 0x40, dupSite + 0xC0))) {
      if (!ins.isCall || ins.rva == buildSite) continue;
      if (LooksEnd(ins.rva)) { h.endSite = ins.rva; h.endFree = true; break; }
    }
    return h;
  }

  static bool LooksBuildWithR8From(uint callSite, string retReg) {
    bool lea = false, rcx = false, r8From = false;
    foreach (var ins in Disasm(callSite > 0x40 ? callSite - 0x40 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("leardx,[rsp") || t.StartsWith("leardx,[rbp")) lea = true;
      if (t.StartsWith("movrcx,")) rcx = true;
      if (t == "movr8," + retReg || t == "movr8d," + retReg) r8From = true;
      if (retReg == "r8" && (t.StartsWith("movr8,rax") || t == "nop")) r8From = true;
    }
    return lea && rcx && r8From;
  }

  static int VtOffset(Instruction raw) {
    try {
      if (!raw.IsIPRelativeMemoryOperand && raw.MemoryBase != Register.None) {
        return (int)raw.MemoryDisplacement64;
      }
    } catch { }
    // fallback parse text
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

  static string Format(Hit h) {
    return "kind=" + h.kind + " func=0x" + h.func.ToString("X")
      + " dup=0x" + h.dupSite.ToString("X") + (h.vtOff >= 0 ? "[+" + h.vtOff.ToString("X") + "]" : "")
      + " build=0x" + h.buildSite.ToString("X") + "->0x" + h.buildCallee.ToString("X")
      + " begin=" + (h.beginSite == 0 ? "0" : "0x" + h.beginSite.ToString("X"))
      + " end=" + (h.endSite == 0 ? "0" : "0x" + h.endSite.ToString("X"));
  }
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
        if (raw.NearBranchTarget != 0 && raw.NearBranchTarget >= ib) {
          ins.isCall = true; ins.target = (uint)(raw.NearBranchTarget - ib);
        } else if (raw.IsCallNearIndirect) {
          ins.isCall = true; ins.target = 0;
        }
      }
      list.Add(ins);
      if (ins.mnem == Mnemonic.Int3) break;
    }
    return list;
  }
  static void Dump(StringBuilder sb, uint center, int before, int after, string label) {
    uint start = center > (uint)before ? center - (uint)before : center;
    sb.AppendLine("--- " + label + " @0x" + center.ToString("X") + " ---");
    foreach (var ins in Disasm(start, center + (uint)after).Take(40)) {
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
