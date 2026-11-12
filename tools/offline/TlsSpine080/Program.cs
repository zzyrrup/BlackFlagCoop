// Prove/falsify whether Dup-hot 0x42B85F0 returns a new heap pointer (selector*),
// and find thin freestanding (1,0) callers that touch the same TLS spine (0xAB8BBC0 / +1C78).
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
  const uint DupHot = 0x42B85F0;
  const uint TlsIdx = 0xAB8BBC0;
  const uint FramePush = 0x4420000;
  static byte[] pe; static ulong ib; static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(new FormatterOptions { RipRelativeAddresses = true }, null, null);
  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha(pe);
    if (!hash.Equals(Expected, StringComparison.OrdinalIgnoreCase)) { Console.Error.WriteLine("hash mismatch"); return 2; }
    Parse();
    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 TLS spine / DupHot return =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("dupHot=0x" + DupHot.ToString("X") + " tlsIdx=0x" + TlsIdx.ToString("X") + " framePush=0x" + FramePush.ToString("X"));

    Console.WriteLine("Dump DupHot epilogue / returns...");
    Dump(sb, DupHot, 0, 0x200, "dupHot");
    // Find ret sites and preceding mov rax
    sb.AppendLine();
    sb.AppendLine("===== DupHot RETURN SHAPES =====");
    AnalyzeReturns(sb, DupHot);

    Console.WriteLine("Sample DupHot call sites (last-def 0,0)...");
    var sites = FindCallers(DupHot).Where(s => LastDefDup00(s)).Take(24).ToList();
    sb.AppendLine("dup00CallSitesSampled=" + sites.Count + " (of " + FindCallers(DupHot).Count + " total callers)");
    int retUsed = 0, buildNear = 0;
    foreach (var site in sites) {
      bool usesRet = UsesRaxAfter(site, 0x40);
      bool build = HasBuildNear(site, 0x80);
      if (usesRet) retUsed++;
      if (build) buildNear++;
      sb.AppendLine("site=0x" + site.ToString("X") + " func=0x" + FuncStart(site).ToString("X")
        + " usesRax=" + usesRet + " buildNear=" + build);
      if (usesRet || build) Dump(sb, site, 0x28, 0x70, "dupSite");
    }
    sb.AppendLine("dup00UsesRax=" + retUsed + " dup00BuildNear=" + buildNear);

    Console.WriteLine("Find code that RIP-loads tlsIdx 0xAB8BBC0...");
    var tlsUsers = FindRipLoad(TlsIdx, max: 200);
    sb.AppendLine();
    sb.AppendLine("===== TLS INDEX 0xAB8BBC0 USERS =====");
    sb.AppendLine("ripLoads=" + tlsUsers.Count);
    // Rank small leaves among users that are freestanding Begin(1,0) callees
    var beginCands = new List<uint>();
    foreach (var u in tlsUsers) {
      uint f = FuncStart(u);
      var p = Profile(f);
      if (p.size > 0 && p.size <= 0x80 && (p.cl || p.dl)) {
        beginCands.Add(f);
        sb.AppendLine("smallTlsLeaf=0x" + f.ToString("X") + " size=" + p.size + " cl=" + p.cl + " dl=" + p.dl + " retAl=" + p.retAl + " at=0x" + u.ToString("X"));
      }
    }
    beginCands = beginCands.Distinct().ToList();
    sb.AppendLine("smallTlsLeaves=" + beginCands.Count);
    foreach (var f in beginCands.Take(20)) {
      Dump(sb, f, 0, 0x60, "tlsLeaf");
      int n10 = CountBegin10Callers(f);
      int nAll = FindCallers(f).Count;
      sb.AppendLine("  callers=" + nAll + " begin10=" + n10);
    }

    // Companion End candidate: 0x4420DB0
    sb.AppendLine();
    sb.AppendLine("===== FRAME POP 0x4420DB0 =====");
    Dump(sb, 0x4420DB0, 0, 0x80, "framePop");

    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    sb.AppendLine("c2Proven=false");
    sb.AppendLine("callEngine=off");
    if (retUsed > 0 && buildNear > 0) {
      sb.AppendLine("decision=DupHot 0x42B85F0 return used + Build-near at some (0,0) sites — candidate Duplicate, identity unproven");
      sb.AppendLine("next=Deep-disasm those sites for Begin/End; prove returned object is RowSelector-like.");
    } else if (retUsed > 0) {
      sb.AppendLine("decision=DupHot return value consumed; Build link not seen under lea-rdx heuristic");
      sb.AppendLine("next=Trace rax consumers; check virtual Build; Find Begin on same TLS frame.");
    } else {
      sb.AppendLine("decision=DupHot (0,0) sites rarely consume rax as new object — likely not RowSelector::Duplicate");
      sb.AppendLine("next=Try other TLS Dup callees (0x42EB100); or virtual [rax+90] Duplicate path.");
    }

    string dir = Path.Combine(root, "reports", "v080-tls-spine-raw");
    Directory.CreateDirectory(dir);
    File.WriteAllText(Path.Combine(dir, "evidence.txt"), sb.ToString());
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-tls-spine.json"),
      "{\n  \"schemaVersion\": 1,\n  \"dupHot\": \"0x42B85F0\",\n  \"tlsIdx\": \"0xAB8BBC0\",\n" +
      "  \"dup00UsesRax\": " + retUsed + ",\n  \"dup00BuildNear\": " + buildNear + ",\n" +
      "  \"smallTlsLeaves\": " + beginCands.Count + ",\n  \"c2Proven\": false,\n  \"callEngine\": false\n}\n");
    Console.WriteLine(string.Join("\n", sb.ToString().Split('\n').Take(60)));
    Console.WriteLine("WROTE reports/v080-tls-spine-raw/evidence.txt");
    return 0;
  }

  static void AnalyzeReturns(StringBuilder sb, uint func) {
    foreach (var ins in Disasm(func, func + 0x500)) {
      if (ins.mnem != Mnemonic.Ret) continue;
      // look back 8 ins
      var win = Disasm(ins.rva > 0x30 ? ins.rva - 0x30 : func, ins.rva);
      sb.AppendLine("ret@0x" + ins.rva.ToString("X"));
      foreach (var w in win.TakeLast(8)) sb.AppendLine("  " + "0x" + w.rva.ToString("X") + " " + w.text);
    }
  }

  static bool UsesRaxAfter(uint callSite, int window) {
    bool saw = false;
    foreach (var ins in Disasm(callSite + 5, callSite + (uint)window)) {
      string t = Norm(ins.text);
      if (t.StartsWith("testrax,") || t.StartsWith("movrcx,rax") || t.StartsWith("movrbx,rax") || t.StartsWith("movrsi,rax")
          || t.StartsWith("movrdi,rax") || t.StartsWith("movr8,rax") || t.StartsWith("mov[") && t.Contains(",rax")
          || t.StartsWith("lea") && t.Contains("rax")) return true;
      if (ins.isCall) break; // stop at next call unless mov happened
      if (t.StartsWith("je") || t.StartsWith("jne") || t.StartsWith("jz") || t.StartsWith("jnz")) { /* keep */ }
    }
    return saw;
  }

  static bool HasBuildNear(uint callSite, int window) {
    foreach (var ins in Disasm(callSite + 5, callSite + (uint)window)) {
      if (!ins.isCall) continue;
      bool lea = false, r8 = false, rcx = false;
      foreach (var p in Disasm(ins.rva > 0x30 ? ins.rva - 0x30 : callSite, ins.rva)) {
        string t = Norm(p.text);
        if (t.StartsWith("leardx,[rsp") || t.StartsWith("leardx,[rbp")) lea = true;
        if (t.StartsWith("movr8,")) r8 = true;
        if (t.StartsWith("movrcx,")) rcx = true;
      }
      if (lea && r8 && rcx) return true;
    }
    return false;
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

  struct Prof { public int size; public bool cl, dl, retAl; }
  static Prof Profile(uint rva) {
    var p = new Prof(); int n = 0;
    foreach (var ins in Disasm(rva, rva + 0xA0)) {
      n++; string t = ins.text.ToLowerInvariant();
      if (t.Contains(", cl") || t.Contains(",cl") || t.Contains("test cl") || t.Contains(" bl, cl") || t.Contains(" sil, cl")) p.cl = true;
      if (t.Contains(", dl") || t.Contains(",dl") || t.Contains("test dl")) p.dl = true;
      if (t.Contains("mov al,") || t.StartsWith("sete al")) p.retAl = true;
      if (ins.mnem == Mnemonic.Ret) { p.size = (int)(ins.rva - rva) + 1; break; }
      if (ins.mnem == Mnemonic.Int3) { p.size = (int)(ins.rva - rva); break; }
      if (n > 80) { p.size = (int)(ins.rva - rva); break; }
    }
    return p;
  }

  static int CountBegin10Callers(uint target) {
    int n = 0;
    foreach (var s in FindCallers(target)) {
      if (LastDefIs(s, "ecx", 1) && LastDefIs(s, "edx", 0) && !LastRcxThis(s)) n++;
    }
    return n;
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

  static List<uint> FindRipLoad(uint dataRva, int max) {
    var list = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      // scan for possible lea/mov with rip-rel — decode densely is slow; sample E8-free window via iced every...
      // Faster: walk with iced in chunks looking for IP-relative to dataRva
      uint i = 0;
      while (i + 8 < lim && list.Count < max) {
        int fo = (int)(s.Ptr + i);
        var reader = new ByteArrayCodeReader(pe); reader.Position = fo;
        var dec = Decoder.Create(64, reader); dec.IP = ib + s.Va + i;
        var raw = dec.Decode();
        if (raw.Length == 0 || raw.Code == Code.INVALID) { i++; continue; }
        if (raw.IsIPRelativeMemoryOperand) {
          uint tgt = (uint)(raw.IPRelativeMemoryAddress - ib);
          if (tgt == dataRva) list.Add((uint)(raw.IP - ib));
        }
        i += (uint)Math.Max(1, raw.Length);
      }
    }
    return list;
  }

  static List<uint> FindCallers(uint target) {
    var list = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 5 <= lim; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        uint site = s.Va + i;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        if (unchecked((uint)(site + 5 + rel)) == target) list.Add(site);
      }
    }
    return list;
  }

  static string Norm(string s) => s.Replace(" ", "").Replace("ptr", "").ToLowerInvariant();
  struct Ins { public uint rva, target; public string text; public Mnemonic mnem; public bool isCall; }
  static List<Ins> Disasm(uint start, uint endEx) {
    var list = new List<Ins>();
    int fo = RvaToFile(start); if (fo < 0) return list;
    var reader = new ByteArrayCodeReader(pe); reader.Position = fo;
    var dec = Decoder.Create(64, reader); dec.IP = ib + start;
    ulong lim = ib + endEx; int g = 0;
    while (dec.IP < lim && g++ < 900) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      var o = new StringOutput(); Fmt.Format(raw, o);
      var ins = new Ins { rva = (uint)(raw.IP - ib), text = o.ToString(), mnem = raw.Mnemonic };
      if (raw.FlowControl == FlowControl.Call && raw.NearBranchTarget != 0 && raw.NearBranchTarget >= ib) {
        ins.isCall = true; ins.target = (uint)(raw.NearBranchTarget - ib);
      }
      list.Add(ins);
      if (ins.mnem == Mnemonic.Int3) break;
    }
    return list;
  }
  static void Dump(StringBuilder sb, uint center, int before, int after, string label) {
    uint start = center > (uint)before ? center - (uint)before : center;
    sb.AppendLine("--- " + label + " @0x" + center.ToString("X") + " ---");
    foreach (var ins in Disasm(start, center + (uint)after).Take(56)) {
      string ex = ins.isCall ? "  ;call=0x" + ins.target.ToString("X") : "";
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
