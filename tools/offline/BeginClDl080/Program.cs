// v0.8.0 — Rank freestanding Begin(1,0) callees that consume BOTH cl and dl,
// prefer multi-caller + TLS/RIP-store + return al. Then expand Dup/End/Build.
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
  sealed class Leaf {
    public uint rva; public int size, callers, callers10;
    public bool usesCl, usesDl, tls, ripStore, retAl;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha(pe);
    if (!hash.Equals(Expected, StringComparison.OrdinalIgnoreCase)) { Console.Error.WriteLine("hash mismatch"); return 2; }
    Parse();
    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 Begin cl+dl multi-caller rank =====");
    sb.AppendLine("exeSha256=" + hash);

    Console.WriteLine("Find strict Begin(1,0) sites...");
    var begins = FindStrictBegin10(4000);
    sb.AppendLine("strictBegin10=" + begins.Count);

    Console.WriteLine("Profile unique callees...");
    var byCal = begins.GroupBy(b => b.callee).ToDictionary(g => g.Key, g => g.ToList());
    var leaves = new List<Leaf>();
    foreach (var kv in byCal) {
      var p = Profile(kv.Key);
      int n10 = kv.Value.Count;
      int nAll = CountCallers(kv.Key);
      leaves.Add(new Leaf {
        rva = kv.Key, size = p.size, callers = nAll, callers10 = n10,
        usesCl = p.cl, usesDl = p.dl, tls = p.tls, ripStore = p.rip, retAl = p.retAl
      });
    }

    var both = leaves.Where(l => l.usesCl && l.usesDl).OrderByDescending(l => l.callers)
      .ThenByDescending(l => l.callers10).ToList();
    var bothTls = both.Where(l => l.tls || l.ripStore).ToList();
    sb.AppendLine("calleesUsingClDl=" + both.Count);
    sb.AppendLine("calleesClDlTlsOrRip=" + bothTls.Count);

    sb.AppendLine();
    sb.AppendLine("===== RANKED cl+dl BEGIN CALLEES =====");
    foreach (var l in both.Take(30)) {
      sb.AppendLine("leaf=0x" + l.rva.ToString("X")
        + " callers=" + l.callers + " begin10=" + l.callers10
        + " size=" + l.size + " tls=" + l.tls + " ripStore=" + l.ripStore + " retAl=" + l.retAl);
    }

    sb.AppendLine();
    sb.AppendLine("===== TOP cl+dl (+TLS preferred) DEEP =====");
    var focus = bothTls.Concat(both.Where(l => !l.tls && !l.ripStore)).Take(12).ToList();
    int triadHits = 0;
    foreach (var l in focus) {
      Dump(sb, l.rva, 0, Math.Min(0xA0, Math.Max(0x30, l.size + 8)), "leaf");
      // expand each begin10 site for this leaf
      foreach (var site in byCal[l.rva].Take(8)) {
        var sand = Expand(site.site, site.callee);
        sb.AppendLine("site=0x" + site.site.ToString("X") + " func=0x" + FuncStart(site.site).ToString("X")
          + " dup=" + Hx(sand.dup) + "->" + Hx(sand.dupCal)
          + " end=" + Hx(sand.end) + "->" + Hx(sand.endCal)
          + " build=" + Hx(sand.build) + "->" + Hx(sand.buildCal));
        if (sand.dup != 0 && sand.end != 0 && sand.build != 0) {
          triadHits++;
          Dump(sb, site.site, 0x20, 0xC0, "TRIAD");
        } else if (sand.dup != 0) {
          Dump(sb, site.site, 0x10, 0x80, "hasDup");
        }
      }
    }
    sb.AppendLine("triadShapedSites=" + triadHits);

    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    sb.AppendLine("c2Proven=false");
    sb.AppendLine("callEngine=off");
    if (triadHits > 0) {
      sb.AppendLine("decision=cl+dl Begin leaves produced triad-shaped sites — identity unproven");
      sb.AppendLine("next=Prove selector this / builder this / out Entity**; backtrace C1 cache.");
    } else if (bothTls.Count > 0) {
      sb.AppendLine("decision=cl+dl TLS Begin leaves found but no Dup/End/Build sandwich yet");
      sb.AppendLine("next=Widen sandwich window; allow End via rip-indirect; check virtual Duplicate.");
    } else if (both.Count > 0) {
      sb.AppendLine("decision=cl+dl Begin leaves exist without TLS store in leaf body");
      sb.AppendLine("next=Check if they call a TLS-arming helper; rank by caller count.");
    } else {
      sb.AppendLine("decision=no Begin(1,0) callee consumes both cl and dl under current profile");
      sb.AppendLine("next=Widen profile window; allow stdcall shadow; ask Agent1 x64 ABI.");
    }

    string dir = Path.Combine(root, "reports", "v080-begin-cldl-raw");
    Directory.CreateDirectory(dir);
    File.WriteAllText(Path.Combine(dir, "evidence.txt"), sb.ToString());
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-begin-cldl.json"),
      "{\n  \"schemaVersion\": 1,\n  \"exeSha256\": \"" + hash + "\",\n" +
      "  \"strictBegin10\": " + begins.Count + ",\n  \"clDlCallees\": " + both.Count + ",\n" +
      "  \"clDlTls\": " + bothTls.Count + ",\n  \"triadShapedSites\": " + triadHits + ",\n" +
      "  \"c2Proven\": false,\n  \"callEngine\": false\n}\n");
    Console.WriteLine(string.Join("\n", sb.ToString().Split('\n').Take(55)));
    Console.WriteLine("WROTE reports/v080-begin-cldl-raw/evidence.txt");
    return 0;
  }

  struct BeginHit { public uint site, callee; }
  struct Sand { public uint dup, dupCal, end, endCal, build, buildCal; }
  struct Prof { public int size; public bool cl, dl, tls, rip, retAl; }

  static List<BeginHit> FindStrictBegin10(int max) {
    var list = new List<BeginHit>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0x20; i + 5 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        bool maybe1 = false, maybe0 = false;
        for (uint j = i - 0x20; j < i; j++) {
          if (pe[s.Ptr + j] == 0xB1 && j + 1 < i && pe[s.Ptr + j + 1] == 1) maybe1 = true;
          if (pe[s.Ptr + j] == 0xB9 && j + 4 < i && pe[s.Ptr + j + 1] == 1 && pe[s.Ptr + j + 2] == 0) maybe1 = true;
          if ((pe[s.Ptr + j] == 0x31 || pe[s.Ptr + j] == 0x33) && j + 1 < i && pe[s.Ptr + j + 1] == 0xD2) maybe0 = true;
        }
        if (!maybe1 || !maybe0) continue;
        uint site = s.Va + i;
        if (!LastDefIs(site, "ecx", 1) || !LastDefIs(site, "edx", 0) || LastRcxThis(site)) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        list.Add(new BeginHit { site = site, callee = unchecked((uint)(site + 5 + rel)) });
      }
    }
    return list;
  }

  static Prof Profile(uint rva) {
    var p = new Prof();
    int n = 0;
    foreach (var ins in Disasm(rva, rva + 0x120)) {
      n++;
      string t = ins.text.ToLowerInvariant();
      if (t.Contains("gs:")) p.tls = true;
      if ((t.StartsWith("mov ") || t.StartsWith("mov byte") || t.StartsWith("mov dword") || t.StartsWith("mov qword"))
          && t.Contains("[") && t.Contains("rip") && t.Contains("],")) p.rip = true;
      // consume cl/dl: store or move from them, test, etc. — not just defining
      if (t.Contains(", cl") || t.Contains(" cl,") || t.EndsWith(" cl") || t.Contains("\tcl")
          || t.Contains(",cl") || t.Contains(" sil, cl") || t.Contains(" bl, cl") || t.Contains("test cl")
          || t.Contains("or cl") || t.Contains("and cl") || t.Contains("movzx") && t.Contains(", cl"))
        p.cl = true;
      if (t.Contains(", dl") || t.Contains(" dl,") || t.EndsWith(" dl") || t.Contains(",dl")
          || t.Contains("test dl") || t.Contains("or dl") || t.Contains("and dl") || t.Contains("movzx") && t.Contains(", dl"))
        p.dl = true;
      // also iced without space variants already covered
      if (t.Contains("mov al,") || t == "mov al,1" || t.StartsWith("sete al") || t.StartsWith("setne al")) p.retAl = true;
      if (ins.mnem == Mnemonic.Ret) { p.size = (int)(ins.rva - rva) + 1; break; }
      if (ins.mnem == Mnemonic.Int3) { p.size = (int)(ins.rva - rva); break; }
      if (n > 100) { p.size = (int)(ins.rva - rva); break; }
    }
    if (p.size == 0) p.size = n * 4;
    return p;
  }

  static Sand Expand(uint beginSite, uint beginCallee) {
    var s = new Sand();
    foreach (var ins in Disasm(beginSite + 5, beginSite + 0x180)) {
      if (ins.mnem == Mnemonic.Int3 && ins.rva > beginSite + 8) break;
      if (ins.mnem == Mnemonic.Ret) break;
      if (!ins.isCall || ins.target == 0) continue;
      if (s.dup == 0 && LastDefDup00(ins.rva)) { s.dup = ins.rva; s.dupCal = ins.target; continue; }
      if (s.dup != 0 && s.end == 0 && LooksEnd(ins.rva)) { s.end = ins.rva; s.endCal = ins.target; continue; }
      if (s.dup != 0 && s.build == 0 && LooksBuild(ins.rva)) { s.build = ins.rva; s.buildCal = ins.target; }
    }
    return s;
  }

  static int CountCallers(uint target) {
    int n = 0;
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 5 <= lim; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        uint site = s.Va + i;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        if (unchecked((uint)(site + 5 + rel)) == target) n++;
      }
    }
    return n;
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
  static bool LooksBuild(uint callSite) {
    bool lea = false, r8 = false, rcx = false;
    foreach (var ins in Disasm(callSite > 0x30 ? callSite - 0x30 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("leardx,[rsp") || t.StartsWith("leardx,[rbp")) lea = true;
      if (t.StartsWith("movr8,")) r8 = true;
      if (t.StartsWith("movrcx,")) rcx = true;
    }
    return lea && r8 && rcx;
  }
  static bool LastDefIs(uint callSite, string reg, int want) {
    string last = null;
    foreach (var ins in Disasm(callSite > 0x30 ? callSite - 0x30 : 0, callSite)) {
      string t = Norm(ins.text);
      if (reg == "ecx" && (t.StartsWith("movecx,") || t.StartsWith("movcl,") || t.StartsWith("xorecx,ecx") || t.StartsWith("movrcx,") || t.StartsWith("xorrcx,rcx") || t.StartsWith("learcx,"))) last = t;
      if (reg == "edx" && (t.StartsWith("movedx,") || t.StartsWith("movdl,") || t.StartsWith("xoredx,edx") || t.StartsWith("movrdx,") || t.StartsWith("xorrdx,rdx") || t.StartsWith("leardx,"))) last = t;
    }
    if (last == null) return false;
    if (want == 0) return last.Contains("xor") || last.EndsWith(",0") || last.EndsWith(",0h");
    return last.EndsWith(",1") || last.EndsWith(",1h");
  }
  static bool LastRcxThis(uint callSite) {
    string last = null;
    foreach (var ins in Disasm(callSite > 0x28 ? callSite - 0x28 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("movrcx,") || t.StartsWith("learcx,") || t.StartsWith("movecx,") || t.StartsWith("movcl,")) last = t;
    }
    if (last == null) return false;
    if (last == "movecx,1" || last == "movcl,1" || last == "movrcx,1") return false;
    return true;
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
    while (dec.IP < lim && g++ < 600) {
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
    foreach (var ins in Disasm(start, center + (uint)after).Take(40)) {
      string ex = ins.isCall ? "  ;call=0x" + ins.target.ToString("X") : "";
      sb.AppendLine("0x" + ins.rva.ToString("X") + " " + Trunc(ins.text, 96) + ex);
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
