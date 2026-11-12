// Follow Begin candidate 0x5001598: all callers + nearby Dup(0,0)/End/Build shapes.
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
  const uint BeginCand = 0x5001598;
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
    sb.AppendLine("===== FOLLOW BeginCand 0x5001598 =====");
    sb.AppendLine("exeSha256=" + hash);
    Dump(sb, BeginCand, 0, 0x40, "leaf");

    var callers = FindCallers(BeginCand);
    sb.AppendLine("callers=" + callers.Count);
    int withDup = 0, withEnd = 0, withBuild = 0, with10 = 0;
    foreach (var site in callers) {
      bool is10 = LastDefIs(site, "ecx", 1) && LastDefIs(site, "edx", 0) && !LastRcxThis(site);
      if (is10) with10++;
      uint func = FuncStart(site);
      var near = ScanWindow(func, func + 0x400);
      if (near.dup != 0) withDup++;
      if (near.end != 0) withEnd++;
      if (near.build != 0) withBuild++;
      sb.AppendLine("site=0x" + site.ToString("X") + " func=0x" + func.ToString("X")
        + " begin10=" + is10
        + " dup=" + Hex(near.dup) + "->" + Hex(near.dupCal)
        + " end=" + Hex(near.end) + "->" + Hex(near.endCal)
        + " build=" + Hex(near.build) + "->" + Hex(near.buildCal));
      Dump(sb, site, 0x30, 0xA0, "caller");
    }
    sb.AppendLine("callersBegin10=" + with10 + " withDup=" + withDup + " withEnd=" + withEnd + " withBuild=" + withBuild);

    // Also dump internal callees of the leaf
    sb.AppendLine();
    sb.AppendLine("===== LEAF INTERNAL CALLEES =====");
    foreach (var ins in Disasm(BeginCand, BeginCand + 0x40)) {
      if (ins.isCall && ins.target != 0) {
        sb.AppendLine("callee=0x" + ins.target.ToString("X"));
        Dump(sb, ins.target, 0, 0x60, "inner");
      }
    }

    // Companion 0x513C2E8 often called just before
    sb.AppendLine();
    sb.AppendLine("===== COMPANION 0x513C2E8 =====");
    Dump(sb, 0x513C2E8, 0, 0x60, "companion");

    string dir = Path.Combine(root, "reports", "v080-begin-follow-raw");
    Directory.CreateDirectory(dir);
    File.WriteAllText(Path.Combine(dir, "evidence.txt"), sb.ToString());
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-begin-follow.json"),
      "{\n  \"schemaVersion\": 1,\n  \"beginCand\": \"0x5001598\",\n  \"callers\": " + callers.Count + ",\n" +
      "  \"callersBegin10\": " + with10 + ",\n  \"withDup\": " + withDup + ",\n  \"withEnd\": " + withEnd + ",\n" +
      "  \"withBuild\": " + withBuild + ",\n  \"c2Proven\": false,\n  \"callEngine\": false\n}\n");
    Console.WriteLine(string.Join("\n", sb.ToString().Split('\n').Take(50)));
    Console.WriteLine("WROTE reports/v080-begin-follow-raw/evidence.txt");
    return 0;
  }

  struct Near { public uint dup, dupCal, end, endCal, build, buildCal; }

  static Near ScanWindow(uint start, uint endEx) {
    var n = new Near();
    foreach (var ins in Disasm(start, endEx)) {
      if (!ins.isCall || ins.target == 0) continue;
      if (n.dup == 0 && LastDefDup00(ins.rva)) { n.dup = ins.rva; n.dupCal = ins.target; }
      else if (n.dup != 0 && n.end == 0 && LooksEnd(ins.rva)) { n.end = ins.rva; n.endCal = ins.target; }
      else if (n.dup != 0 && n.build == 0 && LooksBuild(ins.rva)) { n.build = ins.rva; n.buildCal = ins.target; }
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
    if (want == 1) return last.EndsWith(",1") || last.EndsWith(",1h");
    return false;
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

  static string Hex(uint v) => v == 0 ? "0" : "0x" + v.ToString("X");
  static string Norm(string s) => s.Replace(" ", "").Replace("ptr", "").ToLowerInvariant();

  struct Ins { public uint rva, target; public string text; public Mnemonic mnem; public bool isCall; }
  static List<Ins> Disasm(uint start, uint endEx) {
    var list = new List<Ins>();
    int fo = RvaToFile(start); if (fo < 0) return list;
    var reader = new ByteArrayCodeReader(pe); reader.Position = fo;
    var dec = Decoder.Create(64, reader); dec.IP = ib + start;
    ulong lim = ib + endEx; int g = 0;
    while (dec.IP < lim && g++ < 800) {
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
    foreach (var ins in Disasm(start, center + (uint)after).Take(48)) {
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
