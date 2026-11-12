// v0.8.0 — For dual-adjacent slots, separate FILL (non-zero store) from CLEAR (xor0 store).
// Agent 1 C1 fingerprint: pair filled when local player spawns.
// Read-only PE.
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

  static readonly uint[] PairLos = {
    0xAC028E0, 0xAC027C8, 0xABF8178, 0xB0B6F28, 0xAC56D70,
    0xA95F210, 0xAB86280, 0xB74A928, 0xB74A920, 0xAC0E8C0
  };

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);
  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha256Hex(pe);
    if (!hash.Equals(ExpectedExeSha, StringComparison.OrdinalIgnoreCase)) {
      Console.Error.WriteLine("REFUSING hash mismatch");
      return 2;
    }
    ParsePe();
    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 DUAL-BSS FILL vs CLEAR =====");
    sb.AppendLine("exeSha256=" + hash);

    Console.WriteLine("Scanning stores...");
    var allStores = ScanAllRipQwordStores();
    Console.WriteLine("stores=" + allStores.Count);

    // Also find ALL tight co-publish pairs where BOTH stores are within 16 bytes
    // and NEITHER is immediately preceded by xor-zero of the same register.
    sb.AppendLine();
    sb.AppendLine("===== GLOBAL TIGHT FILL PAIRS (dist<=16, both non-clear) =====");
    var fills = FindTightNonClearFills(allStores, 16);
    sb.AppendLine("tightNonClearFillPairs=" + fills.Count);
    foreach (var line in fills.Take(40)) sb.AppendLine(line);

    sb.AppendLine();
    sb.AppendLine("===== PER-SEED FILL/CLEAR BREAKDOWN =====");
    foreach (uint lo in PairLos) {
      uint hi = lo + 8;
      var loS = allStores.Where(s => s.data == lo).ToList();
      var hiS = allStores.Where(s => s.data == hi).ToList();
      sb.AppendLine();
      sb.AppendLine("lo=0x" + lo.ToString("X") + " hi=0x" + hi.ToString("X")
        + " loStores=" + loS.Count + " hiStores=" + hiS.Count);
      ClassifyStores(sb, "LO", loS);
      ClassifyStores(sb, "HI", hiS);

      // Same-func fill of BOTH slots within 64 bytes?
      var fillLo = loS.Where(s => !s.clear).ToList();
      var fillHi = hiS.Where(s => !s.clear).ToList();
      bool coFill = false;
      foreach (var a in fillLo) {
        foreach (var b in fillHi) {
          if (a.func != 0 && a.func == b.func && Math.Abs((int)a.site - (int)b.site) <= 64) {
            sb.AppendLine("  COFILL siteA=0x" + a.site.ToString("X") + " siteB=0x" + b.site.ToString("X")
              + " dist=" + Math.Abs((int)a.site - (int)b.site) + " func=0x" + a.func.ToString("X")
              + " srcA=" + a.src + " srcB=" + b.src);
            DumpWindow(sb, Math.Min(a.site, b.site), 0x20, 0x40, "cofill");
            var strs = CollectStrings(a.func, 0x180);
            sb.AppendLine("  strings=" + string.Join(" | ", strs.Take(6).Select(x => Trunc(x, 50))));
            coFill = true;
          }
        }
      }
      if (!coFill) sb.AppendLine("  COFILL=none");
    }

    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    sb.AppendLine("c1Proven=false");
    sb.AppendLine("callEngine=off");
    sb.AppendLine("note=Prior 'publish' at 0x67FD520 is dual CLEAR (xor eax,eax) — teardown not fill");
    sb.AppendLine("next=If tightNonClearFillPairs empty for player-shaped slots, hunt singleton object");
    sb.AppendLine("     with member stores [obj+0]/[obj+8] then one static publish of obj*");

    string path = Path.Combine(root, "reports", "v080-dual-bss-raw", "fill.txt");
    Directory.CreateDirectory(Path.GetDirectoryName(path));
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine(sb.ToString());
    Console.WriteLine("WROTE " + path);
    return 0;
  }

  struct St {
    public uint site, data, func;
    public bool clear;
    public string src;
    public string text;
  }

  static List<St> ScanAllRipQwordStores() {
    var list = new List<St>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim; i++) {
        byte b0 = pe[s.Ptr + i];
        if (b0 != 0x48 && b0 != 0x4C) continue;
        if (pe[s.Ptr + i + 1] != 0x89) continue;
        if ((pe[s.Ptr + i + 2] & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 3));
        uint site = s.Va + i;
        uint data = unchecked((uint)(site + 7 + disp));
        if (!IsData(data)) continue;
        // Which register is stored? modrm.reg
        byte modrm = pe[s.Ptr + i + 2];
        int reg = (modrm >> 3) & 7;
        bool rexB = (b0 & 1) != 0; // REX.B — actually REX.R is bit 2 for reg field
        bool rexR = (b0 & 4) != 0;
        if (rexR) reg += 8;
        string[] names = { "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15" };
        string src = names[reg];

        bool clear = IsClearStore(site, reg, b0);
        list.Add(new St {
          site = site, data = data, func = FindFuncStart(site),
          clear = clear, src = src, text = "mov [" + data.ToString("X") + "]," + src
        });
      }
    }
    return list;
  }

  static bool IsClearStore(uint site, int reg, byte rex) {
    // Look back up to 12 bytes for xor r,r or mov r,0 of same reg.
    int fo = RvaToFile(site);
    if (fo < 0) return false;
    // Decode a small window ending at site.
    uint start = site > 0x20 ? site - 0x20 : site;
    foreach (var ins in DisasmRaw(start, site)) {
      // xor r32,r32 zero-extends → clear
      if (ins.mnem == Mnemonic.Xor && ins.text.IndexOf(RegName(reg), StringComparison.OrdinalIgnoreCase) >= 0) {
        // crude: "xor eax,eax" / "xor rax,rax"
        if (ins.text.Replace(" ", "").IndexOf(',' + RegName(reg).Replace("r", "").Replace("e", ""), StringComparison.OrdinalIgnoreCase) >= 0
            || ins.text.Count(c => c == ',') == 1) {
          string t = ins.text.ToLowerInvariant().Replace(" ", "");
          string rn = RegName(reg).ToLowerInvariant();
          string en = rn.StartsWith("r") && rn.Length <= 3 ? "e" + rn.Substring(1) : rn;
          if (t == "xor" + rn + "," + rn || t == "xor" + en + "," + en) return true;
        }
      }
      if (ins.mnem == Mnemonic.Mov && ins.text.StartsWith("mov " + RegName(reg) + ",", StringComparison.OrdinalIgnoreCase)
          && (ins.text.EndsWith(",0") || ins.text.EndsWith(", 0"))) return true;
    }
    // Also check immediate preceding bytes: 33 C0 = xor eax,eax; 48 33 C0 = xor rax,rax
    if (fo >= 2 && pe[fo - 2] == 0x33 && pe[fo - 1] == 0xC0 && reg == 0) return true;
    if (fo >= 3 && pe[fo - 3] == 0x48 && pe[fo - 2] == 0x33 && pe[fo - 1] == 0xC0 && reg == 0) return true;
    if (fo >= 2 && pe[fo - 2] == 0x31 && pe[fo - 1] == 0xC0 && reg == 0) return true;
    return false;
  }

  static string RegName(int reg) {
    string[] names = { "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15" };
    return names[reg];
  }

  static List<string> FindTightNonClearFills(List<St> all, int maxDist) {
    var by = all.Where(s => !s.clear).GroupBy(s => s.data).ToDictionary(g => g.Key, g => g.ToList());
    var lines = new List<string>();
    var scored = new List<(int readersApprox, string line)>();
    foreach (var kv in by) {
      uint lo = kv.Key, hi = lo + 8;
      if (!by.ContainsKey(hi)) continue;
      foreach (var a in kv.Value) {
        foreach (var b in by[hi]) {
          if (a.func == 0 || a.func != b.func) continue;
          int d = Math.Abs((int)a.site - (int)b.site);
          if (d > maxDist || d == 0) continue;
          // Prefer pairs that are NOT part of a long consecutive run in same func
          int run = 0;
          for (uint r = lo; by.ContainsKey(r); r += 8) run++;
          string line = "lo=0x" + lo.ToString("X") + " hi=0x" + hi.ToString("X")
            + " siteA=0x" + a.site.ToString("X") + " siteB=0x" + b.site.ToString("X")
            + " dist=" + d + " func=0x" + a.func.ToString("X")
            + " srcA=" + a.src + " srcB=" + b.src
            + " run=" + run + " sec=" + SecNameOf(lo);
          int score = (run <= 2 ? 1000 : 0) - d;
          scored.Add((score, line));
        }
      }
    }
    return scored.OrderByDescending(x => x.readersApprox).Select(x => x.line).Distinct().Take(60).ToList();
  }

  static void ClassifyStores(StringBuilder sb, string tag, List<St> stores) {
    int clear = stores.Count(s => s.clear);
    int fill = stores.Count - clear;
    sb.AppendLine("  " + tag + " fill=" + fill + " clear=" + clear);
    foreach (var s in stores.Take(8)) {
      sb.AppendLine("    " + (s.clear ? "CLEAR" : "FILL ")
        + " site=0x" + s.site.ToString("X") + " func=0x" + s.func.ToString("X")
        + " src=" + s.src);
    }
  }

  struct Ins { public uint rva; public string text; public Mnemonic mnem; public uint data; }

  static List<Ins> DisasmRaw(uint start, uint endExclusive) {
    var list = new List<Ins>();
    int fo = RvaToFile(start);
    if (fo < 0) return list;
    var reader = new ByteArrayCodeReader(pe);
    reader.Position = fo;
    var dec = Decoder.Create(64, reader);
    dec.IP = imageBase + start;
    ulong limit = imageBase + endExclusive;
    int guard = 0;
    while (dec.IP < limit && guard++ < 400) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      var ins = new Ins { rva = (uint)(raw.IP - imageBase), text = o.ToString(), mnem = raw.Mnemonic };
      for (int oi = 0; oi < raw.OpCount; oi++) {
        if (raw.GetOpKind(oi) != OpKind.Memory || !raw.IsIPRelativeMemoryOperand) continue;
        ulong va = raw.IPRelativeMemoryAddress;
        if (va >= imageBase) ins.data = (uint)(va - imageBase);
      }
      list.Add(ins);
      if (ins.mnem == Mnemonic.Int3) break;
    }
    return list;
  }

  static void DumpWindow(StringBuilder sb, uint center, int before, int after, string label) {
    uint start = center > (uint)before ? center - (uint)before : center;
    sb.AppendLine("  --- " + label + " @0x" + center.ToString("X") + " ---");
    foreach (var ins in DisasmRaw(start, center + (uint)after).Take(24)) {
      string extra = ins.data != 0 ? "  ;data=0x" + ins.data.ToString("X") : "";
      string s = ins.data != 0 ? ReadAscii(ins.data, 40) : "";
      if (IsString(s)) extra = "  ;str=" + Trunc(s, 40);
      sb.AppendLine("  0x" + ins.rva.ToString("X") + " " + Trunc(ins.text, 84) + extra);
    }
  }

  static List<string> CollectStrings(uint start, uint span) {
    var list = new List<string>();
    foreach (var ins in DisasmRaw(start, start + span)) {
      if (ins.data == 0) continue;
      string s = ReadAscii(ins.data, 64);
      if (IsString(s)) list.Add(s);
    }
    return list.Distinct().ToList();
  }

  static IEnumerable<Sec> CodeSecs() {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      bool ok = (s.Char & 0x20000000) != 0
        || s.Name.IndexOf("impdata", StringComparison.OrdinalIgnoreCase) >= 0
        || s.Name.IndexOf("code", StringComparison.OrdinalIgnoreCase) >= 0;
      if (ok) yield return s;
    }
  }

  static bool IsData(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva < s.Va || rva >= s.Va + span) continue;
      return (s.Char & 0x20000000) == 0;
    }
    return false;
  }

  static string SecNameOf(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva >= s.Va && rva < s.Va + span) return s.Name.TrimEnd('\0');
    }
    return "?";
  }

  static uint FindFuncStart(uint site) {
    int fo = RvaToFile(site);
    if (fo < 0) return 0;
    int back = Math.Min(fo, 0x2000);
    int pad = -1;
    for (int i = 1; i < back; i++) {
      if (pe[fo - i] == 0xCC && i + 1 < back && pe[fo - i - 1] == 0xCC) { pad = i; break; }
    }
    if (pad < 0) return site > 0x20 ? site - 0x20 : site;
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
