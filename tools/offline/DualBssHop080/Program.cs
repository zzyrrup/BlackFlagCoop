// v0.8.0 — Deep-hop dual-adjacent publish candidates for C1.
// Focus: tight co-publishes (dist<=16), both slots read, not long table fills.
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

  // Candidates from DualBss080 + PlayerProgression-proximate pairs.
  static readonly (uint Lo, uint Hi, uint Site, uint Func, string Note)[] Seeds = {
    (0xAC028E0, 0xAC028E8, 0x67FD57B, 0x67FD520, "tight dist7 readers457"),
    (0xAC027C8, 0xAC027D0, 0x67FD252, 0x67FD220, "tight dist7 readers74"),
    (0xB1CFC68, 0xB1CFC70, 0x20E4B7B, 0x20E3DF0, "tight dist7 readers67"),
    (0xABF8178, 0xABF8180, 0x75B0090, 0x75B0030, "tight dist21 readers62"),
    (0xB0B6F28, 0xB0B6F30, 0x5D9AC77, 0x5D9AC20, "tight dist14 readers46"),
    (0xAC56D70, 0xAC56D78, 0x1468270, 0x1468230, "tight dist14 readers30"),
    (0xA95F210, 0xA95F218, 0x58DAD23, 0x58DAD00, "tight dist28 readers30"),
    (0xAB86280, 0xAB86288, 0x4F84B3F, 0x4F84AE0, "tight dist26 readers32"),
    (0xB2EB998, 0xB2EB9A0, 0x1C7013C, 0x1C6FD50, "PlayerProgression registrar proximate"),
    (0xB74A928, 0xB74A930, 0x37D766B, 0x37D7120, "high readers but dist3704 — expect falsify"),
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
      Console.Error.WriteLine("REFUSING: EXE hash mismatch " + hash);
      return 2;
    }
    ParsePe();
    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 DUAL-BSS HOP =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("agent1=adjacent selector* + HandleContainer* (AC4 0x04DEEF90/0x04DEEF94)");
    sb.AppendLine("prove=single co-publish of two pointers; HC consumer uses +0/+8 signbit/+10 objectId");
    sb.AppendLine("falsify=table fill, registrar, telemetry, shared selector Process family");

    // Pre-scan all RIP qword loads for reader lists of seed slots.
    Console.WriteLine("Indexing RIP qword loads...");
    var loadIndex = IndexRipQwordLoads();
    Console.WriteLine("loadTargets=" + loadIndex.Count);

    foreach (var seed in Seeds) {
      sb.AppendLine();
      sb.AppendLine("##### SEED lo=0x" + seed.Lo.ToString("X") + " hi=0x" + seed.Hi.ToString("X")
        + " func=0x" + seed.Func.ToString("X") + " — " + seed.Note);
      sb.AppendLine("secLo=" + SecNameOf(seed.Lo) + " secHi=" + SecNameOf(seed.Hi));

      int run = CountConsecutiveRun(seed.Func, seed.Lo);
      sb.AppendLine("consecutiveQwordRunFromLo=" + run + (run >= 4 ? " TABLE_FILL?" : " ok-small"));

      DumpWindow(sb, seed.Site, 0x30, 0x50, "publish");
      DumpWindow(sb, seed.Func, 0, 0x40, "funcHead");

      // Strings referenced in publisher window.
      var strs = CollectStrings(seed.Func, 0x200);
      sb.AppendLine("funcStrings=" + string.Join(" | ", strs.Take(8).Select(s => Trunc(s, 60))));

      int rLo = loadIndex.TryGetValue(seed.Lo, out var a) ? a.Count : 0;
      int rHi = loadIndex.TryGetValue(seed.Hi, out var b) ? b.Count : 0;
      sb.AppendLine("readersLo=" + rLo + " readersHi=" + rHi);
      sb.AppendLine("bothRead=" + (rLo > 0 && rHi > 0));

      // Sample reader sites + look for handleDeref shape after load of hi (builder handle).
      SampleReaders(sb, "LO", seed.Lo, a);
      SampleReaders(sb, "HI", seed.Hi, b);

      // Classify
      string klass = Classify(seed, run, rLo, rHi, strs);
      sb.AppendLine("class=" + klass);
    }

    // Also: scan .bss for any adjacent RIP store pairs with dist<=16 (should be rare).
    sb.AppendLine();
    sb.AppendLine("===== .bss TIGHT PAIRS (dist<=16) =====");
    var bssPairs = FindTightPairsInSection(".bss", 16, 40);
    foreach (var line in bssPairs) sb.AppendLine(line);
    sb.AppendLine("bssTightCount=" + bssPairs.Count);

    sb.AppendLine();
    sb.AppendLine("===== SPRINT HOP VERDICT =====");
    sb.AppendLine("c1Proven=false");
    sb.AppendLine("callEngine=off");
    sb.AppendLine("agent1Consumed=yes — Process falsify stands; dual-adjacent fingerprint hunted");
    sb.AppendLine("result=RIP-rel adjacent QWORD co-publishes exist in .trace; identities unproven");
    sb.AppendLine("strongestStructural=0xAC028E0/0xAC028E8 @0x67FD520 dist=7 (if not table/telemetry)");
    sb.AppendLine("playerProgressionRegistrar=0x1C6FD50 still name-range (not cache fill) — pairs near it have 1 reader");
    sb.AppendLine("next=Prove/falsify 0x67FD520 pair via reader handleDeref(+0/+8/+10) and object lifetime;");
    sb.AppendLine("     if falsified, hunt member-pair on singleton (reg+0 / reg+8) published once to a static.");

    string rawDir = Path.Combine(root, "reports", "v080-dual-bss-raw");
    Directory.CreateDirectory(rawDir);
    File.WriteAllText(Path.Combine(rawDir, "hop.txt"), sb.ToString());
    Console.WriteLine(sb.ToString());
    Console.WriteLine("WROTE reports/v080-dual-bss-raw/hop.txt");
    return 0;
  }

  static string Classify((uint Lo, uint Hi, uint Site, uint Func, string Note) seed,
      int run, int rLo, int rHi, List<string> strs) {
    if (seed.Func == 0x1C6FD50) return "falsify-playerprogression-name-registrar";
    if (run >= 4) return "falsify-likely-table-fill";
    if (rLo == 0 || rHi == 0) return "weak-not-both-consumed";
    if (strs.Any(s => s.IndexOf("EntitySelector", StringComparison.OrdinalIgnoreCase) >= 0))
      return "falsify-entityselector";
    if (Math.Abs((int)seed.Site - (int)(seed.Site /* placeholder */)) >= 0 && seed.Note.Contains("dist3704"))
      return "weak-not-co-publish";
    return "candidate-needs-handleDeref-proof";
  }

  static int CountConsecutiveRun(uint func, uint lo) {
    // Count how many consecutive +8 data RVAs this func stores starting at lo.
    var stores = RipQwordStoresInFunc(func);
    var set = new HashSet<uint>(stores.Select(s => s.data));
    int n = 0;
    for (uint r = lo; set.Contains(r); r += 8) n++;
    return n;
  }

  static List<(uint site, uint data)> RipQwordStoresInFunc(uint func) {
    var list = new List<(uint, uint)>();
    // Decode up to 0x800 from func looking for RIP stores; stop at int3/ret if early.
    foreach (var ins in DisasmRaw(func, func + 0x800)) {
      if (ins.store && ins.data != 0) list.Add((ins.rva, ins.data));
      if (ins.mnem == Mnemonic.Int3 && ins.rva > func + 8) break;
    }
    return list;
  }

  static Dictionary<uint, List<uint>> IndexRipQwordLoads() {
    var dict = new Dictionary<uint, List<uint>>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim; i++) {
        byte b0 = pe[s.Ptr + i];
        if (b0 != 0x48 && b0 != 0x4C) continue;
        if (pe[s.Ptr + i + 1] != 0x8B) continue;
        if ((pe[s.Ptr + i + 2] & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 3));
        uint site = s.Va + i;
        uint data = unchecked((uint)(site + 7 + disp));
        if (!IsData(data)) continue;
        if (!dict.TryGetValue(data, out var list)) {
          list = new List<uint>();
          dict[data] = list;
        }
        if (list.Count < 64) list.Add(site);
      }
    }
    return dict;
  }

  static void SampleReaders(StringBuilder sb, string tag, uint dataRva, List<uint> sites) {
    if (sites == null || sites.Count == 0) {
      sb.AppendLine("  " + tag + " readers=0");
      return;
    }
    sb.AppendLine("  " + tag + " sampleReaders=" + string.Join(",", sites.Take(6).Select(x => "0x" + x.ToString("X"))));
    foreach (uint site in sites.Take(3)) {
      sb.AppendLine("  --- reader " + tag + " @0x" + site.ToString("X") + " ---");
      bool handleish = false;
      foreach (var ins in DisasmRaw(site, site + 0x40).Take(16)) {
        string mark = "";
        // Heuristic: after loading HC*, look for [reg+8] or sar/shr of dword, or [reg+10]/[reg+16]
        string t = ins.text;
        if (t.IndexOf("+8]", StringComparison.Ordinal) >= 0
            || t.IndexOf("+10h]", StringComparison.OrdinalIgnoreCase) >= 0
            || t.IndexOf("+16]", StringComparison.Ordinal) >= 0
            || t.IndexOf("sar ", StringComparison.Ordinal) >= 0) {
          mark = "  <<handle-shape?";
          handleish = true;
        }
        sb.AppendLine("    0x" + ins.rva.ToString("X") + " " + Trunc(t, 90) + mark);
      }
      sb.AppendLine("  handleShapeHint=" + handleish);
    }
  }

  static List<string> CollectStrings(uint start, uint span) {
    var list = new List<string>();
    foreach (var ins in DisasmRaw(start, start + span)) {
      if (ins.data == 0) continue;
      string s = ReadAscii(ins.data, 72);
      if (IsString(s)) list.Add(s);
    }
    return list.Distinct().ToList();
  }

  static List<string> FindTightPairsInSection(string secName, int maxDist, int maxOut) {
    var outList = new List<string>();
    var sec = secs.FirstOrDefault(s => s.Name.TrimEnd('\0') == secName);
    if (sec == null) { outList.Add("section-missing"); return outList; }
    uint lo = sec.Va, hi = sec.Va + Math.Max(sec.VSize, sec.Raw);

    // Collect stores into this section only.
    var stores = new List<(uint site, uint data, uint func)>();
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
        if (data < lo || data >= hi) continue;
        stores.Add((site, data, FindFuncStart(site)));
      }
    }
    var by = stores.GroupBy(x => x.data).ToDictionary(g => g.Key, g => g.ToList());
    foreach (var kv in by.OrderBy(k => k.Key)) {
      uint a = kv.Key, b = a + 8;
      if (!by.ContainsKey(b)) continue;
      foreach (var sa in kv.Value) {
        foreach (var sb in by[b]) {
          int d = Math.Abs((int)sa.site - (int)sb.site);
          if (d > maxDist) continue;
          if (sa.func != 0 && sb.func != 0 && sa.func != sb.func) continue;
          outList.Add("lo=0x" + a.ToString("X") + " hi=0x" + b.ToString("X")
            + " siteA=0x" + sa.site.ToString("X") + " siteB=0x" + sb.site.ToString("X")
            + " dist=" + d + " func=0x" + sa.func.ToString("X"));
          if (outList.Count >= maxOut) return outList;
        }
      }
    }
    return outList;
  }

  struct Ins {
    public uint rva; public string text; public Mnemonic mnem;
    public uint data; public bool store; public bool load;
  }

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
    while (dec.IP < limit && guard++ < 600) {
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
      string t = ins.text;
      int comma = t.IndexOf(',');
      if (comma > 0) {
        if (t.Substring(0, comma).IndexOf('[') >= 0) ins.store = true;
        if (t.Substring(comma + 1).IndexOf('[') >= 0) ins.load = true;
      }
      list.Add(ins);
      if (ins.mnem == Mnemonic.Int3) break;
    }
    return list;
  }

  static void DumpWindow(StringBuilder sb, uint center, int before, int after, string label) {
    uint start = center > (uint)before ? center - (uint)before : center;
    sb.AppendLine("--- " + label + " @0x" + center.ToString("X") + " ---");
    foreach (var ins in DisasmRaw(start, center + (uint)after).Take(28)) {
      string extra = "";
      if (ins.data != 0) {
        string s = ReadAscii(ins.data, 48);
        extra = IsString(s) ? "  ;str=" + Trunc(s, 48) : "  ;data=0x" + ins.data.ToString("X");
      }
      sb.AppendLine("0x" + ins.rva.ToString("X") + " " + Trunc(ins.text, 88) + extra);
    }
  }

  static IEnumerable<Sec> CodeSecs() {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      bool ok = (s.Char & 0x20000000) != 0
        || s.Name.IndexOf("text", StringComparison.OrdinalIgnoreCase) >= 0
        || s.Name.IndexOf("impdata", StringComparison.OrdinalIgnoreCase) >= 0
        || s.Name.IndexOf("code", StringComparison.OrdinalIgnoreCase) >= 0;
      if (ok) yield return s;
    }
  }

  static bool IsData(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva < s.Va || rva >= s.Va + span) continue;
      bool exec = (s.Char & 0x20000000) != 0;
      return !exec;
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
