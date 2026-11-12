// v0.8.0 — Offline: dual adjacent static/BSS pointer publish hunt (C1).
// Agent 1 fingerprint (AC4Coop PlayerProgression.h @ 68355c71):
//   GetCachedSelector()      -> *(RowSelector**)0x04DEEF90
//   GetCachedBuilderHandle() -> *(HandleContainer**)0x04DEEF94
// On x86 those are adjacent 4-byte pointers. On Resynced x64 hunt adjacent
// QWORD RIP-relative stores (delta 8) into non-exec data, NOT EntitySelector tables.
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

  // Already falsified as C1 owner — demote pairs that land in these ranges.
  static readonly (uint Lo, uint Hi, string Tag)[] ExcludeRanges = {
    (0x919F9B0, 0x919FA60, "EntitySelectorMethodTables"),
    (0x7CA9B70, 0x7CA9C00, "SharedSelectorProcess"),
  };

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);

  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }
  sealed class Store {
    public uint Site; public uint DataRva; public int Size; public string Text; public uint Func;
  }
  sealed class Pair {
    public uint Lo; public uint Hi; public uint SiteA; public uint SiteB;
    public uint Func; public int Dist; public int Writers; public int Readers;
    public string SecName; public bool Excluded; public string ExTag;
    public List<uint> WriteSites = new List<uint>();
    public List<uint> ReadSites = new List<uint>();
  }

  static int Main(string[] args) {
    string exe = args.Length > 0
      ? args[0]
      : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1
      ? args[1]
      : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha256Hex(pe);
    Console.WriteLine("exeSha256=" + hash);
    if (!hash.Equals(ExpectedExeSha, StringComparison.OrdinalIgnoreCase)) {
      Console.Error.WriteLine("REFUSING: EXE hash mismatch.");
      return 2;
    }
    ParsePe();
    string rawDir = Path.Combine(root, "reports", "v080-dual-bss-raw");
    Directory.CreateDirectory(rawDir);
    Directory.CreateDirectory(Path.Combine(root, "reports"));

    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 DUAL ADJACENT BSS POINTER PUBLISH =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("agent1Fingerprint=AC4 PlayerProgression.h adjacent 0x04DEEF90/0x04DEEF94");
    sb.AppendLine("resyncedHunt=RIP-rel QWORD stores to DataRva and DataRva+8");
    sb.AppendLine("callEngine=off");

    Console.WriteLine("Scanning RIP-rel QWORD stores...");
    var stores = ScanRipQwordStores();
    Console.WriteLine("qwordStores=" + stores.Count);
    sb.AppendLine("qwordStores=" + stores.Count);

    Console.WriteLine("Scanning RIP-rel QWORD loads...");
    var loads = ScanRipQwordLoads();
    Console.WriteLine("qwordLoads=" + loads.Count);
    sb.AppendLine("qwordLoads=" + loads.Count);

    var pairs = BuildPairs(stores, loads);
    Console.WriteLine("adjacentPairs=" + pairs.Count);
    sb.AppendLine("adjacentPairs=" + pairs.Count);

    var ranked = pairs
      .OrderBy(p => p.Excluded ? 1 : 0)
      .ThenBy(p => p.Writers)
      .ThenByDescending(p => p.Readers)
      .ThenBy(p => p.Dist)
      .ThenBy(p => p.Lo)
      .ToList();

    sb.AppendLine();
    sb.AppendLine("===== TOP CANDIDATES (few writers, many readers, not EntitySelector) =====");
    foreach (var p in ranked.Take(40)) {
      sb.AppendLine(FormatPair(p));
    }

    sb.AppendLine();
    sb.AppendLine("===== SINGLE-WRITER PAIRS (strongest publish shape) =====");
    var single = ranked.Where(p => !p.Excluded && p.Writers == 1).Take(24).ToList();
    foreach (var p in single)
      sb.AppendLine(FormatPair(p));
    sb.AppendLine("singleWriterCount=" + ranked.Count(p => !p.Excluded && p.Writers == 1));

    // Deep-decode windows for top non-excluded single/few-writer pairs.
    sb.AppendLine();
    sb.AppendLine("===== DISASM WINDOWS (top 12 non-excluded) =====");
    var deep = ranked.Where(p => !p.Excluded).Take(12).ToList();
    foreach (var p in deep) {
      uint center = p.SiteA;
      DumpWindow(sb, center, 0x40, 0x80, "pair lo=0x" + p.Lo.ToString("X"));
      // Nearby string LEAs in the function (cheap: decode around func start if known).
      if (p.Func != 0 && p.Func != center)
        DumpWindow(sb, p.Func, 0x0, 0x60, "func=0x" + p.Func.ToString("X"));
    }

    // Cross-check: any pair near PlayerProgression / LocalPlayer / StartupPlayer string LEAs?
    sb.AppendLine();
    sb.AppendLine("===== STRING PROXIMITY (PlayerProgression/LocalPlayer/StartupPlayerSpawner) =====");
    string[] needles = {
      "PlayerProgression", "LocalPlayer", "StartupPlayerSpawner",
      "LoadEntityBuilder", "RowSelector", "EntityBuilder"
    };
    foreach (string n in needles) {
      var hits = FindAscii(n);
      sb.AppendLine(n + " hits=" + hits.Count);
      foreach (uint rva in hits.Take(6)) {
        var leas = FindLeaTo(rva, 12);
        sb.AppendLine("  str=0x" + rva.ToString("X") + " leas=" + leas.Count);
        foreach (uint site in leas.Take(4)) {
          uint fs = FindFuncStart(site);
          var near = ranked.Where(p => !p.Excluded &&
            (Math.Abs((int)p.Func - (int)fs) < 0x40 || Math.Abs((int)p.SiteA - (int)site) < 0x200
             || Math.Abs((int)p.SiteB - (int)site) < 0x200)).Take(4).ToList();
          sb.AppendLine("    lea=0x" + site.ToString("X") + " func=0x" + fs.ToString("X")
            + " nearPairs=" + near.Count);
          foreach (var np in near)
            sb.AppendLine("      " + FormatPair(np));
        }
      }
    }

    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    bool haveSingle = single.Count > 0;
    sb.AppendLine("dualAdjacentPublishCandidates=" + ranked.Count(p => !p.Excluded));
    sb.AppendLine("singleWriterPublishCandidates=" + single.Count);
    if (haveSingle) {
      var best = single[0];
      sb.AppendLine("bestLo=0x" + best.Lo.ToString("X"));
      sb.AppendLine("bestHi=0x" + best.Hi.ToString("X"));
      sb.AppendLine("bestSite=0x" + best.SiteA.ToString("X"));
      sb.AppendLine("bestFunc=0x" + best.Func.ToString("X"));
      sb.AppendLine("bestWriters=" + best.Writers + " bestReaders=" + best.Readers);
      sb.AppendLine("decision=dual-adjacent-publish-candidates-found-identity-unproven");
      sb.AppendLine("blocker=Need to prove which single-writer pair is selector*+HandleContainer*");
      sb.AppendLine("next=Disasm best publisher; follow HandleContainer* consumer that reads objectId (+0x10);");
      sb.AppendLine("     structural CreateReference/load-task by handle layout, not string names.");
    } else if (ranked.Any(p => !p.Excluded)) {
      sb.AppendLine("decision=multi-writer-adjacent-pairs-only-identity-unproven");
      sb.AppendLine("blocker=No single-writer adjacent QWORD pair; may be member stores not statics,");
      sb.AppendLine("        or stores via register-indirect (not RIP-rel).");
      sb.AppendLine("next=Inspect fewest-writer pairs; also scan for mov [reg+disp],reg of two +0/+8");
      sb.AppendLine("     into a static object that itself is published once.");
    } else {
      sb.AppendLine("decision=no-rip-rel-adjacent-qword-publish-found");
      sb.AppendLine("blocker=AC4-style adjacent static pointer pair not present as RIP-rel QWORD stores.");
      sb.AppendLine("next=Hunt absolute imm64 movs, or member-field pair on a singleton object.");
    }
    sb.AppendLine("c1Proven=false");
    sb.AppendLine("callEngine=off");

    string evidence = sb.ToString();
    File.WriteAllText(Path.Combine(rawDir, "evidence.txt"), evidence);
    WriteJson(root, hash, ranked, single);
    // Keep console short: summary + top 8
    Console.WriteLine(string.Join("\n", evidence.Split('\n').Take(20)));
    Console.WriteLine("--- top ---");
    foreach (var p in ranked.Where(x => !x.Excluded).Take(8))
      Console.WriteLine(FormatPair(p));
    Console.WriteLine("WROTE " + Path.Combine(rawDir, "evidence.txt"));
    return 0;
  }

  static string FormatPair(Pair p) {
    return "lo=0x" + p.Lo.ToString("X") + " hi=0x" + p.Hi.ToString("X")
      + " delta=8 siteA=0x" + p.SiteA.ToString("X") + " siteB=0x" + p.SiteB.ToString("X")
      + " dist=" + p.Dist + " func=0x" + p.Func.ToString("X")
      + " writers=" + p.Writers + " readers=" + p.Readers
      + " sec=" + p.SecName
      + (p.Excluded ? " EXCLUDE=" + p.ExTag : "");
  }

  static List<Store> ScanRipQwordStores() {
    var list = new List<Store>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim; i++) {
        byte b0 = pe[s.Ptr + i];`n        // REX.W required for QWORD GPR store`n        if (b0 != 0x48 && b0 != 0x4C) continue;
        if (pe[s.Ptr + i + 1] != 0x89) continue;
        byte modrm = pe[s.Ptr + i + 2];
        if ((modrm & 0xC7) != 0x05) continue; // [rip+disp32]
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 3));
        uint site = s.Va + i;
        uint len = 7;
        uint data = unchecked((uint)(site + len + disp));
        if (!IsWritableData(data)) continue;
        list.Add(new Store {
          Site = site, DataRva = data, Size = 8,
          Text = "mov [rip+d],r64", Func = 0
        });
      }
    }
    // Assign func starts in a second pass (cheap approximate).
    foreach (var st in list)
      st.Func = FindFuncStart(st.Site);
    return list;
  }

  static List<Store> ScanRipQwordLoads() {
    var list = new List<Store>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim; i++) {
        byte b0 = pe[s.Ptr + i];
        if (b0 != 0x48 && b0 != 0x4C) continue;
        // mov r64, [rip+disp] = 8B /r with modrm rip
        if (pe[s.Ptr + i + 1] != 0x8B) continue;
        byte modrm = pe[s.Ptr + i + 2];
        if ((modrm & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 3));
        uint site = s.Va + i;
        uint data = unchecked((uint)(site + 7 + disp));
        if (!IsWritableData(data)) continue;
        list.Add(new Store {
          Site = site, DataRva = data, Size = 8,
          Text = "mov r64,[rip+d]", Func = FindFuncStart(site)
        });
      }
    }
    return list;
  }

  static List<Pair> BuildPairs(List<Store> stores, List<Store> loads) {
    var byRva = stores.GroupBy(s => s.DataRva).ToDictionary(g => g.Key, g => g.ToList());
    var loadBy = loads.GroupBy(s => s.DataRva).ToDictionary(g => g.Key, g => g.ToList());
    var pairs = new List<Pair>();
    var seen = new HashSet<ulong>();

    foreach (var kv in byRva) {
      uint lo = kv.Key;
      uint hi = lo + 8;
      if (!byRva.ContainsKey(hi)) continue;
      ulong key = ((ulong)lo << 32) | hi;
      if (!seen.Add(key)) continue;

      var a = kv.Value;
      var b = byRva[hi];
      // Prefer same-function co-publish; fall back to closest site pair.
      uint bestA = a[0].Site, bestB = b[0].Site, bestFunc = a[0].Func;
      int bestDist = int.MaxValue;
      foreach (var sa in a) {
        foreach (var sb in b) {
          int d = Math.Abs((int)sa.Site - (int)sb.Site);
          bool sameFunc = sa.Func != 0 && sa.Func == sb.Func;
          int score = sameFunc ? d : d + 0x100000;
          if (score < bestDist) {
            bestDist = score;
            bestA = sa.Site; bestB = sb.Site;
            bestFunc = sameFunc ? sa.Func : (d < 0x40 ? sa.Func : 0);
          }
        }
      }

      var writeSites = a.Select(x => x.Site).Concat(b.Select(x => x.Site)).Distinct().OrderBy(x => x).ToList();
      // "Writers" = distinct functions that store either slot (publish fan-in).
      int writers = a.Select(x => x.Func).Concat(b.Select(x => x.Func)).Where(f => f != 0).Distinct().Count();
      if (writers == 0) writers = writeSites.Count;

      int readers = 0;
      var readSites = new List<uint>();
      if (loadBy.TryGetValue(lo, out var la)) { readers += la.Count; readSites.AddRange(la.Select(x => x.Site)); }
      if (loadBy.TryGetValue(hi, out var lb)) { readers += lb.Count; readSites.AddRange(lb.Select(x => x.Site)); }

      string secName = SecNameOf(lo);
      string exTag = null;
      bool ex = IsExcluded(lo, out exTag) || IsExcluded(hi, out exTag);

      pairs.Add(new Pair {
        Lo = lo, Hi = hi, SiteA = bestA, SiteB = bestB,
        Func = bestFunc, Dist = Math.Abs((int)bestA - (int)bestB),
        Writers = writers, Readers = readers,
        SecName = secName, Excluded = ex, ExTag = exTag ?? "",
        WriteSites = writeSites, ReadSites = readSites.Distinct().OrderBy(x => x).Take(24).ToList()
      });
    }
    return pairs;
  }

  static bool IsExcluded(uint rva, out string tag) {
    foreach (var r in ExcludeRanges) {
      if (rva >= r.Lo && rva < r.Hi) { tag = r.Tag; return true; }
    }
    tag = null;
    return false;
  }

  static void DumpWindow(StringBuilder sb, uint center, int before, int after, string label) {
    uint start = center > (uint)before ? center - (uint)before : center;
    uint end = center + (uint)after;
    sb.AppendLine("--- " + label + " center=0x" + center.ToString("X") + " ---");
    foreach (var line in DisasmLines(start, end).Take(40))
      sb.AppendLine(line);
  }

  static List<string> DisasmLines(uint start, uint endExclusive) {
    var list = new List<string>();
    int fo = RvaToFile(start);
    if (fo < 0) return list;
    var reader = new ByteArrayCodeReader(pe);
    reader.Position = fo;
    var dec = Decoder.Create(64, reader);
    dec.IP = imageBase + start;
    ulong limit = imageBase + endExclusive;
    int guard = 0;
    while (dec.IP < limit && guard++ < 200) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      uint rva = (uint)(raw.IP - imageBase);
      string extra = "";
      for (int oi = 0; oi < raw.OpCount; oi++) {
        if (raw.GetOpKind(oi) != OpKind.Memory || !raw.IsIPRelativeMemoryOperand) continue;
        ulong va = raw.IPRelativeMemoryAddress;
        if (va >= imageBase) {
          uint dr = (uint)(va - imageBase);
          string s = ReadAscii(dr, 64);
          extra = IsString(s) ? "  ;str=" + Trunc(s, 64) : "  ;data=0x" + dr.ToString("X");
        }
      }
      if (raw.FlowControl == FlowControl.Call && raw.NearBranchTarget != 0 && raw.NearBranchTarget >= imageBase)
        extra += "  ;call=0x" + ((uint)(raw.NearBranchTarget - imageBase)).ToString("X");
      list.Add("0x" + rva.ToString("X") + " " + Trunc(o.ToString(), 90) + extra);
      if (raw.Mnemonic == Mnemonic.Int3 || raw.Mnemonic == Mnemonic.Ret) break;
    }
    return list;
  }

  static void WriteJson(string root, string hash, List<Pair> ranked, List<Pair> single) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.8.0\",");
    sb.AppendLine("  \"mode\": \"offline-pe-readonly\",");
    sb.AppendLine("  \"contract\": \"C1\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"agent1Fingerprint\": \"AC4 PlayerProgression adjacent 0x04DEEF90/0x04DEEF94\",");
    sb.AppendLine("  \"c1Proven\": false,");
    sb.AppendLine("  \"callEngine\": false,");
    sb.AppendLine("  \"adjacentPairCount\": " + ranked.Count + ",");
    sb.AppendLine("  \"nonExcludedCount\": " + ranked.Count(p => !p.Excluded) + ",");
    sb.AppendLine("  \"singleWriterCount\": " + single.Count + ",");
    sb.AppendLine("  \"top\": [");
    var top = ranked.Where(p => !p.Excluded).Take(16).ToList();
    for (int i = 0; i < top.Count; i++) {
      var p = top[i];
      sb.Append("    {\"lo\": \"0x" + p.Lo.ToString("X") + "\", \"hi\": \"0x" + p.Hi.ToString("X")
        + "\", \"siteA\": \"0x" + p.SiteA.ToString("X") + "\", \"siteB\": \"0x" + p.SiteB.ToString("X")
        + "\", \"func\": \"0x" + p.Func.ToString("X") + "\", \"dist\": " + p.Dist
        + ", \"writers\": " + p.Writers + ", \"readers\": " + p.Readers
        + ", \"sec\": " + J(p.SecName) + "}");
      sb.AppendLine(i + 1 < top.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-dual-bss.json"), sb.ToString());
    Console.WriteLine("WROTE reports/v0.8.0-dual-bss.json");
  }

  static List<uint> FindAscii(string needle) {
    var hits = new List<uint>();
    byte[] pat = Encoding.ASCII.GetBytes(needle);
    int from = 0, guard = 0;
    while (from < pe.Length && guard++ < 32) {
      int at = pe.AsSpan(from).IndexOf(pat);
      if (at < 0) break;
      at += from;
      if (at > 0) {
        byte prev = pe[at - 1];
        if (prev != 0 && prev >= 32 && prev < 127) { from = at + 1; continue; }
      }
      uint rva = FileToRva(at);
      if (rva != 0) hits.Add(rva);
      from = at + pat.Length;
    }
    return hits;
  }

  static List<uint> FindLeaTo(uint target, int max) {
    var list = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim && list.Count < max; i++) {
        int off = 0;
        byte b0 = pe[s.Ptr + i];
        if (b0 == 0x48 || b0 == 0x4C || b0 == 0x49 || b0 == 0x4D) off = 1;
        if (pe[s.Ptr + i + off] != 0x8D) continue;
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

  static IEnumerable<Sec> CodeSecs() {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      bool ok = (s.Char & 0x20000000) != 0
        || s.Name.IndexOf("text", StringComparison.OrdinalIgnoreCase) >= 0;
      if (ok) yield return s;
    }
  }

  static bool IsWritableData(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva < s.Va || rva >= s.Va + span) continue;
      bool exec = (s.Char & 0x20000000) != 0
        || s.Name.IndexOf("text", StringComparison.OrdinalIgnoreCase) >= 0;
      if (exec) return false;
      // Prefer writable; accept any non-exec (BSS may be in .data/.bss).
      return true;
    }
    return false;
  }

  static string SecNameOf(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva >= s.Va && rva < s.Va + span) return s.Name;
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
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }

  static int RvaToFile(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva >= s.Va && rva < s.Va + span && s.Ptr > 0)
        return (int)s.Ptr + (int)(rva - s.Va);
    }
    return -1;
  }

  static uint FileToRva(int fileOff) {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      if (fileOff >= s.Ptr && fileOff < s.Ptr + s.Raw)
        return s.Va + (uint)(fileOff - s.Ptr);
    }
    return 0;
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
