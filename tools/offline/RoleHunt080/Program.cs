// v0.8.0 — C1 role hunt after Agent1 shape reply:
//   Hunt two long-lived pointer roles (Duplicate-this + handle/objectId),
//   NOT "RIP-rel adjacent .bss pair" as a hard requirement.
// Read-only PE. callEngine=off.
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

  static readonly string[] Needles = {
    "Duplicate", "Duplication", "DuplicationManager", "RowSelector",
    "EntityBuilder", "BuildEntityWithSelector", "CreateReference",
    "AddLoadTask", "ObjectID", "HandleContainer", "ManagedObject"
  };

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);
  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }

  sealed class Hit {
    public uint Global; public uint LoadSite; public uint UseSite;
    public string Kind; public uint Func; public string Snippet;
  }

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
    sb.AppendLine("===== v0.8.0 C1 ROLE HUNT (Duplicate-this + handle/objectId) =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("agent1Shape=freestanding adjacent absolute reads proven in AC4; fill shape unknown");
    sb.AppendLine("hunt=long-lived roles, not adjacent-.bss hard requirement");
    sb.AppendLine("callEngine=off");

    // 1) String presence
    sb.AppendLine();
    sb.AppendLine("===== STRINGS =====");
    foreach (string n in Needles) {
      var hits = FindAscii(n);
      string first = hits.Count > 0
        ? " first=" + string.Join(",", hits.Take(4).Select(x => "0x" + x.ToString("X")))
        : " ABSENT";
      sb.AppendLine(n + " count=" + hits.Count + first);
    }

    // 2) handle/objectId role: RIP load of global G, then within window use [reg+10h]
    //    or handleDeref-ish [reg]/[reg+8] sar, then [reg+10h].
    Console.WriteLine("Scanning handle/objectId role sites...");
    var oidHits = ScanObjectIdRole(maxSites: 8000);
    sb.AppendLine();
    sb.AppendLine("===== HANDLE/OBJECTID ROLE (RIP global -> +0x10 use) =====");
    sb.AppendLine("rawHits=" + oidHits.Count);

    Console.WriteLine("Indexing RIP qword stores...");
    var storeIndex = BuildStoreIndex();
    Console.WriteLine("storeTargets=" + storeIndex.Count);

    var byGlobal = oidHits.GroupBy(h => h.Global)
      .Select(g => new {
        G = g.Key,
        Count = g.Count(),
        Sites = g.Select(x => x.LoadSite).Distinct().Take(8).ToList(),
        Funcs = g.Select(x => x.Func).Where(f => f != 0).Distinct().Take(8).ToList(),
        Sec = SecNameOf(g.Key),
        Writers = storeIndex.TryGetValue(g.Key, out var ws) ? ws.Count : 0
      })
      .OrderBy(x => x.Writers)
      .ThenByDescending(x => x.Count)
      .ToList();

    sb.AppendLine("uniqueGlobals=" + byGlobal.Count);
    sb.AppendLine("--- top few-writer objectId globals ---");
    foreach (var g in byGlobal.Where(x => x.Writers <= 3).Take(30)) {
      string loads = string.Join(",", g.Sites.Select(s => "0x" + s.ToString("X")));
      string funcs = string.Join(",", g.Funcs.Select(s => "0x" + s.ToString("X")));
      sb.AppendLine("G=0x" + g.G.ToString("X") + " readers=" + g.Count
        + " writers=" + g.Writers + " sec=" + g.Sec
        + " loads=" + loads + " funcs=" + funcs);
    }

    // Deep dump top 8 few-writer
    sb.AppendLine();
    sb.AppendLine("===== DISASM TOP OBJECTID GLOBALS =====");
    foreach (var g in byGlobal.Where(x => x.Writers <= 2 && x.Count >= 2).Take(8)) {
      sb.AppendLine("### G=0x" + g.G.ToString("X") + " writers=" + g.Writers + " readers=" + g.Count);
      var sample = oidHits.First(h => h.Global == g.G);
      DumpWindow(sb, sample.LoadSite, 0x10, 0x50, "oid-use");
      // writers
      List<uint> wlist = storeIndex.TryGetValue(g.G, out var wl) ? wl : new List<uint>();
      foreach (uint ws in wlist.Take(4)) {
        DumpWindow(sb, ws, 0x20, 0x30, "writer");
        var strs = CollectStrings(FindFuncStart(ws), 0x100);
        sb.AppendLine("  writerStrings=" + string.Join(" | ", strs.Take(5).Select(s => Trunc(s, 48))));
      }
    }

    // 3) Duplicate(0,0) shape: mov edx,0 / xor edx,edx; xor r8d,r8d; call near — with rcx from RIP global
    Console.WriteLine("Scanning Duplicate(0,0)-shaped calls...");
    var dupHits = ScanDuplicateZeroZero(max: 4000);
    sb.AppendLine();
    sb.AppendLine("===== DUPLICATE(0,0)-SHAPED CALLS (rcx from RIP global) =====");
    sb.AppendLine("rawHits=" + dupHits.Count);
    var dupBy = dupHits.GroupBy(h => h.Global)
      .Select(g => new {
        G = g.Key,
        Count = g.Count(),
        Callees = g.Select(x => x.UseSite).Distinct().Take(6).ToList(),
        Writers = storeIndex.TryGetValue(g.Key, out var ws2) ? ws2.Count : 0,
        Sec = SecNameOf(g.Key)
      })
      .OrderBy(x => x.Writers).ThenByDescending(x => x.Count).ToList();
    foreach (var g in dupBy.Where(x => x.Writers <= 4).Take(24)) {
      string callees = string.Join(",", g.Callees.Select(c => "0x" + c.ToString("X")));
      sb.AppendLine("selG=0x" + g.G.ToString("X") + " calls=" + g.Count
        + " writers=" + g.Writers + " sec=" + g.Sec + " callees=" + callees);
    }
    sb.AppendLine();
    sb.AppendLine("===== DISASM TOP DUPLICATE-SHAPED =====");
    foreach (var g in dupBy.Where(x => x.Writers <= 2).Take(6)) {
      var sample = dupHits.First(h => h.Global == g.G);
      DumpWindow(sb, sample.LoadSite, 0x20, 0x40, "dup-call");
      // callee head
      if (sample.UseSite != 0)
        DumpWindow(sb, sample.UseSite, 0, 0x40, "callee");
    }

    // 4) Intersection: globals that appear in BOTH roles (unlikely but strong)
    var oidSet = new HashSet<uint>(byGlobal.Select(x => x.G));
    var dupSet = new HashSet<uint>(dupBy.Select(x => x.G));
    var both = oidSet.Intersect(dupSet).ToList();
    sb.AppendLine();
    sb.AppendLine("===== INTERSECTION (same global in oid-role AND dup-role) =====");
    sb.AppendLine("count=" + both.Count);
    foreach (uint g in both.Take(12))
      sb.AppendLine("G=0x" + g.ToString("X"));

    // Also: pair of distinct globals used in same function — one oid-role load, one dup-role load
    sb.AppendLine();
    sb.AppendLine("===== SAME-FUNC PAIR (dup-global + oid-global) =====");
    var oidFunc = oidHits.GroupBy(h => h.Func).ToDictionary(g => g.Key, g => g.Select(x => x.Global).Distinct().ToList());
    var dupFunc = dupHits.GroupBy(h => h.Func).ToDictionary(g => g.Key, g => g.Select(x => x.Global).Distinct().ToList());
    int pairs = 0;
    foreach (var kv in dupFunc) {
      if (kv.Key == 0 || !oidFunc.ContainsKey(kv.Key)) continue;
      foreach (uint dg in kv.Value) {
        foreach (uint og in oidFunc[kv.Key]) {
          if (dg == og) continue;
          int dw = storeIndex.TryGetValue(dg, out var dws) ? dws.Count : 0;
          int ow = storeIndex.TryGetValue(og, out var ows) ? ows.Count : 0;
          sb.AppendLine("func=0x" + kv.Key.ToString("X") + " dupG=0x" + dg.ToString("X")
            + " oidG=0x" + og.ToString("X")
            + " dupWriters=" + dw + " oidWriters=" + ow);
          pairs++;
          if (pairs >= 40) break;
        }
        if (pairs >= 40) break;
      }
      if (pairs >= 40) break;
    }
    sb.AppendLine("sameFuncPairsListed=" + pairs);

    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    bool haveOid = byGlobal.Any(x => x.Writers <= 2 && x.Count >= 2);
    bool haveDup = dupBy.Any(x => x.Writers <= 2);
    bool havePair = pairs > 0;
    sb.AppendLine("objectIdRoleCandidates=" + byGlobal.Count(x => x.Writers <= 2 && x.Count >= 2));
    sb.AppendLine("duplicateRoleCandidates=" + dupBy.Count(x => x.Writers <= 2));
    sb.AppendLine("sameFuncDupPlusOidPairs=" + pairs);
    sb.AppendLine("c1Proven=false");
    sb.AppendLine("callEngine=off");
    if (havePair) {
      sb.AppendLine("decision=same-func dupG+oidG pairs found — identity unproven");
      sb.AppendLine("next=Disasm strongest few-writer pair; prove oidG is HandleContainer* via +0/+8/+10;");
      sb.AppendLine("     prove dupG thiscall returns consumable selector clone inside Begin/End scope.");
    } else if (haveOid || haveDup) {
      sb.AppendLine("decision=role candidates found separately — no same-func pair yet");
      sb.AppendLine("next=Widen same-func window to callers-of-callers; or match by shared publisher func.");
    } else {
      sb.AppendLine("decision=no strong few-writer role candidates under current heuristics");
      sb.AppendLine("next=Relax writer cap; include member HC at fixed object offsets; Ask Agent1 Duplicate vtable slot.");
    }

    string dir = Path.Combine(root, "reports", "v080-role-hunt-raw");
    Directory.CreateDirectory(dir);
    File.WriteAllText(Path.Combine(dir, "evidence.txt"), sb.ToString());
    WriteJson(root, hash, byGlobal.Take(20).Select(x => (object)new Dictionary<string, object> {
      ["g"] = "0x" + x.G.ToString("X"), ["readers"] = x.Count, ["writers"] = x.Writers, ["sec"] = x.Sec
    }).ToList(), dupBy.Take(20).Select(x => (object)new Dictionary<string, object> {
      ["g"] = "0x" + x.G.ToString("X"), ["calls"] = x.Count, ["writers"] = x.Writers, ["sec"] = x.Sec
    }).ToList(), pairs);
    Console.WriteLine(string.Join("\n", sb.ToString().Split('\n').Take(40)));
    Console.WriteLine("WROTE reports/v080-role-hunt-raw/evidence.txt");
    return 0;
  }

  static List<Hit> ScanObjectIdRole(int maxSites) {
    var hits = new List<Hit>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim && hits.Count < maxSites; i++) {
        byte b0 = pe[s.Ptr + i];
        if (b0 != 0x48 && b0 != 0x4C) continue;
        if (pe[s.Ptr + i + 1] != 0x8B) continue;
        if ((pe[s.Ptr + i + 2] & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 3));
        uint site = s.Va + i;
        uint data = unchecked((uint)(site + 7 + disp));
        if (!IsData(data)) continue;
        // Which reg was loaded into?
        int reg = ((pe[s.Ptr + i + 2] >> 3) & 7) + (((b0 & 4) != 0) ? 8 : 0);
        // Decode following window for [reg+10h] or [reg+16]
        if (WindowUsesOid(site + 7, 0x60, reg)) {
          hits.Add(new Hit {
            Global = data, LoadSite = site, UseSite = site,
            Kind = "objectId", Func = FindFuncStart(site)
          });
        }
      }
    }
    return hits;
  }

  static bool WindowUsesOid(uint start, uint span, int reg) {
    string rn = RegName(reg);
    foreach (var ins in DisasmRaw(start, start + span).Take(28)) {
      string t = ins.text;
      // [rax+10h] / [rax+16] etc — match loaded reg family (rax/eax)
      if (t.IndexOf("[" + rn + "+10h]", StringComparison.OrdinalIgnoreCase) >= 0) return true;
      if (t.IndexOf("[" + rn + "+16]", StringComparison.Ordinal) >= 0) return true;
      // Also allow after mov rbx,rax then [rbx+10h]
      if (ins.mnem == Mnemonic.Mov && t.StartsWith("mov ", StringComparison.Ordinal)
          && t.IndexOf("," + rn, StringComparison.OrdinalIgnoreCase) < 0
          && t.IndexOf(", " + rn, StringComparison.OrdinalIgnoreCase) >= 0) {
        // moved to another reg — crude: continue and also accept any +10h in window
      }
      if (t.IndexOf("+10h]", StringComparison.OrdinalIgnoreCase) >= 0) return true;
    }
    return false;
  }

  static List<Hit> ScanDuplicateZeroZero(int max) {
    var hits = new List<Hit>();
    // Fast prefilter: window before E8 must contain xor edx,edx (33 D2 / 31 D2)
    // and xor r8d,r8d (45 33 C0 / 45 31 C0), then decode.
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0x30; i + 5 <= lim && hits.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        bool zEdx = false, zR8 = false;
        for (uint j = i - 0x30; j + 1 < i; j++) {
          byte a = pe[s.Ptr + j], b = pe[s.Ptr + j + 1];
          if ((a == 0x33 || a == 0x31) && b == 0xD2) zEdx = true;
          if (a == 0x45 && (b == 0x33 || b == 0x31) && j + 2 < i && pe[s.Ptr + j + 2] == 0xC0)
            zR8 = true;
        }
        if (!zEdx || !zR8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        uint site = s.Va + i;
        uint callee = unchecked((uint)(site + 5 + rel));
        uint back = site - 0x30;
        uint ripGlobal = 0, loadSite = 0;
        foreach (var ins in DisasmRaw(back, site)) {
          string t = ins.text.Replace(" ", "").ToLowerInvariant();
          if (ins.loadRip && ins.data != 0 && t.StartsWith("movrcx,")) {
            if (IsData(ins.data)) { ripGlobal = ins.data; loadSite = ins.rva; }
          }
        }
        if (ripGlobal != 0) {
          hits.Add(new Hit {
            Global = ripGlobal, LoadSite = loadSite != 0 ? loadSite : site,
            UseSite = callee, Kind = "dup00", Func = FindFuncStart(site)
          });
        }
      }
    }
    return hits;
  }

  static Dictionary<uint, List<uint>> BuildStoreIndex() {
    var dict = new Dictionary<uint, List<uint>>();
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
        if (!dict.TryGetValue(data, out var list)) {
          list = new List<uint>();
          dict[data] = list;
        }
        if (list.Count < 32) list.Add(site);
      }
    }
    return dict;
  }

  struct Ins {
    public uint rva; public string text; public Mnemonic mnem;
    public uint data; public bool loadRip;
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
    while (dec.IP < limit && guard++ < 400) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      var ins = new Ins { rva = (uint)(raw.IP - imageBase), text = o.ToString(), mnem = raw.Mnemonic };
      for (int oi = 0; oi < raw.OpCount; oi++) {
        if (raw.GetOpKind(oi) != OpKind.Memory || !raw.IsIPRelativeMemoryOperand) continue;
        ulong va = raw.IPRelativeMemoryAddress;
        if (va >= imageBase) { ins.data = (uint)(va - imageBase); ins.loadRip = true; }
      }
      list.Add(ins);
      if (ins.mnem == Mnemonic.Int3) break;
    }
    return list;
  }

  static void DumpWindow(StringBuilder sb, uint center, int before, int after, string label) {
    uint start = center > (uint)before ? center - (uint)before : center;
    sb.AppendLine("--- " + label + " @0x" + center.ToString("X") + " ---");
    foreach (var ins in DisasmRaw(start, center + (uint)after).Take(24)) {
      string extra = "";
      if (ins.data != 0) {
        string s = ReadAscii(ins.data, 40);
        extra = IsString(s) ? "  ;str=" + Trunc(s, 40) : "  ;data=0x" + ins.data.ToString("X");
      }
      sb.AppendLine("0x" + ins.rva.ToString("X") + " " + Trunc(ins.text, 88) + extra);
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

  static void WriteJson(string root, string hash, List<object> oidTop, List<object> dupTop, int pairs) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.8.0\",");
    sb.AppendLine("  \"contract\": \"C1\",");
    sb.AppendLine("  \"mode\": \"offline-pe-readonly\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"agent1Shape\": \"roles not adjacent-bss-hard-requirement\",");
    sb.AppendLine("  \"c1Proven\": false,");
    sb.AppendLine("  \"callEngine\": false,");
    sb.AppendLine("  \"sameFuncDupPlusOidPairs\": " + pairs);
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-role-hunt.json"), sb.ToString());
  }

  static string RegName(int reg) {
    string[] names = { "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15" };
    return names[reg];
  }

  static List<uint> FindAscii(string needle) {
    var hits = new List<uint>();
    byte[] pat = Encoding.ASCII.GetBytes(needle);
    int from = 0, guard = 0;
    while (from < pe.Length && guard++ < 48) {
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
