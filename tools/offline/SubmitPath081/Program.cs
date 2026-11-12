// v0.8.0 follow-up — who submits SpawnNPCParams / SpawnPlayerParams.
// Read-only. Does not launch, inject, or write the game.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;

internal static class Program {
  const uint kNpcCopy = 0x5E3DB0;
  const uint kPlayerCopy = 0x21F5950;
  const uint kSharedCopy = 0x5E3DF0;
  const uint kDestHelper = 0x43DCB00;
  const uint kFieldVisitor = 0x1207200;
  const uint kHashRegister = 0x4572C60;
  const uint kNpcHash = 0x94D05600;
  const uint kPlayerHash = 0x51BA3541;
  const uint kNpcRecord = 0x92D1AA8;
  const uint kPlayerRecord = 0x92D1C68;

  static readonly Dictionary<uint, string> Known = new Dictionary<uint, string> {
    { 0x5E3DB0, "npc_params_copy" },
    { 0x21F5950, "player_params_copy" },
    { 0x5E3DF0, "shared_field_copy" },
    { 0x43DCB00, "dest_object_helper" },
    { 0x1207200, "field_visitor" },
    { 0x12071F0, "npc_field_thunk" },
    { 0x64099B0, "player_field_thunk" },
    { 0x53741F0, "empty_ret_slot" },
    { 0x80F23E0, "SpawnNPCParams_registrar" },
    { 0x80F2A20, "SpawnPlayerParams_registrar" },
    { 0x80F2330, "SpawnCharacterParams_registrar" },
    { 0x80F2580, "SpawnFirstPersonPlayerParams_registrar" },
    { 0x821ABC0, "SpawnPlayerBoatParams_registrar" },
    { 0x8E02960, "SpawnEntityBuilderParams_registrar" },
    { 0x8DFFB90, "SpawnEntityParams_registrar" },
    { 0x80F27E0, "SpawnInventoryParams_registrar" },
    { 0x4572C60, "type_name_hash_register" },
    { 0x4987180, "serializer_epilogue" }
  };

  static byte[] pe;
  static List<Sec> secs;
  static ulong imageBase;
  static readonly NasmFormatter Fmt = new NasmFormatter();

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080\reports";
    pe = File.ReadAllBytes(exe);
    ParsePe();
    Directory.CreateDirectory(outDir);
    Console.WriteLine("imageBase=" + H(imageBase));

    uint[] callTargets = new uint[] {
      kNpcCopy, kPlayerCopy, kSharedCopy, 0x12071F0, 0x64099B0, 0x80F23E0, 0x80F2A20
    };
    var callers = FindE8(callTargets, 4000);
    foreach (uint t in callTargets) {
      int n = 0;
      List<uint> list;
      if (callers.TryGetValue(t, out list)) n = list.Count;
      Console.WriteLine("e8 " + Name(t) + "=" + n);
    }

    var slots = new Dictionary<uint, List<long>>();
    uint[] ptrFns = new uint[] { kNpcCopy, kPlayerCopy, kSharedCopy, kFieldVisitor, 0x80F23E0, 0x80F2A20 };
    foreach (uint fn in ptrFns) slots[fn] = FindU64(imageBase + fn, 8);

    var ripTargets = new HashSet<uint> {
      kNpcRecord, kNpcRecord + 0x18, kPlayerRecord, kPlayerRecord + 0x18
    };
    foreach (var kv in slots) {
      foreach (long fo in kv.Value) {
        uint rva = FileToRva(fo);
        if (rva != 0) ripTargets.Add(rva);
      }
    }

    var hashHits = FindImm32(new uint[] { kNpcHash, kPlayerHash }, 64);
    foreach (var kv in hashHits) {
      Console.WriteLine("imm " + H(kv.Key) + "=" + kv.Value.Count);
      foreach (uint site in kv.Value) ripTargets.Add(site & ~3u);
    }

    var strings = CollectNeedles(new string[] {
      "BuildEntityWithSelector", "BuildEntity", "EntityBuilder", "AddEntity",
      "RowSelector", "DuplicationManager", "GetUnusedPadID", "Duplicate",
      "SpawnNPCParams", "SpawnPlayerParams"
    });
    foreach (var s in strings) ripTargets.Add(s.Rva);

    var ripHits = FindRip(ripTargets, 2000);
    Console.WriteLine("ripHits=" + ripHits.Count + " targets=" + ripTargets.Count);

    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\": 1,\n  \"milestone\": \"v0.8.0-submit\",\n");
    sb.Append("  \"bodies\": [\n");
    uint[] bodies = new uint[] {
      kNpcCopy, kPlayerCopy, kSharedCopy, kDestHelper, kHashRegister, kFieldVisitor
    };
    for (int i = 0; i < bodies.Length; i++) {
      if (i > 0) sb.Append(",\n");
      var ins = Disasm(bodies[i], 90);
      sb.Append("    {\"entry\":\"").Append(H(bodies[i]));
      sb.Append("\",\"role\":").Append(J(Name(bodies[i])));
      sb.Append(",\"calls\":[");
      var seen = new HashSet<uint>();
      int c = 0;
      foreach (var item in ins) {
        if (item.Call == 0 || !seen.Add(item.Call)) continue;
        if (c++ > 0) sb.Append(',');
        sb.Append("{\"target\":\"").Append(H(item.Call));
        sb.Append("\",\"role\":").Append(J(Name(item.Call))).Append('}');
      }
      sb.Append("],\"text\":").Append(J(Join(ins, 70))).Append('}');
    }
    sb.Append("\n  ],\n  \"directCallers\": {\n");
    for (int i = 0; i < callTargets.Length; i++) {
      if (i > 0) sb.Append(",\n");
      uint t = callTargets[i];
      List<uint> list;
      if (!callers.TryGetValue(t, out list)) list = new List<uint>();
      sb.Append("    \"").Append(H(t)).Append("\": [");
      int shown = 0;
      var funcs = new HashSet<uint>();
      for (int k = 0; k < list.Count && shown < 40; k++) {
        uint fn = FindFunc(list[k]);
        if (!funcs.Add(fn)) continue;
        if (shown++ > 0) sb.Append(',');
        sb.Append("{\"site\":\"").Append(H(list[k]));
        sb.Append("\",\"func\":\"").Append(H(fn));
        sb.Append("\",\"known\":").Append(J(Name(fn))).Append('}');
      }
      sb.Append("],\"uniqueFuncsShown\":").Append(shown);
      sb.Append(",\"sitesFound\":").Append(list.Count).Append('}');
    }
    sb.Append("\n  },\n  \"callerDepth2\": [\n");
    AppendDepth2(sb, callers, kNpcCopy);
    sb.Append(",\n");
    AppendDepth2(sb, callers, kPlayerCopy);
    sb.Append("\n  ],\n  \"pointerSlots\": {\n");
    int si = 0;
    foreach (var kv in slots) {
      if (si++ > 0) sb.Append(",\n");
      sb.Append("    \"").Append(H(kv.Key)).Append("\": [");
      for (int i = 0; i < kv.Value.Count; i++) {
        if (i > 0) sb.Append(',');
        long fo = kv.Value[i];
        sb.Append("{\"rva\":\"").Append(H(FileToRva(fo)));
        sb.Append("\",\"section\":").Append(J(SecName(fo))).Append('}');
      }
      sb.Append(']');
    }
    sb.Append("\n  },\n  \"hashImmediates\": {\n");
    AppendHashes(sb, hashHits);
    sb.Append("\n  },\n  \"ripUsers\": [\n");
    int ri = 0;
    foreach (var hit in ripHits) {
      if (ri >= 80) break;
      if (ri++ > 0) sb.Append(",\n");
      uint fn = FindFunc(hit.Site);
      sb.Append("    {\"site\":\"").Append(H(hit.Site));
      sb.Append("\",\"func\":\"").Append(H(fn));
      sb.Append("\",\"known\":").Append(J(Name(fn)));
      sb.Append(",\"target\":\"").Append(H(hit.Target));
      sb.Append("\",\"kind\":").Append(J(hit.Kind)).Append('}');
    }
    sb.Append("\n  ],\n  \"ac4NameStrings\": [\n");
    for (int i = 0; i < strings.Count && i < 40; i++) {
      if (i > 0) sb.Append(",\n");
      sb.Append("    {\"needle\":").Append(J(strings[i].Needle));
      sb.Append(",\"rva\":\"").Append(H(strings[i].Rva));
      sb.Append("\",\"section\":").Append(J(strings[i].Section));
      sb.Append(",\"text\":").Append(J(Trim(strings[i].Text, 120))).Append('}');
    }
    sb.Append("\n  ]\n}\n");

    string path = Path.Combine(outDir, "v0.8.0-submit-path.json");
    File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
    Console.WriteLine("WROTE " + path);
    string follow = Path.Combine(outDir, "v0.8.0-submit-follow.json");
    File.WriteAllText(follow, Follow(), new UTF8Encoding(false));
    Console.WriteLine("WROTE " + follow);
    return 0;
  }

  static string Follow() {
    var sb = new StringBuilder();
    sb.Append("{\n  \"vtablePointerHits\": {\n");
    uint[] bases = new uint[] { kNpcRecord, kPlayerRecord, kNpcRecord + 0x18, 0xA035200, 0xA0352D4 };
    for (int i = 0; i < bases.Length; i++) {
      if (i > 0) sb.Append(",\n");
      var hits = FindU64(imageBase + bases[i], 6);
      sb.Append("    \"").Append(H(bases[i])).Append("\": [");
      for (int k = 0; k < hits.Count; k++) {
        if (k > 0) sb.Append(',');
        long fo = hits[k];
        sb.Append("{\"rva\":\"").Append(H(FileToRva(fo)));
        sb.Append("\",\"section\":").Append(J(SecName(fo))).Append('}');
      }
      sb.Append(']');
      Console.WriteLine("ptr " + H(bases[i]) + "=" + hits.Count);
    }
    sb.Append("\n  },\n  \"absentNames\": {\n");
    string[] names = new string[] {
      "BuildEntityWithSelector", "GetUnusedPadID", "DuplicationManager",
      "RowSelector", "World::AddEntity", "EntityBuilder::", "BuildEntity"
    };
    for (int i = 0; i < names.Length; i++) {
      if (i > 0) sb.Append(",\n");
      int n = CountAscii(names[i]);
      sb.Append("    ").Append(J(names[i])).Append(": ").Append(n);
      Console.WriteLine("name " + names[i] + "=" + n);
    }
    sb.Append("\n  },\n  \"typeGlobalUsers\": [\n");
    uint[] globals = new uint[] { 0xB5378F0, 0xB537FC8, 0xB5377F8, 0xB537AE0, 0xB5B9688 };
    var ghits = FindRip(new HashSet<uint>(globals), 80);
    for (int i = 0; i < ghits.Count; i++) {
      if (i > 0) sb.Append(",\n");
      uint fn = FindFunc(ghits[i].Site);
      sb.Append("    {\"site\":\"").Append(H(ghits[i].Site));
      sb.Append("\",\"func\":\"").Append(H(fn));
      sb.Append("\",\"known\":").Append(J(Name(fn)));
      sb.Append(",\"target\":\"").Append(H(ghits[i].Target));
      sb.Append("\",\"kind\":").Append(J(ghits[i].Kind)).Append('}');
      Console.WriteLine("global " + H(ghits[i].Target) + " " + ghits[i].Kind + " " + H(ghits[i].Site));
    }
    sb.Append("\n  ],\n  \"hashNeighbors\": [\n");
    uint[] hashSites = new uint[] { 0xA0352D4, 0xA035324 };
    for (int i = 0; i < hashSites.Length; i++) {
      if (i > 0) sb.Append(",\n");
      sb.Append("    {\"site\":\"").Append(H(hashSites[i])).Append("\",\"dwords\":[");
      long fo = RvaToFile(hashSites[i] - 0x20);
      for (int k = 0; k < 16; k++) {
        if (k > 0) sb.Append(',');
        uint d = BitConverter.ToUInt32(pe, (int)fo + k * 4);
        sb.Append('"').Append(H(d)).Append('"');
      }
      sb.Append("]}");
    }
    sb.Append("\n  ],\n  \"extraCopies\": [\n");
    uint[] extras = new uint[] {
      0x6454930, 0x80F25F0, FindFunc(0x35E69C3), FindFunc(0x64BF01A), FindFunc(0x335939C)
    };
    for (int i = 0; i < extras.Length; i++) {
      if (i > 0) sb.Append(",\n");
      sb.Append("    {\"entry\":\"").Append(H(extras[i]));
      sb.Append("\",\"text\":").Append(J(Join(DisasmAll(extras[i], 70), 70))).Append('}');
    }
    sb.Append("\n  ],\n  \"windows\": [\n");
    uint[] windows = new uint[] { 0x137AEB0, 0x137AF20, 0x137B000 };
    for (int i = 0; i < windows.Length; i++) {
      if (i > 0) sb.Append(",\n");
      sb.Append("    {\"at\":\"").Append(H(windows[i]));
      sb.Append("\",\"text\":").Append(J(Join(DisasmAll(windows[i], 28), 28))).Append('}');
    }
    sb.Append("\n  ]\n}\n");
    return sb.ToString();
  }

  static int CountAscii(string text) {
    byte[] n = Encoding.ASCII.GetBytes(text);
    int count = 0;
    for (long i = 0; i + n.Length <= pe.Length; i++) {
      bool ok = true;
      for (int j = 0; j < n.Length; j++) if (pe[i + j] != n[j]) { ok = false; break; }
      if (!ok) continue;
      count++;
      if (count >= 20) break;
    }
    return count;
  }

  static string DumpRegion(uint rva, int len) {
    long fo = RvaToFile(rva);
    if (fo < 0) return "";
    var sb = new StringBuilder();
    int n = (int)Math.Min(len, pe.Length - fo);
    for (int i = 0; i < n; i += 16) {
      sb.Append(H((uint)(rva + i))).Append(' ');
      int take = Math.Min(16, n - i);
      var asc = new StringBuilder();
      for (int j = 0; j < take; j++) {
        byte b = pe[fo + i + j];
        sb.Append(b.ToString("X2"));
        if ((j & 3) == 3) sb.Append(' ');
        asc.Append(b >= 32 && b < 127 ? (char)b : '.');
      }
      sb.Append(' ').Append(asc).Append(" | ");
    }
    return sb.ToString();
  }

  static List<Ins> DisasmAll(uint rva, int maxIns) {
    var list = new List<Ins>();
    long fo = RvaToFile(rva);
    if (fo < 0) return list;
    int len = (int)Math.Min(0x400, pe.Length - fo);
    var code = new byte[len];
    Buffer.BlockCopy(pe, (int)fo, code, 0, len);
    var dec = Decoder.Create(64, new ByteArrayCodeReader(code));
    dec.IP = imageBase + rva;
    int rets = 0;
    for (int n = 0; n < maxIns; n++) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      var item = new Ins { Rva = (uint)(raw.IP - imageBase), Text = o.ToString(), Ret = raw.Mnemonic == Mnemonic.Ret };
      if (raw.NearBranchTarget >= imageBase &&
          (raw.FlowControl == FlowControl.Call || raw.FlowControl == FlowControl.IndirectCall))
        item.Call = (uint)(raw.NearBranchTarget - imageBase);
      list.Add(item);
      if (item.Ret && ++rets >= 2 && n > 12) break;
      if (raw.Mnemonic == Mnemonic.Int3 && n > 4) break;
    }
    return list;
  }

  sealed class Sec { public string Name; public uint VA, VS, Raw, Ptr, Char; }
  sealed class Ins { public uint Rva; public string Text; public uint Call; public bool Ret; }
  sealed class Rip { public uint Site; public uint Target; public string Kind; }
  sealed class StrHit { public string Needle; public uint Rva; public string Section; public string Text; }

  static void AppendDepth2(StringBuilder sb, Dictionary<uint, List<uint>> callers, uint root) {
    sb.Append("    {\"root\":\"").Append(H(root)).Append("\",\"callers\":[");
    List<uint> list;
    if (!callers.TryGetValue(root, out list)) list = new List<uint>();
    var funcs = new List<uint>();
    var seen = new HashSet<uint>();
    foreach (uint site in list) {
      uint fn = FindFunc(site);
      if (fn == root) continue;
      if (seen.Add(fn)) funcs.Add(fn);
      if (funcs.Count >= 8) break;
    }
    for (int i = 0; i < funcs.Count; i++) {
      if (i > 0) sb.Append(',');
      uint fn = funcs[i];
      var parents = FindE8(new uint[] { fn }, 24);
      List<uint> p;
      if (!parents.TryGetValue(fn, out p)) p = new List<uint>();
      sb.Append("{\"func\":\"").Append(H(fn));
      sb.Append("\",\"known\":").Append(J(Name(fn)));
      sb.Append(",\"parentSites\":").Append(p.Count);
      sb.Append(",\"decode\":").Append(J(Join(Disasm(fn, 36), 36)));
      sb.Append(",\"parents\":[");
      var pseen = new HashSet<uint>();
      int n = 0;
      foreach (uint site in p) {
        uint pfn = FindFunc(site);
        if (!pseen.Add(pfn)) continue;
        if (n++ > 0) sb.Append(',');
        sb.Append("{\"site\":\"").Append(H(site));
        sb.Append("\",\"func\":\"").Append(H(pfn));
        sb.Append("\",\"known\":").Append(J(Name(pfn))).Append('}');
        if (n >= 8) break;
      }
      sb.Append("]}");
      Console.WriteLine("depth2 " + H(root) + " via " + H(fn) + " parents=" + p.Count);
    }
    sb.Append("]}");
  }

  static void AppendHashes(StringBuilder sb, Dictionary<uint, List<uint>> hits) {
    uint[] keys = new uint[] { kNpcHash, kPlayerHash };
    for (int i = 0; i < keys.Length; i++) {
      if (i > 0) sb.Append(",\n");
      List<uint> list;
      if (!hits.TryGetValue(keys[i], out list)) list = new List<uint>();
      sb.Append("    \"").Append(H(keys[i])).Append("\": [");
      for (int k = 0; k < list.Count; k++) {
        if (k > 0) sb.Append(',');
        uint site = list[k];
        long fo = RvaToFile(site);
        sb.Append("{\"site\":\"").Append(H(site));
        sb.Append("\",\"section\":").Append(J(fo < 0 ? "" : SecName(fo)));
        sb.Append(",\"func\":\"").Append(H(FindFunc(site)));
        sb.Append("\",\"known\":").Append(J(Name(FindFunc(site)))).Append('}');
      }
      sb.Append(']');
    }
  }

  static string Name(uint rva) {
    string n;
    return Known.TryGetValue(rva, out n) ? n : "";
  }

  static void ParsePe() {
    int e = BitConverter.ToInt32(pe, 0x3C);
    ushort num = BitConverter.ToUInt16(pe, e + 6);
    ushort opt = BitConverter.ToUInt16(pe, e + 20);
    ushort magic = BitConverter.ToUInt16(pe, e + 0x18);
    imageBase = magic == 0x20B
      ? BitConverter.ToUInt64(pe, e + 0x18 + 24)
      : BitConverter.ToUInt32(pe, e + 0x18 + 28);
    int secOff = e + 24 + opt;
    secs = new List<Sec>();
    for (int i = 0; i < num; i++) {
      int o = secOff + i * 40;
      var s = new Sec();
      s.Name = Encoding.ASCII.GetString(pe, o, 8).TrimEnd('\0');
      s.VS = BitConverter.ToUInt32(pe, o + 8);
      s.VA = BitConverter.ToUInt32(pe, o + 12);
      s.Raw = BitConverter.ToUInt32(pe, o + 16);
      s.Ptr = BitConverter.ToUInt32(pe, o + 20);
      s.Char = BitConverter.ToUInt32(pe, o + 36);
      secs.Add(s);
    }
  }

  static bool IsExec(Sec s) { return s.Ptr != 0 && (s.Char & 0x20000000) != 0; }
  static string H(uint v) { return "0x" + v.ToString("X"); }
  static string H(ulong v) { return "0x" + v.ToString("X"); }
  static string J(string s) {
    if (s == null) return "null";
    var sb = new StringBuilder(s.Length + 2);
    sb.Append('"');
    foreach (char c in s) {
      if (c == '\\' || c == '"') sb.Append('\\').Append(c);
      else if (c < 32 || c > 126) sb.Append(' ');
      else sb.Append(c);
    }
    return sb.Append('"').ToString();
  }
  static string Trim(string s, int n) {
    if (s == null) return "";
    return s.Length <= n ? s : s.Substring(0, n);
  }

  static long RvaToFile(uint rva) {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      if (rva >= s.VA && rva < s.VA + s.Raw) return s.Ptr + (rva - s.VA);
    }
    return -1;
  }
  static uint FileToRva(long fo) {
    foreach (var s in secs) {
      if (s.Ptr != 0 && fo >= s.Ptr && fo < s.Ptr + s.Raw)
        return s.VA + (uint)(fo - s.Ptr);
    }
    return 0;
  }
  static string SecName(long fo) {
    foreach (var s in secs)
      if (s.Ptr != 0 && fo >= s.Ptr && fo < s.Ptr + s.Raw) return s.Name;
    return "";
  }

  static Dictionary<uint, List<uint>> FindE8(uint[] targets, int maxTotal) {
    var want = new HashSet<uint>(targets);
    var map = new Dictionary<uint, List<uint>>();
    int total = 0;
    foreach (var s in secs) {
      if (!IsExec(s) || total >= maxTotal) break;
      int size = (int)s.Raw;
      for (int i = 0; i + 5 <= size; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        int disp = BitConverter.ToInt32(pe, (int)s.Ptr + i + 1);
        uint site = s.VA + (uint)i;
        uint tgt = unchecked((uint)(site + 5 + disp));
        if (!want.Contains(tgt)) continue;
        List<uint> list;
        if (!map.TryGetValue(tgt, out list)) {
          list = new List<uint>();
          map[tgt] = list;
        }
        list.Add(site);
        if (++total >= maxTotal) break;
      }
    }
    return map;
  }

  static List<long> FindU64(ulong value, int max) {
    var list = new List<long>();
    byte[] pat = BitConverter.GetBytes(value);
    for (long i = 0; i + 8 <= pe.Length; i++) {
      if (pe[i] != pat[0] || pe[i + 1] != pat[1] || pe[i + 2] != pat[2] || pe[i + 3] != pat[3] ||
          pe[i + 4] != pat[4] || pe[i + 5] != pat[5] || pe[i + 6] != pat[6] || pe[i + 7] != pat[7])
        continue;
      list.Add(i);
      if (list.Count >= max) break;
    }
    return list;
  }

  static Dictionary<uint, List<uint>> FindImm32(uint[] values, int maxEach) {
    var pats = new Dictionary<uint, byte[]>();
    var map = new Dictionary<uint, List<uint>>();
    foreach (uint v in values) {
      pats[v] = BitConverter.GetBytes(v);
      map[v] = new List<uint>();
    }
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw < 4) continue;
      int size = (int)s.Raw;
      for (int i = 0; i + 4 <= size; i++) {
        foreach (var kv in pats) {
          var list = map[kv.Key];
          if (list.Count >= maxEach) continue;
          byte[] p = kv.Value;
          if (pe[s.Ptr + i] != p[0] || pe[s.Ptr + i + 1] != p[1] ||
              pe[s.Ptr + i + 2] != p[2] || pe[s.Ptr + i + 3] != p[3]) continue;
          list.Add(s.VA + (uint)i);
        }
      }
    }
    return map;
  }

  static List<Rip> FindRip(HashSet<uint> targets, int max) {
    var list = new List<Rip>();
    foreach (var s in secs) {
      if (!IsExec(s) || list.Count >= max) break;
      int size = (int)s.Raw;
      for (int i = 0; i + 7 <= size; i++) {
        byte b0 = pe[s.Ptr + i];
        byte b1 = pe[s.Ptr + i + 1];
        byte b2 = pe[s.Ptr + i + 2];
        int dispAt = -1;
        int len = 0;
        string kind = "";
        if ((b0 == 0x48 || b0 == 0x4C || b0 == 0x44) &&
            (b1 == 0x8D || b1 == 0x8B || b1 == 0x89) && (b2 & 0xC7) == 0x05) {
          dispAt = 3; len = 7; kind = b1 == 0x8D ? "lea" : "mov";
        } else if (b0 == 0xFF && b1 == 0x15) {
          dispAt = 2; len = 6; kind = "call_rip";
        }
        if (dispAt < 0) continue;
        int disp = BitConverter.ToInt32(pe, (int)s.Ptr + i + dispAt);
        uint site = s.VA + (uint)i;
        uint tgt = unchecked((uint)(site + (uint)len + disp));
        if (!targets.Contains(tgt)) continue;
        list.Add(new Rip { Site = site, Target = tgt, Kind = kind });
        if (list.Count >= max) return list;
      }
    }
    return list;
  }

  static List<StrHit> CollectNeedles(string[] needles) {
    var list = new List<StrHit>();
    var counts = new Dictionary<string, int>();
    foreach (var sec in secs) {
      if (sec.Name != ".edata" && sec.Name != ".rodata") continue;
      long i = sec.Ptr;
      long end = sec.Ptr + sec.Raw;
      while (i < end && list.Count < 60) {
        if (pe[i] < 32 || pe[i] > 126) { i++; continue; }
        long start = i;
        while (i < end && pe[i] >= 32 && pe[i] <= 126) i++;
        int len = (int)(i - start);
        bool term = i < end && pe[i] == 0;
        if (term) i++;
        if (!term || len < 8 || len > 160) continue;
        string text = Encoding.ASCII.GetString(pe, (int)start, len);
        if (text.IndexOf("isOptional", StringComparison.Ordinal) >= 0) continue;
        if (text.IndexOf("\"name\"", StringComparison.Ordinal) >= 0) continue;
        string needle = null;
        foreach (string n in needles) {
          if (text.IndexOf(n, StringComparison.Ordinal) >= 0) { needle = n; break; }
        }
        if (needle == null) continue;
        int have;
        counts.TryGetValue(needle, out have);
        if (have >= 6) continue;
        counts[needle] = have + 1;
        list.Add(new StrHit {
          Needle = needle, Rva = FileToRva(start), Section = sec.Name, Text = text
        });
      }
    }
    return list;
  }

  static uint FindFunc(uint site) {
    long fo = RvaToFile(site);
    if (fo < 0) return site;
    for (int back = 0; back < 0x2000; back++) {
      long pos = fo - back;
      if (pos < 1) break;
      byte prev = pe[pos - 1];
      if ((prev == 0xCC || prev == 0xC3) && LooksPrologue(pos)) return FileToRva(pos);
    }
    return site;
  }

  static bool LooksPrologue(long fo) {
    if (fo + 3 >= pe.Length) return false;
    byte b0 = pe[fo], b1 = pe[fo + 1], b2 = pe[fo + 2];
    if (b0 == 0x40 && (b1 == 0x53 || b1 == 0x55 || b1 == 0x56 || b1 == 0x57)) return true;
    if (b0 == 0x48 && b1 == 0x89) return true;
    if (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC) return true;
    if (b0 == 0x48 && b1 == 0x81 && b2 == 0xEC) return true;
    if (b0 == 0x55 || b0 == 0x53 || b0 == 0x56 || b0 == 0x57) return true;
    if (b0 == 0x41 && b1 >= 0x54 && b1 <= 0x57) return true;
    return false;
  }

  static List<Ins> Disasm(uint rva, int maxIns) {
    var list = new List<Ins>();
    long fo = RvaToFile(rva);
    if (fo < 0) return list;
    int len = (int)Math.Min(0x500, pe.Length - fo);
    var code = new byte[len];
    Buffer.BlockCopy(pe, (int)fo, code, 0, len);
    var dec = Decoder.Create(64, new ByteArrayCodeReader(code));
    dec.IP = imageBase + rva;
    bool sawRet = false;
    for (int n = 0; n < maxIns; n++) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      var item = new Ins {
        Rva = (uint)(raw.IP - imageBase),
        Text = o.ToString(),
        Ret = raw.Mnemonic == Mnemonic.Ret
      };
      if ((raw.FlowControl == FlowControl.Call || raw.FlowControl == FlowControl.IndirectCall) &&
          raw.NearBranchTarget >= imageBase)
        item.Call = (uint)(raw.NearBranchTarget - imageBase);
      list.Add(item);
      if (item.Ret) {
        if (sawRet) break;
        sawRet = true;
        if (n > 8) break;
      }
      if (raw.Mnemonic == Mnemonic.Int3 && n > 2) break;
    }
    return list;
  }

  static string Join(List<Ins> ins, int max) {
    var sb = new StringBuilder();
    int n = Math.Min(max, ins.Count);
    for (int i = 0; i < n; i++) {
      if (i > 0) sb.Append(" | ");
      sb.Append(H(ins[i].Rva)).Append(' ').Append(ins[i].Text);
    }
    if (sb.Length > 1800) return sb.ToString(0, 1800);
    return sb.ToString();
  }
}
