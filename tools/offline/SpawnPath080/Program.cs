// v0.8.0 — focused offline scan for a native character/entity creation path.
// Read-only. Does not launch the game, inject, or write the executable.
// Explicitly excludes the already-disproven deferred-queue / LOD enrollment path.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;

internal static class Program {
  const uint kRegistrar = 0x5CBDFB0;
  const uint kRegistrarEnd = 0x5CBE847;
  const uint kDeferredHandler = 0x1AC380;
  const uint kAllocator = 0x426EE50;
  const uint kFactoryA = 0x238590;
  const uint kFactoryB = 0x256280;

  static readonly string[] kNeedles = new[] {
    "CreateEntity", "DestroyEntity", "EntityManager", "EntityFactory",
    "EntityDescriptor", "EntityBuilder", "WorldEntity", "GameEntity",
    "CloneEntity", "SpawnActor", "SpawnEntity", "SpawnCharacter",
    "CreateActor", "CreateCharacter", "CharacterFactory", "CharacterManager",
    "PlayerCharacter", "Instantiate", "Possess", "Unpossess",
    "PopulationManager", "ManagedObject", "ObjectManager", "Prefab",
    "SpawnPoint", "ActorFactory", "AddComponent", "Archetype",
    "Despawn", "Spawn", "Edward", "Kenway"
  };

  static byte[] pe;
  static List<Sec> secs;
  static ulong imageBase;

  static int Main(string[] args) {
    string exe = args.Length > 0
      ? args[0]
      : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1
      ? args[1]
      : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080\reports";
    pe = File.ReadAllBytes(exe);
    ParsePe();
    Directory.CreateDirectory(outDir);

    Console.WriteLine("imageBase=" + H(imageBase) + " bytes=" + pe.Length);
    foreach (var s in secs) {
      Console.WriteLine("SEC " + s.Name + " va=" + H(s.VA) + " raw=" + s.Raw +
                        " ptr=" + H(s.Ptr) + " chars=" + H(s.Char));
    }

    var strings = CollectStrings();
    Console.WriteLine("candidateStrings=" + strings.Count);
    var targets = new Dictionary<uint, StringHit>();
    foreach (var hit in strings) targets[hit.Rva] = hit;

    var xrefs = FindLeaXrefs(targets);
    Console.WriteLine("leaXrefs=" + xrefs.Count);
    var phases = DecodeRegistrar();
    Console.WriteLine("registrarLeas=" + phases.Count);

    var funcs = GroupFunctions(xrefs);
    Console.WriteLine("functions=" + funcs.Count);
    RankAndDecode(funcs);

    string path = Path.Combine(outDir, "v0.8.0-spawn-string-xrefs.json");
    File.WriteAllText(path, BuildJson(strings, xrefs, phases, funcs), new UTF8Encoding(false));
    Console.WriteLine("WROTE " + path);
    string follow = Path.Combine(outDir, "v0.8.0-spawn-params-follow.json");
    File.WriteAllText(follow, FollowSpawnParams(), new UTF8Encoding(false));
    Console.WriteLine("WROTE " + follow);
    string consumers = Path.Combine(outDir, "v0.8.0-spawn-param-consumers.json");
    File.WriteAllText(consumers, FollowConsumers(), new UTF8Encoding(false));
    Console.WriteLine("WROTE " + consumers);
    string slots = Path.Combine(outDir, "v0.8.0-spawn-fnptr-slots.json");
    File.WriteAllText(slots, FindFunctionPointerSlots(), new UTF8Encoding(false));
    Console.WriteLine("WROTE " + slots);
    return 0;
  }

  static readonly uint[] kParamFns = new uint[] { 0x80F2330, 0x8E02960, 0x8DFFB90, 0x4572C60 };
  static readonly uint[] kHashes = new uint[] { 0xFB7FF6A5, 0x6A484E77, 0xB5BAEE39 };

  static string FollowSpawnParams() {
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\": 1,\n  \"milestone\": \"v0.8.0-follow\",\n");
    sb.Append("  \"clusterStrings\": [\n");
    var cluster = DumpStrings(0xA11D800, 0xA11E200);
    for (int i = 0; i < cluster.Count; i++) {
      if (i > 0) sb.Append(",\n");
      sb.Append("    {\"rva\":\"").Append(H(cluster[i].Rva)).Append("\",\"text\":").Append(J(cluster[i].Text)).Append('}');
    }
    sb.Append("\n  ],\n");

    sb.Append("  \"directCallers\": {\n");
    for (int p = 0; p < kParamFns.Length; p++) {
      if (p > 0) sb.Append(",\n");
      var callers = FindE8Callers(kParamFns[p], kParamFns[p] == 0x4572C60 ? 12 : 40);
      sb.Append("    \"").Append(H(kParamFns[p])).Append("\": [");
      for (int i = 0; i < callers.Count; i++) {
        if (i > 0) sb.Append(',');
        sb.Append('"').Append(H(callers[i])).Append('"');
      }
      sb.Append(']');
      Console.WriteLine("callers " + H(kParamFns[p]) + "=" + callers.Count);
    }
    sb.Append("\n  },\n");

    sb.Append("  \"codePointerLea\": {\n");
    for (int p = 0; p < 3; p++) {
      if (p > 0) sb.Append(",\n");
      var leas = FindLeaToCode(kParamFns[p], 24);
      sb.Append("    \"").Append(H(kParamFns[p])).Append("\": [");
      for (int i = 0; i < leas.Count; i++) {
        if (i > 0) sb.Append(',');
        sb.Append('"').Append(H(leas[i])).Append('"');
      }
      sb.Append(']');
      Console.WriteLine("lea-code " + H(kParamFns[p]) + "=" + leas.Count);
    }
    sb.Append("\n  },\n");

    sb.Append("  \"hashImmediates\": {\n");
    for (int h = 0; h < kHashes.Length; h++) {
      if (h > 0) sb.Append(",\n");
      var sites = FindImm32(kHashes[h], 24);
      sb.Append("    \"").Append(H(kHashes[h])).Append("\": [");
      for (int i = 0; i < sites.Count; i++) {
        if (i > 0) sb.Append(',');
        uint site = sites[i];
        uint fn = FindFunc(site);
        sb.Append("{\"site\":\"").Append(H(site)).Append("\",\"func\":\"").Append(H(fn)).Append("\"}");
      }
      sb.Append(']');
      Console.WriteLine("imm " + H(kHashes[h]) + "=" + sites.Count);
    }
    sb.Append("\n  },\n");

    uint[] deep = new uint[] { 0x80F2330, 0x8E02960, 0x8DFFB90 };
    sb.Append("  \"registrarBodies\": [\n");
    for (int i = 0; i < deep.Length; i++) {
      if (i > 0) sb.Append(",\n");
      sb.Append("    {\"entry\":\"").Append(H(deep[i])).Append("\",\"decode\":").Append(J(Disasm(deep[i], 48))).Append('}');
    }
    sb.Append("\n  ]\n}\n");
    return sb.ToString();
  }

  static string FollowConsumers() {
    uint[] names = new uint[] {
      0xA11DC3F, 0xA11DD1C, 0xA11DD92, 0xA11DDA4, 0xA11DDC1, 0xA11DDF0, 0xA11DC2D
    };
    string[] labels = new string[] {
      "SpawnInventoryParams", "SpawnPlayerBoatParams", "SpawnPlayerParams",
      "SpawnFirstPersonPlayerParams", "SpawnCharacterParams",
      "SpawnEntityBuilderParams", "SpawnEntityParams"
    };
    var leas = FindLeaToTargets(names, 16);
    var sb = new StringBuilder();
    sb.Append("{\n  \"nameLeas\": {\n");
    for (int n = 0; n < names.Length; n++) {
      if (n > 0) sb.Append(",\n");
      List<uint> sites;
      if (!leas.TryGetValue(names[n], out sites)) sites = new List<uint>();
      sb.Append("    \"").Append(labels[n]).Append("\": [");
      for (int i = 0; i < sites.Count; i++) {
        if (i > 0) sb.Append(',');
        uint fn = FindFunc(sites[i]);
        sb.Append("{\"site\":\"").Append(H(sites[i])).Append("\",\"func\":\"").Append(H(fn)).Append("\"}");
      }
      sb.Append(']');
      Console.WriteLine("name " + labels[n] + "=" + sites.Count);
    }
    sb.Append("\n  },\n  \"derivedCallers\": {\n");
    uint[] regs = new uint[] { 0x80F2A20, 0x80F2580, 0x821ABC0, 0x80F23E0, 0x80F27E0 };
    for (int r = 0; r < regs.Length; r++) {
      if (r > 0) sb.Append(",\n");
      var callers = FindE8Callers(regs[r], 16);
      sb.Append("    \"").Append(H(regs[r])).Append("\": [");
      for (int i = 0; i < callers.Count; i++) {
        if (i > 0) sb.Append(',');
        sb.Append('"').Append(H(callers[i])).Append('"');
      }
      sb.Append(']');
      Console.WriteLine("reg-callers " + H(regs[r]) + "=" + callers.Count);
    }
    sb.Append("\n  },\n  \"stringsAt\": [\n");
    uint[] strs = new uint[] { 0xA11E28C, 0xA11DD92, 0xA11DDA4, 0xA11DD1C, 0xA11DDC1 };
    for (int i = 0; i < strs.Length; i++) {
      if (i > 0) sb.Append(",\n");
      sb.Append("    {\"rva\":\"").Append(H(strs[i])).Append("\",\"text\":").Append(J(ReadCString(strs[i]))).Append('}');
    }
    sb.Append("\n  ],\n  \"bodies\": [\n");
    uint[] interest = new uint[] { 0x80F2A20, 0x80F2580, 0x821ABC0, 0x80F23E0, 0x80F27E0 };
    for (int i = 0; i < interest.Length; i++) {
      if (i > 0) sb.Append(",\n");
      sb.Append("    {\"entry\":\"").Append(H(interest[i]));
      sb.Append("\",\"decode\":").Append(J(Disasm(interest[i], 32))).Append('}');
    }
    sb.Append("\n  ]\n}\n");
    return sb.ToString();
  }

  static string FindFunctionPointerSlots() {
    uint[] fns = new uint[] { 0x80F2330, 0x80F2A20, 0x80F23E0, 0x80F2580, 0x821ABC0, 0x8E02960, 0x8DFFB90 };
    var sb = new StringBuilder();
    sb.Append("{\n  \"slots\": [\n");
    int written = 0;
    foreach (uint fn in fns) {
      ulong va = imageBase + fn;
      var hits = FindU64(va, 8);
      Console.WriteLine("qword " + H(fn) + "=" + hits.Count);
      foreach (long fo in hits) {
        if (written++ > 0) sb.Append(",\n");
        uint rva = FileToRva((uint)fo == fo ? fo : 0);
        if (fo > uint.MaxValue) rva = 0;
        rva = FileToRva(fo);
        sb.Append("    {\"fn\":\"").Append(H(fn));
        sb.Append("\",\"slotRva\":\"").Append(H(rva));
        sb.Append("\",\"section\":").Append(J(SecName(fo)));
        sb.Append(",\"neighbors\":[");
        for (int k = -3; k <= 3; k++) {
          if (k > -3) sb.Append(',');
          long nfo = fo + k * 8;
          ulong q = 0;
          if (nfo >= 0 && nfo + 8 <= pe.Length) q = BitConverter.ToUInt64(pe, (int)nfo);
          uint nr = 0;
          if (q >= imageBase && q < imageBase + 0x20000000) nr = (uint)(q - imageBase);
          sb.Append("{\"delta\":").Append(k * 8);
          sb.Append(",\"rva\":\"").Append(nr == 0 ? "" : H(nr)).Append("\"}");
        }
        sb.Append("]}");
      }
    }
    sb.Append("\n  ],\n  \"methodDecode\": [\n");
    uint[] methods = new uint[] {
      0x53741F0, 0x64099B0, 0x21F5950, 0x12071F0, 0x5E3DB0, 0x1207200, 0x5E3DF0, 0x80FCA40
    };
    for (int i = 0; i < methods.Length; i++) {
      if (i > 0) sb.Append(",\n");
      string dec = Disasm(methods[i], 22);
      bool alloc = dec.IndexOf("426EE50", StringComparison.OrdinalIgnoreCase) >= 0;
      sb.Append("    {\"entry\":\"").Append(H(methods[i]));
      sb.Append("\",\"mentionsAllocator\":").Append(alloc ? "true" : "false");
      sb.Append(",\"decode\":").Append(J(dec)).Append('}');
    }
    sb.Append("\n  ]\n}\n");
    return sb.ToString();
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

  static string ReadCString(uint rva) {
    long fo = RvaToFile(rva);
    if (fo < 0) return "";
    int n = 0;
    while (n < 96 && fo + n < pe.Length && pe[fo + n] >= 32 && pe[fo + n] < 127) n++;
    if (n == 0 || fo + n >= pe.Length || pe[fo + n] != 0) return "";
    return Encoding.ASCII.GetString(pe, (int)fo, n);
  }

  static Dictionary<uint, List<uint>> FindLeaToTargets(uint[] targets, int maxEach) {
    var want = new HashSet<uint>(targets);
    var map = new Dictionary<uint, List<uint>>();
    foreach (var s in secs) {
      if (!IsExec(s)) continue;
      int size = (int)s.Raw;
      for (int i = 0; i + 7 <= size; i++) {
        byte b0 = pe[s.Ptr + i];
        if (b0 != 0x48 && b0 != 0x4C) continue;
        if (pe[s.Ptr + i + 1] != 0x8D) continue;
        if ((pe[s.Ptr + i + 2] & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)s.Ptr + i + 3);
        uint site = s.VA + (uint)i;
        uint tgt = unchecked((uint)(site + 7 + disp));
        if (!want.Contains(tgt)) continue;
        List<uint> list;
        if (!map.TryGetValue(tgt, out list)) {
          list = new List<uint>();
          map[tgt] = list;
        }
        if (list.Count >= maxEach) continue;
        list.Add(site);
      }
    }
    return map;
  }

  static List<StringHit> DumpStrings(uint rva, uint endRva) {
    var list = new List<StringHit>();
    long fo = RvaToFile(rva);
    long end = RvaToFile(endRva);
    if (fo < 0 || end < 0) return list;
    long i = fo;
    while (i < end && list.Count < 80) {
      if (pe[i] < 32 || pe[i] > 126) { i++; continue; }
      long start = i;
      while (i < end && pe[i] >= 32 && pe[i] <= 126) i++;
      int len = (int)(i - start);
      if (i < pe.Length && pe[i] == 0 && len >= 4) {
        list.Add(new StringHit {
          Text = Encoding.ASCII.GetString(pe, (int)start, len),
          Rva = FileToRva(start)
        });
      }
      if (i < pe.Length && pe[i] == 0) i++;
    }
    return list;
  }

  static List<uint> FindE8Callers(uint target, int max) {
    var list = new List<uint>();
    foreach (var s in secs) {
      if (!IsExec(s)) continue;
      int size = (int)s.Raw;
      for (int i = 0; i + 5 <= size; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        int disp = BitConverter.ToInt32(pe, (int)s.Ptr + i + 1);
        uint site = s.VA + (uint)i;
        uint tgt = unchecked((uint)(site + 5 + disp));
        if (tgt != target) continue;
        list.Add(site);
        if (list.Count >= max) return list;
      }
    }
    return list;
  }

  static List<uint> FindLeaToCode(uint target, int max) {
    var list = new List<uint>();
    foreach (var s in secs) {
      if (!IsExec(s)) continue;
      int size = (int)s.Raw;
      for (int i = 0; i + 7 <= size; i++) {
        byte b0 = pe[s.Ptr + i];
        if (b0 != 0x48 && b0 != 0x4C) continue;
        if (pe[s.Ptr + i + 1] != 0x8D) continue;
        if ((pe[s.Ptr + i + 2] & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)s.Ptr + i + 3);
        uint site = s.VA + (uint)i;
        uint tgt = unchecked((uint)(site + 7 + disp));
        if (tgt != target) continue;
        list.Add(site);
        if (list.Count >= max) return list;
      }
    }
    return list;
  }

  static List<uint> FindImm32(uint imm, int max) {
    var list = new List<uint>();
    byte b0 = (byte)imm;
    byte b1 = (byte)(imm >> 8);
    byte b2 = (byte)(imm >> 16);
    byte b3 = (byte)(imm >> 24);
    foreach (var s in secs) {
      if (!IsExec(s)) continue;
      int size = (int)s.Raw;
      for (int i = 0; i + 4 <= size; i++) {
        if (pe[s.Ptr + i] != b0 || pe[s.Ptr + i + 1] != b1 ||
            pe[s.Ptr + i + 2] != b2 || pe[s.Ptr + i + 3] != b3) continue;
        list.Add(s.VA + (uint)i);
        if (list.Count >= max) return list;
      }
    }
    return list;
  }

  sealed class Sec {
    public string Name;
    public uint VA, VS, Raw, Ptr, Char;
  }

  sealed class StringHit {
    public string Needle;
    public string Text;
    public uint Rva;
    public long FileOffset;
    public string Section;
    public string Class;
  }

  sealed class Xref {
    public uint Site;
    public uint Target;
    public string Needle;
    public string Text;
    public string Class;
    public uint Func;
  }

  sealed class Phase {
    public uint Site;
    public uint Target;
    public string Kind;
    public string Text;
  }

  sealed class FuncInfo {
    public uint Entry;
    public int XrefCount;
    public readonly List<Xref> Xrefs = new List<Xref>();
    public readonly List<uint> Calls = new List<uint>();
    public bool CallsAllocator;
    public bool CallsTightFactory;
    public bool CallsDeferredHandler;
    public int SpecificScore;
    public string Decode = "";
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

  static string H(ulong v) { return "0x" + v.ToString("X"); }
  static string H(uint v) { return "0x" + v.ToString("X"); }

  static string J(string s) {
    if (s == null) return "null";
    var sb = new StringBuilder(s.Length + 2);
    sb.Append('"');
    foreach (char c in s) {
      if (c == '\\' || c == '"') sb.Append('\\').Append(c);
      else if (c < 32 || c > 126) sb.Append(' ');
      else sb.Append(c);
    }
    sb.Append('"');
    return sb.ToString();
  }

  static long RvaToFile(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VS, s.Raw);
      if (rva >= s.VA && rva < s.VA + span && s.Ptr != 0 && rva - s.VA < s.Raw)
        return s.Ptr + (rva - s.VA);
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
    foreach (var s in secs) {
      if (s.Ptr != 0 && fo >= s.Ptr && fo < s.Ptr + s.Raw) return s.Name;
    }
    return "";
  }

  static bool IsExec(Sec s) {
    return s.Ptr != 0 && (s.Char & 0x20000000) != 0;
  }

  static List<StringHit> CollectStrings() {
    var list = new List<StringHit>();
    var seen = new HashSet<uint>();
    var perNeedle = new Dictionary<string, int>();
    foreach (var sec in secs) {
      if (sec.Ptr == 0 || sec.Raw < 8) continue;
      if (sec.Name != ".edata" && sec.Name != ".rdata" && !sec.Name.StartsWith(".rdata"))
        continue;
      long begin = sec.Ptr;
      long end = sec.Ptr + sec.Raw;
      long i = begin;
      while (i < end) {
        byte b = pe[i];
        if (b < 32 || b > 126) { i++; continue; }
        long start = i;
        while (i < end && pe[i] >= 32 && pe[i] <= 126) i++;
        int len = (int)(i - start);
        bool terminated = i < end && pe[i] == 0;
        if (terminated) i++;
        if (!terminated || len < 6 || len > 180) continue;
        string text = Encoding.ASCII.GetString(pe, (int)start, len);
        string needle = MatchNeedle(text);
        if (needle == null) continue;
        int spec = Specificity(needle);
        int cap = spec >= 4 ? 24 : (spec >= 3 ? 16 : 8);
        int have;
        perNeedle.TryGetValue(needle, out have);
        if (have >= cap) continue;
        string cls = Classify(text);
        if (cls == "telemetry_schema") continue;
        if (cls == "havok") continue;
        uint rva = FileToRva(start);
        if (rva == 0 || !seen.Add(rva)) continue;
        perNeedle[needle] = have + 1;
        list.Add(new StringHit {
          Needle = needle,
          Text = text,
          Rva = rva,
          FileOffset = start,
          Section = sec.Name,
          Class = cls
        });
      }
    }
    return list;
  }

  static string MatchNeedle(string text) {
    foreach (var n in kNeedles) {
      if (text.IndexOf(n, StringComparison.Ordinal) >= 0) return n;
    }
    return null;
  }

  static string Classify(string text) {
    if (text.IndexOf("\"name\"", StringComparison.Ordinal) >= 0 ||
        text.IndexOf("isOptional", StringComparison.Ordinal) >= 0 ||
        text.IndexOf("customAttributes", StringComparison.Ordinal) >= 0 ||
        text.StartsWith("custom.", StringComparison.Ordinal) ||
        text.IndexOf("typeAttributes", StringComparison.Ordinal) >= 0)
      return "telemetry_schema";
    if (text.IndexOf("hkai", StringComparison.Ordinal) >= 0 ||
        text.IndexOf("hknp", StringComparison.Ordinal) >= 0 ||
        text.IndexOf("Havok", StringComparison.Ordinal) >= 0)
      return "havok";
    if (text.IndexOf("SingleThreaded", StringComparison.Ordinal) >= 0 ||
        text.IndexOf("GatherActor", StringComparison.Ordinal) >= 0)
      return "frame_phase_label";
    if (text.IndexOf("Pad_", StringComparison.Ordinal) >= 0 ||
        text.IndexOf("Key_", StringComparison.Ordinal) >= 0)
      return "input_action";
    if (text.IndexOf("ERROR", StringComparison.Ordinal) >= 0 ||
        text.IndexOf("Failed", StringComparison.Ordinal) >= 0 ||
        text.IndexOf("Could not", StringComparison.Ordinal) >= 0 ||
        text.IndexOf("failed", StringComparison.Ordinal) >= 0)
      return "log_message";
    if (text.IndexOf("Leaderboard", StringComparison.Ordinal) >= 0 ||
        text.IndexOf("KenwayFleet", StringComparison.Ordinal) >= 0)
      return "content_ui";
    return "identifier_or_message";
  }

  static int Specificity(string needle) {
    switch (needle) {
      case "CreateEntity":
      case "EntityFactory":
      case "EntityBuilder":
      case "SpawnActor":
      case "SpawnEntity":
      case "SpawnCharacter":
      case "CreateCharacter":
      case "CharacterFactory":
      case "ActorFactory":
      case "PlayerCharacter":
        return 5;
      case "EntityManager":
      case "EntityDescriptor":
      case "WorldEntity":
      case "GameEntity":
      case "CloneEntity":
      case "CreateActor":
      case "CharacterManager":
      case "PopulationManager":
      case "Instantiate":
      case "Possess":
      case "Unpossess":
        return 4;
      case "ManagedObject":
      case "ObjectManager":
      case "Prefab":
      case "SpawnPoint":
      case "AddComponent":
      case "Archetype":
        return 3;
      case "Edward":
      case "Kenway":
        return 2;
      default:
        return 1;
    }
  }

  static List<Xref> FindLeaXrefs(Dictionary<uint, StringHit> targets) {
    var list = new List<Xref>();
    foreach (var s in secs) {
      if (!IsExec(s)) continue;
      int size = (int)s.Raw;
      for (int i = 0; i + 7 <= size; i++) {
        byte b0 = pe[s.Ptr + i];
        if (b0 != 0x48 && b0 != 0x4C) continue;
        if (pe[s.Ptr + i + 1] != 0x8D) continue;
        if ((pe[s.Ptr + i + 2] & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)s.Ptr + i + 3);
        uint site = s.VA + (uint)i;
        uint tgt = unchecked((uint)(site + 7 + disp));
        StringHit hit;
        if (!targets.TryGetValue(tgt, out hit)) continue;
        list.Add(new Xref {
          Site = site,
          Target = tgt,
          Needle = hit.Needle,
          Text = hit.Text,
          Class = hit.Class
        });
        if (list.Count >= 4000) return list;
      }
    }
    return list;
  }

  static List<Phase> DecodeRegistrar() {
    var list = new List<Phase>();
    long fo = RvaToFile(kRegistrar);
    if (fo < 0) return list;
    int size = (int)Math.Min(kRegistrarEnd - kRegistrar, 0x2000);
    for (int i = 0; i + 7 <= size; i++) {
      byte b0 = pe[fo + i];
      if (b0 != 0x48 && b0 != 0x4C) continue;
      if (pe[fo + i + 1] != 0x8D) continue;
      if ((pe[fo + i + 2] & 0xC7) != 0x05) continue;
      int disp = BitConverter.ToInt32(pe, (int)fo + i + 3);
      uint site = kRegistrar + (uint)i;
      uint tgt = unchecked((uint)(site + 7 + disp));
      var phase = new Phase { Site = site, Target = tgt, Kind = "code_or_data", Text = "" };
      long tfo = RvaToFile(tgt);
      if (tfo >= 0 && tfo + 4 < pe.Length) {
        bool ascii = pe[tfo] >= 32 && pe[tfo] < 127;
        if (ascii) {
          int n = 0;
          while (n < 120 && tfo + n < pe.Length && pe[tfo + n] >= 32 && pe[tfo + n] < 127) n++;
          if (n >= 4 && tfo + n < pe.Length && pe[tfo + n] == 0) {
            phase.Kind = "string";
            phase.Text = Encoding.ASCII.GetString(pe, (int)tfo, n);
          }
        }
        if (phase.Kind != "string") phase.Kind = "pointer";
      }
      list.Add(phase);
    }
    return list;
  }

  static uint FindFunc(uint site) {
    long fo = RvaToFile(site);
    if (fo < 0) return site;
    for (int back = 0; back < 0x1800; back++) {
      long pos = fo - back;
      if (pos < 1) break;
      byte prev = pe[pos - 1];
      if ((prev == 0xCC || prev == 0xC3 || prev == 0x90) && LooksPrologue(pos))
        return FileToRva(pos);
    }
    return site;
  }

  static bool LooksPrologue(long fo) {
    if (fo + 4 >= pe.Length) return false;
    byte b0 = pe[fo], b1 = pe[fo + 1], b2 = pe[fo + 2];
    if (b0 == 0x40 && (b1 == 0x53 || b1 == 0x55 || b1 == 0x56 || b1 == 0x57)) return true;
    if (b0 == 0x48 && (b1 == 0x89 || b1 == 0x83 || b1 == 0x81)) return true;
    if (b0 == 0x48 && b1 == 0x8B && b2 == 0xC4) return true;
    if (b0 == 0x55 || b0 == 0x53 || b0 == 0x56 || b0 == 0x57) return true;
    if (b0 == 0x41 && b1 >= 0x54 && b1 <= 0x57) return true;
    if (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC) return true;
    if (b0 == 0x48 && b1 == 0x81 && b2 == 0xEC) return true;
    return false;
  }

  static List<FuncInfo> GroupFunctions(List<Xref> xrefs) {
    var map = new Dictionary<uint, FuncInfo>();
    foreach (var x in xrefs) {
      x.Func = FindFunc(x.Site);
      FuncInfo info;
      if (!map.TryGetValue(x.Func, out info)) {
        info = new FuncInfo { Entry = x.Func };
        map[x.Func] = info;
      }
      info.Xrefs.Add(x);
      info.XrefCount++;
      int spec = Specificity(x.Needle);
      if (x.Class == "telemetry_schema" || x.Class == "content_ui" || x.Class == "frame_phase_label")
        spec = Math.Min(spec, 1);
      if (spec > info.SpecificScore) info.SpecificScore = spec;
    }
    var list = new List<FuncInfo>(map.Values);
    foreach (var info in list) ScanCalls(info);
    list.Sort(delegate(FuncInfo a, FuncInfo b) {
      int c = Rank(b).CompareTo(Rank(a));
      if (c != 0) return c;
      return a.Entry.CompareTo(b.Entry);
    });
    return list;
  }

  static int Rank(FuncInfo f) {
    int r = f.SpecificScore * 10;
    if (f.CallsAllocator) r += 50;
    if (f.CallsTightFactory) r += 40;
    if (f.CallsDeferredHandler) r -= 30;
    if (f.Entry == kRegistrar) r -= 100;
    return r;
  }

  static void ScanCalls(FuncInfo info) {
    long fo = RvaToFile(info.Entry);
    if (fo < 0) return;
    int size = 0x900;
    long limit = Math.Min(pe.Length, fo + size);
    var seen = new HashSet<uint>();
    for (long i = fo; i + 5 < limit; i++) {
      if (pe[i] != 0xE8) continue;
      int disp = BitConverter.ToInt32(pe, (int)i + 1);
      uint site = FileToRva(i);
      uint tgt = unchecked((uint)(site + 5 + disp));
      if (tgt < 0x1000 || tgt > 0x0E000000) continue;
      if (!seen.Add(tgt)) continue;
      info.Calls.Add(tgt);
      if (tgt == kAllocator) info.CallsAllocator = true;
      if (tgt == kFactoryA || tgt == kFactoryB) info.CallsTightFactory = true;
      if (tgt == kDeferredHandler) info.CallsDeferredHandler = true;
      if (info.Calls.Count >= 24) break;
    }
  }

  static void RankAndDecode(List<FuncInfo> funcs) {
    int decoded = 0;
    foreach (var f in funcs) {
      if (decoded >= 16) break;
      if (f.SpecificScore < 3 && !f.CallsAllocator && !f.CallsTightFactory) continue;
      if (f.Entry == kRegistrar) continue;
      f.Decode = Disasm(f.Entry, 36);
      decoded++;
    }
  }

  static string Disasm(uint rva, int maxIns) {
    long fo = RvaToFile(rva);
    if (fo < 0) return "";
    int len = (int)Math.Min(0x180, pe.Length - fo);
    var code = new byte[len];
    Buffer.BlockCopy(pe, (int)fo, code, 0, len);
    var reader = new ByteArrayCodeReader(code);
    var decoder = Decoder.Create(64, reader);
    decoder.IP = imageBase + rva;
    var sb = new StringBuilder();
    var formatter = new NasmFormatter();
    for (int n = 0; n < maxIns; n++) {
      var ins = decoder.Decode();
      if (ins.Code == Code.INVALID || ins.Length == 0) break;
      if (ins.Mnemonic == Mnemonic.Int3 && n > 4) break;
      var output = new StringOutput();
      formatter.Format(ins, output);
      if (sb.Length > 0) sb.Append(" | ");
      sb.Append(H((uint)(ins.IP - imageBase)));
      sb.Append(' ');
      sb.Append(output.ToString());
      if (ins.Mnemonic == Mnemonic.Ret && n > 2) break;
    }
    if (sb.Length > 1400) return sb.ToString(0, 1400);
    return sb.ToString();
  }

  static string BuildJson(List<StringHit> strings, List<Xref> xrefs, List<Phase> phases,
                           List<FuncInfo> funcs) {
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\": 1,\n");
    sb.Append("  \"milestone\": \"v0.8.0\",\n");
    sb.Append("  \"mode\": \"offline-pe-readonly\",\n");
    sb.Append("  \"excludedAsFactory\": [\"0x1AC380 deferred queue\", \"0x2E97FC0 LOD enqueue\", \"0x426EE50 generic allocator alone\"],\n");
    sb.Append("  \"stringCandidates\": ").Append(strings.Count).Append(",\n");
    sb.Append("  \"leaXrefs\": ").Append(xrefs.Count).Append(",\n");
    sb.Append("  \"functionsTouchingCandidates\": ").Append(funcs.Count).Append(",\n");

    sb.Append("  \"needleCounts\": {\n");
    var counts = new Dictionary<string, int>();
    foreach (var s in strings) {
      int c;
      counts.TryGetValue(s.Needle, out c);
      counts[s.Needle] = c + 1;
    }
    int ni = 0;
    foreach (var kv in counts) {
      if (ni++ > 0) sb.Append(",\n");
      sb.Append("    ").Append(J(kv.Key)).Append(": ").Append(kv.Value.ToString(CultureInfo.InvariantCulture));
    }
    sb.Append("\n  },\n");

    sb.Append("  \"nonSchemaSamples\": [\n");
    int shown = 0;
    foreach (var s in strings) {
      if (s.Class == "telemetry_schema" || s.Class == "content_ui") continue;
      if (shown >= 80) break;
      if (shown++ > 0) sb.Append(",\n");
      sb.Append("    {\"needle\":").Append(J(s.Needle));
      sb.Append(",\"class\":").Append(J(s.Class));
      sb.Append(",\"rva\":\"").Append(H(s.Rva)).Append("\"");
      sb.Append(",\"text\":").Append(J(s.Text)).Append('}');
    }
    sb.Append("\n  ],\n");

    sb.Append("  \"registrarPhaseLeas\": [\n");
    for (int i = 0; i < phases.Count; i++) {
      if (i > 0) sb.Append(",\n");
      var p = phases[i];
      sb.Append("    {\"site\":\"").Append(H(p.Site));
      sb.Append("\",\"target\":\"").Append(H(p.Target));
      sb.Append("\",\"kind\":").Append(J(p.Kind));
      sb.Append(",\"text\":").Append(J(p.Text)).Append('}');
    }
    sb.Append("\n  ],\n");

    sb.Append("  \"rankedFunctions\": [\n");
    int fi = 0;
    foreach (var f in funcs) {
      if (fi >= 40) break;
      if (f.SpecificScore < 2 && !f.CallsAllocator && !f.CallsTightFactory) continue;
      if (fi++ > 0) sb.Append(",\n");
      sb.Append("    {\"entry\":\"").Append(H(f.Entry)).Append("\"");
      sb.Append(",\"score\":").Append(f.SpecificScore);
      sb.Append(",\"rank\":").Append(Rank(f));
      sb.Append(",\"callsAllocator\":").Append(f.CallsAllocator ? "true" : "false");
      sb.Append(",\"callsTightFactory\":").Append(f.CallsTightFactory ? "true" : "false");
      sb.Append(",\"callsDeferredHandler\":").Append(f.CallsDeferredHandler ? "true" : "false");
      sb.Append(",\"xrefs\":[");
      for (int i = 0; i < f.Xrefs.Count && i < 6; i++) {
        if (i > 0) sb.Append(',');
        var x = f.Xrefs[i];
        sb.Append("{\"site\":\"").Append(H(x.Site));
        sb.Append("\",\"needle\":").Append(J(x.Needle));
        sb.Append(",\"class\":").Append(J(x.Class));
        sb.Append(",\"text\":").Append(J(Trim(x.Text, 140))).Append('}');
      }
      sb.Append("],\"calls\":[");
      for (int i = 0; i < f.Calls.Count && i < 12; i++) {
        if (i > 0) sb.Append(',');
        sb.Append('"').Append(H(f.Calls[i])).Append('"');
      }
      sb.Append("],\"decode\":").Append(J(f.Decode)).Append('}');
    }
    sb.Append("\n  ]\n}\n");
    return sb.ToString();
  }

  static string Trim(string s, int n) {
    if (s == null) return "";
    return s.Length <= n ? s : s.Substring(0, n);
  }
}
