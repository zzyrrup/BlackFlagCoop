// v0.6.3 — Offline trace of input consumer 0x187F0550 and deferred-create 0x5CBDFB0.
// Read-only. No spawn/inject/launch.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

class InputActorTrace063 {
  static byte[] pe;
  static List<Sec> secs;
  static ulong imageBase;

  const uint InputEntry = 0x187F0550u;
  const uint InputLeaSite = 0x187F0558u;
  const uint DeferredEntry = 0x5CBDFB0u;
  const uint DeferredLeaSite = 0x5CBE0C7u;
  const uint PadLockRva = 0xA10D838u; // Pad_LockAndTurnMovement from v0.6.2
  const uint CreateDeferredRva = 0xA17A4F0u;

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";
    pe = File.ReadAllBytes(exe);
    ParsePe();
    Directory.CreateDirectory(outDir);

    var input = AnalyzeFunc(InputEntry, 0x2000, "input_0x187F0550");
    // Ensure includes LEA site
    EnsureContains(input, InputLeaSite);
    var deferred = AnalyzeFunc(DeferredEntry, 0x2000, "deferred_0x5CBDFB0");
    EnsureContains(deferred, DeferredLeaSite);

    var inputCallers = FindE8Callers(input.EntryRva, 30);
    var defCallers = FindE8Callers(deferred.EntryRva, 30);
    // Also callers to LEA sites' containing funcs already are entry

    var inputLeas = ExtractLeas(input.EntryRva, input.SizeBytes);
    var inputCalls = ExtractCalls(input.EntryRva, input.SizeBytes);
    var defLeas = ExtractLeas(deferred.EntryRva, deferred.SizeBytes);
    var defCalls = ExtractCalls(deferred.EntryRva, deferred.SizeBytes);

    // Classify LEA targets
    ClassifyLeas(inputLeas);
    ClassifyLeas(defLeas);

    // Check if either function references the other via call
    bool inputCallsDeferred = false, deferredCallsInput = false;
    foreach (var c in inputCalls) if (Overlaps(c.Dest, deferred)) inputCallsDeferred = true;
    foreach (var c in defCalls) if (Overlaps(c.Dest, input)) deferredCallsInput = true;

    // Shared callees
    var shared = SharedCallees(inputCalls, defCalls);

    // Nearby sibling functions that also LEA Pad_* / CreateActors*
    var padSiblings = FindLeaToRva(PadLockRva, 20);
    var createSiblings = FindLeaToRva(CreateDeferredRva, 20);

    // Immmediate string LEAs that look like other Pad_ in input func
    int padLeasInInput = 0, schemaLeasInInput = 0, otherEdataInInput = 0;
    foreach (var l in inputLeas) {
      if (l.Class == "input_action_name") padLeasInInput++;
      else if (l.Class == "schema_json_like") schemaLeasInInput++;
      else if (l.Class.StartsWith("edata")) otherEdataInInput++;
    }
    int createNameLeas = 0, schemaInDef = 0;
    foreach (var l in defLeas) {
      if (l.Class == "frame_phase_label") createNameLeas++;
      if (l.Class == "schema_json_like") schemaInDef++;
    }

    Write(outDir + @"\v0.6.3-input-callgraph.json", BuildInputJson(
      input, inputCallers, inputLeas, inputCalls, padSiblings, padLeasInInput));
    Write(outDir + @"\v0.6.3-deferred-create-callgraph.json", BuildDeferredJson(
      deferred, defCallers, defLeas, defCalls, createSiblings, createNameLeas));
    Write(outDir + @"\v0.6.3-input-actor-connections.json", BuildConvergenceJson(
      input, deferred, shared, inputCallsDeferred, deferredCallsInput,
      padLeasInInput, schemaLeasInInput, createNameLeas, schemaInDef));
    Write(outDir + @"\v0.6.3-second-edward-feasibility.json", BuildFeasibilityJson(
      input, deferred, padLeasInInput, createNameLeas));

    Console.WriteLine("input size=0x{0:X} lea={1} call={2} callers={3} padLeas={4}",
      input.SizeBytes, inputLeas.Count, inputCalls.Count, inputCallers.Count, padLeasInInput);
    Console.WriteLine("deferred size=0x{0:X} lea={1} call={2} callers={3}",
      deferred.SizeBytes, defLeas.Count, defCalls.Count, defCallers.Count);
    Console.WriteLine("sharedCallees={0} input->def={1} def->input={2}",
      shared.Count, inputCallsDeferred, deferredCallsInput);
    return 0;
  }

  class Sec { public string Name; public uint VA, VS, Raw, Ptr, Char; }
  class FuncInfo {
    public string Name; public uint EntryRva; public long EntryFile;
    public uint EndRva; int _size;
    public int SizeBytes { get { return _size; } set { _size = value; EndRva = EntryRva + (uint)value; } }
    public string Prologue; public string BoundaryMethod;
  }
  class LeaRef {
    public uint Site; public uint Target; public long TargetFile; public string Class; public string Preview;
  }
  class CallRef { public uint Site; public uint Dest; }

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

  static string H(uint v) { return "0x" + v.ToString("X"); }
  static string H(ulong v) { return "0x" + v.ToString("X"); }
  static string J(string s) {
    if (s == null) return "null";
    var sb = new StringBuilder("\"");
    foreach (char c in s) {
      if (c == '\\' || c == '"') sb.Append('\\').Append(c);
      else if (c < 32) sb.Append(' ');
      else sb.Append(c);
    }
    return sb.Append('"').ToString();
  }
  static void Write(string path, string json) {
    File.WriteAllText(path, json, new UTF8Encoding(false));
    Console.WriteLine("WROTE " + path);
  }

  static long RvaToFile(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VS, s.Raw);
      if (rva >= s.VA && rva < s.VA + span && s.Ptr > 0)
        return s.Ptr + (rva - s.VA);
    }
    return -1;
  }
  static string SecForRva(uint rva) {
    long fo = RvaToFile(rva);
    if (fo < 0) return null;
    foreach (var s in secs)
      if (fo >= s.Ptr && fo < s.Ptr + s.Raw) return s.Name;
    return null;
  }
  static string AsciiAt(long fo, int n) {
    if (fo < 0 || fo >= pe.Length) return "";
    int len = (int)Math.Min(n, pe.Length - fo);
    var sb = new StringBuilder(len);
    for (int i = 0; i < len; i++) {
      byte b = pe[fo + i];
      sb.Append(b >= 32 && b < 127 ? (char)b : '.');
    }
    return sb.ToString();
  }
  static string HexAt(uint rva, int n) {
    long fo = RvaToFile(rva);
    if (fo < 0) return "";
    int len = (int)Math.Min(n, pe.Length - fo);
    var sb = new StringBuilder();
    for (int i = 0; i < len; i++) {
      if (i > 0) sb.Append(' ');
      sb.Append(pe[fo + i].ToString("X2"));
    }
    return sb.ToString();
  }

  static FuncInfo AnalyzeFunc(uint entry, int maxScan, string name) {
    long fo = RvaToFile(entry);
    var fi = new FuncInfo {
      Name = name, EntryRva = entry, EntryFile = fo,
      Prologue = HexAt(entry, 24), BoundaryMethod = "maxscan"
    };
    if (fo < 0) { fi.SizeBytes = 0; return fi; }
    int end = maxScan;
    for (int i = 16; i + 3 < maxScan && fo + i + 3 < pe.Length; i++) {
      if (pe[fo + i] == 0xC3) {
        int j = i + 1;
        while (j < maxScan && pe[fo + j] == 0xCC) j++;
        if (j - (i + 1) >= 2) { end = i + 1; fi.BoundaryMethod = "ret_then_int3"; break; }
      }
      if (i > 32 && pe[fo + i] == 0xCC && pe[fo + i + 1] == 0xCC && pe[fo + i + 2] == 0xCC) {
        end = i; fi.BoundaryMethod = "int3_run"; break;
      }
    }
    fi.SizeBytes = end;
    return fi;
  }

  static void EnsureContains(FuncInfo f, uint site) {
    if (site < f.EntryRva) return;
    int need = (int)(site - f.EntryRva) + 0x80;
    if (f.SizeBytes < need) {
      var bigger = AnalyzeFunc(f.EntryRva, Math.Max(0x4000, need + 0x200), f.Name);
      if (bigger.SizeBytes > f.SizeBytes) {
        f.SizeBytes = bigger.SizeBytes;
        f.BoundaryMethod = bigger.BoundaryMethod + "_expanded";
      } else {
        f.SizeBytes = need;
        f.BoundaryMethod = "forced_past_key_site";
      }
    }
  }

  static bool Overlaps(uint dest, FuncInfo f) {
    return dest >= f.EntryRva && dest < f.EndRva;
  }

  static List<uint> FindE8Callers(uint target, int max) {
    var list = new List<uint>();
    foreach (var s in secs) {
      if ((s.Char & 0x20000000) == 0 || s.Ptr == 0) continue;
      int size = (int)s.Raw;
      for (int i = 0; i + 5 <= size; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        uint site = s.VA + (uint)i;
        uint dest = unchecked((uint)(site + 5 + rel));
        if (dest != target) continue;
        list.Add(site);
        if (list.Count >= max) return list;
      }
    }
    return list;
  }

  static List<uint> FindLeaToRva(uint target, int max) {
    var list = new List<uint>();
    foreach (var s in secs) {
      if ((s.Char & 0x20000000) == 0 || s.Ptr == 0) continue;
      int size = (int)s.Raw;
      for (int i = 0; i + 7 <= size; i++) {
        byte b0 = pe[s.Ptr + i];
        if ((b0 != 0x48 && b0 != 0x4C) || pe[s.Ptr + i + 1] != 0x8D) continue;
        if ((pe[s.Ptr + i + 2] & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 3));
        uint site = s.VA + (uint)i;
        uint tgt = unchecked((uint)(site + 7 + disp));
        if (tgt != target) continue;
        list.Add(site);
        if (list.Count >= max) return list;
      }
    }
    return list;
  }

  static List<LeaRef> ExtractLeas(uint entry, int size) {
    var list = new List<LeaRef>();
    long fo = RvaToFile(entry);
    if (fo < 0) return list;
    for (int i = 0; i + 7 <= size; i++) {
      byte b0 = pe[fo + i];
      if ((b0 != 0x48 && b0 != 0x4C) || pe[fo + i + 1] != 0x8D) continue;
      if ((pe[fo + i + 2] & 0xC7) != 0x05) continue;
      int disp = BitConverter.ToInt32(pe, (int)(fo + i + 3));
      uint site = entry + (uint)i;
      uint tgt = unchecked((uint)(site + 7 + disp));
      long tf = RvaToFile(tgt);
      list.Add(new LeaRef { Site = site, Target = tgt, TargetFile = tf, Class = "pending", Preview = AsciiAt(tf, 72) });
    }
    return list;
  }

  static List<CallRef> ExtractCalls(uint entry, int size) {
    var list = new List<CallRef>();
    long fo = RvaToFile(entry);
    if (fo < 0) return list;
    for (int i = 0; i + 5 <= size; i++) {
      if (pe[fo + i] != 0xE8) continue;
      int rel = BitConverter.ToInt32(pe, (int)(fo + i + 1));
      uint site = entry + (uint)i;
      uint dest = unchecked((uint)(site + 5 + rel));
      list.Add(new CallRef { Site = site, Dest = dest });
    }
    return list;
  }

  static void ClassifyLeas(List<LeaRef> leas) {
    foreach (var l in leas) {
      string p = l.Preview ?? "";
      if (l.Target == PadLockRva || p.Contains("Pad_") || p.Contains("Key_PlayerInput"))
        l.Class = "input_action_name";
      else if (l.Target == CreateDeferredRva || p.Contains("CreateActorsDeferred") || p.Contains("SingleThreaded"))
        l.Class = "frame_phase_label";
      else if (p.Contains("\"name\":") || p.Contains("compositions") || p.Contains("customAttributes"))
        l.Class = "schema_json_like";
      else if (p.Contains("hk") || p.Contains("Havok") || p.Contains("hkai"))
        l.Class = "havok_naming";
      else if (l.Target >= 0x9036000u && l.Target < 0xA2B2000u)
        l.Class = "edata_other";
      else
        l.Class = "non_edata_or_code_data";
    }
  }

  static List<uint> SharedCallees(List<CallRef> a, List<CallRef> b) {
    var set = new HashSet<uint>();
    foreach (var c in a) set.Add(c.Dest);
    var shared = new List<uint>();
    var seen = new HashSet<uint>();
    foreach (var c in b) {
      if (set.Contains(c.Dest) && seen.Add(c.Dest)) shared.Add(c.Dest);
    }
    return shared;
  }

  static string LeasJson(List<LeaRef> leas, int max) {
    var sb = new StringBuilder("[\n");
    int n = Math.Min(max, leas.Count);
    for (int i = 0; i < n; i++) {
      if (i > 0) sb.Append(",\n");
      var l = leas[i];
      sb.Append("    {\"site\":\"").Append(H(l.Site)).Append("\",\"target\":\"")
        .Append(H(l.Target)).Append("\",\"class\":").Append(J(l.Class))
        .Append(",\"preview\":").Append(J(l.Preview)).Append("}");
    }
    sb.Append("\n  ]");
    return sb.ToString();
  }

  static string CallsJson(List<CallRef> calls, int maxUnique) {
    var sb = new StringBuilder("[");
    var seen = new HashSet<uint>();
    bool first = true;
    foreach (var c in calls) {
      if (!seen.Add(c.Dest)) continue;
      if (!first) sb.Append(",");
      first = false;
      sb.Append("{\"site\":\"").Append(H(c.Site)).Append("\",\"dest\":\"").Append(H(c.Dest)).Append("\"}");
      if (seen.Count >= maxUnique) break;
    }
    sb.Append("]");
    return sb.ToString();
  }

  static string BuildInputJson(FuncInfo f, List<uint> callers, List<LeaRef> leas, List<CallRef> calls,
      List<uint> padLeaSites, int padLeas) {
    // High-signal disasm around InputLeaSite
    string window = HexAt(InputLeaSite > 0x10 ? InputLeaSite - 0x10 : InputLeaSite, 0x40);
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"function\":{\n");
    sb.Append("    \"entryRva\":\"").Append(H(f.EntryRva)).Append("\",\n");
    sb.Append("    \"entryFileOffset\":\"").Append(H((ulong)f.EntryFile)).Append("\",\n");
    sb.Append("    \"endRva\":\"").Append(H(f.EndRva)).Append("\",\n");
    sb.Append("    \"sizeBytes\":").Append(f.SizeBytes).Append(",\n");
    sb.Append("    \"section\":").Append(J(SecForRva(f.EntryRva))).Append(",\n");
    sb.Append("    \"prologue\":").Append(J(f.Prologue)).Append(",\n");
    sb.Append("    \"boundaryMethod\":").Append(J(f.BoundaryMethod)).Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"padLockAndTurnLeaSite\":{\n");
    sb.Append("    \"rva\":\"").Append(H(InputLeaSite)).Append("\",\n");
    sb.Append("    \"targetRva\":\"").Append(H(PadLockRva)).Append("\",\n");
    sb.Append("    \"hexWindow\":").Append(J(window)).Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"directCallersE8\":[");
    for (int i = 0; i < callers.Count; i++) {
      if (i > 0) sb.Append(",");
      sb.Append("\"").Append(H(callers[i])).Append("\"");
    }
    sb.Append("],\n");
    sb.Append("  \"globalLeaSitesToPadLockString\":[");
    for (int i = 0; i < padLeaSites.Count; i++) {
      if (i > 0) sb.Append(",");
      sb.Append("\"").Append(H(padLeaSites[i])).Append("\"");
    }
    sb.Append("],\n");
    sb.Append("  \"leaRipTargetsSample\":").Append(LeasJson(leas, 40)).Append(",\n");
    sb.Append("  \"calleesE8UniqueSample\":").Append(CallsJson(calls, 40)).Append(",\n");
    sb.Append("  \"metrics\":{\"leaCount\":").Append(leas.Count)
      .Append(",\"callCount\":").Append(calls.Count)
      .Append(",\"inputActionNameLeas\":").Append(padLeas).Append("},\n");
    sb.Append("  \"conclusions\":{\n");
    sb.Append("    \"isConfirmedPlayerMovementController\":false,\n");
    sb.Append("    \"referencesPadLockAndTurnMovement\":true,\n");
    sb.Append("    \"likelyRole\":").Append(J(
      padLeas >= 1
        ? "References input action name string(s); may be action-table registration, binding, or logging — not proven as per-frame movement applicator"
        : "Contains LEA to Pad_LockAndTurnMovement; broader role unclear")).Append(",\n");
    sb.Append("    \"actorEntityComponentRefsFound\":false,\n");
    sb.Append("    \"separateInputContextsFound\":false,\n");
    sb.Append("    \"movementCommandDestination\":").Append(J("untraced")).Append("\n");
    sb.Append("  }\n}\n");
    return sb.ToString();
  }

  static string BuildDeferredJson(FuncInfo f, List<uint> callers, List<LeaRef> leas, List<CallRef> calls,
      List<uint> createLeaSites, int createNameLeas) {
    string window = HexAt(DeferredLeaSite > 0x10 ? DeferredLeaSite - 0x10 : DeferredLeaSite, 0x40);
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"function\":{\n");
    sb.Append("    \"entryRva\":\"").Append(H(f.EntryRva)).Append("\",\n");
    sb.Append("    \"entryFileOffset\":\"").Append(H((ulong)f.EntryFile)).Append("\",\n");
    sb.Append("    \"endRva\":\"").Append(H(f.EndRva)).Append("\",\n");
    sb.Append("    \"sizeBytes\":").Append(f.SizeBytes).Append(",\n");
    sb.Append("    \"section\":").Append(J(SecForRva(f.EntryRva))).Append(",\n");
    sb.Append("    \"prologue\":").Append(J(f.Prologue)).Append(",\n");
    sb.Append("    \"boundaryMethod\":").Append(J(f.BoundaryMethod)).Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"createActorsDeferredLeaSite\":{\n");
    sb.Append("    \"rva\":\"").Append(H(DeferredLeaSite)).Append("\",\n");
    sb.Append("    \"targetRva\":\"").Append(H(CreateDeferredRva)).Append("\",\n");
    sb.Append("    \"hexWindow\":").Append(J(window)).Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"directCallersE8\":[");
    for (int i = 0; i < callers.Count; i++) {
      if (i > 0) sb.Append(",");
      sb.Append("\"").Append(H(callers[i])).Append("\"");
    }
    sb.Append("],\n");
    sb.Append("  \"globalLeaSitesToCreateDeferredString\":[");
    for (int i = 0; i < createLeaSites.Count; i++) {
      if (i > 0) sb.Append(",");
      sb.Append("\"").Append(H(createLeaSites[i])).Append("\"");
    }
    sb.Append("],\n");
    sb.Append("  \"leaRipTargetsSample\":").Append(LeasJson(leas, 40)).Append(",\n");
    sb.Append("  \"calleesE8UniqueSample\":").Append(CallsJson(calls, 40)).Append(",\n");
    sb.Append("  \"metrics\":{\"leaCount\":").Append(leas.Count)
      .Append(",\"callCount\":").Append(calls.Count)
      .Append(",\"framePhaseLabelLeas\":").Append(createNameLeas).Append("},\n");
    sb.Append("  \"conclusions\":{\n");
    sb.Append("    \"isConfirmedActorFactory\":false,\n");
    sb.Append("    \"referencesCreateActorsDeferredString\":true,\n");
    sb.Append("    \"likelyRole\":").Append(J(
      "Uses the CreateActorsDeferredSingleThreaded phase name string — consistent with profiler/log/phase registration, not proven as the deferred spawn implementation")).Append(",\n");
    sb.Append("    \"objectsCreatedOrQueued\":").Append(J("unknown — no entity/archetype/transform init pattern confirmed from this function alone")).Append(",\n");
    sb.Append("    \"characterCreationUsesThisPathway\":").Append(J("unverified")).Append("\n");
    sb.Append("  }\n}\n");
    return sb.ToString();
  }

  static string BuildConvergenceJson(FuncInfo input, FuncInfo deferred, List<uint> shared,
      bool a2b, bool b2a, int padLeas, int schemaInInput, int createLeas, int schemaInDef) {
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"directCallBetweenSystems\":{\"inputCallsDeferred\":")
      .Append(a2b ? "true" : "false").Append(",\"deferredCallsInput\":")
      .Append(b2a ? "true" : "false").Append("},\n");
    sb.Append("  \"sharedCalleesE8\":[");
    for (int i = 0; i < Math.Min(30, shared.Count); i++) {
      if (i > 0) sb.Append(",");
      sb.Append("\"").Append(H(shared[i])).Append("\"");
    }
    sb.Append("],\n");
    sb.Append("  \"sharedCalleeCount\":").Append(shared.Count).Append(",\n");
    sb.Append("  \"sharedEntityIdEvidence\":false,\n");
    sb.Append("  \"sharedActorHandleEvidence\":false,\n");
    sb.Append("  \"sharedComponentRegistryEvidence\":false,\n");
    sb.Append("  \"sharedCharacterReferenceEvidence\":false,\n");
    sb.Append("  \"sharedTransformObjectEvidence\":false,\n");
    sb.Append("  \"sharedOwnershipStructureEvidence\":false,\n");
    sb.Append("  \"metrics\":{\"inputActionLeas\":").Append(padLeas)
      .Append(",\"inputSchemaLeas\":").Append(schemaInInput)
      .Append(",\"deferredPhaseLeas\":").Append(createLeas)
      .Append(",\"deferredSchemaLeas\":").Append(schemaInDef).Append("},\n");
    sb.Append("  \"verifiedCreatedEntityToInputReceiverLink\":false,\n");
    sb.Append("  \"assessment\":").Append(J(
      shared.Count > 0
        ? "Functions share some E8 callees (often runtime helpers). No verified shared entity/actor/transform/ownership object tying deferred creation to movement input."
        : "No direct call link and no shared callees found in sampled sets; systems appear unconnected at recovered edges.")).Append("\n");
    sb.Append("}\n");
    return sb.ToString();
  }

  static string BuildFeasibilityJson(FuncInfo input, FuncInfo deferred, int padLeas, int createLeas) {
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"reassessmentAfterLeadTrace\":true,\n");
    sb.Append("  \"assessments\":{\n");
    sb.Append("    \"secondSimultaneousCharacterActor\":{\"class\":").Append(J("plausible_but_unverified"))
      .Append(",\"reason\":").Append(J("Deferred-create lead did not resolve to a character factory")).Append("},\n");
    sb.Append("    \"twoSeparatelyUpdatedTransforms\":{\"class\":").Append(J("plausible_but_unverified"))
      .Append(",\"reason\":").Append(J("Input lead did not expose transform objects")).Append("},\n");
    sb.Append("    \"twoInputContexts\":{\"class\":").Append(J("unknown"))
      .Append(",\"reason\":").Append(J("Pad action string consumer found; multi-context not evidenced")).Append("},\n");
    sb.Append("    \"independentControlOfBothActors\":{\"class\":").Append(J("unknown"))
      .Append(",\"reason\":").Append(J("No ownership/possession layer recovered from these leads")).Append("}\n");
    sb.Append("  },\n");
    sb.Append("  \"inputLeadResolvedToMovementController\":false,\n");
    sb.Append("  \"deferredLeadResolvedToCharacterFactory\":false,\n");
    sb.Append("  \"nextBestInvestigation\":").Append(J(
      "If input function LEAs many Pad_* names, treat as action registry and find writers of action→handler tables. Separately search Domino/scimitar character spawn nodes without relying on CreateActorsDeferred string consumers.")).Append("\n");
    sb.Append("}\n");
    return sb.ToString();
  }
}
