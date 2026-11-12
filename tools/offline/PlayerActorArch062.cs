// v0.6.2 — Offline player actor / control architecture investigation.
// Read-only. No spawn/inject/launch.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

class PlayerActorArch062 {
  static byte[] pe;
  static List<Sec> secs;
  static ulong imageBase;

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";
    pe = File.ReadAllBytes(exe);
    ParsePe();
    Directory.CreateDirectory(outDir);

    // High-value needles for actor/control (prefer distinctive over generic Physics)
    string[] actorNeedles = new string[] {
      "CreateActorsDeferred", "CreateActorsDeferredSingleThreaded",
      "DestroyActors", "DestroyActor",
      "PlayerDespawn", "PlayerKill", "PlayerNav",
      "Pad_LockAndTurnMovement", "Pad_StartAutomovement",
      "Key_PlayerInput_", "Pad_PlayerInput_",
      "Edward", "edward",
      "LocalPlayer", "PlayerController", "PlayerCharacter",
      "Possess", "Unpossess", "SplitScreen", "LocalCoop",
      "EntityId", "Archetype",
      "initialCharacterPosition",
      "CLBoardingRealization",
      "HasAuthority", "NetOwner"
    };

    string[] controlNeedles = new string[] {
      "Pad_LockAndTurnMovement", "Pad_StartAutomovement",
      "Pad_PlayerInput_HiddenHandAssassinationAbility",
      "Key_PlayerInput_HiddenHandAssassinationAbility",
      "ConnectedInputDeviceList",
      "PlayerNavStartSignal", "PlayerNavStopSignal",
      "PlayerDespawnSignal", "PlayerKillSignal"
    };

    string[] lifecycleNeedles = new string[] {
      "CreateActorsDeferredSingleThreaded",
      "DestroyActors",
      "UpdateAISingleThreaded",
      "PlayerDespawnSignal",
      "PlayerKillSignal",
      "custom.PlayerDespawn",
      "custom.PlayerKill"
    };

    var actorHits = ProbeNeedles(actorNeedles, 3);
    var controlHits = ProbeNeedles(controlNeedles, 3);
    var lifeHits = ProbeNeedles(lifecycleNeedles, 3);

    // RIP LEA refs to selected high-value strings
    var ripFocus = new[] {
      "CreateActorsDeferredSingleThreaded",
      "Pad_LockAndTurnMovement",
      "Edward",
      "PlayerDespawnSignal",
      "PlayerKillSignal",
      "PlayerNavStartSignal",
      "initialCharacterPosition"
    };
    var ripReport = new StringBuilder();
    ripReport.Append("[\n");
    for (int i = 0; i < ripFocus.Length; i++) {
      if (i > 0) ripReport.Append(",\n");
      ripReport.Append(RipToStringJson(ripFocus[i]));
      Console.WriteLine("RIP done: " + ripFocus[i]);
    }
    ripReport.Append("\n  ]");

    // Limited 0x1A64E70 follow-up
    string helperBrief = AnalyzeHelper1A64E70();

    // Exports related to actor/player (sparse)
    string exports = RelatedExports();

    Write(outDir + @"\v0.6.2-player-actor-candidates.json", BuildActorCandidates(actorHits, ripReport.ToString(), exports));
    Write(outDir + @"\v0.6.2-actor-lifecycle-callgraph.json", BuildLifecycle(lifeHits, ripReport.ToString()));
    Write(outDir + @"\v0.6.2-player-control-input-trace.json", BuildControl(controlHits));
    Write(outDir + @"\v0.6.2-second-edward-feasibility.json", BuildFeasibility(helperBrief));

    Console.WriteLine("Done v0.6.2");
    return 0;
  }

  class Sec { public string Name; public uint VA, VS, Raw, Ptr, Char; }
  class Hit {
    public string Needle; public long FileOffset; public uint Rva; public string Section; public string Context;
    public int TotalHits; public string EvidenceClass;
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
  static uint? FileToRva(long fo) {
    foreach (var s in secs)
      if (fo >= s.Ptr && fo < s.Ptr + s.Raw)
        return s.VA + (uint)(fo - s.Ptr);
    return null;
  }
  static string SecForFile(long fo) {
    foreach (var s in secs)
      if (fo >= s.Ptr && fo < s.Ptr + s.Raw) return s.Name;
    return null;
  }
  static string AsciiAt(long fo, int before, int after) {
    long s = Math.Max(0, fo - before);
    int len = (int)Math.Min(pe.Length - s, before + after);
    var sb = new StringBuilder(len);
    for (int i = 0; i < len; i++) {
      byte b = pe[s + i];
      sb.Append(b >= 32 && b < 127 ? (char)b : '.');
    }
    return sb.ToString();
  }

  static List<long> FindAll(string needle) {
    byte[] n = Encoding.ASCII.GetBytes(needle);
    var hits = new List<long>();
    // Prefer .edata for string tables; also scan whole image for short distinctive needles
    long start = 0, end = pe.Length;
    foreach (var s in secs) {
      if (s.Name.StartsWith(".edata")) { start = s.Ptr; end = s.Ptr + s.Raw; break; }
    }
    // For code-ish names also search executable sections if not found in edata
    SearchRange(n, start, end, hits);
    if (hits.Count == 0) {
      foreach (var s in secs) {
        if ((s.Char & 0x20000000) == 0 || s.Ptr == 0) continue;
        SearchRange(n, s.Ptr, s.Ptr + s.Raw, hits);
        if (hits.Count > 0) break;
      }
    }
    if (hits.Count == 0) SearchRange(n, 0, pe.Length, hits);
    return hits;
  }

  static void SearchRange(byte[] n, long start, long end, List<long> hits) {
    end = Math.Min(end, pe.Length);
    for (long i = start; i + n.Length <= end; i++) {
      bool ok = true;
      for (int j = 0; j < n.Length; j++) if (pe[i + j] != n[j]) { ok = false; break; }
      if (ok) hits.Add(i);
    }
  }

  static List<Hit> ProbeNeedles(string[] needles, int maxEach) {
    var list = new List<Hit>();
    foreach (var n in needles) {
      var hits = FindAll(n);
      if (hits.Count == 0) {
        list.Add(new Hit {
          Needle = n, FileOffset = -1, Rva = 0, Section = null, Context = "",
          TotalHits = 0, EvidenceClass = "absent"
        });
        continue;
      }
      int take = Math.Min(maxEach, hits.Count);
      for (int i = 0; i < take; i++) {
        long fo = hits[i];
        uint rva = FileToRva(fo) ?? 0;
        list.Add(new Hit {
          Needle = n, FileOffset = fo, Rva = rva, Section = SecForFile(fo),
          Context = AsciiAt(fo, 60, 140), TotalHits = hits.Count,
          EvidenceClass = ClassifyContext(n, AsciiAt(fo, 40, 120))
        });
      }
    }
    return list;
  }

  static string ClassifyContext(string needle, string ctx) {
    if (ctx.Contains("\"name\":") || ctx.Contains("compositions") || ctx.Contains("customAttributes"))
      return "telemetry_or_composition_schema";
    if (ctx.Contains("hk") || ctx.Contains("Havok") || ctx.Contains("hkai") || ctx.Contains("hknp"))
      return "havok_or_physics_naming";
    if (ctx.Contains("Pad_") || ctx.Contains("Key_PlayerInput"))
      return "input_action_table";
    if (ctx.Contains("SingleThreaded") || ctx.Contains("Update"))
      return "frame_update_phase_label";
    if (needle == "Edward" || needle == "edward")
      return "content_name_table_or_ui";
    if (ctx.Contains("Leaderboard") || ctx.Contains("KenwayFleet"))
      return "content_name_table_or_ui";
    return "string_occurrence";
  }

  static List<uint> FindLeaToRva(uint targetRva, int max) {
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
        if (tgt != targetRva) continue;
        list.Add(site);
        if (list.Count >= max) return list;
      }
    }
    return list;
  }

  static uint FindPrologue(uint site, int maxBack) {
    long fo = RvaToFile(site);
    if (fo < 0) return site;
    for (int back = 0; back < maxBack; back++) {
      long pos = fo - back;
      if (pos < 1) break;
      if ((pe[pos - 1] == 0xCC || pe[pos - 1] == 0xC3) && LooksPrologue(pos))
        return FileToRva(pos) ?? site;
    }
    return site & ~0xFu;
  }

  static bool LooksPrologue(long fo) {
    if (fo + 3 >= pe.Length) return false;
    byte b0 = pe[fo], b1 = pe[fo + 1], b2 = pe[fo + 2];
    if (b0 == 0x55 || b0 == 0x53 || b0 == 0x56 || b0 == 0x57) return true;
    if (b0 == 0x41 && b1 >= 0x50 && b1 <= 0x57) return true;
    if (b0 == 0x40 && b1 >= 0x50 && b1 <= 0x57) return true;
    if (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC) return true;
    if (b0 == 0x48 && b1 == 0x89) return true;
    return false;
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

  static string RipToStringJson(string needle) {
    var hits = FindAll(needle);
    var sb = new StringBuilder();
    sb.Append("    {\"needle\":").Append(J(needle)).Append(",\"stringHits\":").Append(hits.Count);
    if (hits.Count == 0) {
      sb.Append(",\"leaSites\":[],\"note\":").Append(J("string not found")).Append("}");
      return sb.ToString();
    }
    // Use first hit that looks like a standalone token when possible
    long fo = hits[0];
    uint rva = FileToRva(fo) ?? 0;
    var leas = FindLeaToRva(rva, 15);
    sb.Append(",\"firstFileOffset\":\"").Append(H((ulong)fo)).Append("\",\"firstRva\":\"")
      .Append(H(rva)).Append("\",\"context\":").Append(J(AsciiAt(fo, 50, 100)))
      .Append(",\"evidenceClass\":").Append(J(ClassifyContext(needle, AsciiAt(fo, 40, 100))))
      .Append(",\"leaRipCount\":").Append(leas.Count).Append(",\"leaSites\":[");
    for (int i = 0; i < leas.Count; i++) {
      if (i > 0) sb.Append(",");
      uint entry = FindPrologue(leas[i], 0x200);
      var callers = FindE8Callers(entry, 5);
      sb.Append("{\"leaSiteRva\":\"").Append(H(leas[i])).Append("\",\"approxFuncEntry\":\"")
        .Append(H(entry)).Append("\",\"entryCallersE8\":[");
      for (int j = 0; j < callers.Count; j++) {
        if (j > 0) sb.Append(",");
        sb.Append("\"").Append(H(callers[j])).Append("\"");
      }
      sb.Append("]}");
    }
    sb.Append("]}");
    return sb.ToString();
  }

  static string AnalyzeHelper1A64E70() {
    uint entry = 0x1A64E70u;
    long fo = RvaToFile(entry);
    if (fo < 0) return "{\"found\":false}";
    // size from prior: ~374
    int size = 0x200;
    // find int3
    for (int i = 32; i + 2 < size; i++) {
      if (pe[fo + i] == 0xCC && pe[fo + i + 1] == 0xCC) { size = i; break; }
    }
    int calls = 0;
    var callees = new List<uint>();
    int storeCount = 0;
    for (int i = 0; i + 5 < size; i++) {
      if (pe[fo + i] == 0xE8) {
        calls++;
        int rel = BitConverter.ToInt32(pe, (int)(fo + i + 1));
        uint dest = unchecked((uint)(entry + (uint)i + 5 + rel));
        if (callees.Count < 16) callees.Add(dest);
      }
      // mov [reg+disp], reg  rough: 48 89 xx
      if (pe[fo + i] == 0x48 && pe[fo + i + 1] == 0x89) storeCount++;
    }
    var sb = new StringBuilder();
    sb.Append("{\"entryRva\":\"0x1A64E70\",\"sizeBytes\":").Append(size)
      .Append(",\"e8Calls\":").Append(calls)
      .Append(",\"movR64MemRoughCount\":").Append(storeCount)
      .Append(",\"callees\":[");
    for (int i = 0; i < callees.Count; i++) {
      if (i > 0) sb.Append(",");
      sb.Append("\"").Append(H(callees[i])).Append("\"");
    }
    sb.Append("],\"assessment\":")
      .Append(J("Small helper with several calls and stores; likely forwards/transforms an object (possibly string). Not a schema JSON parser. Do not displace actor research."))
      .Append(",\"storesOrForwardsSchemaStrings\":\"plausible_unverified\"}");
    return sb.ToString();
  }

  static string RelatedExports() {
    // Parse export names briefly
    int e = BitConverter.ToInt32(pe, 0x3C);
    ushort magic = BitConverter.ToUInt16(pe, e + 0x18);
    int dd = magic == 0x20B ? e + 0x18 + 112 : e + 0x18 + 96;
    uint er = BitConverter.ToUInt32(pe, dd);
    if (er == 0) return "[]";
    long efo = RvaToFile(er);
    if (efo < 0) return "[]";
    uint numNames = BitConverter.ToUInt32(pe, (int)efo + 24);
    uint namesRva = BitConverter.ToUInt32(pe, (int)efo + 32);
    long namesFo = RvaToFile(namesRva);
    var sb = new StringBuilder("[");
    bool first = true;
    int matched = 0;
    for (uint i = 0; i < numNames && matched < 30; i++) {
      uint nr = BitConverter.ToUInt32(pe, (int)(namesFo + i * 4));
      long nf = RvaToFile(nr);
      if (nf < 0) continue;
      string name = ReadCString(nf);
      if (name.IndexOf("Actor", StringComparison.OrdinalIgnoreCase) < 0 &&
          name.IndexOf("Player", StringComparison.OrdinalIgnoreCase) < 0 &&
          name.IndexOf("Character", StringComparison.OrdinalIgnoreCase) < 0 &&
          name.IndexOf("Possess", StringComparison.OrdinalIgnoreCase) < 0 &&
          name.IndexOf("Input", StringComparison.OrdinalIgnoreCase) < 0)
        continue;
      // skip huge unrelated
      if (name.StartsWith("Harbour_Keel")) continue;
      if (!first) sb.Append(",");
      first = false;
      sb.Append(J(name));
      matched++;
    }
    sb.Append("]");
    return sb.ToString();
  }

  static string ReadCString(long fo) {
    var sb = new StringBuilder();
    for (long i = fo; i < pe.Length && i < fo + 256; i++) {
      if (pe[i] == 0) break;
      if (pe[i] < 32 || pe[i] > 126) break;
      sb.Append((char)pe[i]);
    }
    return sb.ToString();
  }

  static string HitsJson(List<Hit> hits) {
    var sb = new StringBuilder("[\n");
    for (int i = 0; i < hits.Count; i++) {
      var h = hits[i];
      if (i > 0) sb.Append(",\n");
      sb.Append("    {\"needle\":").Append(J(h.Needle))
        .Append(",\"totalHits\":").Append(h.TotalHits)
        .Append(",\"fileOffset\":").Append(h.FileOffset < 0 ? "null" : ("\"" + H((ulong)h.FileOffset) + "\""))
        .Append(",\"rva\":").Append(h.FileOffset < 0 ? "null" : ("\"" + H(h.Rva) + "\""))
        .Append(",\"section\":").Append(J(h.Section))
        .Append(",\"evidenceClass\":").Append(J(h.EvidenceClass))
        .Append(",\"context\":").Append(J(h.Context)).Append("}");
    }
    sb.Append("\n  ]");
    return sb.ToString();
  }

  static string BuildActorCandidates(List<Hit> hits, string rip, string exports) {
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"method\":").Append(J("string_context_classification_plus_rip_lea_to_selected_tokens")).Append(",\n");
    sb.Append("  \"imageBase\":\"").Append(H(imageBase)).Append("\",\n");
    sb.Append("  \"needleHits\":").Append(HitsJson(hits)).Append(",\n");
    sb.Append("  \"ripLeaToSelectedStrings\":").Append(rip).Append(",\n");
    sb.Append("  \"relatedExportsSample\":").Append(exports).Append(",\n");
    sb.Append("  \"conclusions\":{\n");
    sb.Append("    \"activePlayerActorTypeIdentified\":false,\n");
    sb.Append("    \"edwardIsActorClass\":false,\n");
    sb.Append("    \"edwardLiteralIsContentNameTable\":true,\n");
    sb.Append("    \"bestLifecycleLead\":").Append(J("CreateActorsDeferredSingleThreaded frame-phase label + PlayerDespawn/PlayerKill schema signals — not proven factories")).Append(",\n");
    sb.Append("    \"playerControllerSymbolFound\":false,\n");
    sb.Append("    \"note\":").Append(J("Absent LocalPlayer/PlayerController/Possess/SplitScreen strings. Architecture remains opaque at factory/ownership level.")).Append("\n");
    sb.Append("  }\n}\n");
    return sb.ToString();
  }

  static string BuildLifecycle(List<Hit> hits, string rip) {
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"needleHits\":").Append(HitsJson(hits)).Append(",\n");
    sb.Append("  \"ripLeaReuse\":").Append(J("See player-actor-candidates ripLeaToSelectedStrings for CreateActorsDeferred*/PlayerDespawn*")).Append(",\n");
    sb.Append("  \"stages\":{\n");
    sb.Append("    \"creation\":{\"status\":\"unverified\",\"lead\":").Append(J("CreateActorsDeferredSingleThreaded is an update-phase name; RIP LEAs to the string may be log/profiler references, not the factory body")).Append("},\n");
    sb.Append("    \"constructionInit\":{\"status\":\"unverified\",\"lead\":null},\n");
    sb.Append("    \"componentAttachment\":{\"status\":\"unverified\",\"lead\":null},\n");
    sb.Append("    \"transformInit\":{\"status\":\"unverified\",\"lead\":").Append(J("initialCharacterPosition remains Havok/nav naming; not Edward transform API")).Append("},\n");
    sb.Append("    \"activation\":{\"status\":\"unverified\",\"lead\":null},\n");
    sb.Append("    \"destruction\":{\"status\":\"naming_only\",\"lead\":").Append(J("DestroyActors in swarm/Havok operator tables; PlayerDespawn/PlayerKill are telemetry compositions")).Append("}\n");
    sb.Append("  },\n");
    sb.Append("  \"conclusions\":{\n");
    sb.Append("    \"characterFactoryIdentified\":false,\n");
    sb.Append("    \"edwardSpawnPathIdentified\":false,\n");
    sb.Append("    \"prioritizeCharacterOverPhysics\":true,\n");
    sb.Append("    \"note\":").Append(J("No defensible character actor create/destroy function body identified offline in this pass.")).Append("\n");
    sb.Append("  }\n}\n");
    return sb.ToString();
  }

  static string BuildControl(List<Hit> hits) {
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"needleHits\":").Append(HitsJson(hits)).Append(",\n");
    // RIP for pad lock
    var padHits = FindAll("Pad_LockAndTurnMovement");
    sb.Append("  \"padLockAndTurn\":{\n");
    if (padHits.Count > 0) {
      long fo = padHits[0];
      uint rva = FileToRva(fo) ?? 0;
      var leas = FindLeaToRva(rva, 20);
      sb.Append("    \"fileOffset\":\"").Append(H((ulong)fo)).Append("\",\"rva\":\"").Append(H(rva)).Append("\",\n");
      sb.Append("    \"leaRipCount\":").Append(leas.Count).Append(",\"leaSiteSamples\":[");
      for (int i = 0; i < Math.Min(10, leas.Count); i++) {
        if (i > 0) sb.Append(",");
        uint entry = FindPrologue(leas[i], 0x180);
        sb.Append("{\"lea\":\"").Append(H(leas[i])).Append("\",\"approxEntry\":\"").Append(H(entry)).Append("\"}");
      }
      sb.Append("]\n");
    } else sb.Append("    \"found\":false\n");
    sb.Append("  },\n");
    sb.Append("  \"conclusions\":{\n");
    sb.Append("    \"activePlayerIdentificationMechanism\":").Append(J("unknown")).Append(",\n");
    sb.Append("    \"inputActionTableExists\":true,\n");
    sb.Append("    \"playerControllerObjectFound\":false,\n");
    sb.Append("    \"possessionApiFound\":false,\n");
    sb.Append("    \"ownershipSeparateFromExistence\":").Append(J("unknown")).Append(",\n");
    sb.Append("    \"multipleControlContextsEvidence\":false,\n");
    sb.Append("    \"note\":").Append(J("Pad_/Key_PlayerInput_* tables show single-player-oriented action naming. Code that binds actions to an actor is not yet identified.")).Append("\n");
    sb.Append("  }\n}\n");
    return sb.ToString();
  }

  static string BuildFeasibility(string helperBrief) {
    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\":1,\n");
    sb.Append("  \"generatedUtc\":").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"helper1A64E70Brief\":").Append(helperBrief).Append(",\n");
    sb.Append("  \"assessments\":{\n");
    sb.Append("    \"twoSimultaneousCharacterActors\":{\"class\":").Append(J("plausible_but_unverified"))
      .Append(",\"reason\":").Append(J("Deferred multi-actor create vocabulary exists; no proof of two playable characters")).Append("},\n");
    sb.Append("    \"twoIndependentTransforms\":{\"class\":").Append(J("plausible_but_unverified"))
      .Append(",\"reason\":").Append(J("Engine is a 3D character game with many entities; dual player transforms unproven")).Append("},\n");
    sb.Append("    \"separateInputOwnership\":{\"class\":").Append(J("unknown"))
      .Append(",\"reason\":").Append(J("No PlayerController/Possess/SplitScreen evidence; input tables look single-local")).Append("},\n");
    sb.Append("    \"separateCameraControlContexts\":{\"class\":").Append(J("unknown"))
      .Append(",\"reason\":").Append(J("No split-player camera architecture found in string/export scan")).Append("},\n");
    sb.Append("    \"twoEdwardArchetypeInstances\":{\"class\":").Append(J("unknown"))
      .Append(",\"reason\":").Append(J("Edward is a content name-table token, not a proven archetype factory handle")).Append("}\n");
    sb.Append("  },\n");
    sb.Append("  \"biggestBlocker\":").Append(J("No identified player-actor factory, ownership/possession model, or input→actor binding that could host a second Edward.")).Append(",\n");
    sb.Append("  \"safestNextExperiment\":").Append(J("Offline: deepen RIP/call analysis of Pad_* action dispatch and CreateActorsDeferred phase handlers that are character-scoped (exclude Havok swarm DestroyActors). Still no spawn.")).Append("\n");
    sb.Append("}\n");
    return sb.ToString();
  }
}
