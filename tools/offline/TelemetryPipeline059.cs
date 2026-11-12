// Offline v0.5.9 telemetry pipeline investigation. Read-only.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

class TelemetryPipeline059 {
  static byte[] pe;
  static List<Sec> secs;
  static ulong imageBase;

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";
    pe = File.ReadAllBytes(exe);
    ParsePe();
    Directory.CreateDirectory(outDir);

    var schema = BuildSchemaRegistration();
    var dispatch = BuildDispatch();
    var producer = BuildProducerTrace();
    var edward = BuildEdward();

    Write(outDir + @"\v0.5.9-schema-registration.json", schema);
    Write(outDir + @"\v0.5.9-telemetry-dispatch.json", dispatch);
    Write(outDir + @"\v0.5.9-position-producer-trace.json", producer);
    Write(outDir + @"\v0.5.9-edward-connection-assessment.json", edward);
    Console.WriteLine("WROTE v0.5.9 reports to " + outDir);
    return 0;
  }

  class Sec {
    public string Name; public uint VA, VS, Raw, Ptr, Char;
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
      Sec s = new Sec();
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
  static string H(long v) { return "0x" + v.ToString("X"); }
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "\\n") + "\"";
  }
  static string SecForFile(long fo) {
    foreach (var s in secs)
      if (fo >= s.Ptr && fo < s.Ptr + s.Raw) return s.Name;
    return null;
  }
  static uint? RvaForFile(long fo) {
    foreach (var s in secs)
      if (fo >= s.Ptr && fo < s.Ptr + s.Raw)
        return s.VA + (uint)(fo - s.Ptr);
    return null;
  }
  static string AsciiCtx(long fo, int before, int after) {
    long s = Math.Max(0, fo - before);
    int len = (int)Math.Min(pe.Length - s, before + after);
    var sb = new StringBuilder(len);
    for (int i = 0; i < len; i++) {
      byte b = pe[s + i];
      sb.Append(b >= 32 && b < 127 ? (char)b : '.');
    }
    return sb.ToString();
  }

  static List<long> FindAll(byte[] hay, byte[] needle, long start, long end) {
    var hits = new List<long>();
    end = Math.Min(end, hay.Length);
    int n = needle.Length;
    for (long i = start; i + n <= end; i++) {
      bool ok = true;
      for (int j = 0; j < n; j++) if (hay[i + j] != needle[j]) { ok = false; break; }
      if (ok) hits.Add(i);
    }
    return hits;
  }

  static int CountImm64Exec(ulong va) {
    byte[] needle = BitConverter.GetBytes(va);
    int c = 0;
    foreach (var s in secs) {
      if ((s.Char & 0x20000000) == 0 || s.Ptr == 0 || s.Raw == 0) continue;
      long start = s.Ptr; int size = (int)s.Raw;
      if (start + size > pe.Length) continue;
      for (int i = 0; i + 8 <= size; i++) {
        bool ok = true;
        for (int j = 0; j < 8; j++) if (pe[start + i + j] != needle[j]) { ok = false; break; }
        if (ok) c++;
      }
    }
    return c;
  }

  static List<object> HitList(string[] needles, long start, long end, int maxEach) {
    var list = new List<object>();
    foreach (var n in needles) {
      var bytes = Encoding.ASCII.GetBytes(n);
      var hits = FindAll(pe, bytes, start, end);
      int take = Math.Min(maxEach, hits.Count);
      for (int i = 0; i < take; i++) {
        long fo = hits[i];
        uint? rva = RvaForFile(fo);
        list.Add(new {
          needle = n,
          hitIndex = i,
          totalHitsAtLeast = hits.Count,
          fileOffset = H(fo),
          rva = rva.HasValue ? H(rva.Value) : null,
          section = SecForFile(fo),
          context = AsciiCtx(fo, 60, 140),
          evidenceClass = "string_occurrence"
        });
      }
      if (hits.Count == 0) {
        list.Add(new {
          needle = n,
          hitIndex = -1,
          totalHitsAtLeast = 0,
          fileOffset = (string)null,
          rva = (string)null,
          section = (string)null,
          context = "",
          evidenceClass = "absent_in_scan_window"
        });
      }
    }
    return list;
  }

  // Serialize anonymous objects via manual JSON is painful; build StringBuilders instead.
  static void Write(string path, string json) {
    File.WriteAllText(path, json, Encoding.UTF8);
    Console.WriteLine("  " + path);
  }

  static string BuildSchemaRegistration() {
    // Known sites from prior milestones
    long playerPosComp = 0xA1D77B5;
    long playerPosEvent = 0xA1DE0FE;
    long playerPosXDict = 0xA1D6605;
    long playerPosCstr = 0xA13E3DE;

    // Scan .edata for schema structure extents
    Sec edata = null;
    foreach (var s in secs) if (s.Name.StartsWith(".edata")) { edata = s; break; }
    long edataStart = edata != null ? edata.Ptr : 0x9035600L;
    long edataEnd = edata != null ? edata.Ptr + edata.Raw : edataStart + 0x127C000;

    // Count STANDARD/CUSTOM event definitions and composition maps in edata
    int standardCount = FindAll(pe, Encoding.ASCII.GetBytes("\"type\":\"STANDARD\""), edataStart, edataEnd).Count;
    int customCount = FindAll(pe, Encoding.ASCII.GetBytes("\"type\":\"CUSTOM\""), edataStart, edataEnd).Count;
    int compositionMaps = FindAll(pe, Encoding.ASCII.GetBytes("\"compositions\":["), edataStart, edataEnd).Count;
    int playerPositionName = FindAll(pe, Encoding.ASCII.GetBytes("\"name\":\"PlayerPosition\""), edataStart, edataEnd).Count;
    int playerPositionEvent = FindAll(pe, Encoding.ASCII.GetBytes("\"name\":\"player.position\""), edataStart, edataEnd).Count;

    // Extract full event object text around player.position
    string eventObj = ExtractJsonObjectNear(playerPosEvent, 800);
    string compObj = ExtractJsonObjectNear(playerPosComp, 400);

    // Parse-error / loader beacons (not assuming Harbour)
    string[] parseNeedles = new string[] {
      "Failed to parse", "failed to parse", "ParseError", "JSON parse",
      "customAttributes", "typeAttributes", "isOptional",
      "RegisterEvent", "RegisterComposition", "LoadSchema", "schema",
      "CompositionRegistry", "TelemetrySchema", "EventSchema",
      "STANDARD", "LiveTelemetry", "Metric Categories",
      "us-sdkClientTelemetry", "UIComposition"
    };
    var beacons = new StringBuilder();
    beacons.Append("[\n");
    bool first = true;
    foreach (var n in parseNeedles) {
      var hits = FindAll(pe, Encoding.ASCII.GetBytes(n), edataStart, edataEnd);
      int take = Math.Min(2, hits.Count);
      if (hits.Count == 0) {
        if (!first) beacons.Append(",\n"); first = false;
        beacons.Append("    {\"needle\":").Append(J(n)).Append(",\"totalHits\":0,\"samples\":[]}");
        continue;
      }
      if (!first) beacons.Append(",\n"); first = false;
      beacons.Append("    {\"needle\":").Append(J(n)).Append(",\"totalHits\":").Append(hits.Count).Append(",\"samples\":[");
      for (int i = 0; i < take; i++) {
        long fo = hits[i];
        uint? rva = RvaForFile(fo);
        if (i > 0) beacons.Append(",");
        beacons.Append("{\"fileOffset\":\"").Append(H(fo)).Append("\",\"rva\":")
          .Append(rva.HasValue ? ("\"" + H(rva.Value) + "\"") : "null")
          .Append(",\"section\":").Append(J(SecForFile(fo)))
          .Append(",\"context\":").Append(J(AsciiCtx(fo, 40, 100))).Append("}");
      }
      beacons.Append("]}");
    }
    beacons.Append("\n  ]");

    // PE export names that look schema/telemetry related (exclude huge Harbour_Keel noise unless Telemetry)
    var exportHits = new StringBuilder();
    exportHits.Append("[\n");
    var exports = ListExports();
    bool ef = true;
    int exportMatch = 0;
    foreach (var ex in exports) {
      string name = ex.Item1;
      bool interesting =
        name.IndexOf("Schema", StringComparison.OrdinalIgnoreCase) >= 0 ||
        name.IndexOf("Telemetry", StringComparison.OrdinalIgnoreCase) >= 0 ||
        name.IndexOf("Composition", StringComparison.OrdinalIgnoreCase) >= 0 ||
        name.IndexOf("Metric", StringComparison.OrdinalIgnoreCase) >= 0 ||
        (name.IndexOf("Harbour_StringId", StringComparison.Ordinal) >= 0) ||
        (name.IndexOf("Json", StringComparison.OrdinalIgnoreCase) >= 0 && name.IndexOf("Harbour", StringComparison.Ordinal) < 0);
      if (!interesting) continue;
      exportMatch++;
      if (!ef) exportHits.Append(",\n"); ef = false;
      exportHits.Append("    {\"name\":").Append(J(name))
        .Append(",\"rva\":\"").Append(H(ex.Item2)).Append("\",\"fileOffset\":\"").Append(H(ex.Item3))
        .Append("\",\"section\":").Append(J(SecForFile(ex.Item3)))
        .Append(",\"note\":\"export_symbol_only_not_proven_schema_loader\"}");
    }
    exportHits.Append("\n  ]");

    // Absolute VA xrefs to key string sites
    uint? cstrRva = RvaForFile(playerPosCstr);
    uint? eventRva = RvaForFile(playerPosEvent);
    uint? dictRva = RvaForFile(playerPosXDict);
    int cstrXrefs = cstrRva.HasValue ? CountImm64Exec(imageBase + cstrRva.Value) : 0;
    int eventXrefs = eventRva.HasValue ? CountImm64Exec(imageBase + eventRva.Value) : 0;
    int dictXrefs = dictRva.HasValue ? CountImm64Exec(imageBase + dictRva.Value) : 0;

    var sb = new StringBuilder();
    sb.Append("{\n");
    sb.Append("  \"schemaVersion\": 1,\n");
    sb.Append("  \"generatedUtc\": ").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"method\": \"offline_edata_structure_export_and_string_beacon_scan\",\n");
    sb.Append("  \"imageBase\": \"").Append(H(imageBase)).Append("\",\n");
    sb.Append("  \"edataWindow\": {\"fileStart\":\"").Append(H(edataStart)).Append("\",\"fileEnd\":\"").Append(H(edataEnd)).Append("\"},\n");
    sb.Append("  \"blobInventory\": {\n");
    sb.Append("    \"typeStandardOccurrences\": ").Append(standardCount).Append(",\n");
    sb.Append("    \"typeCustomOccurrences\": ").Append(customCount).Append(",\n");
    sb.Append("    \"compositionsArrayOccurrences\": ").Append(compositionMaps).Append(",\n");
    sb.Append("    \"namePlayerPositionOccurrences\": ").Append(playerPositionName).Append(",\n");
    sb.Append("    \"namePlayerDotPositionOccurrences\": ").Append(playerPositionEvent).Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"confirmedSites\": {\n");
    sb.Append("    \"PlayerPositionComposition\": {\"fileOffset\":\"").Append(H(playerPosComp)).Append("\",\"rva\":\"").Append(H(RvaForFile(playerPosComp).Value)).Append("\",\"section\":").Append(J(SecForFile(playerPosComp))).Append(",\"objectSnippet\":").Append(J(compObj)).Append("},\n");
    sb.Append("    \"playerPositionEvent\": {\"fileOffset\":\"").Append(H(playerPosEvent)).Append("\",\"rva\":\"").Append(H(RvaForFile(playerPosEvent).Value)).Append("\",\"section\":").Append(J(SecForFile(playerPosEvent))).Append(",\"objectSnippet\":").Append(J(eventObj)).Append("},\n");
    sb.Append("    \"PlayerPosXDictionary\": {\"fileOffset\":\"").Append(H(playerPosXDict)).Append("\",\"rva\":\"").Append(H(RvaForFile(playerPosXDict).Value)).Append("\",\"section\":").Append(J(SecForFile(playerPosXDict))).Append(",\"type\":\"float\",\"context\":").Append(J(AsciiCtx(playerPosXDict, 20, 180))).Append("},\n");
    sb.Append("    \"playerPositionCStringToken\": {\"fileOffset\":\"").Append(H(playerPosCstr)).Append("\",\"rva\":\"").Append(H(cstrRva.Value)).Append("\",\"section\":").Append(J(SecForFile(playerPosCstr))).Append(",\"context\":").Append(J(AsciiCtx(playerPosCstr, 40, 80))).Append("}\n");
    sb.Append("  },\n");
    sb.Append("  \"absoluteVaXrefsInExecutableSections\": {\n");
    sb.Append("    \"playerPositionCString\": ").Append(cstrXrefs).Append(",\n");
    sb.Append("    \"playerPositionEventJsonSite\": ").Append(eventXrefs).Append(",\n");
    sb.Append("    \"PlayerPosXDictSite\": ").Append(dictXrefs).Append(",\n");
    sb.Append("    \"note\": \"0 means no classic relocated pointer table found; relative/blob parse still possible\"\n");
    sb.Append("  },\n");
    sb.Append("  \"parseAndLoaderStringBeacons\": ").Append(beacons).Append(",\n");
    sb.Append("  \"relatedPeExports\": ").Append(exportHits).Append(",\n");
    sb.Append("  \"relatedPeExportCount\": ").Append(exportMatch).Append(",\n");
    sb.Append("  \"conclusions\": {\n");
    sb.Append("    \"compositionSchemasEmbeddedInEdata\": true,\n");
    sb.Append("    \"playerPositionRegisteredAsSchemaEntry\": true,\n");
    sb.Append("    \"playerPositionRegistrationMeans\": \"static JSON-like schema blob entry PlayerPosition -> player.position AND STANDARD event named player.position; runtime registration function NOT identified\",\n");
    sb.Append("    \"credibleJsonParserFunctionIdentified\": false,\n");
    sb.Append("    \"harbourAssumedInvolved\": false,\n");
    sb.Append("    \"harbourProvenInvolved\": false,\n");
    sb.Append("    \"confirmedVsGuess\": {\n");
    sb.Append("      \"confirmed\": [\"PlayerPosition composition map\",\"player.position STANDARD event schema\",\"PlayerPosX/Y/Z float dictionary entries\",\"schemas live in .edata\"],\n");
    sb.Append("      \"notConfirmed\": [\"runtime JSON parser RVA\",\"composition registry object\",\"callers that load these blobs\",\"runtime registration of player.position beyond static embedding\"]\n");
    sb.Append("    }\n");
    sb.Append("  }\n");
    sb.Append("}\n");
    return sb.ToString();
  }

  static string ExtractJsonObjectNear(long fo, int maxLen) {
    // Walk left to nearest '{' then right to matching-ish end or maxLen
    long start = fo;
    long min = Math.Max(0, fo - 200);
    while (start > min && pe[start] != (byte)'{') start--;
    if (pe[start] != (byte)'{') start = fo;
    var sb = new StringBuilder();
    int depth = 0;
    for (long i = start; i < pe.Length && sb.Length < maxLen; i++) {
      char c = pe[i] >= 32 && pe[i] < 127 ? (char)pe[i] : '?';
      sb.Append(c);
      if (pe[i] == (byte)'{') depth++;
      else if (pe[i] == (byte)'}') {
        depth--;
        if (depth == 0 && sb.Length > 10) break;
      }
    }
    return sb.ToString();
  }

  static List<Tuple<string, uint, long>> ListExports() {
    var list = new List<Tuple<string, uint, long>>();
    int e = BitConverter.ToInt32(pe, 0x3C);
    ushort magic = BitConverter.ToUInt16(pe, e + 0x18);
    int ddOff = magic == 0x20B ? e + 0x18 + 112 : e + 0x18 + 96; // export dir RVA/size
    uint exportRva = BitConverter.ToUInt32(pe, ddOff);
    if (exportRva == 0) return list;
    long exportFo = RvaToFile(exportRva);
    if (exportFo < 0) return list;
    uint numNames = BitConverter.ToUInt32(pe, (int)exportFo + 24);
    uint addrOfFuncs = BitConverter.ToUInt32(pe, (int)exportFo + 28);
    uint addrOfNames = BitConverter.ToUInt32(pe, (int)exportFo + 32);
    uint addrOfOrds = BitConverter.ToUInt32(pe, (int)exportFo + 36);
    long namesFo = RvaToFile(addrOfNames);
    long ordsFo = RvaToFile(addrOfOrds);
    long funcsFo = RvaToFile(addrOfFuncs);
    for (uint i = 0; i < numNames; i++) {
      uint nameRva = BitConverter.ToUInt32(pe, (int)(namesFo + i * 4));
      long nameFo = RvaToFile(nameRva);
      if (nameFo < 0) continue;
      string name = ReadCString(nameFo);
      ushort ord = BitConverter.ToUInt16(pe, (int)(ordsFo + i * 2));
      uint funcRva = BitConverter.ToUInt32(pe, (int)(funcsFo + ord * 4));
      long funcFo = RvaToFile(funcRva);
      list.Add(Tuple.Create(name, funcRva, funcFo < 0 ? 0 : funcFo));
    }
    return list;
  }

  static long RvaToFile(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VS, s.Raw);
      if (rva >= s.VA && rva < s.VA + span && s.Ptr > 0)
        return s.Ptr + (rva - s.VA);
    }
    return -1;
  }

  static string ReadCString(long fo) {
    var sb = new StringBuilder();
    for (long i = fo; i < pe.Length && i < fo + 512; i++) {
      if (pe[i] == 0) break;
      if (pe[i] < 32 || pe[i] >= 127) break;
      sb.Append((char)pe[i]);
    }
    return sb.ToString();
  }

  static string BuildDispatch() {
    Sec edata = null;
    foreach (var s in secs) if (s.Name.StartsWith(".edata")) { edata = s; break; }
    long edataStart = edata != null ? edata.Ptr : 0x9035600L;
    long edataEnd = edata != null ? edata.Ptr + edata.Raw : edataStart + 0x127C000;

    string[] needles = new string[] {
      "LiveTelemetry", "us-sdkClientTelemetry", "Metric Categories",
      "SendEvent", "EventQueue", "submit", "SubmitEvent",
      "JobQueueAndSendEvents", "PrimaryStoreSyncAndSendEvent",
      "telemetry", "Analytics", "TelemetryEvent",
      "PlayerPosX", "PositionSource", "FightState",
      "invalid string_view position", "rawPosition"
    };

    var samples = new StringBuilder();
    samples.Append("[\n");
    bool first = true;
    foreach (var n in needles) {
      // Prefer whole-file for dispatch-ish names; PlayerPos limited to edata for speed
      long start = (n == "PlayerPosX" || n == "PositionSource" || n == "FightState") ? edataStart : 0;
      long end = (n == "PlayerPosX" || n == "PositionSource" || n == "FightState") ? edataEnd : pe.Length;
      // Actually full file for SendEvent etc is slow on 478MB - scan edata + .impdata exec for non-schema
      if (n != "PlayerPosX" && n != "PositionSource" && n != "FightState") {
        // scan edata only for string table density; also scan first/last? Use edata + search impdata strings area
        start = edataStart; end = edataEnd;
      }
      var hits = FindAll(pe, Encoding.ASCII.GetBytes(n), start, end);
      if (!first) samples.Append(",\n"); first = false;
      samples.Append("    {\"needle\":").Append(J(n)).Append(",\"hitsInScanWindow\":").Append(hits.Count).Append(",\"windowNote\":")
        .Append(J("edata_section")).Append(",\"samples\":[");
      int take = Math.Min(2, hits.Count);
      for (int i = 0; i < take; i++) {
        long fo = hits[i];
        if (i > 0) samples.Append(",");
        samples.Append("{\"fileOffset\":\"").Append(H(fo)).Append("\",\"rva\":\"")
          .Append(H(RvaForFile(fo).Value)).Append("\",\"context\":").Append(J(AsciiCtx(fo, 50, 120))).Append("}");
      }
      samples.Append("]}");
    }
    samples.Append("\n  ]");

    // Classify sink hypotheses from string contexts
    var sb = new StringBuilder();
    sb.Append("{\n");
    sb.Append("  \"schemaVersion\": 1,\n");
    sb.Append("  \"generatedUtc\": ").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"method\": \"offline_string_beacon_dispatch_sink_scan\",\n");
    sb.Append("  \"stringBeacons\": ").Append(samples).Append(",\n");
    sb.Append("  \"standardEventConstruction\": {\n");
    sb.Append("    \"schemaShapeConfirmed\": true,\n");
    sb.Append("    \"builderFunctionIdentified\": false,\n");
    sb.Append("    \"attributeIdResolutionIdentified\": false,\n");
    sb.Append("    \"floatPopulationRoutineIdentified\": false,\n");
    sb.Append("    \"notes\": \"player.position is declared STANDARD with named customAttributes; no offline builder/dispatch RVA found\"\n");
    sb.Append("  },\n");
    sb.Append("  \"sinkHypotheses\": [\n");
    sb.Append("    {\"id\":\"live_telemetry_export\",\"confidence\":\"naming_only\",\"detail\":\"LiveTelemetry / Metric Categories / us-sdkClientTelemetry strings suggest external metrics export path\",\"provenForPlayerPosition\":false},\n");
    sb.Append("    {\"id\":\"job_send_event_primary_store\",\"confidence\":\"naming_only\",\"detail\":\"Job*SendEvent / PrimaryStoreSyncAndSendEvent strings are store-sync jobs, not proven player.position dispatch\",\"provenForPlayerPosition\":false},\n");
    sb.Append("    {\"id\":\"local_file_sink\",\"confidence\":\"unverified\",\"detail\":\"No confirmed local telemetry log format for these events in this pass\",\"provenForPlayerPosition\":false},\n");
    sb.Append("    {\"id\":\"in_memory_only\",\"confidence\":\"unverified\",\"detail\":\"Possible that events are built and dropped/sampled without durable local retention\",\"provenForPlayerPosition\":false}\n");
    sb.Append("  ],\n");
    sb.Append("  \"conclusions\": {\n");
    sb.Append("    \"dispatchFunctionFound\": false,\n");
    sb.Append("    \"serializationFunctionFound\": false,\n");
    sb.Append("    \"playerPosLinkedToGameplayProducer\": false,\n");
    sb.Append("    \"eventDataRetention\": \"unknown\",\n");
    sb.Append("    \"strongestDispatchLead\": \"LiveTelemetry / client telemetry naming — unproven connection to player.position\"\n");
    sb.Append("  }\n");
    sb.Append("}\n");
    return sb.ToString();
  }

  static string BuildProducerTrace() {
    long x = 0xA1D6605, y = 0xA1D663D, z = 0xA1D6675;
    uint? xr = RvaForFile(x), yr = RvaForFile(y), zr = RvaForFile(z);
    int xx = xr.HasValue ? CountImm64Exec(imageBase + xr.Value) : 0;
    int yx = yr.HasValue ? CountImm64Exec(imageBase + yr.Value) : 0;
    int zx = zr.HasValue ? CountImm64Exec(imageBase + zr.Value) : 0;

    // Nearby transform-ish strings in edata — naming only
    string[] nearby = new string[] {
      "initialCharacterPosition", "AgentPosition", "rawPosition",
      "BodyDropGlobalPositionX", "PinPosX", "WorldEncounterSpawn",
      "IKPositionSource", "PositionSource"
    };
    Sec edata = null;
    foreach (var s in secs) if (s.Name.StartsWith(".edata")) { edata = s; break; }
    long es = edata.Ptr, ee = edata.Ptr + edata.Raw;

    var nb = new StringBuilder();
    nb.Append("[\n");
    bool first = true;
    foreach (var n in nearby) {
      var hits = FindAll(pe, Encoding.ASCII.GetBytes(n), es, ee);
      if (!first) nb.Append(",\n"); first = false;
      nb.Append("    {\"needle\":").Append(J(n)).Append(",\"hits\":").Append(hits.Count);
      if (hits.Count > 0) {
        nb.Append(",\"firstFileOffset\":\"").Append(H(hits[0])).Append("\",\"firstContext\":")
          .Append(J(AsciiCtx(hits[0], 40, 100)));
      }
      nb.Append(",\"linkedToPlayerPosProducer\":false,\"evidenceClass\":\"naming_beacon_only\"}");
    }
    nb.Append("\n  ]");

    var sb = new StringBuilder();
    sb.Append("{\n");
    sb.Append("  \"schemaVersion\": 1,\n");
    sb.Append("  \"generatedUtc\": ").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"attributeSites\": {\n");
    sb.Append("    \"PlayerPosX\": {\"fileOffset\":\"").Append(H(x)).Append("\",\"rva\":\"").Append(H(xr.Value)).Append("\",\"type\":\"float\",\"absVaXrefs\":").Append(xx).Append("},\n");
    sb.Append("    \"PlayerPosY\": {\"fileOffset\":\"").Append(H(y)).Append("\",\"rva\":\"").Append(H(yr.Value)).Append("\",\"type\":\"float\",\"absVaXrefs\":").Append(yx).Append("},\n");
    sb.Append("    \"PlayerPosZ\": {\"fileOffset\":\"").Append(H(z)).Append("\",\"rva\":\"").Append(H(zr.Value)).Append("\",\"type\":\"float\",\"absVaXrefs\":").Append(zx).Append("}\n");
    sb.Append("  },\n");
    sb.Append("  \"relatedPositionNamingBeacons\": ").Append(nb).Append(",\n");
    sb.Append("  \"conclusions\": {\n");
    sb.Append("    \"xyzOriginateFrom\": \"unknown — schema declares float attributes; no producer routine identified\",\n");
    sb.Append("    \"gameplayTransformLink\": false,\n");
    sb.Append("    \"navigationSystemLink\": false,\n");
    sb.Append("    \"absolutePointerXrefsToDictEntries\": false,\n");
    sb.Append("    \"safeReadPathExists\": false\n");
    sb.Append("  }\n");
    sb.Append("}\n");
    return sb.ToString();
  }

  static string BuildEdward() {
    long edward = 0xA1708A7;
    long playerPosEvent = 0xA1DE0FE;
    long playerPosComp = 0xA1D77B5;
    long distanceToEvent = Math.Abs(playerPosEvent - edward);
    long distanceToComp = Math.Abs(playerPosComp - edward);

    // Search Edward variants
    string[] names = new string[] { "Edward", "edward", "Kenway", "PlayerCharacter", "LocalPlayer" };
    Sec edata = null;
    foreach (var s in secs) if (s.Name.StartsWith(".edata")) { edata = s; break; }
    long es = edata.Ptr, ee = edata.Ptr + edata.Raw;

    var hitsSb = new StringBuilder();
    hitsSb.Append("[\n");
    bool first = true;
    foreach (var n in names) {
      var hits = FindAll(pe, Encoding.ASCII.GetBytes(n), es, ee);
      if (!first) hitsSb.Append(",\n"); first = false;
      hitsSb.Append("    {\"needle\":").Append(J(n)).Append(",\"hitsInEdata\":").Append(hits.Count);
      if (hits.Count > 0) {
        hitsSb.Append(",\"firstFileOffset\":\"").Append(H(hits[0])).Append("\",\"firstContext\":")
          .Append(J(AsciiCtx(hits[0], 50, 120)));
      }
      hitsSb.Append(",\"linkedToPlayerPositionSchema\":false}");
    }
    hitsSb.Append("\n  ]");

    // Character field on schemas?
    int characterInPlayerPosObj = ExtractJsonObjectNear(playerPosEvent, 800).IndexOf("Character", StringComparison.Ordinal);
    int edwardInPlayerPosObj = ExtractJsonObjectNear(playerPosEvent, 800).IndexOf("Edward", StringComparison.Ordinal);

    var sb = new StringBuilder();
    sb.Append("{\n");
    sb.Append("  \"schemaVersion\": 1,\n");
    sb.Append("  \"generatedUtc\": ").Append(J(DateTime.UtcNow.ToString("o"))).Append(",\n");
    sb.Append("  \"edwardStringSite\": {\"fileOffset\":\"").Append(H(edward)).Append("\",\"rva\":\"").Append(H(RvaForFile(edward).Value)).Append("\",\"context\":").Append(J(AsciiCtx(edward, 60, 140))).Append("},\n");
    sb.Append("  \"distanceBytes\": {\"toPlayerPositionEvent\":").Append(distanceToEvent).Append(",\"toPlayerPositionComposition\":").Append(distanceToComp).Append("},\n");
    sb.Append("  \"nameScans\": ").Append(hitsSb).Append(",\n");
    sb.Append("  \"playerPositionSchemaContains\": {\n");
    sb.Append("    \"EdwardField\": ").Append(edwardInPlayerPosObj >= 0 ? "true" : "false").Append(",\n");
    sb.Append("    \"CharacterField\": ").Append(characterInPlayerPosObj >= 0 ? "true" : "false").Append("\n");
    sb.Append("  },\n");
    sb.Append("  \"conclusions\": {\n");
    sb.Append("    \"verifiedConnectionToEdwardActor\": false,\n");
    sb.Append("    \"verifiedConnectionToActivePlayerCharacter\": false,\n");
    sb.Append("    \"verifiedWorldCoordinates\": false,\n");
    sb.Append("    \"verifiedTransformOrMovementUpdates\": false,\n");
    sb.Append("    \"edwardLiteralClassification\": \"content/UI/leaderboard name-table token near richard/standard; not an actor-definition link to player.position\",\n");
    sb.Append("    \"assessment\": \"No defensible Edward connection from telemetry schema pipeline offline\"\n");
    sb.Append("  }\n");
    sb.Append("}\n");
    return sb.ToString();
  }
}
