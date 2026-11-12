// v0.6.3 deep pass — refine tiny input wrappers + callee 0x18EADD0 + deferred phase table.
// Read-only. No spawn/inject/launch.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

class InputActorTrace063Deep {
  static byte[] pe;
  static List<Sec> secs;
  static ulong imageBase;

  const uint InputEntry = 0x187F0550u;
  const uint DeferredEntry = 0x5CBDFB0u;
  const uint SharedHelper = 0x18EADD0u; // first E8 from input wrapper

  struct Sec { public string Name; public uint Va, VSize, Raw, Ptr; public uint Char; }
  class Lea { public uint Site, Target; public string Preview, Class; }
  class Call { public uint Site, Dest; public bool DestMapped; }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";
    pe = File.ReadAllBytes(exe);
    ParsePe();
    Directory.CreateDirectory(outDir);

    // --- Input: true boundary to first RET ---
    uint inputEnd = FindRetEnd(InputEntry, 0x80);
    uint inputSize = inputEnd - InputEntry;
    var inputCalls = ExtractCalls(InputEntry, inputSize);
    var inputLeas = ExtractLeas(InputEntry, inputSize);
    ClassifyLeas(inputLeas);

    // Sibling Pad_/Key_ wrappers in ±0x800 window around input entry
    var siblings = FindNearbyInputWrappers(InputEntry - 0x200, 0x1000, 80);

    // Analyze shared helper
    uint helperEnd = FindRetEnd(SharedHelper, 0x800);
    if (helperEnd <= SharedHelper) helperEnd = SharedHelper + 0x400;
    uint helperSize = helperEnd - SharedHelper;
    var helperCalls = ExtractCalls(SharedHelper, helperSize);
    var helperLeas = ExtractLeas(SharedHelper, helperSize);
    ClassifyLeas(helperLeas);
    var helperCallers = FindE8Callers(SharedHelper, 40);

    // Absolute/RIP qword pointers to InputEntry and DeferredEntry
    var ptrsToInput = FindQwordPointersTo(InputEntry, 25);
    var ptrsToDef = FindQwordPointersTo(DeferredEntry, 25);
    var ptrsToHelper = FindQwordPointersTo(SharedHelper, 25);

    // --- Deferred ---
    uint defEnd = FindInt3OrRetEnd(DeferredEntry, 0x3000);
    uint defSize = defEnd - DeferredEntry;
    var defCalls = ExtractCalls(DeferredEntry, defSize);
    var defLeas = ExtractLeas(DeferredEntry, defSize);
    ClassifyLeas(defLeas);
    var defCallersE8 = FindE8Callers(DeferredEntry, 30);

    // Valid mapped callees only
    var defMapped = new List<Call>();
    foreach (var c in defCalls) if (c.DestMapped) defMapped.Add(c);
    var helperMapped = new List<Call>();
    foreach (var c in helperCalls) if (c.DestMapped) helperMapped.Add(c);

    // Shared mapped callees between helper and deferred
    var shared = new HashSet<uint>();
    var helperDests = new HashSet<uint>();
    foreach (var c in helperMapped) helperDests.Add(c.Dest);
    foreach (var c in defMapped) if (helperDests.Contains(c.Dest)) shared.Add(c.Dest);

    // Phase labels in deferred
    var phases = new List<string>();
    foreach (var l in defLeas) {
      if (l.Class == "frame_phase_label" || l.Class == "edata_other") {
        string first = FirstToken(l.Preview);
        if (first.Length > 0) phases.Add(first);
      }
    }

    // Count Pad_ in sibling set
    int padSib = 0, keySib = 0;
    foreach (var s in siblings) {
      if (s.StartsWith("Pad_")) padSib++;
      if (s.StartsWith("Key_")) keySib++;
    }

    // Write refined overlays into reports (merge-style standalone deep reports)
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\":1,");
    sb.AppendLine("  \"generatedUtc\":\"" + DateTime.UtcNow.ToString("o") + "\",");
    sb.AppendLine("  \"pass\":\"deep_refine\",");
    sb.AppendLine("  \"inputWrapper\":{");
    sb.AppendLine("    \"entryRva\":\"0x" + InputEntry.ToString("X") + "\",");
    sb.AppendLine("    \"endRva\":\"0x" + inputEnd.ToString("X") + "\",");
    sb.AppendLine("    \"sizeBytes\":" + inputSize + ",");
    sb.AppendLine("    \"prologue\":\"" + Hex(InputEntry, 32) + "\",");
    sb.AppendLine("    \"boundaryMethod\":\"first_ret\",");
    sb.AppendLine("    \"pattern\":\"push rsi; sub rsp,20h; mov rsi,rdx; lea r8,[Pad_LockAndTurnMovement]; mov rcx,rdx; mov edx,1; call helper; mov rax,rsi; epilogue; ret\",");
    sb.AppendLine("    \"leaTargets\":" + JsonLeas(inputLeas) + ",");
    sb.AppendLine("    \"callees\":" + JsonCalls(inputCalls) + ",");
    sb.AppendLine("    \"directE8Callers\":" + JsonUints(FindE8Callers(InputEntry, 20)) + ",");
    sb.AppendLine("    \"qwordPointersToEntry\":" + JsonUints(ptrsToInput));
    sb.AppendLine("  },");
    sb.AppendLine("  \"sharedHelper\":{");
    sb.AppendLine("    \"entryRva\":\"0x" + SharedHelper.ToString("X") + "\",");
    sb.AppendLine("    \"endRva\":\"0x" + helperEnd.ToString("X") + "\",");
    sb.AppendLine("    \"sizeBytes\":" + helperSize + ",");
    sb.AppendLine("    \"prologue\":\"" + Hex(SharedHelper, 32) + "\",");
    sb.AppendLine("    \"e8CallerCountSample\":" + helperCallers.Count + ",");
    sb.AppendLine("    \"e8CallersSample\":" + JsonUints(helperCallers) + ",");
    sb.AppendLine("    \"qwordPointersToEntry\":" + JsonUints(ptrsToHelper) + ",");
    sb.AppendLine("    \"mappedCalleesSample\":" + JsonCalls(Take(helperMapped, 30)) + ",");
    sb.AppendLine("    \"leaSample\":" + JsonLeas(Take(helperLeas, 20)) + ",");
    sb.AppendLine("    \"roleHypothesis\":\"Receives (object*, flags=1, actionName*). Likely registers/binds/looks-up an input action name against a table owned by arg0 — not a movement applicator.\"");
    sb.AppendLine("  },");
    sb.AppendLine("  \"nearbyInputWrappers\":{");
    sb.AppendLine("    \"count\":" + siblings.Count + ",");
    sb.AppendLine("    \"padCount\":" + padSib + ",");
    sb.AppendLine("    \"keyCount\":" + keySib + ",");
    sb.AppendLine("    \"sample\":" + JsonStrings(siblings));
    sb.AppendLine("  },");
    sb.AppendLine("  \"deferred\":{");
    sb.AppendLine("    \"entryRva\":\"0x" + DeferredEntry.ToString("X") + "\",");
    sb.AppendLine("    \"endRva\":\"0x" + defEnd.ToString("X") + "\",");
    sb.AppendLine("    \"sizeBytes\":" + defSize + ",");
    sb.AppendLine("    \"section\":\"" + SecName(DeferredEntry) + "\",");
    sb.AppendLine("    \"prologue\":\"" + Hex(DeferredEntry, 32) + "\",");
    sb.AppendLine("    \"directE8Callers\":" + JsonUints(defCallersE8) + ",");
    sb.AppendLine("    \"qwordPointersToEntry\":" + JsonUints(ptrsToDef) + ",");
    sb.AppendLine("    \"phaseLabelSample\":" + JsonStrings(Take(phases, 25)) + ",");
    sb.AppendLine("    \"mappedCalleesSample\":" + JsonCalls(Take(defMapped, 40)) + ",");
    sb.AppendLine("    \"roleHypothesis\":\"Registers/wires many single-/multi-threaded actor/AI/update phase names to handler addresses — frame-phase table builder, not an actor factory.\"");
    sb.AppendLine("  },");
    sb.AppendLine("  \"convergence\":{");
    sb.AppendLine("    \"sharedMappedCallees\":" + JsonUints(new List<uint>(shared)) + ",");
    sb.AppendLine("    \"sharedMappedCalleeCount\":" + shared.Count + ",");
    sb.AppendLine("    \"inputWrapperCallsDeferred\":false,");
    sb.AppendLine("    \"deferredCallsInputWrapper\":false,");
    sb.AppendLine("    \"verifiedEntityToInputLink\":false");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    string deepPath = Path.Combine(outDir, "v0.6.3-deep-refine.json");
    File.WriteAllText(deepPath, sb.ToString());
    Console.WriteLine("WROTE " + deepPath);
    Console.WriteLine("inputSize=0x" + inputSize.ToString("X") + " helperSize=0x" + helperSize.ToString("X") +
      " siblings=" + siblings.Count + " helperCallers=" + helperCallers.Count +
      " ptrsIn=" + ptrsToInput.Count + " ptrsDef=" + ptrsToDef.Count +
      " defSize=0x" + defSize.ToString("X") + " shared=" + shared.Count);
    return 0;
  }

  static List<T> Take<T>(List<T> src, int n) {
    if (src.Count <= n) return src;
    return src.GetRange(0, n);
  }

  static string FirstToken(string s) {
    if (string.IsNullOrEmpty(s)) return "";
    int i = 0;
    while (i < s.Length && s[i] != '.' && s[i] != '\0' && !char.IsControl(s[i])) i++;
    return s.Substring(0, i);
  }

  static uint FindRetEnd(uint entry, uint max) {
    long fo = RvaFile(entry);
    if (fo < 0) return entry;
    for (uint i = 0; i < max; i++) {
      byte b = pe[fo + i];
      if (b == 0xC3) return entry + i + 1;
      // RETN imm16
      if (b == 0xC2 && i + 2 < max) return entry + i + 3;
    }
    return entry + max;
  }

  static uint FindInt3OrRetEnd(uint entry, uint max) {
    long fo = RvaFile(entry);
    if (fo < 0) return entry;
    int ccRun = 0;
    for (uint i = 1; i < max; i++) {
      byte b = pe[fo + i];
      if (b == 0xCC) {
        ccRun++;
        if (ccRun >= 4) return (uint)(entry + i - (uint)ccRun + 1);
      } else ccRun = 0;
    }
    return entry + max;
  }

  // Pattern: 56 48 83 EC 20 48 89 D6 4C 8D 05 xx xx xx xx 48 89 D1 BA 01 00 00 00 E8
  static List<string> FindNearbyInputWrappers(uint start, uint span, int max) {
    var list = new List<string>();
    long fo = RvaFile(start);
    if (fo < 0) return list;
    long foEnd = fo + span;
    if (foEnd > pe.Length) foEnd = pe.Length;
    for (long p = fo; p + 24 < foEnd && list.Count < max; p++) {
      if (pe[p] != 0x56 || pe[p + 1] != 0x48 || pe[p + 2] != 0x83 || pe[p + 3] != 0xEC || pe[p + 4] != 0x20)
        continue;
      if (pe[p + 5] != 0x48 || pe[p + 6] != 0x89 || pe[p + 7] != 0xD6) continue;
      if (pe[p + 8] != 0x4C || pe[p + 9] != 0x8D || pe[p + 10] != 0x05) continue;
      // LEA r8, [rip+disp]
      int disp = BitConverter.ToInt32(pe, (int)(p + 11));
      uint site = (uint)(start + (p - fo) + 8); // lea opcode site
      uint target = (uint)(site + 7 + disp);
      string preview = ReadAscii(target, 80);
      if (preview.StartsWith("Pad_") || preview.StartsWith("Key_") || preview.StartsWith("Mouse_") ||
          preview.Contains("PlayerInput") || preview.Contains("Movement")) {
        uint entry = (uint)(start + (p - fo));
        list.Add("0x" + entry.ToString("X") + " -> " + FirstToken(preview));
      }
    }
    return list;
  }

  static List<uint> FindE8Callers(uint dest, int max) {
    var list = new List<uint>();
    foreach (var s in secs) {
      if ((s.Char & 0x20000000) == 0 || s.Ptr == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize);
      for (uint i = 0; i + 5 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        long site = (long)s.Va + i;
        long d = site + 5 + rel;
        if (d == (long)(uint)dest) list.Add((uint)site);
      }
    }
    return list;
  }

  static List<uint> FindQwordPointersTo(uint destRva, int max) {
    var list = new List<uint>();
    ulong abs = imageBase + destRva;
    byte[] needle = BitConverter.GetBytes(abs);
    foreach (var s in secs) {
      if (s.Ptr == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 8 <= lim && list.Count < max; i++) {
        bool ok = true;
        for (int k = 0; k < 8; k++) if (pe[s.Ptr + i + k] != needle[k]) { ok = false; break; }
        if (ok) list.Add(s.Va + i);
      }
    }
    return list;
  }

  static List<Call> ExtractCalls(uint entry, uint size) {
    var list = new List<Call>();
    long fo = RvaFile(entry);
    if (fo < 0) return list;
    for (uint i = 0; i + 5 <= size; i++) {
      if (pe[fo + i] != 0xE8) continue;
      int rel = BitConverter.ToInt32(pe, (int)(fo + i + 1));
      uint site = entry + i;
      uint dest = (uint)(site + 5 + rel);
      list.Add(new Call { Site = site, Dest = dest, DestMapped = RvaFile(dest) >= 0 });
    }
    return list;
  }

  static List<Lea> ExtractLeas(uint entry, uint size) {
    var list = new List<Lea>();
    long fo = RvaFile(entry);
    if (fo < 0) return list;
    for (uint i = 0; i + 7 <= size; i++) {
      // 48/4C 8D 05/0D/15/1D/25/2D/35/3D
      byte rex = pe[fo + i];
      if (rex != 0x48 && rex != 0x4C) continue;
      if (pe[fo + i + 1] != 0x8D) continue;
      byte modrm = pe[fo + i + 2];
      if ((modrm & 0xC7) != 0x05) continue; // [rip+disp32]
      int disp = BitConverter.ToInt32(pe, (int)(fo + i + 3));
      uint site = entry + i;
      uint target = (uint)(site + 7 + disp);
      list.Add(new Lea { Site = site, Target = target, Preview = ReadAscii(target, 72) });
    }
    return list;
  }

  static void ClassifyLeas(List<Lea> leas) {
    for (int i = 0; i < leas.Count; i++) {
      var l = leas[i];
      string p = l.Preview ?? "";
      if (p.StartsWith("Pad_") || p.StartsWith("Key_") || p.StartsWith("Mouse_") ||
          p.Contains("PlayerInput") || p.Contains("LockAndTurn"))
        l.Class = "input_action_name";
      else if (p.Contains("CreateActorsDeferred") || p.Contains("SingleThreaded") ||
               p.Contains("MultiThreaded") || p.Contains("UpdateActor"))
        l.Class = "frame_phase_label";
      else if (p.Contains("::") || p.Contains("Actor") || p.Contains("Component"))
        l.Class = "edata_other";
      else if (p.StartsWith("{") || p.Contains("\"type\""))
        l.Class = "schema_json_like";
      else
        l.Class = "other";
    }
  }

  static string ReadAscii(uint rva, int max) {
    long fo = RvaFile(rva);
    if (fo < 0) return "";
    var sb = new StringBuilder();
    for (int i = 0; i < max && fo + i < pe.Length; i++) {
      byte b = pe[fo + i];
      if (b == 0) break;
      if (b >= 32 && b < 127) sb.Append((char)b);
      else sb.Append('.');
    }
    return sb.ToString();
  }

  static string Hex(uint rva, int n) {
    long fo = RvaFile(rva);
    if (fo < 0) return "";
    var sb = new StringBuilder();
    for (int i = 0; i < n; i++) {
      if (i > 0) sb.Append(' ');
      sb.Append(pe[fo + i].ToString("X2"));
    }
    return sb.ToString();
  }

  static string SecName(uint rva) {
    foreach (var s in secs)
      if (rva >= s.Va && rva < s.Va + Math.Max(s.VSize, s.Raw)) return s.Name;
    return "?";
  }

  static long RvaFile(uint rva) {
    foreach (var s in secs) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva >= s.Va && rva < s.Va + span && s.Ptr > 0)
        return (long)s.Ptr + (rva - s.Va);
    }
    return -1;
  }

  static void ParsePe() {
    int e = BitConverter.ToInt32(pe, 0x3C);
    imageBase = BitConverter.ToUInt64(pe, e + 0x30);
    ushort num = BitConverter.ToUInt16(pe, e + 6);
    ushort opt = BitConverter.ToUInt16(pe, e + 20);
    int sec = e + 24 + opt;
    secs = new List<Sec>();
    for (int i = 0; i < num; i++) {
      int o = sec + i * 40;
      string name = Encoding.ASCII.GetString(pe, o, 8).TrimEnd('\0');
      secs.Add(new Sec {
        Name = name,
        VSize = BitConverter.ToUInt32(pe, o + 8),
        Va = BitConverter.ToUInt32(pe, o + 12),
        Raw = BitConverter.ToUInt32(pe, o + 16),
        Ptr = BitConverter.ToUInt32(pe, o + 20),
        Char = BitConverter.ToUInt32(pe, o + 36)
      });
    }
  }

  static string JsonUints(List<uint> xs) {
    var sb = new StringBuilder("[");
    for (int i = 0; i < xs.Count; i++) {
      if (i > 0) sb.Append(',');
      sb.Append("\"0x" + xs[i].ToString("X") + "\"");
    }
    return sb.Append(']').ToString();
  }

  static string JsonStrings(List<string> xs) {
    var sb = new StringBuilder("[");
    for (int i = 0; i < xs.Count; i++) {
      if (i > 0) sb.Append(',');
      sb.Append('\"').Append(Esc(xs[i])).Append('\"');
    }
    return sb.Append(']').ToString();
  }

  static string JsonLeas(List<Lea> xs) {
    var sb = new StringBuilder("[");
    for (int i = 0; i < xs.Count; i++) {
      if (i > 0) sb.Append(',');
      sb.Append("{\"site\":\"0x" + xs[i].Site.ToString("X") +
        "\",\"target\":\"0x" + xs[i].Target.ToString("X") +
        "\",\"class\":\"" + Esc(xs[i].Class) +
        "\",\"preview\":\"" + Esc(xs[i].Preview) + "\"}");
    }
    return sb.Append(']').ToString();
  }

  static string JsonCalls(List<Call> xs) {
    var sb = new StringBuilder("[");
    for (int i = 0; i < xs.Count; i++) {
      if (i > 0) sb.Append(',');
      sb.Append("{\"site\":\"0x" + xs[i].Site.ToString("X") +
        "\",\"dest\":\"0x" + xs[i].Dest.ToString("X") +
        "\",\"mapped\":" + (xs[i].DestMapped ? "true" : "false") + "}");
    }
    return sb.Append(']').ToString();
  }

  static string Esc(string s) {
    if (s == null) return "";
    return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
  }
}
