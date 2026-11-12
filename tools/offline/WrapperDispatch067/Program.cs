// v0.6.7 — Offline dispatch of enqueue wrapper 0x2E97FC0 + subject type leads.
// Read-only PE. No launch, inject, live memory, or game writes.
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;

internal static class Program {
  const string ExpectedExeSha =
    "19920F34BB2FAC814023EE3C27F0CECA1872E80A2AAFB37C092C419FFF77CC0D";
  const uint Registrar = 0x5CBDFB0;
  const uint DeferredHandler = 0x1AC380;
  const uint EnqueueHelper = 0x2E97B60;
  const uint EnqueueWrapper = 0x2E97FC0;
  const uint WorkerA = 0x725400;
  const uint WorkerB = 0xE95E80;
  const uint Lookup = 0x429F9E0;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);

  sealed class Sec {
    public string Name;
    public uint Va, VSize, Raw, Ptr, Char;
  }

  sealed class Phase {
    public string Name = "";
    public uint NameLea;
    public uint HandlerRva;
    public uint HandlerLea;
    public string Note = "";
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v067-raw");
    pe = File.ReadAllBytes(exe);
    string hash = Sha256Hex(pe);
    Console.WriteLine("exeSha256=" + hash);
    if (!hash.Equals(ExpectedExeSha, StringComparison.OrdinalIgnoreCase)) {
      Console.Error.WriteLine("REFUSING: EXE hash mismatch.");
      return 2;
    }
    ParsePe();
    Directory.CreateDirectory(outDir);

    var sb = new StringBuilder();
    sb.AppendLine("===== v0.6.7 WRAPPER DISPATCH + SUBJECT TYPE =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("imageBase=0x" + imageBase.ToString("X"));

    // --- A: xrefs to wrapper / helper ---
    sb.AppendLine();
    sb.AppendLine("===== XREFS =====");
    DumpXrefs(sb, EnqueueWrapper, "0x2E97FC0 wrapper");
    DumpXrefs(sb, EnqueueHelper, "0x2E97B60 enqueue");
    DumpXrefs(sb, DeferredHandler, "0x1AC380 deferred (control)");
    sb.AppendLine();
    sb.AppendLine("===== RVA DWORD HITS (image-relative tables) =====");
    DumpRvaDwords(sb, EnqueueWrapper, "wrapper");
    DumpRvaDwords(sb, EnqueueHelper, "enqueue");
    DumpRvaDwords(sb, DeferredHandler, "deferred");

    // --- B: phase registrar dump ---
    sb.AppendLine();
    sb.AppendLine("===== PHASE REGISTRAR 0x5CBDFB0 =====");
    var phases = DecodeRegistrar(sb);
    bool wrapperInPhases = false;
    bool deferredInPhases = false;
    foreach (var p in phases) {
      if (p.HandlerRva == EnqueueWrapper) wrapperInPhases = true;
      if (p.HandlerRva == DeferredHandler) deferredInPhases = true;
    }
    sb.AppendLine("phaseCount=" + phases.Count
      + " deferredMapped=" + deferredInPhases
      + " wrapperMapped=" + wrapperInPhases);
    Console.WriteLine("phases=" + phases.Count + " deferredMapped=" + deferredInPhases
      + " wrapperMapped=" + wrapperInPhases);
    // Also accept LEA xref control even if phase pairing still misses.
    bool deferredLea = FindLeaTo(DeferredHandler, 5).Count > 0;
    if (!deferredInPhases && !deferredLea) {
      Console.Error.WriteLine("Self-test failed: CreateActorsDeferred handler not found in registrar.");
      File.WriteAllText(Path.Combine(outDir, "evidence.txt"), sb.ToString());
      return 4;
    }
    if (!deferredInPhases && deferredLea)
      sb.AppendLine("NOTE: deferred LEA xref exists; phase pairing may still be incomplete.");

    // --- C: search for wrapper address as imm64 / stored qword near actor strings ---
    sb.AppendLine();
    sb.AppendLine("===== NEARBY ACTOR PHASE NAMES (string scan) =====");
    foreach (var needle in new[] {
      "CreateActorsDeferred", "UpdateActor", "GatherActor", "ActorState",
      "Deferred", "Enqueue", "ActivateActor", "SpawnActor"
    }) {
      WriteStringHits(sb, needle, 12);
    }

    // --- D: subject type leads from worker B / wrapper virtual calls ---
    sb.AppendLine();
    sb.AppendLine("===== SUBJECT VIRTUAL CALLS (0xE95E80) =====");
    DumpVirtualCalls(sb, WorkerB, 0x2000);
    sb.AppendLine();
    sb.AppendLine("===== SUBJECT FIELD / VCALL USE (0x725400) =====");
    DumpVirtualCalls(sb, WorkerA, 0x800);
    sb.AppendLine();
    sb.AppendLine("===== WRAPPER 0x2E97FC0 VIRTUAL CALLS / STRINGS =====");
    DumpVirtualCalls(sb, EnqueueWrapper, 0x6000);
    DumpFuncStrings(sb, EnqueueWrapper, 0x6000);

    // --- E: lookup helper + opaque key ---
    sb.AppendLine();
    sb.AppendLine("===== LOOKUP 0x429F9E0 / KEY 0xB2898C8 =====");
    DescribeLookup(sb);

    // --- F: try RTTI on any LEA targets that look like vtables inside workers ---
    sb.AppendLine();
    sb.AppendLine("===== RTTI PROBES ON IP-REL LEAS IN WORKERS/WRAPPER =====");
    ProbeRttiInFunc(sb, WorkerB, 0x2000);
    ProbeRttiInFunc(sb, EnqueueWrapper, 0x6000);
    ProbeRttiInFunc(sb, WorkerA, 0x800);

    // --- G: scan for lea of wrapper inside registrar window even if pairing missed ---
    sb.AppendLine();
    sb.AppendLine("===== REGISTRAR WINDOW RAW HANDLER LEAS =====");
    DumpCodeLeasInRange(sb, Registrar, 0x900);

    string path = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path + " chars=" + sb.Length);

    WritePhasesJson(Path.Combine(ReportsRoot, "v0.6.7-phase-registrations.json"), hash, phases, wrapperInPhases);
    WriteSummaryJson(Path.Combine(ReportsRoot, "v0.6.7-dispatch-summary.json"), hash,
      wrapperInPhases, deferredInPhases, phases);
    return 0;
  }

  static void DumpXrefs(StringBuilder sb, uint target, string name) {
    var e8 = FindE8(target, 30);
    var lea = FindLeaTo(target, 30);
    var qw = FindQword(target, 30);
    sb.AppendLine(name + " E8=" + e8.Count + " LEA=" + lea.Count + " QWORD=" + qw.Count);
    foreach (var s in e8) sb.AppendLine("  e8 0x" + s.ToString("X") + " sec=" + SecName(s) + " func≈0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in lea) sb.AppendLine("  lea 0x" + s.ToString("X") + " sec=" + SecName(s) + " func≈0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in qw) sb.AppendLine("  qw 0x" + s.ToString("X") + " sec=" + SecName(s));
  }

  static List<Phase> DecodeRegistrar(StringBuilder sb) {
    var phases = new List<Phase>();
    uint end = FindFuncEnd(Registrar, 0x2000);
    sb.AppendLine("registrarEnd=0x" + end.ToString("X") + " size=" + (end - Registrar));
    var ins = Disasm(Registrar, end);
    // Pair nearby: LEA to ASCII string, then LEA to executable code within ~0x40 bytes.
    for (int i = 0; i < ins.Count; i++) {
      var a = ins[i];
      if (a.Mnemonic != Mnemonic.Lea || !a.IpRel) continue;
      string name = ReadAscii(a.DataRva, 96);
      if (!IsLikelyPhaseName(name)) continue;
      uint handler = 0;
      uint handlerLea = 0;
      for (int j = i + 1; j < ins.Count && j <= i + 12; j++) {
        var b = ins[j];
        if (b.Mnemonic != Mnemonic.Lea || !b.IpRel) continue;
        if (RvaToFile(b.DataRva) < 0) continue;
        if (!LooksLikeCode(b.DataRva)) continue;
        // Prefer code in .impdata/.code
        handler = b.DataRva;
        handlerLea = b.Rva;
        break;
      }
      var p = new Phase {
        Name = name,
        NameLea = a.Rva,
        HandlerRva = handler,
        HandlerLea = handlerLea
      };
      if (handler == DeferredHandler) p.Note = "CreateActorsDeferred handler (control)";
      if (handler == EnqueueWrapper) p.Note = "ENQUEUE WRAPPER MATCH";
      if (handler == EnqueueHelper) p.Note = "enqueue helper match";
      phases.Add(p);
      sb.AppendLine("PHASE \"" + Trunc(name, 80) + "\" nameLea=0x" + a.Rva.ToString("X")
        + " handler=0x" + handler.ToString("X") + " handlerLea=0x" + handlerLea.ToString("X")
        + (string.IsNullOrEmpty(p.Note) ? "" : " :: " + p.Note));
    }
    return phases;
  }

  static bool IsLikelyPhaseName(string s) {
    if (string.IsNullOrEmpty(s) || s.Length < 6) return false;
    if (!IsString(s)) return false;
    // Reject x64 prologue false-reads (push/pop register name soup).
    if (s.StartsWith("AWAV", StringComparison.Ordinal) || s.StartsWith("ATVW", StringComparison.Ordinal)
        || s.Contains("VWSH") || s.Contains("VWUSH"))
      return false;
    int letters = 0;
    foreach (char c in s) if (char.IsLetter(c)) letters++;
    if (letters < 4) return false;
    string low = s.ToLowerInvariant();
    if (low.Contains("actor") || low.Contains("create") || low.Contains("update")
        || low.Contains("gather") || low.Contains("deferred") || low.Contains("begin")
        || low.Contains("end") || low.Contains("component") || low.Contains("anim")
        || low.Contains("state") || low.Contains("lod") || s.Contains("::"))
      return true;
    return char.IsUpper(s[0]) && s.IndexOf(' ') < 0 && s.Length >= 10;
  }

  static bool LooksLikeCode(uint rva) {
    int fo = RvaToFile(rva);
    if (fo < 0 || fo + 4 > pe.Length) return false;
    string sec = SecName(rva);
    if (sec.IndexOf("impdata", StringComparison.OrdinalIgnoreCase) < 0
        && sec.IndexOf("code", StringComparison.OrdinalIgnoreCase) < 0
        && sec.IndexOf("text", StringComparison.OrdinalIgnoreCase) < 0)
      return false;
    byte b0 = pe[fo], b1 = pe[fo + 1], b2 = pe[fo + 2];
    // Common x64 prologues: push r64 (0x40-4F REX + 0x50-57), sub rsp, mov, etc.
    if (b0 >= 0x40 && b0 <= 0x4F) return true; // REX prefix
    if (b0 >= 0x50 && b0 <= 0x57) return true; // push reg
    if (b0 == 0x48 || b0 == 0x55 || b0 == 0x53 || b0 == 0x56 || b0 == 0x57) return true;
    if (b0 == 0xE9 || b0 == 0xEB || b0 == 0xE8) return true; // jmp/call
    // Reject long printable ASCII runs (string false-positives)
    if (b0 >= 0x20 && b0 < 0x7F && b1 >= 0x20 && b1 < 0x7F && b2 >= 0x20 && b2 < 0x7F
        && pe[fo + 3] >= 0x20 && pe[fo + 3] < 0x7F)
      return false;
    return true;
  }

  static void DumpRvaDwords(StringBuilder sb, uint target, string tag) {
    byte[] needle = BitConverter.GetBytes(target);
    int hits = 0;
    foreach (var s in secs) {
      if (s.Ptr == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 4 <= lim && hits < 25; i++) {
        bool ok = true;
        for (int k = 0; k < 4; k++) if (pe[s.Ptr + i + k] != needle[k]) { ok = false; break; }
        if (!ok) continue;
        // Skip the code bytes of the function itself
        uint site = s.Va + i;
        if (site >= target && site < target + 0x20) continue;
        sb.AppendLine("  rva32 " + tag + " @0x" + site.ToString("X") + " sec=" + s.Name);
        hits++;
      }
    }
    if (hits == 0) sb.AppendLine("  (none for " + tag + ")");
  }

  static void DumpCodeLeasInRange(StringBuilder sb, uint entry, int maxBytes) {
    uint end = entry + (uint)maxBytes;
    var ins = Disasm(entry, end);
    foreach (var a in ins) {
      if (a.Mnemonic != Mnemonic.Lea || !a.IpRel) continue;
      if (!LooksLikeCode(a.DataRva)) continue;
      sb.AppendLine("  codeLea 0x" + a.Rva.ToString("X") + " -> 0x" + a.DataRva.ToString("X")
        + " sec=" + SecName(a.DataRva)
        + (a.DataRva == EnqueueWrapper ? " *** WRAPPER ***" : "")
        + (a.DataRva == DeferredHandler ? " *** DEFERRED ***" : "")
        + " prologue=" + Hex(a.DataRva, 8));
    }
  }

  sealed class Ins {
    public uint Rva;
    public string Text;
    public Mnemonic Mnemonic;
    public bool IpRel;
    public uint DataRva;
    public bool IsCall;
    public bool IsIndirectCall;
    public bool HasMem;
    public Register MemBase;
    public long Disp;
    public Instruction Raw;
  }

  static List<Ins> Disasm(uint start, uint endExclusive) {
    var list = new List<Ins>();
    int fo = RvaToFile(start);
    if (fo < 0) return list;
    var reader = new ByteArrayCodeReader(pe);
    reader.Position = fo;
    var dec = Decoder.Create(64, reader);
    dec.IP = imageBase + start;
    ulong limit = imageBase + endExclusive;
    int guard = 0;
    while (dec.IP < limit && guard++ < 100000) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      if (raw.IP < imageBase) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      var ins = new Ins {
        Raw = raw,
        Rva = (uint)(raw.IP - imageBase),
        Text = o.ToString(),
        Mnemonic = raw.Mnemonic,
        IsCall = raw.FlowControl == FlowControl.Call || raw.FlowControl == FlowControl.IndirectCall,
        IsIndirectCall = raw.FlowControl == FlowControl.IndirectCall
      };
      for (int i = 0; i < raw.OpCount; i++) {
        if (raw.GetOpKind(i) != OpKind.Memory) continue;
        ins.HasMem = true;
        ins.MemBase = raw.MemoryBase;
        if (raw.IsIPRelativeMemoryOperand) {
          ins.IpRel = true;
          ulong va = raw.IPRelativeMemoryAddress;
          if (va >= imageBase) ins.DataRva = (uint)(va - imageBase);
        } else {
          int sz = raw.MemoryDisplSize;
          if (sz == 1) ins.Disp = unchecked((sbyte)raw.MemoryDisplacement32);
          else if (sz == 2) ins.Disp = unchecked((short)raw.MemoryDisplacement32);
          else if (sz == 4) ins.Disp = unchecked((int)raw.MemoryDisplacement32);
          else if (sz == 8) ins.Disp = unchecked((long)raw.MemoryDisplacement64);
        }
        break;
      }
      list.Add(ins);
      if (raw.Mnemonic == Mnemonic.Int3 && list.Count > 1) break;
    }
    return list;
  }

  static uint FindFuncEnd(uint entry, int maxScan) {
    var list = Disasm(entry, entry + (uint)maxScan);
    foreach (var ins in list) {
      if (ins.Mnemonic == Mnemonic.Int3) return ins.Rva;
      if (ins.Mnemonic == Mnemonic.Ret) {
        uint next = ins.Rva + (uint)ins.Raw.Length;
        int fo = RvaToFile(next);
        if (fo >= 0 && fo < pe.Length && pe[fo] == 0xCC) return next;
      }
    }
    return list.Count > 0 ? list[list.Count - 1].Rva + (uint)list[list.Count - 1].Raw.Length : entry;
  }

  static void DumpVirtualCalls(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEnd(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    var ins = Disasm(entry, end);
    int n = 0;
    foreach (var a in ins) {
      if (!a.IsIndirectCall) continue;
      // call qword ptr [reg+disp]
      if (!a.HasMem || a.IpRel) {
        sb.AppendLine("  0x" + a.Rva.ToString("X") + " " + a.Text);
        if (++n >= 40) break;
        continue;
      }
      sb.AppendLine("  0x" + a.Rva.ToString("X") + " " + a.Text
        + " :: base=" + a.MemBase + " disp=0x" + a.Disp.ToString("X"));
      if (++n >= 40) break;
    }
    if (n == 0) sb.AppendLine("  (none)");
  }

  static void DumpFuncStrings(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEnd(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    var ins = Disasm(entry, end);
    var seen = new HashSet<string>();
    foreach (var a in ins) {
      if (!a.IpRel) continue;
      string s = ReadAscii(a.DataRva, 80);
      if (!IsString(s) || s.Length < 5) continue;
      string line = "0x" + a.Rva.ToString("X") + " \"" + Trunc(s, 70) + "\"";
      if (seen.Add(line)) sb.AppendLine("  str " + line);
      if (seen.Count >= 25) break;
    }
  }

  static void DescribeLookup(StringBuilder sb) {
    sb.AppendLine("key@0xB2898C8 hex=" + Hex(0xB2898C8, 32));
    sb.AppendLine("key ascii=" + ReadAscii(0xB2898C8, 32));
    uint end = FindFuncEnd(Lookup, 0x2000);
    sb.AppendLine("lookup end=0x" + end.ToString("X") + " size=" + (end > Lookup ? end - Lookup : 0));
    var ins = Disasm(Lookup, Math.Min(end, Lookup + 0x80));
    int shown = 0;
    foreach (var a in ins) {
      sb.AppendLine("  " + HexRva(a.Rva) + " " + a.Text);
      if (++shown >= 20) break;
    }
    DumpFuncStrings(sb, Lookup, 0x1000);
    // E8 callers already known; count them
    sb.AppendLine("lookup E8 callers=" + FindE8(Lookup, 40).Count);
  }

  static void ProbeRttiInFunc(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEnd(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    var ins = Disasm(entry, end);
    int hits = 0;
    foreach (var a in ins) {
      if (!a.IpRel) continue;
      string rtti = TryRttiName(a.DataRva);
      if (rtti == null) continue;
      sb.AppendLine("  0x" + a.Rva.ToString("X") + " lea/data 0x" + a.DataRva.ToString("X") + " -> " + rtti);
      if (++hits >= 20) break;
    }
    if (hits == 0) sb.AppendLine("  (no MSVC RTTI hits in 0x" + entry.ToString("X") + ")");
  }

  static string TryRttiName(uint maybeVtable) {
    if (maybeVtable < 8) return null;
    int fo = RvaToFile(maybeVtable - 8);
    if (fo < 0 || fo + 8 > pe.Length) return null;
    ulong colVa = BitConverter.ToUInt64(pe, fo);
    if (colVa < imageBase) return null;
    uint col = (uint)(colVa - imageBase);
    int cfo = RvaToFile(col);
    if (cfo < 0 || cfo + 0x18 > pe.Length) return null;
    uint sig = BitConverter.ToUInt32(pe, cfo);
    if (sig != 1) return null;
    uint self = BitConverter.ToUInt32(pe, cfo + 0x14);
    if (self != col) return null;
    uint td = BitConverter.ToUInt32(pe, cfo + 0x0C);
    string name = ReadAscii(td + 0x10, 96);
    if (name.Length < 6 || !name.StartsWith(".?A", StringComparison.Ordinal)) return null;
    return Demangle(name) + " [" + name + "]";
  }

  static string Demangle(string n) {
    string s = n;
    if (s.StartsWith(".?AV", StringComparison.Ordinal) || s.StartsWith(".?AU", StringComparison.Ordinal))
      s = s.Substring(4);
    int at = s.IndexOf("@@", StringComparison.Ordinal);
    if (at >= 0) s = s.Substring(0, at);
    return s;
  }

  static void WriteStringHits(StringBuilder sb, string needle, int max) {
    var sites = FindAscii(needle, max);
    sb.AppendLine("ascii~\"" + needle + "\" hits=" + sites.Count);
    foreach (var rva in sites) {
      string full = ReadAscii(rva, 96);
      sb.AppendLine("  0x" + rva.ToString("X") + " \"" + Trunc(full, 80) + "\" sec=" + SecName(rva));
      foreach (var c in FindLeaTo(rva, 8))
        sb.AppendLine("    lea 0x" + c.ToString("X") + " func≈0x" + FindFuncStart(c).ToString("X"));
    }
  }

  static void WritePhasesJson(string path, string hash, List<Phase> phases, bool wrapperMapped) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.7\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"registrar\": \"0x5CBDFB0\",");
    sb.AppendLine("  \"wrapperMappedInRegistrar\": " + (wrapperMapped ? "true" : "false") + ",");
    sb.AppendLine("  \"phases\": [");
    for (int i = 0; i < phases.Count; i++) {
      var p = phases[i];
      sb.Append("    { \"name\": " + J(p.Name)
        + ", \"nameLea\": \"0x" + p.NameLea.ToString("X")
        + "\", \"handler\": \"0x" + p.HandlerRva.ToString("X")
        + "\", \"handlerLea\": \"0x" + p.HandlerLea.ToString("X")
        + "\", \"note\": " + J(p.Note) + " }");
      sb.AppendLine(i + 1 < phases.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static void WriteSummaryJson(string path, string hash, bool wrapperMapped, bool deferredMapped, List<Phase> phases) {
    string deferredName = "";
    foreach (var p in phases) if (p.HandlerRva == DeferredHandler) { deferredName = p.Name; break; }
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.7\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"enqueueWrapper\": \"0x2E97FC0\",");
    sb.AppendLine("  \"enqueueHelper\": \"0x2E97B60\",");
    sb.AppendLine("  \"wrapperInPhaseRegistrar\": " + (wrapperMapped ? "true" : "false") + ",");
    sb.AppendLine("  \"deferredHandlerInPhaseRegistrar\": " + (deferredMapped ? "true" : "false") + ",");
    sb.AppendLine("  \"deferredPhaseName\": " + J(deferredName) + ",");
    sb.AppendLine("  \"phaseCount\": " + phases.Count + ",");
    sb.AppendLine("  \"e8CallersOfWrapper\": " + FindE8(EnqueueWrapper, 30).Count + ",");
    sb.AppendLine("  \"leaXrefsOfWrapper\": " + FindLeaTo(EnqueueWrapper, 30).Count + ",");
    sb.AppendLine("  \"qwordXrefsOfWrapper\": " + FindQword(EnqueueWrapper, 30).Count);
    sb.AppendLine("}");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }

  static List<uint> FindE8(uint dest, int max) {
    var list = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 5 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        if ((long)s.Va + i + 5 + rel == dest) list.Add(s.Va + i);
      }
    }
    return list;
  }

  static List<uint> FindLeaTo(uint target, int max) {
    var list = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim && list.Count < max; i++) {
        int off = 0;
        byte b0 = pe[s.Ptr + i];
        if (b0 == 0x48 || b0 == 0x4C || b0 == 0x49 || b0 == 0x4D) off = 1;
        byte op = pe[s.Ptr + i + off];
        if (op != 0x8D && op != 0x8B) continue;
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

  static List<uint> FindQword(uint destRva, int max) {
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

  static List<uint> FindAscii(string s, int max) {
    var list = new List<uint>();
    byte[] n = Encoding.ASCII.GetBytes(s);
    foreach (var sec in secs) {
      if (sec.Ptr == 0) continue;
      uint lim = Math.Min(sec.Raw, sec.VSize > 0 ? sec.VSize : sec.Raw);
      for (uint i = 0; i + (uint)n.Length <= lim && list.Count < max; i++) {
        bool ok = true;
        for (int k = 0; k < n.Length; k++) if (pe[sec.Ptr + i + k] != n[k]) { ok = false; break; }
        if (ok) list.Add(sec.Va + i);
      }
    }
    return list;
  }

  static IEnumerable<Sec> CodeSecs() {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      bool ok = (s.Char & 0x20000000) != 0
        || s.Name.IndexOf("impdata", StringComparison.OrdinalIgnoreCase) >= 0
        || s.Name.IndexOf("code", StringComparison.OrdinalIgnoreCase) >= 0
        || s.Name.IndexOf("text", StringComparison.OrdinalIgnoreCase) >= 0;
      if (ok) yield return s;
    }
  }

  static uint FindFuncStart(uint site) {
    int fo = RvaToFile(site);
    if (fo < 0) return 0;
    int back = Math.Min(fo, 0x8000);
    int pad = -1;
    for (int i = 1; i < back; i++) {
      if (pe[fo - i] == 0xCC && i + 1 < back && pe[fo - i - 1] == 0xCC) { pad = i; break; }
    }
    if (pad < 0) return site > 0x40 ? site - 0x40 : site;
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

  static string Hex(uint rva, int n) {
    int fo = RvaToFile(rva);
    if (fo < 0) return "UNMAPPED";
    var sb = new StringBuilder();
    for (int i = 0; i < n && fo + i < pe.Length; i++) {
      if (i > 0) sb.Append(' ');
      sb.Append(pe[fo + i].ToString("X2"));
    }
    return sb.ToString();
  }

  static string HexRva(uint rva) { return "0x" + rva.ToString("X"); }
  static string Trunc(string s, int n) { return s == null ? "" : (s.Length <= n ? s : s.Substring(0, n)); }

  static string SecName(uint rva) {
    foreach (var s in secs)
      if (rva >= s.Va && rva < s.Va + Math.Max(s.VSize, s.Raw)) return s.Name;
    return "?";
  }

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
    Console.WriteLine("imageBase=0x" + imageBase.ToString("X") + " sections=" + secs.Count);
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
