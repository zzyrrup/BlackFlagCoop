// v0.6.9 — Offline deep-decode of fingerprint ctor candidates + LOD comparator/thunk consumers.
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
  const uint CandA = 0x519E20;
  const uint CandB = 0x2D4F30;
  const uint CandC = 0x1D9CC0;
  const uint LodCmp = 0x67BDB30;
  const uint LodThunk = 0x1A5A00;
  const uint LodStub = 0x1A5A70;
  const uint EnqueueWrapper = 0x2E97FC0;
  const uint EnqueueHelper = 0x2E97B60;
  const uint WorkerA = 0x725400;
  const uint WorkerB = 0xE95E80;
  const uint Deferred = 0x1AC380;
  const uint Lookup = 0x429F9E0;
  const uint Registrar = 0x5CBDFB0;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static readonly uint[] Known = {
    CandA, CandB, CandC, LodCmp, LodThunk, LodStub, EnqueueWrapper, EnqueueHelper,
    WorkerA, WorkerB, Deferred, Lookup, Registrar, 0x426EE50, 0x47CC9B0, 0x4DF2B90
  };

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);

  sealed class Sec {
    public string Name;
    public uint Va, VSize, Raw, Ptr, Char;
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
    public int Length;
    public Instruction Raw;
  }

  sealed class CandReport {
    public uint Entry;
    public uint End;
    public int Size;
    public string Section = "";
    public List<uint> DirectCallees = new List<uint>();
    public List<uint> CallersE8 = new List<uint>();
    public List<uint> CallersLea = new List<uint>();
    public List<string> Strings = new List<string>();
    public List<string> FieldNotes = new List<string>();
    public List<uint> Vtables = new List<uint>();
    public List<uint> ImmAllocSizes = new List<uint>();
    public bool CallsEnqueue;
    public bool CallsWorker;
    public bool CallsLookup;
    public bool CallsDeferred;
    public bool Touches61;
    public bool Touches98;
    public bool NestedChain;
    public List<string> DisasmHead = new List<string>();
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v069-raw");
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
    sb.AppendLine("===== v0.6.9 CTOR DEEP + LOD CONSUMERS =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("imageBase=0x" + imageBase.ToString("X"));

    var reports = new List<CandReport>();
    foreach (uint c in new[] { CandA, CandB, CandC }) {
      sb.AppendLine();
      sb.AppendLine("===== CANDIDATE 0x" + c.ToString("X") + " =====");
      reports.Add(DeepDecode(sb, c));
    }

    sb.AppendLine();
    sb.AppendLine("===== CROSS-LINKS AMONG CANDIDATES / QUEUE =====");
    DumpCrossLinks(sb, reports);

    sb.AppendLine();
    sb.AppendLine("===== LOD COMPARATOR 0x67BDB30 CONSUMERS =====");
    var cmpConsumers = DumpConsumers(sb, LodCmp, "lodCmp");

    sb.AppendLine();
    sb.AppendLine("===== LOD THUNK 0x1A5A00 CONSUMERS =====");
    var thunkConsumers = DumpConsumers(sb, LodThunk, "lodThunk");

    sb.AppendLine();
    sb.AppendLine("===== REGISTRAR STORES OF CMP/THUNK (control) =====");
    DescribeRegistrarStores(sb);

    string path = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path + " chars=" + sb.Length);

    WriteCandJson(hash, reports);
    WriteConsumerJson(hash, cmpConsumers, thunkConsumers);
    WriteSummaryJson(hash, reports, cmpConsumers, thunkConsumers);
    WriteFeasibilityJson(hash, reports);

    bool ok = reports.All(r => r.Size > 0) && cmpConsumers.Count > 0;
    Console.WriteLine("selfCheck candidates=" + reports.Count
      + " cmpConsumers=" + cmpConsumers.Count
      + " thunkConsumers=" + thunkConsumers.Count
      + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static CandReport DeepDecode(StringBuilder sb, uint entry) {
    var r = new CandReport { Entry = entry, Section = SecName(entry) };
    r.End = FindFuncEnd(entry, 0x8000);
    if (r.End <= entry) r.End = entry + 0x400;
    r.Size = (int)(r.End - entry);
    sb.AppendLine("entry=0x" + entry.ToString("X")
      + " end=0x" + r.End.ToString("X")
      + " size=" + r.Size
      + " sec=" + r.Section
      + " prologue=" + Hex(entry, 16));

    var ins = Disasm(entry, r.End);
    int head = 0;
    foreach (var a in ins) {
      if (head < 40) {
        r.DisasmHead.Add("0x" + a.Rva.ToString("X") + " " + a.Text);
        sb.AppendLine("  " + HexRva(a.Rva) + " " + a.Text);
        head++;
      }
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        r.DirectCallees.Add(dest);
        if (dest == EnqueueHelper || dest == EnqueueWrapper) r.CallsEnqueue = true;
        if (dest == WorkerA || dest == WorkerB) r.CallsWorker = true;
        if (dest == Lookup) r.CallsLookup = true;
        if (dest == Deferred) r.CallsDeferred = true;
      }
      if (a.HasMem && !a.IpRel) {
        if (a.Disp == 0x61) {
          r.Touches61 = true;
          if (r.FieldNotes.Count < 20)
            r.FieldNotes.Add("+0x61 @0x" + a.Rva.ToString("X") + " " + a.Text);
        }
        if (a.Disp == 0x98) {
          r.Touches98 = true;
          if (r.FieldNotes.Count < 20)
            r.FieldNotes.Add("+0x98 @0x" + a.Rva.ToString("X") + " " + a.Text);
        }
      }
      // imm sizes often passed in edx/r8d for allocators
      if (a.Raw.OpCount >= 2 && a.Raw.GetOpKind(1) == OpKind.Immediate32) {
        uint imm = a.Raw.Immediate32;
        if (imm == 0x160 || imm == 0x98 || imm == 0x61 || imm >= 0x40 && imm <= 0x4000 && (imm % 8 == 0))
          r.ImmAllocSizes.Add(imm);
      }
      if (a.Mnemonic == Mnemonic.Lea && a.IpRel && (a.DataRva & 7) == 0) {
        // vtable-ish if followed by mov [reg], ...
        r.Vtables.Add(a.DataRva);
      }
    }
    if (ins.Count > 40) sb.AppendLine("  ... (" + (ins.Count - 40) + " more ins) ...");

    // Nested chain inside function
    for (int i = 0; i < ins.Count; i++) {
      if (!ins[i].HasMem || ins[i].IpRel || ins[i].Disp != 0x18) continue;
      bool a8 = false, c3 = false;
      for (int j = i + 1; j < ins.Count && j <= i + 24; j++) {
        if (!ins[j].HasMem || ins[j].IpRel) continue;
        if (ins[j].Disp == 0xA8) a8 = true;
        if (ins[j].Disp == 0x3CD0) c3 = true;
      }
      if (a8 && c3) { r.NestedChain = true; break; }
    }

    // Filter vtables: keep only those followed by store to [reg+0] within 6 ins
    var realVt = new List<uint>();
    for (int i = 0; i < ins.Count; i++) {
      var a = ins[i];
      if (a.Mnemonic != Mnemonic.Lea || !a.IpRel || (a.DataRva & 7) != 0) continue;
      bool stored = false;
      for (int j = i + 1; j < ins.Count && j <= i + 6; j++) {
        if (ins[j].Mnemonic == Mnemonic.Mov && ins[j].HasMem && !ins[j].IpRel && ins[j].Disp == 0)
          stored = true;
      }
      if (stored) realVt.Add(a.DataRva);
    }
    r.Vtables = realVt.Distinct().ToList();

    r.DirectCallees = r.DirectCallees.Distinct().ToList();
    r.ImmAllocSizes = r.ImmAllocSizes.Distinct().OrderBy(x => x).ToList();

    sb.AppendLine("directCallees=" + r.DirectCallees.Count);
    foreach (var c in r.DirectCallees.Take(40)) {
      string tag = TagKnown(c);
      sb.AppendLine("  call 0x" + c.ToString("X") + tag + " sec=" + SecName(c));
    }
    if (r.DirectCallees.Count > 40) sb.AppendLine("  ... +" + (r.DirectCallees.Count - 40));

    // Strings
    var seen = new HashSet<string>();
    foreach (var a in ins) {
      if (!a.IpRel) continue;
      string s = ReadAscii(a.DataRva, 96);
      if (!IsString(s) || s.Length < 5) continue;
      string line = "0x" + a.Rva.ToString("X") + " \"" + Trunc(s, 80) + "\"";
      if (seen.Add(line)) {
        r.Strings.Add(line);
        sb.AppendLine("  str " + line);
      }
      if (seen.Count >= 30) break;
    }

    foreach (var n in r.FieldNotes) sb.AppendLine("  field " + n);
    sb.AppendLine("touches61=" + r.Touches61 + " touches98=" + r.Touches98
      + " nestedChain=" + r.NestedChain
      + " callsEnqueue=" + r.CallsEnqueue
      + " callsWorker=" + r.CallsWorker
      + " callsLookup=" + r.CallsLookup
      + " callsDeferred=" + r.CallsDeferred);
    sb.AppendLine("vtInstalls=" + r.Vtables.Count + " : "
      + string.Join(", ", r.Vtables.Take(12).Select(v => "0x" + v.ToString("X"))));
    sb.AppendLine("immSizes=" + string.Join(", ", r.ImmAllocSizes.Take(20).Select(v => "0x" + v.ToString("X"))));

    // Callers
    r.CallersE8 = FindE8(entry, 40);
    r.CallersLea = FindLeaTo(entry, 40);
    sb.AppendLine("callersE8=" + r.CallersE8.Count + " callersLea=" + r.CallersLea.Count);
    foreach (var s in r.CallersE8.Take(20))
      sb.AppendLine("  e8 @0x" + s.ToString("X") + " func≈0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in r.CallersLea.Take(20))
      sb.AppendLine("  lea @0x" + s.ToString("X") + " func≈0x" + FindFuncStart(s).ToString("X"));

    // Sample callees that look like ctors (size, strings)
    foreach (var c in r.DirectCallees.Where(x => !Known.Contains(x)).Take(8)) {
      sb.AppendLine("--- sample callee 0x" + c.ToString("X") + " ---");
      DumpShort(sb, c, 0x80);
      DumpFuncStrings(sb, c, 0x400);
    }
    return r;
  }

  static void DumpCrossLinks(StringBuilder sb, List<CandReport> reports) {
    var set = reports.Select(r => r.Entry).ToHashSet();
    foreach (var r in reports) {
      var hits = r.DirectCallees.Where(set.Contains).ToList();
      sb.AppendLine("0x" + r.Entry.ToString("X") + " callsOtherCandidates=["
        + string.Join(", ", hits.Select(x => "0x" + x.ToString("X"))) + "]");
      bool toQueue = r.DirectCallees.Any(c =>
        c == EnqueueHelper || c == EnqueueWrapper || c == WorkerA || c == WorkerB || c == Deferred || c == Lookup);
      sb.AppendLine("  linksQueueHelpers=" + toQueue
        + " size=" + r.Size
        + " +61=" + r.Touches61 + " +98=" + r.Touches98);
    }
  }

  sealed class Consumer {
    public string Kind; // e8/lea/qword
    public uint Site;
    public uint Func;
    public string Note = "";
    public List<string> Context = new List<string>();
  }

  static List<Consumer> DumpConsumers(StringBuilder sb, uint target, string tag) {
    var list = new List<Consumer>();
    foreach (var s in FindE8(target, 50)) {
      var c = BuildConsumer("e8", s, target);
      list.Add(c);
      sb.AppendLine(tag + " e8 @0x" + s.ToString("X") + " func≈0x" + c.Func.ToString("X") + " " + c.Note);
      foreach (var line in c.Context) sb.AppendLine("    " + line);
    }
    foreach (var s in FindLeaTo(target, 60)) {
      var c = BuildConsumer("lea", s, target);
      list.Add(c);
      sb.AppendLine(tag + " lea @0x" + s.ToString("X") + " func≈0x" + c.Func.ToString("X") + " " + c.Note);
      foreach (var line in c.Context) sb.AppendLine("    " + line);
    }
    foreach (var s in FindQword(target, 30)) {
      var c = new Consumer { Kind = "qword", Site = s, Func = 0, Note = "sec=" + SecName(s) };
      list.Add(c);
      sb.AppendLine(tag + " qword @0x" + s.ToString("X") + " " + c.Note);
    }
    sb.AppendLine(tag + " consumerCount=" + list.Count
      + " uniqueFuncs=" + list.Where(x => x.Func != 0).Select(x => x.Func).Distinct().Count());
    return list;
  }

  static Consumer BuildConsumer(string kind, uint site, uint target) {
    var c = new Consumer { Kind = kind, Site = site, Func = FindFuncStart(site) };
    // Window around site: look for mov [reg+disp], rax/lea-result and nearby phase strings
    uint start = site > 0x40 ? site - 0x40 : c.Func;
    if (c.Func != 0 && start < c.Func) start = c.Func;
    var ins = Disasm(start, site + 0x60);
    foreach (var a in ins.Take(36)) {
      c.Context.Add("0x" + a.Rva.ToString("X") + " " + a.Text);
      if (a.Mnemonic == Mnemonic.Mov && a.HasMem && !a.IpRel) {
        c.Note += " storeDisp=0x" + a.Disp.ToString("X");
      }
      if (a.IpRel) {
        string s = ReadAscii(a.DataRva, 64);
        if (IsString(s) && s.Length >= 6 && (s.Contains("Actor") || s.Contains("LOD") || s.Contains("Update")))
          c.Note += " str=\"" + Trunc(s, 40) + "\"";
      }
    }
    if (c.Func == Registrar || (c.Func >= Registrar && c.Func < Registrar + 0x2000))
      c.Note += " [registrar-window]";
    if (c.Func == target) c.Note += " [self]";
    return c;
  }

  static void DescribeRegistrarStores(StringBuilder sb) {
    // Re-scan UpdateActorLOD area for stores of cmp/thunk/stub
    var ins = Disasm(Registrar, Registrar + 0x900);
    foreach (var a in ins) {
      if (a.Mnemonic != Mnemonic.Lea || !a.IpRel) continue;
      if (a.DataRva != LodCmp && a.DataRva != LodThunk && a.DataRva != LodStub && a.DataRva != EnqueueWrapper)
        continue;
      sb.AppendLine("  registrarLea 0x" + a.Rva.ToString("X") + " -> 0x" + a.DataRva.ToString("X")
        + TagKnown(a.DataRva));
    }
    // Also dump nearby phase name strings
    foreach (var a in ins) {
      if (!a.IpRel) continue;
      string s = ReadAscii(a.DataRva, 64);
      if (!IsString(s)) continue;
      if (s.Contains("Actor") || s.Contains("LOD") || s.Contains("Deferred"))
        sb.AppendLine("  phaseStr 0x" + a.Rva.ToString("X") + " \"" + Trunc(s, 60) + "\"");
    }
  }

  static void DumpShort(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEndFirstRet(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    sb.AppendLine("  func 0x" + entry.ToString("X") + " end=0x" + end.ToString("X")
      + " size=" + (end - entry) + " prologue=" + Hex(entry, 12));
    foreach (var a in Disasm(entry, end).Take(24))
      sb.AppendLine("    " + HexRva(a.Rva) + " " + a.Text);
  }

  static void DumpFuncStrings(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEnd(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    var seen = new HashSet<string>();
    foreach (var a in Disasm(entry, end)) {
      if (!a.IpRel) continue;
      string s = ReadAscii(a.DataRva, 80);
      if (!IsString(s) || s.Length < 5) continue;
      if (seen.Add(s)) sb.AppendLine("    str \"" + Trunc(s, 70) + "\"");
      if (seen.Count >= 8) break;
    }
  }

  static string TagKnown(uint rva) {
    if (rva == EnqueueWrapper) return " *** enqueue wrapper ***";
    if (rva == EnqueueHelper) return " *** enqueue helper ***";
    if (rva == WorkerA) return " *** workerA ***";
    if (rva == WorkerB) return " *** workerB ***";
    if (rva == Deferred) return " *** deferred ***";
    if (rva == Lookup) return " *** lookup ***";
    if (rva == LodCmp) return " *** lodCmp ***";
    if (rva == LodThunk) return " *** lodThunk ***";
    if (rva == LodStub) return " *** lodStub ***";
    if (rva == CandA || rva == CandB || rva == CandC) return " *** cand ***";
    return "";
  }

  static void WriteCandJson(string hash, List<CandReport> reports) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.9\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"candidates\": [");
    for (int i = 0; i < reports.Count; i++) {
      var r = reports[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + r.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"end\": \"0x" + r.End.ToString("X") + "\",");
      sb.AppendLine("      \"size\": " + r.Size + ",");
      sb.AppendLine("      \"section\": " + J(r.Section) + ",");
      sb.AppendLine("      \"touches61\": " + T(r.Touches61) + ",");
      sb.AppendLine("      \"touches98\": " + T(r.Touches98) + ",");
      sb.AppendLine("      \"nestedChain\": " + T(r.NestedChain) + ",");
      sb.AppendLine("      \"callsEnqueue\": " + T(r.CallsEnqueue) + ",");
      sb.AppendLine("      \"callsWorker\": " + T(r.CallsWorker) + ",");
      sb.AppendLine("      \"callsLookup\": " + T(r.CallsLookup) + ",");
      sb.AppendLine("      \"callsDeferred\": " + T(r.CallsDeferred) + ",");
      sb.AppendLine("      \"directCalleeCount\": " + r.DirectCallees.Count + ",");
      sb.AppendLine("      \"directCalleesSample\": [" + string.Join(", ", r.DirectCallees.Take(25).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callersE8\": [" + string.Join(", ", r.CallersE8.Take(15).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callersLea\": [" + string.Join(", ", r.CallersLea.Take(15).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"vtableInstalls\": [" + string.Join(", ", r.Vtables.Take(12).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"immSizes\": [" + string.Join(", ", r.ImmAllocSizes.Take(15).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"strings\": [" + string.Join(", ", r.Strings.Take(15).Select(J)) + "],");
      sb.AppendLine("      \"fieldNotes\": [" + string.Join(", ", r.FieldNotes.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", r.DisasmHead.Take(20).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < reports.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    string path = Path.Combine(ReportsRoot, "v0.6.9-ctor-candidates-deep.json");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static void WriteConsumerJson(string hash, List<Consumer> cmp, List<Consumer> thunk) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.9\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"lodComparator\": \"0x67BDB30\",");
    sb.AppendLine("  \"lodThunk\": \"0x1A5A00\",");
    WriteConsumerArray(sb, "comparatorConsumers", cmp);
    sb.AppendLine(",");
    WriteConsumerArray(sb, "thunkConsumers", thunk);
    sb.AppendLine();
    sb.AppendLine("}");
    string path = Path.Combine(ReportsRoot, "v0.6.9-lod-consumers.json");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static void WriteConsumerArray(StringBuilder sb, string name, List<Consumer> list) {
    sb.AppendLine("  \"" + name + "\": [");
    var uniq = list.GroupBy(x => x.Kind + ":" + x.Site.ToString("X")).Select(g => g.First()).Take(50).ToList();
    for (int i = 0; i < uniq.Count; i++) {
      var c = uniq[i];
      sb.Append("    { \"kind\": " + J(c.Kind)
        + ", \"site\": \"0x" + c.Site.ToString("X")
        + "\", \"func\": \"0x" + c.Func.ToString("X")
        + "\", \"note\": " + J(c.Note) + " }");
      sb.AppendLine(i + 1 < uniq.Count ? "," : "");
    }
    sb.Append("  ]");
  }

  static void WriteSummaryJson(string hash, List<CandReport> reports, List<Consumer> cmp, List<Consumer> thunk) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.9\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"anyCandidateLinksEnqueue\": " + T(reports.Any(r => r.CallsEnqueue)) + ",");
    sb.AppendLine("  \"anyCandidateLinksWorker\": " + T(reports.Any(r => r.CallsWorker)) + ",");
    sb.AppendLine("  \"anyCandidateLinksLookup\": " + T(reports.Any(r => r.CallsLookup)) + ",");
    sb.AppendLine("  \"comparatorConsumerFuncs\": "
      + cmp.Where(x => x.Func != 0).Select(x => x.Func).Distinct().Count() + ",");
    sb.AppendLine("  \"thunkConsumerFuncs\": "
      + thunk.Where(x => x.Func != 0).Select(x => x.Func).Distinct().Count() + ",");
    sb.AppendLine("  \"candidateSizes\": {");
    for (int i = 0; i < reports.Count; i++) {
      var r = reports[i];
      sb.Append("    \"0x" + r.Entry.ToString("X") + "\": " + r.Size);
      sb.AppendLine(i + 1 < reports.Count ? "," : "");
    }
    sb.AppendLine("  },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    string path = Path.Combine(ReportsRoot, "v0.6.9-deep-summary.json");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static void WriteFeasibilityJson(string hash, List<CandReport> reports) {
    bool link = reports.Any(r => r.CallsEnqueue || r.CallsWorker);
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.9\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Candidates not shown to create Edward or call enqueue/workers\" },");
    sb.AppendLine("  \"candidateIsQueueSubjectCtor\": { \"class\": "
      + (link ? "\"plausible\"" : "\"unsupported\"")
      + ", \"reason\": \"Direct call edges to enqueue/workers "
      + (link ? "present" : "absent") + "\" },");
    sb.AppendLine("  \"lodComparatorConsumersMapped\": { \"class\": \"confirmed\", \"reason\": \"LEA/E8 consumer sites enumerated offline\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized this milestone\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Trace who invokes UpdateActorLOD bundle slots; follow any candidate that gains a queue edge\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    string path = Path.Combine(ReportsRoot, "v0.6.9-second-edward-feasibility.json");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static string T(bool b) => b ? "true" : "false";
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
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
    while (dec.IP < limit && guard++ < 200000) {
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
        Length = raw.Length,
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
        uint next = ins.Rva + (uint)ins.Length;
        int fo = RvaToFile(next);
        if (fo >= 0 && fo < pe.Length && pe[fo] == 0xCC) return next;
      }
    }
    return list.Count > 0 ? list[list.Count - 1].Rva + (uint)list[list.Count - 1].Length : entry;
  }

  static uint FindFuncEndFirstRet(uint entry, int maxScan) {
    var list = Disasm(entry, entry + (uint)maxScan);
    foreach (var ins in list) {
      if (ins.Mnemonic == Mnemonic.Int3) return ins.Rva;
      if (ins.Mnemonic == Mnemonic.Ret) return ins.Rva + (uint)ins.Length;
    }
    return list.Count > 0 ? list[list.Count - 1].Rva + (uint)list[list.Count - 1].Length : entry;
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

  static string HexRva(uint rva) => "0x" + rva.ToString("X");
  static string Trunc(string s, int n) => s == null ? "" : (s.Length <= n ? s : s.Substring(0, n));

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
