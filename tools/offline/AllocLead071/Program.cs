// v0.6.11 — Offline deep-decode of allocator nested-chain leads 0x400B50 / 0x4444C0
// and callers toward enqueue enrollment.
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
  const uint LeadA = 0x400B50;
  const uint LeadB = 0x4444C0;
  const uint Allocator = 0x426EE50;
  const uint Lookup = 0x429F9E0;
  const uint EnqueueWrapper = 0x2E97FC0;
  const uint EnqueueHelper = 0x2E97B60;
  const uint WorkerA = 0x725400;
  const uint WorkerB = 0xE95E80;
  const uint Deferred = 0x1AC380;
  const uint LodStub = 0x1A5A70;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static readonly HashSet<uint> QueueSet = new HashSet<uint> {
    EnqueueWrapper, EnqueueHelper, WorkerA, WorkerB, Deferred, Lookup, LodStub, Allocator
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
    public long Disp;
    public int Length;
    public Instruction Raw;
  }

  sealed class LeadReport {
    public uint Entry;
    public uint End;
    public int Size;
    public List<uint> Callees = new List<uint>();
    public List<uint> CallersE8 = new List<uint>();
    public List<uint> CallersLea = new List<uint>();
    public List<string> Strings = new List<string>();
    public List<string> FieldNotes = new List<string>();
    public List<uint> ImmSizes = new List<uint>();
    public List<uint> Vtables = new List<uint>();
    public List<string> DisasmHead = new List<string>();
    public List<string> AllocSites = new List<string>();
    public List<string> LookupSites = new List<string>();
    public bool NestedChain;
    public bool CallsAllocator;
    public bool CallsLookup;
    public bool CallsEnqueue;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v071-raw");
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
    sb.AppendLine("===== v0.6.11 ALLOC LEADS + ENQUEUE ENROLLMENT =====");
    sb.AppendLine("exeSha256=" + hash);

    var reports = new List<LeadReport>();
    foreach (uint lead in new[] { LeadA, LeadB }) {
      sb.AppendLine();
      sb.AppendLine("===== LEAD 0x" + lead.ToString("X") + " =====");
      reports.Add(DeepDecode(sb, lead));
    }

    sb.AppendLine();
    sb.AppendLine("===== CALLER → ENQUEUE ENROLLMENT =====");
    var enroll = TraceEnrollment(sb, reports);

    sb.AppendLine();
    sb.AppendLine("===== CROSS: DO LEADS REACH WRAPPER/HELPER? =====");
    foreach (var r in reports) {
      bool reach = ReachQueue(r.Entry, 3, out var path);
      sb.AppendLine("0x" + r.Entry.ToString("X") + " forwardReachQueue=" + reach
        + (reach ? " path=" + path : ""));
    }

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteLeadJson(hash, reports);
    WriteEnrollJson(hash, enroll);
    WriteSummaryJson(hash, reports, enroll);
    WriteFeasibilityJson(hash, reports, enroll);

    bool ok = reports.All(r => r.Size > 0) && reports.All(r => r.CallsAllocator && r.CallsLookup);
    Console.WriteLine("selfCheck leads=" + reports.Count + " enrollEdges=" + enroll.Count + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static LeadReport DeepDecode(StringBuilder sb, uint entry) {
    var r = new LeadReport { Entry = entry };
    r.End = FindFuncEnd(entry, 0x6000);
    if (r.End <= entry) r.End = entry + 0x400;
    r.Size = (int)(r.End - entry);
    sb.AppendLine("entry=0x" + entry.ToString("X") + " end=0x" + r.End.ToString("X")
      + " size=" + r.Size + " sec=" + SecName(entry) + " prologue=" + Hex(entry, 16));

    var ins = Disasm(entry, r.End);
    bool saw18 = false, sawA8 = false, saw3 = false;
    int head = 0;
    for (int i = 0; i < ins.Count; i++) {
      var a = ins[i];
      if (head < 48) {
        string line = "0x" + a.Rva.ToString("X") + " " + a.Text;
        r.DisasmHead.Add(line);
        sb.AppendLine("  " + line);
        head++;
      }
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        r.Callees.Add(dest);
        string tag = Tag(dest);
        if (dest == Allocator) {
          r.CallsAllocator = true;
          r.AllocSites.Add("0x" + a.Rva.ToString("X") + " call allocator" + ContextImm(ins, i));
        }
        if (dest == Lookup) {
          r.CallsLookup = true;
          r.LookupSites.Add("0x" + a.Rva.ToString("X") + " call lookup");
        }
        if (dest == EnqueueHelper || dest == EnqueueWrapper) r.CallsEnqueue = true;
        if (!string.IsNullOrEmpty(tag))
          sb.AppendLine("  *** call 0x" + dest.ToString("X") + tag + " @0x" + a.Rva.ToString("X"));
      }
      if (a.HasMem && !a.IpRel) {
        if (a.Disp == 0x18) saw18 = true;
        if (a.Disp == 0xA8) sawA8 = true;
        if (a.Disp == 0x3CD0) {
          saw3 = true;
          if (r.FieldNotes.Count < 16)
            r.FieldNotes.Add("+0x3CD0 @0x" + a.Rva.ToString("X") + " " + a.Text);
        }
        if ((a.Disp == 0x98 || a.Disp == 0xA8 || a.Disp == 0x18) && r.FieldNotes.Count < 16)
          r.FieldNotes.Add("disp0x" + a.Disp.ToString("X") + " @0x" + a.Rva.ToString("X") + " " + a.Text);
      }
      if (a.Raw.OpCount >= 2 && a.Raw.GetOpKind(1) == OpKind.Immediate32) {
        uint imm = a.Raw.Immediate32;
        if (imm == 0x160 || imm == 0x1C8 || imm == 0xE0 || imm == 0x50 || imm == 0x100
            || (imm >= 0x40 && imm <= 0x4000 && (imm % 8) == 0))
          r.ImmSizes.Add(imm);
      }
      if (a.Mnemonic == Mnemonic.Lea && a.IpRel && (a.DataRva & 7) == 0) {
        bool stored = false;
        for (int j = i + 1; j < ins.Count && j <= i + 6; j++) {
          if (ins[j].Mnemonic == Mnemonic.Mov && ins[j].HasMem && !ins[j].IpRel && ins[j].Disp == 0)
            stored = true;
        }
        if (stored) r.Vtables.Add(a.DataRva);
      }
      if (a.IpRel) {
        string s = ReadAscii(a.DataRva, 96);
        if (IsString(s) && s.Length >= 5 && !s.StartsWith("AWAV", StringComparison.Ordinal)
            && !s.Contains("VWUSH") && r.Strings.Count < 20
            && !r.Strings.Contains(s))
          r.Strings.Add(s);
      }
    }
    if (ins.Count > 48) sb.AppendLine("  ... +" + (ins.Count - 48) + " ins ...");
    r.NestedChain = saw18 && sawA8 && saw3;
    r.Callees = r.Callees.Distinct().ToList();
    r.ImmSizes = r.ImmSizes.Distinct().OrderBy(x => x).ToList();
    r.Vtables = r.Vtables.Distinct().ToList();

    r.CallersE8 = FindE8(entry, 40);
    r.CallersLea = FindLeaTo(entry, 40);

    sb.AppendLine("nestedChain=" + r.NestedChain + " alloc=" + r.CallsAllocator
      + " lookup=" + r.CallsLookup + " enqueue=" + r.CallsEnqueue);
    sb.AppendLine("immSizes=[" + string.Join(",", r.ImmSizes.Select(x => "0x" + x.ToString("X"))) + "]");
    sb.AppendLine("vtInstalls=" + r.Vtables.Count + " : "
      + string.Join(", ", r.Vtables.Take(10).Select(v => "0x" + v.ToString("X"))));
    foreach (var s in r.Strings) sb.AppendLine("  str \"" + Trunc(s, 80) + "\"");
    foreach (var n in r.FieldNotes) sb.AppendLine("  field " + n);
    foreach (var a in r.AllocSites) sb.AppendLine("  " + a);
    foreach (var a in r.LookupSites) sb.AppendLine("  " + a);
    sb.AppendLine("callersE8=" + r.CallersE8.Count + " callersLea=" + r.CallersLea.Count);
    foreach (var s in r.CallersE8.Take(25))
      sb.AppendLine("  e8 @0x" + s.ToString("X") + " func≈0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in r.CallersLea.Take(15))
      sb.AppendLine("  lea @0x" + s.ToString("X") + " func≈0x" + FindFuncStart(s).ToString("X"));

    // Sample interesting callees
    foreach (var c in r.Callees.Where(x => !QueueSet.Contains(x)).Take(6)) {
      sb.AppendLine("--- callee 0x" + c.ToString("X") + " ---");
      DumpShort(sb, c, 0x60);
      DumpStrings(sb, c, 0x400);
    }
    return r;
  }

  static string ContextImm(List<Ins> ins, int callIdx) {
    // Look backward for mov edx/r8d imm near allocator call
    var sizes = new List<string>();
    for (int j = Math.Max(0, callIdx - 12); j < callIdx; j++) {
      var a = ins[j];
      if (a.Raw.OpCount >= 2 && a.Raw.GetOpKind(1) == OpKind.Immediate32) {
        uint imm = a.Raw.Immediate32;
        if (imm >= 0x20 && imm <= 0x4000)
          sizes.Add("0x" + a.Rva.ToString("X") + ":" + a.Text);
      }
    }
    return sizes.Count == 0 ? "" : " :: " + string.Join(" | ", sizes.Take(4));
  }

  sealed class EnrollEdge {
    public uint Lead;
    public uint CallerFunc;
    public uint Site;
    public string Kind;
    public bool CallsEnqueue;
    public bool CallsLookup;
    public bool CallsWrapper;
    public bool NestedChain;
    public bool CallsAllocator;
    public List<string> Strings = new List<string>();
    public string Note = "";
  }

  static List<EnrollEdge> TraceEnrollment(StringBuilder sb, List<LeadReport> reports) {
    var edges = new List<EnrollEdge>();
    var seenCaller = new HashSet<uint>();
    foreach (var r in reports) {
      sb.AppendLine("-- callers of 0x" + r.Entry.ToString("X") + " --");
      var sites = r.CallersE8.Concat(r.CallersLea).Distinct().ToList();
      foreach (var site in sites) {
        uint caller = FindFuncStart(site);
        var e = AnalyzeCaller(caller, site, r.Entry, r.CallersE8.Contains(site) ? "e8" : "lea");
        edges.Add(e);
        sb.AppendLine("  " + e.Kind + " site=0x" + site.ToString("X") + " caller=0x" + caller.ToString("X")
          + " enq=" + e.CallsEnqueue + " wrap=" + e.CallsWrapper + " lookup=" + e.CallsLookup
          + " nest=" + e.NestedChain + " alloc=" + e.CallsAllocator
          + " " + e.Note);
        foreach (var s in e.Strings.Take(4)) sb.AppendLine("    str \"" + Trunc(s, 60) + "\"");

        // One more hop: callers of this caller if it looks enrollment-related
        if (!seenCaller.Add(caller)) continue;
        if (e.CallsEnqueue || e.CallsWrapper || e.CallsLookup || e.NestedChain) {
          foreach (var s2 in FindE8(caller, 15)) {
            uint c2 = FindFuncStart(s2);
            var e2 = AnalyzeCaller(c2, s2, caller, "e8-hop2");
            edges.Add(e2);
            sb.AppendLine("    hop2 e8 site=0x" + s2.ToString("X") + " caller=0x" + c2.ToString("X")
              + " enq=" + e2.CallsEnqueue + " wrap=" + e2.CallsWrapper + " lookup=" + e2.CallsLookup
              + " nest=" + e2.NestedChain);
          }
        }
      }
    }

    // Also check if any caller (or hop2) reaches enqueue helper/wrapper via forward scan
    sb.AppendLine("-- enrollment summary --");
    int directEnq = edges.Count(e => e.CallsEnqueue || e.CallsWrapper);
    int viaLookup = edges.Count(e => e.CallsLookup);
    sb.AppendLine("callerEdges=" + edges.Count + " withEnqueueOrWrapper=" + directEnq
      + " withLookup=" + viaLookup);
    return edges;
  }

  static EnrollEdge AnalyzeCaller(uint caller, uint site, uint lead, string kind) {
    var e = new EnrollEdge {
      Lead = lead, CallerFunc = caller, Site = site, Kind = kind
    };
    uint end = FindFuncEnd(caller, 0x3000);
    if (end <= caller) end = caller + 0x400;
    var ins = Disasm(caller, end);
    bool s18 = false, sA8 = false, s3 = false;
    foreach (var a in ins) {
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        if (dest == EnqueueHelper) { e.CallsEnqueue = true; e.Note += " callsHelper"; }
        if (dest == EnqueueWrapper) { e.CallsWrapper = true; e.Note += " callsWrapper"; }
        if (dest == Lookup) e.CallsLookup = true;
        if (dest == Allocator) e.CallsAllocator = true;
        if (dest == WorkerA || dest == WorkerB) e.Note += " callsWorker";
        if (dest == Deferred) e.Note += " callsDeferred";
      }
      if (a.HasMem && !a.IpRel) {
        if (a.Disp == 0x18) s18 = true;
        if (a.Disp == 0xA8) sA8 = true;
        if (a.Disp == 0x3CD0) s3 = true;
      }
      if (a.IpRel) {
        string s = ReadAscii(a.DataRva, 80);
        if (IsString(s) && s.Length >= 5 && e.Strings.Count < 8
            && !s.StartsWith("AWAV", StringComparison.Ordinal) && !s.Contains("VWUSH")
            && !e.Strings.Contains(s))
          e.Strings.Add(s);
      }
    }
    e.NestedChain = s18 && sA8 && s3;
    return e;
  }

  static bool ReachQueue(uint entry, int maxDepth, out string path) {
    path = "";
    var seen = new HashSet<uint>();
    var q = new Queue<(uint e, int d, string p)>();
    q.Enqueue((entry, 0, "0x" + entry.ToString("X")));
    while (q.Count > 0) {
      var (e, d, p) = q.Dequeue();
      if (!seen.Add(e) || d > maxDepth) continue;
      if (e != entry && (e == EnqueueWrapper || e == EnqueueHelper || e == Deferred || e == LodStub)) {
        path = p + " -> QUEUE(0x" + e.ToString("X") + ")";
        return true;
      }
      uint end = FindFuncEnd(e, 0x2000);
      if (end <= e) end = e + 0x200;
      foreach (var a in Disasm(e, end)) {
        if (!a.IsCall || a.IsIndirectCall || a.Raw.NearBranchTarget == 0) continue;
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        if (dest == Lookup || dest == Allocator) continue; // noisy; still allow queue targets
        q.Enqueue((dest, d + 1, p + " -> 0x" + dest.ToString("X")));
      }
    }
    return false;
  }

  static void DumpShort(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEndFirstRet(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    sb.AppendLine("  func 0x" + entry.ToString("X") + " size=" + (end - entry)
      + " prologue=" + Hex(entry, 12));
    foreach (var a in Disasm(entry, end).Take(20))
      sb.AppendLine("    0x" + a.Rva.ToString("X") + " " + a.Text);
  }

  static void DumpStrings(StringBuilder sb, uint entry, int maxBytes) {
    uint end = FindFuncEnd(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    var seen = new HashSet<string>();
    foreach (var a in Disasm(entry, end)) {
      if (!a.IpRel) continue;
      string s = ReadAscii(a.DataRva, 80);
      if (!IsString(s) || s.Length < 5) continue;
      if (seen.Add(s)) sb.AppendLine("    str \"" + Trunc(s, 70) + "\"");
      if (seen.Count >= 6) break;
    }
  }

  static string Tag(uint rva) {
    if (rva == Allocator) return " *** ALLOCATOR ***";
    if (rva == Lookup) return " *** LOOKUP ***";
    if (rva == EnqueueWrapper) return " *** WRAPPER ***";
    if (rva == EnqueueHelper) return " *** HELPER ***";
    if (rva == WorkerA) return " *** WORKER_A ***";
    if (rva == WorkerB) return " *** WORKER_B ***";
    if (rva == Deferred) return " *** DEFERRED ***";
    return "";
  }

  static void WriteLeadJson(string hash, List<LeadReport> reports) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.11\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"leads\": [");
    for (int i = 0; i < reports.Count; i++) {
      var r = reports[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + r.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"end\": \"0x" + r.End.ToString("X") + "\",");
      sb.AppendLine("      \"size\": " + r.Size + ",");
      sb.AppendLine("      \"nestedChain\": " + T(r.NestedChain) + ",");
      sb.AppendLine("      \"callsAllocator\": " + T(r.CallsAllocator) + ",");
      sb.AppendLine("      \"callsLookup\": " + T(r.CallsLookup) + ",");
      sb.AppendLine("      \"callsEnqueue\": " + T(r.CallsEnqueue) + ",");
      sb.AppendLine("      \"immSizes\": [" + string.Join(", ", r.ImmSizes.Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"vtables\": [" + string.Join(", ", r.Vtables.Take(10).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"strings\": [" + string.Join(", ", r.Strings.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"allocSites\": [" + string.Join(", ", r.AllocSites.Take(8).Select(J)) + "],");
      sb.AppendLine("      \"lookupSites\": [" + string.Join(", ", r.LookupSites.Take(8).Select(J)) + "],");
      sb.AppendLine("      \"fieldNotes\": [" + string.Join(", ", r.FieldNotes.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"calleesSample\": [" + string.Join(", ", r.Callees.Take(20).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callersE8\": [" + string.Join(", ", r.CallersE8.Take(20).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"callersLea\": [" + string.Join(", ", r.CallersLea.Take(15).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", r.DisasmHead.Take(24).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < reports.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.11-alloc-leads-deep.json"), sb.ToString());
    Console.WriteLine("WROTE " + Path.Combine(ReportsRoot, "v0.6.11-alloc-leads-deep.json"));
  }

  static void WriteEnrollJson(string hash, List<EnrollEdge> edges) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.11\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"edges\": [");
    for (int i = 0; i < Math.Min(edges.Count, 80); i++) {
      var e = edges[i];
      sb.Append("    { \"lead\": \"0x" + e.Lead.ToString("X")
        + "\", \"caller\": \"0x" + e.CallerFunc.ToString("X")
        + "\", \"site\": \"0x" + e.Site.ToString("X")
        + "\", \"kind\": " + J(e.Kind)
        + ", \"callsEnqueue\": " + T(e.CallsEnqueue)
        + ", \"callsWrapper\": " + T(e.CallsWrapper)
        + ", \"callsLookup\": " + T(e.CallsLookup)
        + ", \"callsAllocator\": " + T(e.CallsAllocator)
        + ", \"nestedChain\": " + T(e.NestedChain)
        + ", \"note\": " + J(e.Note)
        + ", \"strings\": [" + string.Join(", ", e.Strings.Take(5).Select(J)) + "] }");
      sb.AppendLine(i + 1 < Math.Min(edges.Count, 80) ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"withEnqueueOrWrapper\": " + edges.Count(e => e.CallsEnqueue || e.CallsWrapper) + ",");
    sb.AppendLine("  \"withLookup\": " + edges.Count(e => e.CallsLookup));
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.11-enqueue-enrollment.json"), sb.ToString());
    Console.WriteLine("WROTE " + Path.Combine(ReportsRoot, "v0.6.11-enqueue-enrollment.json"));
  }

  static void WriteSummaryJson(string hash, List<LeadReport> reports, List<EnrollEdge> edges) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.11\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"leadsDecoded\": [" + string.Join(", ", reports.Select(r => "\"0x" + r.Entry.ToString("X") + "\"")) + "],");
    sb.AppendLine("  \"anyLeadCallsEnqueue\": " + T(reports.Any(r => r.CallsEnqueue)) + ",");
    sb.AppendLine("  \"anyCallerCallsEnqueueOrWrapper\": " + T(edges.Any(e => e.CallsEnqueue || e.CallsWrapper)) + ",");
    sb.AppendLine("  \"leadSizes\": { \"0x400B50\": " + reports.First(r => r.Entry == LeadA).Size
      + ", \"0x4444C0\": " + reports.First(r => r.Entry == LeadB).Size + " },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.11-summary.json"), sb.ToString());
    Console.WriteLine("WROTE " + Path.Combine(ReportsRoot, "v0.6.11-summary.json"));
  }

  static void WriteFeasibilityJson(string hash, List<LeadReport> reports, List<EnrollEdge> edges) {
    bool enroll = edges.Any(e => e.CallsEnqueue || e.CallsWrapper);
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.11\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Leads use allocator+lookup/nested-chain but are not shown as Edward factories\" },");
    sb.AppendLine("  \"leadsAreQueueSubjectCtors\": { \"class\": "
      + (enroll || reports.Any(r => r.CallsEnqueue) ? "\"plausible\"" : "\"unsupported\"")
      + ", \"reason\": \"Direct/caller enqueue enrollment "
      + (enroll || reports.Any(r => r.CallsEnqueue) ? "observed" : "not observed") + "\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Follow any enrollment-positive callers; map allocated object layout from 0x400B50/0x4444C0\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.11-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE " + Path.Combine(ReportsRoot, "v0.6.11-second-edward-feasibility.json"));
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
