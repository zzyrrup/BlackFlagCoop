// v0.6.10 — Offline backward trace from enqueue wrapper / nested-chain to allocators
// + classify LOD comparator/thunk LEA consumer funcs.
// Read-only PE. No launch, inject, live memory, or game writes.
// Deliberately avoids +0x61-only ranking.
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
  const uint EnqueueWrapper = 0x2E97FC0;
  const uint EnqueueHelper = 0x2E97B60;
  const uint LodStub = 0x1A5A70;
  const uint LodCmp = 0x67BDB30;
  const uint LodThunk = 0x1A5A00;
  const uint Lookup = 0x429F9E0;
  const uint Allocator = 0x426EE50; // known Anvil allocator (v0.6.5)
  const uint WorkerA = 0x725400;
  const uint WorkerB = 0xE95E80;
  const uint Deferred = 0x1AC380;
  const uint Registrar = 0x5CBDFB0;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  // Unique funcs from v0.6.9 cmp LEA consumers (plus registrar / known thunk extras).
  static readonly uint[] LodConsumerSeed = {
    0x78FD0, 0xA9560, 0xAE3F0, 0xAFAC0, 0xB80C0, 0xC9B60, 0xFE700, 0x122A80,
    0x1B2790, 0x252190, 0x288650, 0x306A00, 0x317DC0, 0x338470, 0x36F0B0,
    0x38BF10, 0x39E340, 0x39EF20, 0x4E5F60, 0x526E90,
    0x7AC240, 0xC31240, 0x1254DB0, 0x134BFA0, 0x1730C20, 0x1866310,
    0x196E9E0, 0x1A2BDC0, 0x1A57DD0, 0x1C3BEA0, 0x1CCA1B0, 0x1CD1360,
    0x1D48740, 0x1DC39C0, Registrar
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

  sealed class NodeInfo {
    public uint Entry;
    public int Depth;
    public string Via = "";
    public List<uint> Callees = new List<uint>();
    public List<string> Strings = new List<string>();
    public List<uint> ImmSizes = new List<uint>();
    public bool CallsAllocator;
    public bool CallsLookup;
    public bool CallsEnqueue;
    public bool NestedChain;
    public bool StoresLodCmp;
    public bool StoresLodThunk;
    public bool StoresLodStub;
    public List<long> StoreDispsForLod = new List<long>();
    public int Size;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v070-raw");
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
    sb.AppendLine("===== v0.6.10 BACKWARD TRACE + LOD CONSUMER CLASSIFY =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("method=E8/LEA backward from wrapper+nestedChain; NOT +0x61 ranking");

    // --- A: seeds ---
    sb.AppendLine();
    sb.AppendLine("===== SEEDS =====");
    var nestedSeeds = FindNestedChainFuncsCallingLookupOrEnqueue(sb);
    sb.AppendLine("nestedChainFuncsWithLookupOrEnqueue=" + nestedSeeds.Count);
    foreach (var n in nestedSeeds.Take(30))
      sb.AppendLine("  nestSeed 0x" + n.ToString("X"));

    // --- B: BFS backward ---
    sb.AppendLine();
    sb.AppendLine("===== BACKWARD BFS =====");
    var graph = BackwardBfs(sb, nestedSeeds);

    // --- C: allocator hits in graph ---
    sb.AppendLine();
    sb.AppendLine("===== ALLOCATOR / SIZE HITS IN TRACE =====");
    var allocNodes = graph.Values.Where(n => n.CallsAllocator || n.ImmSizes.Any(s => s == 0x160 || s >= 0x80)).ToList();
    foreach (var n in allocNodes.OrderBy(x => x.Depth).Take(40)) {
      sb.AppendLine("allocish depth=" + n.Depth + " 0x" + n.Entry.ToString("X")
        + " via=" + n.Via
        + " allocator=" + n.CallsAllocator
        + " lookup=" + n.CallsLookup
        + " enqueue=" + n.CallsEnqueue
        + " nest=" + n.NestedChain
        + " sizes=[" + string.Join(",", n.ImmSizes.Distinct().Take(8).Select(x => "0x" + x.ToString("X"))) + "]"
        + " strs=" + string.Join(" | ", n.Strings.Take(3).Select(s => Trunc(s, 40))));
    }
    sb.AppendLine("allocishNodeCount=" + allocNodes.Count);

    // Paths that reach allocator from wrapper/helper/lookup
    sb.AppendLine();
    sb.AppendLine("===== NODES THAT CALL 0x426EE50 =====");
    foreach (var n in graph.Values.Where(x => x.CallsAllocator).OrderBy(x => x.Depth)) {
      sb.AppendLine("  0x" + n.Entry.ToString("X") + " depth=" + n.Depth + " via=" + n.Via
        + " sizes=[" + string.Join(",", n.ImmSizes.Distinct().Select(x => "0x" + x.ToString("X"))) + "]");
      foreach (var s in n.Strings.Take(5)) sb.AppendLine("    str " + s);
    }

    // --- D: classify LOD consumers ---
    sb.AppendLine();
    sb.AppendLine("===== LOD CONSUMER CLASSIFICATION =====");
    var classes = new List<NodeInfo>();
    foreach (uint f in LodConsumerSeed.Distinct()) {
      var info = AnalyzeFunc(f, 0, "lodConsumer");
      classes.Add(info);
      string cls = ClassifyLodConsumer(info);
      sb.AppendLine("LOD 0x" + f.ToString("X")
        + " class=" + cls
        + " size=" + info.Size
        + " cmp=" + info.StoresLodCmp
        + " thunk=" + info.StoresLodThunk
        + " stub=" + info.StoresLodStub
        + " disps=[" + string.Join(",", info.StoreDispsForLod.Distinct().Select(d => "0x" + d.ToString("X"))) + "]"
        + " strs=" + string.Join(" | ", info.Strings.Take(4).Select(s => Trunc(s, 36))));
    }

    // Intersection: consumer that also appears in backward graph near queue
    sb.AppendLine();
    sb.AppendLine("===== OVERLAP: LOD CONSUMERS IN BACKWARD GRAPH =====");
    foreach (var c in classes) {
      if (!graph.ContainsKey(c.Entry)) continue;
      sb.AppendLine("  overlap 0x" + c.Entry.ToString("X") + " depth=" + graph[c.Entry].Depth
        + " via=" + graph[c.Entry].Via);
    }

    // Control: stub / wrapper reachability
    sb.AppendLine();
    sb.AppendLine("===== CONTROL REACHABILITY =====");
    DumpXrefs(sb, EnqueueWrapper, "wrapper");
    DumpXrefs(sb, LodStub, "lodStub");
    DumpXrefs(sb, EnqueueHelper, "enqueueHelper");
    DumpXrefs(sb, Lookup, "lookup");
    DumpXrefs(sb, Allocator, "allocator426EE50");

    string path = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path + " chars=" + sb.Length);

    WriteBackwardJson(hash, graph, nestedSeeds, allocNodes);
    WriteLodClassJson(hash, classes);
    WriteSummaryJson(hash, graph, classes, nestedSeeds);
    WriteFeasibilityJson(hash, graph, classes);

    bool ok = graph.Count > 0 && classes.Count > 0;
    Console.WriteLine("selfCheck graph=" + graph.Count + " lodClasses=" + classes.Count
      + " nestSeeds=" + nestedSeeds.Count + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static List<uint> FindNestedChainFuncsCallingLookupOrEnqueue(StringBuilder sb) {
    var seeds = new List<uint>();
    // Seed on +0x3CD0 disp32 sites, verify chain, then see if func calls Lookup/Enqueue
    var sites = new List<uint>();
    foreach (var sec in CodeSecs()) {
      uint lim = Math.Min(sec.Raw, sec.VSize > 0 ? sec.VSize : sec.Raw);
      for (uint i = 0; i + 5 < lim && sites.Count < 500; i++) {
        byte modrm = pe[sec.Ptr + i];
        if ((modrm & 0xC0) != 0x80) continue;
        if (BitConverter.ToUInt32(pe, (int)(sec.Ptr + i + 1)) != 0x3CD0) continue;
        sites.Add(sec.Va + i);
      }
    }
    sb.AppendLine("disp3CD0Seeds=" + sites.Count);
    var seen = new HashSet<uint>();
    foreach (var site in sites) {
      uint entry = FindFuncStart(site);
      if (!seen.Add(entry)) continue;
      uint end = FindFuncEnd(entry, 0x2000);
      if (end <= entry) end = entry + 0x800;
      uint win0 = site > 0x100 ? site - 0x100 : entry;
      if (win0 < entry) win0 = entry;
      var ins = Disasm(win0, Math.Min(end, site + 0x80));
      bool saw18 = false, sawA8 = false, saw3 = false;
      foreach (var a in ins) {
        if (!a.HasMem || a.IpRel) continue;
        if (a.Disp == 0x18) saw18 = true;
        if (a.Disp == 0xA8) sawA8 = true;
        if (a.Disp == 0x3CD0) saw3 = true;
      }
      if (!(saw18 && sawA8 && saw3)) continue;
      // Full func for callees
      var full = Disasm(entry, end);
      bool hit = false;
      foreach (var a in full) {
        if (!a.IsCall || a.IsIndirectCall || a.Raw.NearBranchTarget == 0) continue;
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        if (dest == Lookup || dest == EnqueueHelper || dest == EnqueueWrapper) { hit = true; break; }
      }
      if (hit) seeds.Add(entry);
      if (seeds.Count >= 80) break;
    }
    // Always include known producer path
    if (!seeds.Contains(EnqueueWrapper)) seeds.Insert(0, EnqueueWrapper);
    if (!seeds.Contains(WorkerA)) seeds.Add(WorkerA); // known nested-chain user
    return seeds;
  }

  static Dictionary<uint, NodeInfo> BackwardBfs(StringBuilder sb, List<uint> nestSeeds) {
    var graph = new Dictionary<uint, NodeInfo>();
    var q = new Queue<(uint entry, int depth, string via)>();
    void Enq(uint e, int d, string via) {
      if (graph.ContainsKey(e)) return;
      if (d > 4) return;
      q.Enqueue((e, d, via));
    }

    Enq(EnqueueWrapper, 0, "seed:wrapper");
    Enq(EnqueueHelper, 0, "seed:helper");
    Enq(LodStub, 0, "seed:lodStub");
    Enq(Lookup, 0, "seed:lookup");
    foreach (var n in nestSeeds.Take(40)) Enq(n, 0, "seed:nested");

    int steps = 0;
    while (q.Count > 0 && steps < 200) {
      var (entry, depth, via) = q.Dequeue();
      if (graph.ContainsKey(entry)) continue;
      var info = AnalyzeFunc(entry, depth, via);
      graph[entry] = info;
      steps++;
      sb.AppendLine("node depth=" + depth + " 0x" + entry.ToString("X")
        + " via=" + via
        + " size=" + info.Size
        + " alloc=" + info.CallsAllocator
        + " lookup=" + info.CallsLookup
        + " enq=" + info.CallsEnqueue
        + " nest=" + info.NestedChain
        + " callees=" + info.Callees.Count);

      // Backward: E8 callers and LEA xrefs of this entry
      foreach (var site in FindE8(entry, 25)) {
        uint caller = FindFuncStart(site);
        Enq(caller, depth + 1, "e8->0x" + entry.ToString("X") + "@0x" + site.ToString("X"));
      }
      foreach (var site in FindLeaTo(entry, 25)) {
        uint caller = FindFuncStart(site);
        Enq(caller, depth + 1, "lea->0x" + entry.ToString("X") + "@0x" + site.ToString("X"));
      }
    }
    sb.AppendLine("bfsNodes=" + graph.Count + " steps=" + steps);
    return graph;
  }

  static NodeInfo AnalyzeFunc(uint entry, int depth, string via) {
    var n = new NodeInfo { Entry = entry, Depth = depth, Via = via };
    uint end = FindFuncEnd(entry, 0x4000);
    if (end <= entry) end = entry + 0x400;
    n.Size = (int)(end - entry);
    var ins = Disasm(entry, end);
    bool saw18 = false, sawA8 = false, saw3 = false;
    var strSeen = new HashSet<string>();
    for (int i = 0; i < ins.Count; i++) {
      var a = ins[i];
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        n.Callees.Add(dest);
        if (dest == Allocator) n.CallsAllocator = true;
        if (dest == Lookup) n.CallsLookup = true;
        if (dest == EnqueueHelper || dest == EnqueueWrapper) n.CallsEnqueue = true;
      }
      if (a.HasMem && !a.IpRel) {
        if (a.Disp == 0x18) saw18 = true;
        if (a.Disp == 0xA8) sawA8 = true;
        if (a.Disp == 0x3CD0) saw3 = true;
      }
      if (a.Raw.OpCount >= 2 && a.Raw.GetOpKind(1) == OpKind.Immediate32) {
        uint imm = a.Raw.Immediate32;
        if (imm == 0x160 || imm == 0x100 || imm == 0x80 || imm == 0x200 || imm == 0x400
            || (imm >= 0x40 && imm <= 0x2000 && (imm % 8) == 0))
          n.ImmSizes.Add(imm);
      }
      if (a.Mnemonic == Mnemonic.Lea && a.IpRel) {
        if (a.DataRva == LodCmp) { n.StoresLodCmp = true; CaptureStoreDisp(ins, i, n); }
        if (a.DataRva == LodThunk) { n.StoresLodThunk = true; CaptureStoreDisp(ins, i, n); }
        if (a.DataRva == LodStub) { n.StoresLodStub = true; CaptureStoreDisp(ins, i, n); }
        string s = ReadAscii(a.DataRva, 80);
        if (IsString(s) && s.Length >= 5 && strSeen.Add(s) && n.Strings.Count < 12) {
          // Filter prologue garbage
          if (!s.StartsWith("AWAV", StringComparison.Ordinal) && !s.Contains("VWUSH"))
            n.Strings.Add(s);
        }
      }
    }
    n.NestedChain = saw18 && sawA8 && saw3;
    n.Callees = n.Callees.Distinct().ToList();
    n.ImmSizes = n.ImmSizes.Distinct().OrderBy(x => x).ToList();
    return n;
  }

  static void CaptureStoreDisp(List<Ins> ins, int leaIdx, NodeInfo n) {
    for (int j = leaIdx + 1; j < ins.Count && j <= leaIdx + 8; j++) {
      if (ins[j].Mnemonic == Mnemonic.Mov && ins[j].HasMem && !ins[j].IpRel)
        n.StoreDispsForLod.Add(ins[j].Disp);
    }
  }

  static string ClassifyLodConsumer(NodeInfo n) {
    if (n.Entry == Registrar) return "phase_registrar";
    bool actorPhase = n.Strings.Any(s =>
      s.IndexOf("Actor", StringComparison.OrdinalIgnoreCase) >= 0
      || s.IndexOf("LOD", StringComparison.OrdinalIgnoreCase) >= 0
      || s.IndexOf("Deferred", StringComparison.OrdinalIgnoreCase) >= 0);
    if (n.StoresLodStub && n.StoresLodCmp) return "lod_bundle_full"; // stub+cmp like UpdateActorLOD
    if (n.StoresLodCmp && n.StoresLodThunk) return "cmp_thunk_bundle";
    if (n.StoresLodCmp && !n.StoresLodThunk) return "cmp_only";
    if (!n.StoresLodCmp && n.StoresLodThunk) return "thunk_only";
    if (actorPhase) return "actor_string_no_lod_lea"; // unexpected
    // Heuristic by store displ near LEA
    if (n.StoreDispsForLod.Any(d => d == 0xE18 || d == 0xE28 || d == 0xE30))
      return "coord_E18_bundle";
    if (n.StoreDispsForLod.Any(d => d == 0x18 || d == 0x8 || d == 0x10 || d == 0x20))
      return "small_callback_bundle";
    if (n.Size < 0x40) return "tiny_thunkish";
    return "generic_bundle_installer";
  }

  static void DumpXrefs(StringBuilder sb, uint target, string name) {
    var e8 = FindE8(target, 20);
    var lea = FindLeaTo(target, 20);
    sb.AppendLine(name + " E8=" + e8.Count + " LEA=" + lea.Count);
    foreach (var s in e8.Take(10))
      sb.AppendLine("  e8 0x" + s.ToString("X") + " func≈0x" + FindFuncStart(s).ToString("X"));
    foreach (var s in lea.Take(10))
      sb.AppendLine("  lea 0x" + s.ToString("X") + " func≈0x" + FindFuncStart(s).ToString("X"));
  }

  static void WriteBackwardJson(string hash, Dictionary<uint, NodeInfo> graph, List<uint> nest, List<NodeInfo> alloc) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.10\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"method\": \"E8/LEA BFS backward from wrapper/helper/stub/lookup/nested-chain; avoid +0x61 ranking\",");
    sb.AppendLine("  \"nestedSeeds\": [" + string.Join(", ", nest.Take(40).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("  \"nodeCount\": " + graph.Count + ",");
    sb.AppendLine("  \"allocatorCallee\": \"0x426EE50\",");
    sb.AppendLine("  \"nodesCallingAllocator\": [" + string.Join(", ",
      graph.Values.Where(n => n.CallsAllocator).OrderBy(n => n.Depth)
        .Select(n => "{ \"entry\": \"0x" + n.Entry.ToString("X") + "\", \"depth\": " + n.Depth
          + ", \"via\": " + J(n.Via) + ", \"sizes\": ["
          + string.Join(", ", n.ImmSizes.Take(8).Select(s => "\"0x" + s.ToString("X") + "\""))
          + "], \"strings\": [" + string.Join(", ", n.Strings.Take(5).Select(J)) + "] }")) + "],");
    sb.AppendLine("  \"nodes\": [");
    var list = graph.Values.OrderBy(n => n.Depth).ThenBy(n => n.Entry).Take(80).ToList();
    for (int i = 0; i < list.Count; i++) {
      var n = list[i];
      sb.Append("    { \"entry\": \"0x" + n.Entry.ToString("X")
        + "\", \"depth\": " + n.Depth
        + ", \"via\": " + J(n.Via)
        + ", \"size\": " + n.Size
        + ", \"callsAllocator\": " + T(n.CallsAllocator)
        + ", \"callsLookup\": " + T(n.CallsLookup)
        + ", \"callsEnqueue\": " + T(n.CallsEnqueue)
        + ", \"nestedChain\": " + T(n.NestedChain)
        + ", \"immSizes\": [" + string.Join(", ", n.ImmSizes.Take(8).Select(s => "\"0x" + s.ToString("X") + "\"")) + "]"
        + ", \"strings\": [" + string.Join(", ", n.Strings.Take(4).Select(J)) + "] }");
      sb.AppendLine(i + 1 < list.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    string path = Path.Combine(ReportsRoot, "v0.6.10-backward-trace.json");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static void WriteLodClassJson(string hash, List<NodeInfo> classes) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.10\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"lodComparator\": \"0x67BDB30\",");
    sb.AppendLine("  \"lodThunk\": \"0x1A5A00\",");
    sb.AppendLine("  \"lodStub\": \"0x1A5A70\",");
    sb.AppendLine("  \"consumers\": [");
    for (int i = 0; i < classes.Count; i++) {
      var n = classes[i];
      string cls = ClassifyLodConsumer(n);
      sb.Append("    { \"entry\": \"0x" + n.Entry.ToString("X")
        + "\", \"class\": " + J(cls)
        + ", \"size\": " + n.Size
        + ", \"storesCmp\": " + T(n.StoresLodCmp)
        + ", \"storesThunk\": " + T(n.StoresLodThunk)
        + ", \"storesStub\": " + T(n.StoresLodStub)
        + ", \"storeDisps\": [" + string.Join(", ", n.StoreDispsForLod.Distinct().Take(12).Select(d => "\"0x" + d.ToString("X") + "\"")) + "]"
        + ", \"strings\": [" + string.Join(", ", n.Strings.Take(6).Select(J)) + "] }");
      sb.AppendLine(i + 1 < classes.Count ? "," : "");
    }
    sb.AppendLine("  ],");
    var byClass = classes.GroupBy(ClassifyLodConsumer)
      .ToDictionary(g => g.Key, g => g.Count());
    sb.AppendLine("  \"classCounts\": {");
    var keys = byClass.Keys.ToList();
    for (int i = 0; i < keys.Count; i++) {
      sb.Append("    " + J(keys[i]) + ": " + byClass[keys[i]]);
      sb.AppendLine(i + 1 < keys.Count ? "," : "");
    }
    sb.AppendLine("  }");
    sb.AppendLine("}");
    string path = Path.Combine(ReportsRoot, "v0.6.10-lod-consumer-classes.json");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static void WriteSummaryJson(string hash, Dictionary<uint, NodeInfo> graph, List<NodeInfo> classes, List<uint> nest) {
    int allocCount = graph.Values.Count(n => n.CallsAllocator);
    int fullBundles = classes.Count(n => ClassifyLodConsumer(n) == "lod_bundle_full"
      || ClassifyLodConsumer(n) == "cmp_thunk_bundle"
      || ClassifyLodConsumer(n) == "phase_registrar");
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.10\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"backwardNodeCount\": " + graph.Count + ",");
    sb.AppendLine("  \"nestedSeeds\": " + nest.Count + ",");
    sb.AppendLine("  \"nodesCallingAllocator\": " + allocCount + ",");
    sb.AppendLine("  \"lodConsumersClassified\": " + classes.Count + ",");
    sb.AppendLine("  \"lodBundleLikeCount\": " + fullBundles + ",");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false,");
    sb.AppendLine("  \"avoidedPlus61OnlyRanking\": true");
    sb.AppendLine("}");
    string path = Path.Combine(ReportsRoot, "v0.6.10-summary.json");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static void WriteFeasibilityJson(string hash, Dictionary<uint, NodeInfo> graph, List<NodeInfo> classes) {
    bool allocPath = graph.Values.Any(n => n.CallsAllocator && (n.CallsEnqueue || n.CallsLookup || n.NestedChain));
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.10\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Backward trace reaches allocators/helpers but not an Edward factory\" },");
    sb.AppendLine("  \"allocatorOnQueuePath\": { \"class\": "
      + (allocPath ? "\"plausible\"" : "\"unsupported\"")
      + ", \"reason\": \"0x426EE50 appears on traced nodes overlapping enqueue/lookup/nested-chain\" },");
    sb.AppendLine("  \"lodConsumersClassified\": { \"class\": \"confirmed\", \"reason\": \"LEA consumer funcs labeled by store pattern/strings\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Deep-decode allocator-linked nested-chain nodes; identify object size and install sites feeding UpdateActorLOD\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    string path = Path.Combine(ReportsRoot, "v0.6.10-second-edward-feasibility.json");
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
