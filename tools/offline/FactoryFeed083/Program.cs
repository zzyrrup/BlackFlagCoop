// v0.6.23 — Offline: which tight-factory callers feed TypeInfo for 0xB2898C8 / 0x20F0;
// deep-decode possession-like 0x546D150 consumers. Read-only PE. No launch/inject/live memory.
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
  const uint Lookup = 0x429F9E0;
  const uint Allocator = 0x426EE50;
  const uint LookupKey = 0xB2898C8;
  const uint OuterCtor = 0x59D9660;
  const uint Helper546 = 0x546D150;
  const uint Neighbor = 0x2335140;
  const uint SizeImm = 0x20F0;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static readonly uint[] TightFactories = {
    0x238590, 0x256280, 0x218900, 0x218660, 0x21FA70
  };

  // Possession-like / interesting helper consumers from v0.6.22 roles + remaining list
  static readonly uint[] PossessionSeeds = {
    0x2336560, // arm-neighbor-like
    0x2335140, // neighbor (baseline)
    0x1D25E20, // multi-site block-copy
    0x21525F0,
    0x184400,
    0x14769B0,
    0x5FDE0F0,
    0x5FC47B0,
    0x34EABE0,
    0x4BDAA20,
    0x66E3F20,
    0x7F9BE80,
    0x8D76E90
  };

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);

  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }
  sealed class Ins {
    public uint Rva; public string Text; public Mnemonic Mnemonic;
    public bool IpRel; public uint DataRva; public bool IsCall, IsIndirectCall, HasMem;
    public long Disp; public int Length; public Instruction Raw; public uint NearTarget;
    public bool IsRet; public ulong Imm;
    public bool HasImm;
  }
  sealed class CallerHit {
    public uint Factory, CallSite, Func;
    public bool UsesKey, UsesSizeImm, CallsLookup, CallsAlloc, CallsOuter;
    public bool PassesKeyToLookup; // LEA key near call Lookup before factory call
    public List<string> Notes = new List<string>();
    public List<string> Disasm = new List<string>();
    public List<string> Strings = new List<string>();
  }
  sealed class ConsumerDeep {
    public uint Entry; public string Role;
    public bool Touches98, TouchesA0, Touches40, Nested, Vcall2B0;
    public bool CallsAlloc, CallsLookup, CallsHelper, StoresRet, BlockCopy;
    public bool UsesKey, UsesSizeImm, CallsOuter, CallsFactory;
    public List<uint> Callees = new List<uint>();
    public List<string> Notes = new List<string>();
    public List<string> Disasm = new List<string>();
    public List<string> Strings = new List<string>();
    public int Size;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v083-raw");
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
    sb.AppendLine("===== v0.6.23 FACTORY FEED + POSSESSION-LIKE HELPERS =====");
    sb.AppendLine("exeSha256=" + hash);

    // ---- 1) Callers of tight factories ----
    sb.AppendLine();
    sb.AppendLine("===== TIGHT FACTORY CALLERS =====");
    var callers = new List<CallerHit>();
    var keyLeaSites = FindLeaTo(LookupKey, 120);
    sb.AppendLine("LEA LookupKey sites=" + keyLeaSites.Count);
    var keyFuncs = new HashSet<uint>(keyLeaSites.Select(FindFuncStart));

    foreach (uint factory in TightFactories) {
      var e8 = FindE8(factory, 200);
      var lea = FindLeaTo(factory, 40);
      sb.AppendLine();
      sb.AppendLine("--- factory 0x" + factory.ToString("X")
        + " E8=" + e8.Count + " LEA=" + lea.Count + " ---");
      var sites = new HashSet<uint>(e8);
      // Also treat LEA to factory as potential indirect call setup sites (same func)
      foreach (var l in lea) sites.Add(l);

      var byFunc = new Dictionary<uint, List<uint>>();
      foreach (uint site in sites) {
        uint fs = FindFuncStart(site);
        if (!byFunc.ContainsKey(fs)) byFunc[fs] = new List<uint>();
        byFunc[fs].Add(site);
      }
      sb.AppendLine("uniqueCallerFuncs=" + byFunc.Count);

      // Prioritize key-tied callers, then funcs that also Lookup
      var ordered = byFunc.OrderByDescending(kv => keyFuncs.Contains(kv.Key))
        .ThenBy(kv => kv.Key).ToList();

      int decoded = 0;
      foreach (var kv in ordered) {
        var hit = AnalyzeCaller(factory, kv.Key, kv.Value, keyFuncs.Contains(kv.Key));
        callers.Add(hit);
        bool interesting = hit.UsesKey || hit.UsesSizeImm || hit.PassesKeyToLookup
          || hit.CallsOuter || (hit.CallsLookup && hit.UsesKey);
        if (interesting || decoded < 8 || keyFuncs.Contains(kv.Key)) {
          sb.AppendLine("  CALLER 0x" + hit.Func.ToString("X")
            + " sites=" + kv.Value.Count
            + " key=" + hit.UsesKey
            + " sizeImm=" + hit.UsesSizeImm
            + " keyLookup=" + hit.PassesKeyToLookup
            + " lookup=" + hit.CallsLookup
            + " alloc=" + hit.CallsAlloc
            + " outer=" + hit.CallsOuter);
          foreach (var n in hit.Notes.Take(10)) sb.AppendLine("    " + n);
          if (interesting) {
            sb.AppendLine("    --- disasm head ---");
            foreach (var line in hit.Disasm.Take(40)) sb.AppendLine("    " + line);
          }
        }
        decoded++;
      }
    }

    // Cross: any caller with key?
    var keyCallers = callers.Where(c => c.UsesKey || c.PassesKeyToLookup).ToList();
    var sizeCallers = callers.Where(c => c.UsesSizeImm).ToList();
    sb.AppendLine();
    sb.AppendLine("===== FACTORY FEED CROSS =====");
    sb.AppendLine("totalCallerRecords=" + callers.Count);
    sb.AppendLine("keyTiedCallers=" + keyCallers.Count);
    sb.AppendLine("sizeImmCallers=" + sizeCallers.Count);
    sb.AppendLine("outerCtorCallers=" + callers.Count(c => c.CallsOuter));
    foreach (var c in keyCallers.Take(20))
      sb.AppendLine("  KEY_CALLER factory=0x" + c.Factory.ToString("X")
        + " func=0x" + c.Func.ToString("X")
        + " keyLookup=" + c.PassesKeyToLookup
        + " sizeImm=" + c.UsesSizeImm);

    // Also: funcs that LEA key AND call a tight factory (even if Analyze missed)
    sb.AppendLine();
    sb.AppendLine("===== KEY-FUNC ∩ FACTORY-CALLER =====");
    var factoryCallerFuncs = new HashSet<uint>(callers.Select(c => c.Func));
    int intersect = 0;
    foreach (uint kf in keyFuncs) {
      if (!factoryCallerFuncs.Contains(kf)) continue;
      intersect++;
      sb.AppendLine("  INTERSECT func=0x" + kf.ToString("X"));
    }
    sb.AppendLine("intersectCount=" + intersect);

    // Scan: within each key-LEA function, is there E8 to any tight factory?
    sb.AppendLine();
    sb.AppendLine("===== KEY-LEA FUNCS: factory/Lookup/Alloc edges =====");
    int keyFuncDecoded = 0;
    foreach (uint kf in keyFuncs.OrderBy(x => x)) {
      uint fe = FindFuncEnd(kf, 0x2000);
      if (fe <= kf) fe = kf + 0x400;
      if (fe - kf > 0x3000) fe = kf + 0x3000;
      var body = DisasmRaw(kf, fe);
      bool hasFactory = false, hasLookup = false, hasAlloc = false, hasOuter = false;
      bool hasSizeImm = false;
      var factoryHits = new List<uint>();
      foreach (var ins in body) {
        if (ins.IsCall && !ins.IsIndirectCall) {
          if (TightFactories.Contains(ins.NearTarget)) {
            hasFactory = true; factoryHits.Add(ins.NearTarget);
          }
          if (ins.NearTarget == Lookup) hasLookup = true;
          if (ins.NearTarget == Allocator) hasAlloc = true;
          if (ins.NearTarget == OuterCtor) hasOuter = true;
        }
        if (ins.HasImm && ins.Imm == SizeImm) hasSizeImm = true;
      }
      if (hasFactory || (hasLookup && hasAlloc) || hasOuter || hasSizeImm) {
        sb.AppendLine("  KEYFUNC 0x" + kf.ToString("X")
          + " factory=" + hasFactory
          + " lookup=" + hasLookup
          + " alloc=" + hasAlloc
          + " outer=" + hasOuter
          + " sizeImm=" + hasSizeImm
          + " factories=[" + string.Join(",", factoryHits.Distinct().Select(x => "0x" + x.ToString("X"))) + "]");
        keyFuncDecoded++;
      }
    }
    sb.AppendLine("keyFuncsWithInterestingEdges=" + keyFuncDecoded);

    // ---- 2) Possession-like helper consumers ----
    sb.AppendLine();
    sb.AppendLine("===== POSSESSION-LIKE 0x546D150 CONSUMERS =====");
    var helperSites = FindE8(Helper546, 80);
    var helperFuncs = new Dictionary<uint, List<uint>>();
    foreach (var site in helperSites) {
      uint fs = FindFuncStart(site);
      if (!helperFuncs.ContainsKey(fs)) helperFuncs[fs] = new List<uint>();
      helperFuncs[fs].Add(site);
    }
    sb.AppendLine("helperSites=" + helperSites.Count + " uniqueFuncs=" + helperFuncs.Count);

    // Decode all seeds + any with vcall2B0 / key / factory
    var deepList = new List<ConsumerDeep>();
    var toDecode = new HashSet<uint>(PossessionSeeds);
    foreach (var kv in helperFuncs) toDecode.Add(kv.Key);

    int deepN = 0;
    foreach (uint entry in toDecode.OrderBy(x => x)) {
      if (!helperFuncs.ContainsKey(entry) && !PossessionSeeds.Contains(entry)) continue;
      // Cap deep dumps but always do seeds
      bool isSeed = PossessionSeeds.Contains(entry);
      if (!isSeed && deepN >= 22) continue;
      var d = DeepPossession(sb, entry, entry == Neighbor ? "neighbor-baseline"
        : (entry == 0x2336560 ? "arm-neighbor-like" : "helper-consumer"));
      deepList.Add(d);
      if (!isSeed) deepN++;
    }

    // Classify possession signals
    sb.AppendLine();
    sb.AppendLine("===== POSSESSION SIGNAL CROSS =====");
    sb.AppendLine("decoded=" + deepList.Count
      + " v2B0=" + deepList.Count(d => d.Vcall2B0)
      + " key=" + deepList.Count(d => d.UsesKey)
      + " factory=" + deepList.Count(d => d.CallsFactory)
      + " outer=" + deepList.Count(d => d.CallsOuter)
      + " blockCopy=" + deepList.Count(d => d.BlockCopy)
      + " side98=" + deepList.Count(d => d.Touches98));

    foreach (var d in deepList.Where(x => x.Vcall2B0 || x.UsesKey || x.CallsFactory || x.CallsOuter
        || x.Entry == 0x2336560 || x.Entry == Neighbor).OrderBy(x => x.Entry)) {
      sb.AppendLine("  SIGNAL 0x" + d.Entry.ToString("X") + " role=" + d.Role
        + " v2B0=" + d.Vcall2B0 + " key=" + d.UsesKey
        + " factory=" + d.CallsFactory + " outer=" + d.CallsOuter
        + " block=" + d.BlockCopy);
    }

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteJson(hash, callers, keyCallers, sizeCallers, deepList, intersect, keyFuncDecoded);

    bool ok = callers.Count > 0 && deepList.Count > 0;
    Console.WriteLine("selfCheck callers=" + callers.Count
      + " keyTied=" + keyCallers.Count
      + " sizeImm=" + sizeCallers.Count
      + " intersect=" + intersect
      + " deepHelpers=" + deepList.Count
      + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static CallerHit AnalyzeCaller(uint factory, uint func, List<uint> sites, bool keyHint) {
    var hit = new CallerHit {
      Factory = factory, Func = func, CallSite = sites[0], UsesKey = keyHint
    };
    uint fe = FindFuncEnd(func, 0x2000);
    if (fe <= func) fe = func + 0x400;
    if (fe - func > 0x3000) fe = func + 0x3000;
    // Ensure we cover call sites
    uint end = Math.Max(fe, sites.Max() + 0x80);
    if (end - func > 0x4000) end = func + 0x4000;
    var body = DisasmRaw(func, end);
    uint lastKeyLea = 0;
    foreach (var ins in body) {
      if (hit.Disasm.Count < 50)
        hit.Disasm.Add("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 90));
      if (ins.IpRel && ins.DataRva == LookupKey) {
        hit.UsesKey = true;
        lastKeyLea = ins.Rva;
        hit.Notes.Add("KEY @0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 50));
      }
      if (ins.HasImm && ins.Imm == SizeImm) {
        hit.UsesSizeImm = true;
        hit.Notes.Add("SIZE_IMM @0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 50));
      }
      if (ins.IsCall && !ins.IsIndirectCall) {
        if (ins.NearTarget == Lookup) {
          hit.CallsLookup = true;
          hit.Notes.Add("LOOKUP @0x" + ins.Rva.ToString("X"));
          if (lastKeyLea != 0 && ins.Rva > lastKeyLea && ins.Rva - lastKeyLea < 0x40)
            hit.PassesKeyToLookup = true;
        }
        if (ins.NearTarget == Allocator) { hit.CallsAlloc = true; hit.Notes.Add("ALLOC @0x" + ins.Rva.ToString("X")); }
        if (ins.NearTarget == OuterCtor) { hit.CallsOuter = true; hit.Notes.Add("OUTER @0x" + ins.Rva.ToString("X")); }
        if (ins.NearTarget == factory) hit.Notes.Add("CALL_FACTORY @0x" + ins.Rva.ToString("X"));
      }
      if (ins.IpRel) {
        string s = ReadAscii(ins.DataRva, 48);
        if (IsString(s) && s.Length >= 5 && !hit.Strings.Contains(s)) hit.Strings.Add(s);
      }
    }
    foreach (var s in hit.Strings.Take(4)) hit.Notes.Add("str \"" + Trunc(s, 50) + "\"");
    return hit;
  }

  static ConsumerDeep DeepPossession(StringBuilder sb, uint entry, string role) {
    var r = new ConsumerDeep { Entry = entry, Role = role };
    uint fe = FindFuncEnd(entry, 0x1800);
    if (fe <= entry) fe = entry + 0x300;
    if (fe - entry > 0x2000) fe = entry + 0x2000;
    r.Size = (int)(fe - entry);
    sb.AppendLine();
    sb.AppendLine("===== DEEP 0x" + entry.ToString("X") + " (" + role + ") size=" + r.Size
      + " sec=" + SecName(entry) + " =====");
    var body = DisasmRaw(entry, fe);
    int head = 0;
    foreach (var i in body) {
      if (head++ < 55) {
        string mark = "";
        if (i.NearTarget == Helper546) mark = " *** HELPER ***";
        if (i.NearTarget == Lookup) mark = " *** LOOKUP ***";
        if (i.NearTarget == Allocator) mark = " *** ALLOC ***";
        if (i.NearTarget == OuterCtor) mark = " *** OUTER ***";
        if (TightFactories.Contains(i.NearTarget)) mark = " *** FACTORY ***";
        if (i.IpRel && i.DataRva == LookupKey) mark += " *** KEY ***";
        if (i.IsIndirectCall && (i.Disp == 0x2B0 || i.Text.Contains("+2B0"))) mark += " *** V2B0 ***";
        if (i.HasMem && !i.IpRel && i.Disp == 0x98) mark += " *** +98 ***";
        if (i.HasMem && !i.IpRel && i.Disp == 0xA0) mark += " *** +A0 ***";
        r.Disasm.Add("0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 88) + mark);
      }
      if (i.HasMem && !i.IpRel) {
        if (i.Disp == 0x98) r.Touches98 = true;
        if (i.Disp == 0xA0) r.TouchesA0 = true;
        if (i.Disp == 0x40 || i.Disp == 0x50 || i.Disp == 0x60 || i.Disp == 0x70 || i.Disp == 0x80)
          r.Touches40 = true;
        if (i.Disp == 0x18 || i.Disp == 0xA8) r.Nested = true;
        if (i.Disp == 0x2B0) r.Vcall2B0 = true;
      }
      if (i.IsIndirectCall && (i.Disp == 0x2B0 || i.Text.Contains("+2B0"))) r.Vcall2B0 = true;
      if (i.Mnemonic == Mnemonic.Vmovups || i.Mnemonic == Mnemonic.Movups || i.Mnemonic == Mnemonic.Movaps
          || i.Text.Contains("vmovups") || i.Text.Contains("movaps"))
        r.BlockCopy = true;
      if (i.IsCall && !i.IsIndirectCall) {
        r.Callees.Add(i.NearTarget);
        if (i.NearTarget == Helper546) { r.CallsHelper = true; r.Notes.Add("CALL_HELPER @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Allocator) { r.CallsAlloc = true; r.Notes.Add("CALL_ALLOC @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Lookup) { r.CallsLookup = true; r.Notes.Add("CALL_LOOKUP @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == OuterCtor) { r.CallsOuter = true; r.Notes.Add("CALL_OUTER @0x" + i.Rva.ToString("X")); }
        if (TightFactories.Contains(i.NearTarget)) {
          r.CallsFactory = true;
          r.Notes.Add("CALL_FACTORY 0x" + i.NearTarget.ToString("X") + " @0x" + i.Rva.ToString("X"));
        }
      }
      if (i.IpRel && i.DataRva == LookupKey) {
        r.UsesKey = true;
        r.Notes.Add("KEY @0x" + i.Rva.ToString("X"));
      }
      if (i.HasImm && i.Imm == SizeImm) {
        r.UsesSizeImm = true;
        r.Notes.Add("SIZE_IMM @0x" + i.Rva.ToString("X"));
      }
      if (r.CallsHelper && (i.Text.StartsWith("mov [") || i.Text.Contains(",rax"))
          && i.Text.Contains("["))
        r.StoresRet = true;
      if (i.IpRel) {
        string s = ReadAscii(i.DataRva, 48);
        if (IsString(s) && s.Length >= 5 && !r.Strings.Contains(s)) r.Strings.Add(s);
      }
    }

    // Refine role
    if (r.Entry == Neighbor) r.Role = "neighbor-baseline";
    else if (r.Vcall2B0) r.Role = "arm-neighbor-like";
    else if (r.UsesKey || r.CallsFactory || r.CallsOuter) r.Role = "key-or-factory-linked";
    else if (r.BlockCopy && r.Touches40) r.Role = "block-copy-consumer";
    else if (r.Touches98 || r.TouchesA0) r.Role = "sideblock-walker";
    else if (r.Size <= 0x40) r.Role = "thin-wrapper";
    else r.Role = "helper-consumer";

    sb.AppendLine("role=" + r.Role
      + " t98=" + r.Touches98 + " tA0=" + r.TouchesA0 + " t40=" + r.Touches40
      + " v2B0=" + r.Vcall2B0 + " block=" + r.BlockCopy
      + " key=" + r.UsesKey + " factory=" + r.CallsFactory
      + " outer=" + r.CallsOuter + " alloc=" + r.CallsAlloc
      + " lookup=" + r.CallsLookup);
    foreach (var n in r.Notes) sb.AppendLine("  " + n);
    foreach (var s in r.Strings.Take(6)) sb.AppendLine("  str \"" + Trunc(s, 60) + "\"");
    foreach (var c in r.Callees.Distinct().Take(14)) {
      string mark = c == Helper546 ? " *** HELPER ***"
        : TightFactories.Contains(c) ? " *** FACTORY ***"
        : c == OuterCtor ? " *** OUTER ***" : "";
      sb.AppendLine("  callee 0x" + c.ToString("X") + mark);
    }
    sb.AppendLine("--- head ---");
    foreach (var line in r.Disasm.Take(45)) sb.AppendLine(line);
    return r;
  }

  static void WriteJson(string hash, List<CallerHit> callers, List<CallerHit> keyCallers,
      List<CallerHit> sizeCallers, List<ConsumerDeep> deep, int intersect, int keyEdges) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.23\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"factoryFeed\": {");
    sb.AppendLine("    \"callerRecords\": " + callers.Count + ",");
    sb.AppendLine("    \"keyTiedCallers\": " + keyCallers.Count + ",");
    sb.AppendLine("    \"sizeImmCallers\": " + sizeCallers.Count + ",");
    sb.AppendLine("    \"keyFuncFactoryIntersect\": " + intersect + ",");
    sb.AppendLine("    \"keyFuncsWithInterestingEdges\": " + keyEdges + ",");
    sb.AppendLine("    \"keyCallerFuncs\": [" + string.Join(", ",
      keyCallers.Select(c => "\"0x" + c.Func.ToString("X") + "\"").Distinct()) + "]");
    sb.AppendLine("  },");
    sb.AppendLine("  \"possessionHelpers\": {");
    sb.AppendLine("    \"decoded\": " + deep.Count + ",");
    sb.AppendLine("    \"vcall2B0\": " + deep.Count(d => d.Vcall2B0) + ",");
    sb.AppendLine("    \"keyLinked\": " + deep.Count(d => d.UsesKey) + ",");
    sb.AppendLine("    \"factoryLinked\": " + deep.Count(d => d.CallsFactory) + ",");
    sb.AppendLine("    \"roles\": {" + string.Join(", ",
      deep.GroupBy(d => d.Role).Select(g => J(g.Key) + ": " + g.Count())) + "}");
    sb.AppendLine("  },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.23-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.23-summary.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.23\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"callers\": [");
    var interesting = callers
      .Where(c => c.UsesKey || c.UsesSizeImm || c.PassesKeyToLookup || c.CallsOuter)
      .Concat(callers.GroupBy(c => c.Factory).SelectMany(g => g.Take(3)))
      .GroupBy(c => c.Func.ToString("X") + ":" + c.Factory.ToString("X"))
      .Select(g => g.First()).Take(60).ToList();
    for (int i = 0; i < interesting.Count; i++) {
      var c = interesting[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"factory\": \"0x" + c.Factory.ToString("X") + "\",");
      sb.AppendLine("      \"func\": \"0x" + c.Func.ToString("X") + "\",");
      sb.AppendLine("      \"usesKey\": " + T(c.UsesKey) + ",");
      sb.AppendLine("      \"passesKeyToLookup\": " + T(c.PassesKeyToLookup) + ",");
      sb.AppendLine("      \"usesSizeImm\": " + T(c.UsesSizeImm) + ",");
      sb.AppendLine("      \"callsLookup\": " + T(c.CallsLookup) + ",");
      sb.AppendLine("      \"callsOuter\": " + T(c.CallsOuter) + ",");
      sb.AppendLine("      \"notes\": [" + string.Join(", ", c.Notes.Take(12).Select(J)) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", c.Disasm.Take(25).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < interesting.Count ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"consumers\": [");
    for (int i = 0; i < deep.Count; i++) {
      var d = deep[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + d.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(d.Role) + ",");
      sb.AppendLine("      \"size\": " + d.Size + ",");
      sb.AppendLine("      \"vcall2B0\": " + T(d.Vcall2B0) + ",");
      sb.AppendLine("      \"usesKey\": " + T(d.UsesKey) + ",");
      sb.AppendLine("      \"callsFactory\": " + T(d.CallsFactory) + ",");
      sb.AppendLine("      \"callsOuter\": " + T(d.CallsOuter) + ",");
      sb.AppendLine("      \"blockCopy\": " + T(d.BlockCopy) + ",");
      sb.AppendLine("      \"touches98\": " + T(d.Touches98) + ",");
      sb.AppendLine("      \"notes\": [" + string.Join(", ", d.Notes.Select(J)) + "],");
      sb.AppendLine("      \"callees\": [" + string.Join(", ",
        d.Callees.Distinct().Take(16).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"strings\": [" + string.Join(", ", d.Strings.Take(8).Select(J)) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", d.Disasm.Take(40).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < deep.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.23-funcs-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.23-funcs-deep.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.23\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    string feedClass = keyCallers.Count > 0 ? "partial" : (intersect > 0 ? "partial" : "unsupported");
    string feedReason = keyCallers.Count > 0
      ? "Found key-tied callers of tight factories"
      : (intersect > 0
        ? "Key-func intersect with factory callers without proven key->factory arg feed"
        : "No tight-factory caller LEAs LookupKey 0xB2898C8 or size imm 0x20F0");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"No Edward create; factory feed and helper consumers do not prove possession\" },");
    sb.AppendLine("  \"factoryKeyFeed\": { \"class\": \"" + feedClass + "\", \"reason\": " + J(feedReason)
      + ", \"keyTiedCallers\": " + keyCallers.Count + ", \"sizeImmCallers\": " + sizeCallers.Count + " },");
    sb.AppendLine("  \"possessionLikeHelpers\": { \"class\": \"partial\", \"reason\": "
      + J("Deep-decoded " + deep.Count + " helper consumers; v2B0="
        + deep.Count(d => d.Vcall2B0) + " key=" + deep.Count(d => d.UsesKey)
        + " — possession/control not proven") + " },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"If no key-tied factory caller: reverse from InstallerA/outer ctor registration into create sites; continue possession-like helper decode\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\", \"field-offset 0x20F0 as heap size\", \"treat loose fullPattern as proven\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.23-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.23-second-edward-feasibility.json");
  }

  static string T(bool b) => b ? "true" : "false";
  static string J(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
  }

  static List<Ins> DisasmRaw(uint start, uint endExclusive) {
    var list = new List<Ins>();
    int fo = RvaToFile(start);
    if (fo < 0) return list;
    var reader = new ByteArrayCodeReader(pe);
    reader.Position = fo;
    var dec = Decoder.Create(64, reader);
    dec.IP = imageBase + start;
    ulong limit = imageBase + endExclusive;
    int guard = 0;
    while (dec.IP < limit && guard++ < 400000) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      if (raw.IP < imageBase) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      var ins = new Ins {
        Raw = raw, Rva = (uint)(raw.IP - imageBase), Text = o.ToString(),
        Mnemonic = raw.Mnemonic, Length = raw.Length,
        IsCall = raw.FlowControl == FlowControl.Call || raw.FlowControl == FlowControl.IndirectCall,
        IsIndirectCall = raw.FlowControl == FlowControl.IndirectCall,
        IsRet = raw.Mnemonic == Mnemonic.Ret
      };
      if (ins.IsCall && !ins.IsIndirectCall && raw.NearBranchTarget != 0 && raw.NearBranchTarget >= imageBase)
        ins.NearTarget = (uint)(raw.NearBranchTarget - imageBase);
      for (int oi = 0; oi < raw.OpCount; oi++) {
        var kind = raw.GetOpKind(oi);
        if (kind == OpKind.Immediate8 || kind == OpKind.Immediate8to16 || kind == OpKind.Immediate8to32
            || kind == OpKind.Immediate8to64 || kind == OpKind.Immediate16 || kind == OpKind.Immediate32
            || kind == OpKind.Immediate32to64 || kind == OpKind.Immediate64) {
          ins.HasImm = true;
          try { ins.Imm = raw.GetImmediate(oi); } catch { }
        }
        if (kind != OpKind.Memory) continue;
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
      }
      list.Add(ins);
    }
    return list;
  }

  static uint FindFuncEnd(uint entry, int maxScan) {
    var list = DisasmRaw(entry, entry + (uint)maxScan);
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
        if (op != 0x8D) continue;
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
