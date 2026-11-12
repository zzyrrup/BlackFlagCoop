// v0.6.22 — Offline: generic TypeInfo factory Lookup→[ti+0x20]→Alloc→[ti+0x50]
// for 0x20F0 / 0xB2898C8 record; map 0x546D150 consumers beyond edx=3 neighbor.
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
  const uint Lookup = 0x429F9E0;
  const uint Allocator = 0x426EE50;
  const uint LookupKey = 0xB2898C8;
  const uint OuterCtor = 0x59D9660;
  const uint Helper546 = 0x546D150;
  const uint Neighbor = 0x2335140;
  const uint RegSize = 0x20F0;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

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
    public bool IsRet;
  }
  sealed class FactoryHit {
    public uint Func, LookupSite, SizeLoad, AllocSite, CtorLoad, CtorCall;
    public bool UsesKey, FullPattern, TightVerified;
    public int XrefCount;
    public List<string> Notes = new List<string>();
  }
  sealed class ConsumerRep {
    public uint Entry, End; public int Size; public string Role;
    public bool CallsHelper, Touches98, TouchesA0, Touches40, Nested;
    public bool CallsAlloc, CallsLookup, Vcall2B0, IsNeighbor;
    public List<uint> Callees = new List<uint>();
    public List<string> Notes = new List<string>();
    public List<string> Disasm = new List<string>();
    public List<string> Strings = new List<string>();
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v082-raw");
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
    sb.AppendLine("===== v0.6.22 TYPEINFO FACTORY + HELPER CONSUMERS =====");
    sb.AppendLine("exeSha256=" + hash);

    // ---- 1) Factory pattern scan ----
    sb.AppendLine();
    sb.AppendLine("===== FACTORY PATTERN SCAN =====");
    var lookupSites = FindE8(Lookup, 500);
    sb.AppendLine("E8->Lookup count=" + lookupSites.Count);
    var factories = new List<FactoryHit>();
    var keyLeaFuncs = new HashSet<uint>();
    foreach (var lea in FindLeaTo(LookupKey, 80))
      keyLeaFuncs.Add(FindFuncStart(lea));
    sb.AppendLine("funcs LEA LookupKey=" + keyLeaFuncs.Count);

    var seenFunc = new HashSet<uint>();
    foreach (var site in lookupSites) {
      uint fs = FindFuncStart(site);
      if (!seenFunc.Add(fs)) continue;
      // Analyze whole function (capped) for pattern
      uint fe = FindFuncEnd(fs, 0x1800);
      if (fe <= fs) fe = fs + 0x400;
      if (fe - fs > 0x2000) fe = fs + 0x2000;
      var body = Disasm(fs, fe);
      var hit = AnalyzeFactory(fs, body, keyLeaFuncs.Contains(fs));
      if (hit != null && (hit.FullPattern || (hit.UsesKey && (hit.AllocSite != 0 || hit.SizeLoad != 0)))) {
        factories.Add(hit);
      }
    }
    // Also analyze key-LEA funcs even if Lookup call was missed by FindFuncStart grouping
    foreach (uint fs in keyLeaFuncs) {
      if (factories.Any(f => f.Func == fs)) continue;
      uint fe = FindFuncEnd(fs, 0x1800);
      if (fe <= fs) fe = fs + 0x400;
      var body = Disasm(fs, Math.Min(fe, fs + 0x2000));
      var hit = AnalyzeFactory(fs, body, true);
      if (hit != null) factories.Add(hit);
    }

    // Tight-verify: size dword from [reg+0x20] feeds edx into Allocator; ctor via [ti+0x50] icall
    foreach (var f in factories.Where(x => x.FullPattern)) {
      f.TightVerified = TightVerifyFactory(f);
      f.XrefCount = FindE8(f.Func, 80).Count;
    }

    sb.AppendLine("factoryCandidates=" + factories.Count
      + " fullPattern=" + factories.Count(f => f.FullPattern)
      + " tightVerified=" + factories.Count(f => f.TightVerified)
      + " withKey=" + factories.Count(f => f.UsesKey)
      + " keyAndTight=" + factories.Count(f => f.UsesKey && f.TightVerified));
    foreach (var f in factories
        .OrderByDescending(x => x.TightVerified)
        .ThenByDescending(x => x.FullPattern)
        .ThenByDescending(x => x.UsesKey)
        .Take(30)) {
      sb.AppendLine("  FACT 0x" + f.Func.ToString("X")
        + " full=" + f.FullPattern + " tight=" + f.TightVerified + " key=" + f.UsesKey
        + " xrefs=" + f.XrefCount
        + " lookup@0x" + f.LookupSite.ToString("X")
        + " sizeLd@0x" + f.SizeLoad.ToString("X")
        + " alloc@0x" + f.AllocSite.ToString("X")
        + " ctorLd@0x" + f.CtorLoad.ToString("X")
        + " ctorCall@0x" + f.CtorCall.ToString("X"));
      foreach (var n in f.Notes.Take(10)) sb.AppendLine("    " + n);
    }

    // Deep-decode tight + key-false-positive factories (force span past early rets)
    sb.AppendLine();
    sb.AppendLine("===== FACTORY DEEP DECODES =====");
    var deepFacts = factories
      .Where(f => f.TightVerified || (f.UsesKey && f.FullPattern) || (f.FullPattern && f.CtorCall != 0 && f.SizeLoad != 0))
      .OrderByDescending(f => f.TightVerified)
      .ThenByDescending(f => f.UsesKey)
      .ThenByDescending(f => f.XrefCount)
      .Take(8).ToList();
    if (deepFacts.Count == 0)
      deepFacts = factories.Where(f => f.FullPattern).Take(4).ToList();
    foreach (var f in deepFacts) {
      sb.AppendLine();
      sb.AppendLine("--- deep 0x" + f.Func.ToString("X")
        + " tight=" + f.TightVerified + " key=" + f.UsesKey + " xrefs=" + f.XrefCount + " ---");
      uint end = Math.Max(f.Func + 0x200,
        Math.Max(f.AllocSite == 0 ? f.Func : f.AllocSite + 0x80,
          f.CtorCall == 0 ? f.Func : f.CtorCall + 0x40));
      if (end - f.Func > 0x400) end = f.Func + 0x400;
      // DisasmRaw spans early rets (do not stop on Int3/Ret)
      var body = DisasmRaw(f.Func, end);
      foreach (var ins in body.Take(90)) {
        string mark = "";
        if (ins.NearTarget == Lookup) mark = " *** LOOKUP ***";
        if (ins.NearTarget == Allocator) mark = " *** ALLOC ***";
        if (ins.NearTarget == OuterCtor) mark = " *** OUTER ***";
        if (ins.IpRel && ins.DataRva == LookupKey) mark += " *** KEY ***";
        if (ins.HasMem && !ins.IpRel && ins.Disp == 0x20 && !ins.Text.Contains("[rsp") && !ins.Text.Contains("[rbp"))
          mark += " *** +20 ***";
        if (ins.HasMem && !ins.IpRel && ins.Disp == 0x50 && !ins.Text.Contains("[rsp"))
          mark += " *** +50 ***";
        if (ins.IsIndirectCall) mark += " *** ICALL ***";
        sb.AppendLine("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 90) + mark);
      }
      // Sample callers of tight factories
      if (f.TightVerified || f.XrefCount > 0) {
        sb.AppendLine("  callers(sample):");
        foreach (var site in FindE8(f.Func, 12).Take(8))
          sb.AppendLine("    E8@0x" + site.ToString("X") + " fromFunc=0x" + FindFuncStart(site).ToString("X"));
      }
    }

    // ---- 2) Helper 0x546D150 consumers ----
    sb.AppendLine();
    sb.AppendLine("===== 0x546D150 CONSUMERS =====");
    var helperCallers = FindE8(Helper546, 80);
    sb.AppendLine("E8->0x546D150 count=" + helperCallers.Count);
    var consumerFuncs = new Dictionary<uint, List<uint>>();
    foreach (var site in helperCallers) {
      uint fs = FindFuncStart(site);
      if (!consumerFuncs.ContainsKey(fs)) consumerFuncs[fs] = new List<uint>();
      consumerFuncs[fs].Add(site);
    }
    sb.AppendLine("uniqueCallerFuncs=" + consumerFuncs.Count);

    var consumerReps = new List<ConsumerRep>();
    int decoded = 0;
    foreach (var kv in consumerFuncs.OrderBy(k => k.Key)) {
      uint fs = kv.Key;
      bool isNeigh = fs == Neighbor || (fs >= Neighbor && fs < Neighbor + 0x20);
      string role = isNeigh ? "neighbor-2335140" : "helper-consumer";
      sb.AppendLine();
      sb.AppendLine("===== CONSUMER 0x" + fs.ToString("X") + " (" + role + ") sites=" + kv.Value.Count + " =====");
      var rep = DeepConsumer(sb, fs, role, isNeigh);
      consumerReps.Add(rep);
      decoded++;
      if (decoded >= 18) {
        sb.AppendLine("(capped consumer deep-decodes at 18; remaining=" + (consumerFuncs.Count - decoded) + ")");
        // Still list remaining
        foreach (var rest in consumerFuncs.OrderBy(k => k.Key).Skip(decoded))
          sb.AppendLine("  remainingFunc 0x" + rest.Key.ToString("X") + " sites=" + rest.Value.Count);
        break;
      }
    }

    // Cross
    sb.AppendLine();
    sb.AppendLine("===== CROSS =====");
    bool factoryConfirmed = factories.Any(f => f.TightVerified);
    bool looseFull = factories.Any(f => f.FullPattern);
    bool keyFactory = factories.Any(f => f.UsesKey && f.AllocSite != 0 && f.SizeLoad != 0);
    bool keyTight = factories.Any(f => f.UsesKey && f.TightVerified);
    sb.AppendLine("tightFactoryPattern=" + factoryConfirmed);
    sb.AppendLine("looseFullFactoryPattern=" + looseFull);
    sb.AppendLine("keyTiedPartialFactory=" + keyFactory);
    sb.AppendLine("keyTiedTightFactory=" + keyTight);
    sb.AppendLine("helperConsumers=" + consumerFuncs.Count
      + " beyondNeighbor=" + consumerFuncs.Count(kv => kv.Key != Neighbor));
    sb.AppendLine("neighborPresent=" + consumerFuncs.ContainsKey(Neighbor));

    // Classify beyond-neighbor consumers
    var beyond = consumerReps.Where(r => !r.IsNeighbor).ToList();
    sb.AppendLine("beyondDecoded=" + beyond.Count
      + " touch98=" + beyond.Count(r => r.Touches98)
      + " vcall2B0=" + beyond.Count(r => r.Vcall2B0)
      + " alloc=" + beyond.Count(r => r.CallsAlloc)
      + " roles=" + string.Join(",", beyond.GroupBy(r => r.Role).Select(g => g.Key + "=" + g.Count())));

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteJson(hash, factories, consumerReps, consumerFuncs, factoryConfirmed, keyFactory, keyTight);

    Console.WriteLine("selfCheck factories=" + factories.Count
      + " full=" + factories.Count(f => f.FullPattern)
      + " tight=" + factories.Count(f => f.TightVerified)
      + " helperCallers=" + helperCallers.Count
      + " beyond=" + consumerFuncs.Count(kv => kv.Key != Neighbor)
      + " ok=" + (helperCallers.Count > 0 && factoryConfirmed));
    return helperCallers.Count > 0 && factoryConfirmed ? 0 : 4;
  }

  // Confirmed idiom: after TypeInfo in a reg, mov edx,[ti+0x20]; call Alloc; call [ti+0x50]
  static bool TightVerifyFactory(FactoryHit f) {
    if (f.SizeLoad == 0 || f.AllocSite == 0 || f.CtorCall == 0) return false;
    if (!(f.SizeLoad < f.AllocSite && f.AllocSite < f.CtorCall)) return false;
    // Window covering size→alloc→ctor
    uint start = f.SizeLoad > 0x10 ? f.SizeLoad - 0x10 : f.SizeLoad;
    uint end = f.CtorCall + 0x20;
    var body = DisasmRaw(start, end);
    bool sizeDword = false;
    bool edxFed = false;
    bool ctor50 = false;
    string sizeText = "";
    foreach (var ins in body) {
      if (ins.Rva == f.SizeLoad) {
        sizeText = ins.Text;
        // Prefer 32-bit size loads: mov e*d / r*d, [reg+20]
        sizeDword = (ins.Text.Contains("mov e") || ins.Text.Contains("mov r") && ins.Text.Contains("d,["))
          && ins.HasMem && ins.Disp == 0x20
          && !ins.Text.Contains("[rsp") && !ins.Text.Contains("qword");
        // Also accept mov r11d,[reg+20] style (already covered by Contains "mov r" + "d,[")
        if (ins.Text.Contains("d,[") && ins.Disp == 0x20) sizeDword = true;
        if (ins.Text.StartsWith("mov eax,[") || ins.Text.StartsWith("mov ecx,[")
            || ins.Text.StartsWith("mov edx,[") || ins.Text.StartsWith("mov ebx,[")
            || ins.Text.StartsWith("mov esi,[") || ins.Text.StartsWith("mov edi,[")
            || ins.Text.Contains("mov r8d,[") || ins.Text.Contains("mov r9d,[")
            || ins.Text.Contains("mov r10d,[") || ins.Text.Contains("mov r11d,[")
            || ins.Text.Contains("mov r12d,[") || ins.Text.Contains("mov r13d,[")
            || ins.Text.Contains("mov r14d,[") || ins.Text.Contains("mov r15d,["))
          sizeDword = true;
      }
      // Between size and alloc: mov edx,<sizeReg>
      if (ins.Rva > f.SizeLoad && ins.Rva < f.AllocSite) {
        if (ins.Text.StartsWith("mov edx,") || ins.Text == "mov edx,eax" || ins.Text.Contains("mov edx,r"))
          edxFed = true;
      }
      if (ins.Rva == f.AllocSite - 0) { /* Alloc itself */ }
      // Ctor: call [reg+50] or call via previously loaded +50
      if (ins.Rva == f.CtorCall) {
        if (ins.IsIndirectCall && (ins.Disp == 0x50 || ins.Text.Contains("+50]") || ins.Text.Contains("+0x50]")))
          ctor50 = true;
        // Some sites: mov reg,[ti+50] then call reg — accept if CtorLoad set nearby
        if (f.CtorLoad != 0 && f.CtorLoad < f.CtorCall && f.CtorCall - f.CtorLoad < 0x40)
          ctor50 = true;
        if (ins.Text.Contains("[") && ins.Text.Contains("+50"))
          ctor50 = true;
      }
    }
    // Also check body notes already recorded
    if (!ctor50 && f.Notes.Any(n => n.Contains("CTOR_ICALL") && n.Contains("+50")))
      ctor50 = true;
    if (!ctor50 && f.Notes.Any(n => n.Contains("call qword ptr [") && n.Contains("+50")))
      ctor50 = true;

    bool ok = sizeDword && edxFed && ctor50;
    f.Notes.Add("TIGHT sizeDword=" + sizeDword + " edxFed=" + edxFed + " ctor50=" + ctor50
      + " sizeTxt=" + Trunc(sizeText, 40) + " => " + ok);
    // False-positive guard: key-tied with unrelated Alloc imm (e.g. 0x238) — if Alloc site
    // is far from size load (>0x100) and no edx feed, reject (already covered by edxFed).
    return ok;
  }

  static FactoryHit AnalyzeFactory(uint fs, List<Ins> body, bool usesKeyHint) {
    var hit = new FactoryHit { Func = fs, UsesKey = usesKeyHint };
    // Track sequence loosely: Lookup site, then later +0x20 dword/qword load from a reg,
    // Allocator call, +0x50 load, indirect call
    bool sawLookup = false;
    foreach (var ins in body) {
      if (ins.IpRel && ins.DataRva == LookupKey) {
        hit.UsesKey = true;
        hit.Notes.Add("KEY @0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 50));
      }
      if (ins.IsCall && !ins.IsIndirectCall && ins.NearTarget == Lookup) {
        sawLookup = true;
        hit.LookupSite = ins.Rva;
        hit.Notes.Add("LOOKUP @0x" + ins.Rva.ToString("X"));
      }
      if (!sawLookup && hit.LookupSite == 0) continue;

      // After lookup: mov r32/r64, [reg+0x20] — size field
      if (ins.HasMem && !ins.IpRel && ins.Disp == 0x20
          && (ins.Mnemonic == Mnemonic.Mov || ins.Mnemonic == Mnemonic.Movzx || ins.Mnemonic == Mnemonic.Movsxd)) {
        // Prefer loads INTO a register (destination not memory-only). Heuristic: text starts with mov e/r
        if (ins.Text.StartsWith("mov e") || ins.Text.StartsWith("mov r") || ins.Text.StartsWith("movzx")
            || ins.Text.Contains("mov eax") || ins.Text.Contains("mov ecx") || ins.Text.Contains("mov edx")
            || ins.Text.Contains("mov r8d") || ins.Text.Contains("mov ebx") || ins.Text.Contains("mov esi")
            || ins.Text.Contains("mov edi") || ins.Text.Contains("mov rax") || ins.Text.Contains("mov rcx")
            || ins.Text.Contains("mov rdx") || ins.Text.Contains("mov rbx")) {
          // Exclude stack [rsp+20]
          if (!ins.Text.Contains("[rsp") && !ins.Text.Contains("[rbp")) {
            if (hit.SizeLoad == 0) {
              hit.SizeLoad = ins.Rva;
              hit.Notes.Add("SIZE_LOAD +20 @0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 55));
            }
          }
        }
      }
      if (ins.IsCall && !ins.IsIndirectCall && ins.NearTarget == Allocator) {
        hit.AllocSite = ins.Rva;
        hit.Notes.Add("ALLOC @0x" + ins.Rva.ToString("X"));
      }
      if (ins.IsCall && !ins.IsIndirectCall && ins.NearTarget == OuterCtor) {
        hit.Notes.Add("OUTER_CTOR @0x" + ins.Rva.ToString("X"));
        hit.CtorCall = ins.Rva;
      }
      // +0x50 load (ctor pointer)
      if (ins.HasMem && !ins.IpRel && ins.Disp == 0x50
          && (ins.Mnemonic == Mnemonic.Mov)
          && !ins.Text.Contains("[rsp") && !ins.Text.Contains("[rbp")
          && (ins.Text.StartsWith("mov r") || ins.Text.Contains("mov rax") || ins.Text.Contains("mov rcx")
              || ins.Text.Contains("mov rdx") || ins.Text.Contains("mov rbx") || ins.Text.Contains("mov rsi")
              || ins.Text.Contains("mov rdi") || ins.Text.Contains("mov r8") || ins.Text.Contains("mov r9"))) {
        if (hit.CtorLoad == 0) {
          hit.CtorLoad = ins.Rva;
          hit.Notes.Add("CTOR_LOAD +50 @0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 55));
        }
      }
      // Indirect call after alloc — possible ctor call
      if (ins.IsIndirectCall && hit.AllocSite != 0 && ins.Rva > hit.AllocSite) {
        if (hit.CtorCall == 0) {
          hit.CtorCall = ins.Rva;
          hit.Notes.Add("CTOR_ICALL @0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 55));
        }
      }
    }
    hit.FullPattern = hit.LookupSite != 0 && hit.SizeLoad != 0 && hit.AllocSite != 0
      && (hit.CtorLoad != 0 || hit.CtorCall != 0);
    // Keep only if something interesting
    if (hit.LookupSite == 0 && !hit.UsesKey) return null;
    if (hit.SizeLoad == 0 && hit.AllocSite == 0 && hit.CtorLoad == 0 && !hit.UsesKey) return null;
    // Require at least size or alloc after lookup for non-key
    if (!hit.UsesKey && hit.SizeLoad == 0 && hit.AllocSite == 0) return null;
    return hit;
  }

  static ConsumerRep DeepConsumer(StringBuilder sb, uint entry, string role, bool isNeigh) {
    var r = new ConsumerRep { Entry = entry, Role = role, IsNeighbor = isNeigh };
    r.End = FindFuncEnd(entry, 0x1000);
    if (r.End <= entry) r.End = entry + 0x200;
    if (r.End - entry > 0x1500) r.End = entry + 0x1500;
    r.Size = (int)(r.End - entry);
    sb.AppendLine("size=" + r.Size + " sec=" + SecName(entry) + " prologue=" + Hex(entry, 10));
    var ins = DisasmRaw(entry, r.End); // continue past early rets inside consumer
    int head = 0;
    bool storesHelperRet = false;
    bool copiesBlock = false;
    foreach (var i in ins) {
      if (head++ < 45) r.Disasm.Add("0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 90));
      if (i.HasMem && !i.IpRel) {
        if (i.Disp == 0x98) r.Touches98 = true;
        if (i.Disp == 0xA0) r.TouchesA0 = true;
        if (i.Disp == 0x40 || i.Disp == 0x50 || i.Disp == 0x60 || i.Disp == 0x70 || i.Disp == 0x80) r.Touches40 = true;
        if (i.Disp == 0x18 || i.Disp == 0xA8) r.Nested = true;
        if (i.Disp == 0x2B0) r.Vcall2B0 = true;
      }
      if (i.IsIndirectCall && (i.Disp == 0x2B0 || i.Text.Contains("+2B0"))) r.Vcall2B0 = true;
      if (i.Mnemonic == Mnemonic.Vmovups || i.Mnemonic == Mnemonic.Movups || i.Mnemonic == Mnemonic.Movaps
          || i.Text.Contains("vmovups") || i.Text.Contains("movaps"))
        copiesBlock = true;
      if (i.IsCall && !i.IsIndirectCall) {
        r.Callees.Add(i.NearTarget);
        if (i.NearTarget == Helper546) { r.CallsHelper = true; r.Notes.Add("CALL_HELPER @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Allocator) { r.CallsAlloc = true; r.Notes.Add("CALL_ALLOC @0x" + i.Rva.ToString("X")); }
        if (i.NearTarget == Lookup) { r.CallsLookup = true; r.Notes.Add("CALL_LOOKUP @0x" + i.Rva.ToString("X")); }
      }
      // After helper call: store rax / use return
      if (r.CallsHelper && (i.Text.StartsWith("mov [") || i.Text.StartsWith("mov qword ptr ["))
          && (i.Text.Contains(",rax") || i.Text.Contains(",rax")))
        storesHelperRet = true;
      if (i.IpRel) {
        string s = ReadAscii(i.DataRva, 50);
        if (IsString(s) && s.Length >= 5 && !r.Strings.Contains(s)) r.Strings.Add(s);
      }
    }
    // Role refine for beyond-neighbor
    if (!isNeigh) {
      if (r.Vcall2B0) r.Role = "arm-neighbor-like";
      else if (copiesBlock && r.Touches40) r.Role = "block-copy-consumer";
      else if (r.CallsAlloc) r.Role = "alloc+helper";
      else if (r.Touches98 || r.TouchesA0) r.Role = "sideblock-walker";
      else if (r.Size <= 0x40) r.Role = "thin-wrapper";
      else r.Role = "helper-consumer";
      if (storesHelperRet) r.Notes.Add("storesHelperRet");
      if (copiesBlock) r.Notes.Add("blockCopy");
    }
    sb.AppendLine("role=" + r.Role + " t98=" + r.Touches98 + " tA0=" + r.TouchesA0 + " t40range=" + r.Touches40
      + " nested=" + r.Nested + " v2B0=" + r.Vcall2B0
      + " alloc=" + r.CallsAlloc + " lookup=" + r.CallsLookup
      + " callees=" + r.Callees.Distinct().Count());
    foreach (var n in r.Notes) sb.AppendLine("  " + n);
    foreach (var s in r.Strings.Take(5)) sb.AppendLine("  str \"" + Trunc(s, 60) + "\"");
    foreach (var c in r.Callees.Distinct().Take(12)) {
      string mark = c == Helper546 ? " *** HELPER ***" : c == Allocator ? " *** ALLOC ***" : "";
      sb.AppendLine("  callee 0x" + c.ToString("X") + mark);
    }
    sb.AppendLine("--- head ---");
    foreach (var line in r.Disasm.Take(35)) sb.AppendLine(line);
    return r;
  }

  static void WriteJson(string hash, List<FactoryHit> factories, List<ConsumerRep> consumers,
      Dictionary<uint, List<uint>> consumerFuncs, bool tight, bool keyPartial, bool keyTight) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.22\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    var tightHits = factories.Where(f => f.TightVerified).ToList();
    sb.AppendLine("  \"factory\": {");
    sb.AppendLine("    \"candidates\": " + factories.Count + ",");
    sb.AppendLine("    \"looseFullPattern\": " + T(factories.Any(f => f.FullPattern)) + ",");
    sb.AppendLine("    \"tightVerified\": " + T(tight) + ",");
    sb.AppendLine("    \"keyTiedPartial\": " + T(keyPartial) + ",");
    sb.AppendLine("    \"keyTiedTight\": " + T(keyTight) + ",");
    sb.AppendLine("    \"idiom\": \"Lookup/ti -> dword[ti+0x20] size -> Allocator(edx=size) -> icall[ti+0x50] ctor\",");
    sb.AppendLine("    \"tightHits\": [" + string.Join(", ",
      tightHits.Select(f => "\"0x" + f.Func.ToString("X") + "\"")) + "],");
    sb.AppendLine("    \"looseFullHits\": [" + string.Join(", ",
      factories.Where(f => f.FullPattern).Select(f => "\"0x" + f.Func.ToString("X") + "\"")) + "],");
    sb.AppendLine("    \"keyHits\": [" + string.Join(", ",
      factories.Where(f => f.UsesKey).Take(20).Select(f => "\"0x" + f.Func.ToString("X") + "\"")) + "]");
    sb.AppendLine("  },");
    sb.AppendLine("  \"helper546\": {");
    sb.AppendLine("    \"callerSites\": " + consumerFuncs.Values.Sum(v => v.Count) + ",");
    sb.AppendLine("    \"uniqueFuncs\": " + consumerFuncs.Count + ",");
    sb.AppendLine("    \"beyondNeighbor\": " + consumerFuncs.Count(kv => kv.Key != Neighbor) + ",");
    sb.AppendLine("    \"decoded\": " + consumers.Count + ",");
    sb.AppendLine("    \"roles\": {" + string.Join(", ",
      consumers.Where(c => !c.IsNeighbor).GroupBy(c => c.Role)
        .Select(g => J(g.Key) + ": " + g.Count())) + "}");
    sb.AppendLine("  },");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.22-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.22-summary.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.22\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"factories\": [");
    for (int i = 0; i < factories.Count; i++) {
      var f = factories[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"func\": \"0x" + f.Func.ToString("X") + "\",");
      sb.AppendLine("      \"fullPattern\": " + T(f.FullPattern) + ",");
      sb.AppendLine("      \"tightVerified\": " + T(f.TightVerified) + ",");
      sb.AppendLine("      \"usesKey\": " + T(f.UsesKey) + ",");
      sb.AppendLine("      \"xrefCount\": " + f.XrefCount + ",");
      sb.AppendLine("      \"lookupSite\": \"0x" + f.LookupSite.ToString("X") + "\",");
      sb.AppendLine("      \"sizeLoad\": \"0x" + f.SizeLoad.ToString("X") + "\",");
      sb.AppendLine("      \"allocSite\": \"0x" + f.AllocSite.ToString("X") + "\",");
      sb.AppendLine("      \"ctorLoad\": \"0x" + f.CtorLoad.ToString("X") + "\",");
      sb.AppendLine("      \"ctorCall\": \"0x" + f.CtorCall.ToString("X") + "\",");
      sb.AppendLine("      \"notes\": [" + string.Join(", ", f.Notes.Take(14).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < factories.Count ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"consumers\": [");
    for (int i = 0; i < consumers.Count; i++) {
      var r = consumers[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"entry\": \"0x" + r.Entry.ToString("X") + "\",");
      sb.AppendLine("      \"role\": " + J(r.Role) + ",");
      sb.AppendLine("      \"size\": " + r.Size + ",");
      sb.AppendLine("      \"isNeighbor\": " + T(r.IsNeighbor) + ",");
      sb.AppendLine("      \"touches98\": " + T(r.Touches98) + ",");
      sb.AppendLine("      \"vcall2B0\": " + T(r.Vcall2B0) + ",");
      sb.AppendLine("      \"callsAlloc\": " + T(r.CallsAlloc) + ",");
      sb.AppendLine("      \"notes\": [" + string.Join(", ", r.Notes.Select(J)) + "],");
      sb.AppendLine("      \"callees\": [" + string.Join(", ", r.Callees.Distinct().Take(16).Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"disasmHead\": [" + string.Join(", ", r.Disasm.Take(30).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < consumers.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.22-funcs-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.22-funcs-deep.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.22\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Tight TypeInfo factories construct typed heap objects from arbitrary TypeInfo; no Edward-specific create or possession path proven\" },");
    string fClass = tight ? "confirmed" : (keyPartial ? "partial" : "unsupported");
    string fReason = tight
      ? "Confirmed generic factory idiom Lookup/ti -> dword[ti+0x20] -> Allocator(edx=size) -> icall[ti+0x50]; not LookupKey-tied for 0xB2898C8"
      : (keyPartial
        ? "LookupKey-tied functions with partial size/alloc edges; full ctor chain not closed"
        : "No tight Lookup→[+0x20]→Alloc→[+0x50] pattern recovered");
    sb.AppendLine("  \"typeInfoFactory\": { \"class\": \"" + fClass + "\", \"reason\": " + J(fReason)
      + ", \"keyTiedTight\": " + T(keyTight) + " },");
    sb.AppendLine("  \"helper546Consumers\": { \"class\": \"confirmed\", \"reason\": "
      + J("Mapped " + consumerFuncs.Count + " caller funcs (" + consumerFuncs.Count(kv => kv.Key != Neighbor)
        + " beyond neighbor); roles classified offline") + " },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Find which tight-factory callers feed TypeInfo for key 0xB2898C8 / size 0x20F0; deep-decode possession-like helper consumers\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\", \"field-offset 0x20F0 as heap size\", \"treat loose fullPattern as proven\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.22-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.22-second-edward-feasibility.json");
  }

  // Disassemble without stopping on early Ret/Int3 (multi-exit factory bodies)
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
    while (dec.IP < limit && guard++ < 300000) {
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
    }
    return list;
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
    while (dec.IP < limit && guard++ < 300000) {
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
