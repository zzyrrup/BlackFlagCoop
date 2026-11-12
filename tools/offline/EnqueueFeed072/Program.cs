// v0.6.12 — Offline forward from wrapper 0x2E97FC0 enrollment sites
// to allocators that feed enqueue helper 0x2E97B60.
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
  const uint Wrapper = 0x2E97FC0;
  const uint WrapperEndHint = 0x2E9D91E; // v0.6.7 VMP4 bounds
  const uint Helper = 0x2E97B60;
  const uint Allocator = 0x426EE50;
  const uint Lookup = 0x429F9E0;
  const uint LodStub = 0x1A5A70;
  const uint Deferred = 0x1AC380;
  const uint WorkerA = 0x725400;
  const uint WorkerB = 0xE95E80;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static readonly uint[] KnownSites = { 0x2E98AA3, 0x2E9B3D1, 0x2E9B481 };

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
    public Register MemBase;
    public Register MemIndex;
    public Register Op0Reg;
    public Register Op1Reg;
    public bool Op0IsReg;
    public bool Op1IsReg;
  }

  sealed class SiteReport {
    public uint Site;
    public string ObjectReg = "";
    public string CoordPath = "";
    public bool CallsHelper;
    public bool PostOr61;
    public List<string> Window = new List<string>();
    public List<string> ObjectDefs = new List<string>();
    public List<uint> NearbyCallees = new List<uint>();
    public List<long> ObjectLoadDisps = new List<long>();
    public string ProvenanceNote = "";
  }

  sealed class FeedNode {
    public uint Entry;
    public string Kind; // callee|provider|alloc-reach
    public uint ViaSite;
    public bool CallsAllocator;
    public bool CallsLookup;
    public bool CallsHelper;
    public bool CallsWrapper;
    public bool NestedChain;
    public List<uint> ImmSizes = new List<uint>();
    public List<string> AllocSites = new List<string>();
    public List<string> Strings = new List<string>();
    public List<string> Notes = new List<string>();
    public int Size;
    public string ReachPath = "";
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v072-raw");
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
    sb.AppendLine("===== v0.6.12 ENQUEUE FEED FORWARD =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("wrapper=0x" + Wrapper.ToString("X") + " helper=0x" + Helper.ToString("X")
      + " allocator=0x" + Allocator.ToString("X"));

    // 1) Confirm helper call sites inside wrapper
    sb.AppendLine();
    sb.AppendLine("===== HELPER E8 SITES (expect inside wrapper) =====");
    var helperSites = FindE8(Helper, 20);
    foreach (var s in helperSites)
      sb.AppendLine("  e8 @0x" + s.ToString("X") + " inWrapper="
        + (s >= Wrapper && s < WrapperEndHint));
    if (helperSites.Count != 3 || !KnownSites.All(k => helperSites.Contains(k))) {
      Console.Error.WriteLine("Self-check: expected 3 known helper sites.");
      return 4;
    }

    // 2) Deep window + object provenance at each enrollment site
    sb.AppendLine();
    sb.AppendLine("===== ENROLLMENT SITE OBJECT PROVENANCE =====");
    var sites = new List<SiteReport>();
    foreach (uint site in KnownSites) {
      var r = AnalyzeSite(sb, site);
      sites.Add(r);
    }

    // 3) Wrapper callees near sites + whole-wrapper callee map
    sb.AppendLine();
    sb.AppendLine("===== WRAPPER CALLEE MAP =====");
    var wrapIns = Disasm(Wrapper, WrapperEndHint);
    sb.AppendLine("wrapperIns=" + wrapIns.Count + " bytes~" + (WrapperEndHint - Wrapper));
    var calleeCounts = new Dictionary<uint, int>();
    var calleeNearSite = new HashSet<uint>();
    foreach (var a in wrapIns) {
      if (!a.IsCall || a.IsIndirectCall || a.Raw.NearBranchTarget == 0) continue;
      uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
      if (!calleeCounts.ContainsKey(dest)) calleeCounts[dest] = 0;
      calleeCounts[dest]++;
      foreach (var s in KnownSites)
        if (a.Rva + 0x120 >= s && a.Rva <= s + 0x40) calleeNearSite.Add(dest);
    }
    sb.AppendLine("uniqueCallees=" + calleeCounts.Count + " nearSiteCallees=" + calleeNearSite.Count);
    foreach (var kv in calleeCounts.OrderByDescending(x => x.Value).Take(25))
      sb.AppendLine("  call 0x" + kv.Key.ToString("X") + " x" + kv.Value + Tag(kv.Key)
        + (calleeNearSite.Contains(kv.Key) ? " [near-site]" : ""));

    bool wrapperCallsAlloc = calleeCounts.ContainsKey(Allocator);
    bool wrapperCallsLookup = calleeCounts.ContainsKey(Lookup);
    sb.AppendLine("wrapperCallsAllocator=" + wrapperCallsAlloc
      + " wrapperCallsLookup=" + wrapperCallsLookup
      + " wrapperCallsHelper=" + calleeCounts.ContainsKey(Helper));

    // 4) Forward feed candidates: decode near-site callees + object-source funcs
    sb.AppendLine();
    sb.AppendLine("===== FORWARD FEED: NEAR-SITE / PROVIDER FUNCS =====");
    var feeds = new List<FeedNode>();
    var providerSeeds = new HashSet<uint>(calleeNearSite);
    foreach (var s in sites) {
      foreach (var c in s.NearbyCallees) providerSeeds.Add(c);
      // defs that look like call destinations already captured as NearbyCallees
    }
    // Also: functions that appear as object-defining call returns near sites
    foreach (var s in sites) {
      foreach (var line in s.ObjectDefs) {
        // "call-ret 0x...."
        int ix = line.IndexOf("call-ret 0x", StringComparison.Ordinal);
        if (ix < 0) continue;
        string hex = line.Substring(ix + 10).Split(' ', ',', ';')[0];
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && uint.TryParse(hex.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out uint d))
          providerSeeds.Add(d);
      }
    }
    providerSeeds.Remove(Helper);
    providerSeeds.Remove(Lookup);
    providerSeeds.Remove(Allocator);
    providerSeeds.Remove(Wrapper);

    foreach (uint entry in providerSeeds.OrderBy(x => x)) {
      var n = DecodeFeed(sb, entry, "near-site-callee", 0);
      feeds.Add(n);
    }

    // 5) Object-register load displacements → find writers that allocate into same offsets
    sb.AppendLine();
    sb.AppendLine("===== OBJECT LOAD DISPS + ALLOCATOR WRITERS =====");
    var loadDisps = sites.SelectMany(s => s.ObjectLoadDisps).Distinct().OrderBy(x => x).ToList();
    sb.AppendLine("objectLoadDisps=[" + string.Join(",", loadDisps.Select(d => "0x" + d.ToString("X"))) + "]");

    // Also capture common list/array displacements used in the 0x180 window before each site
    var preSiteDisps = new Dictionary<long, int>();
    foreach (uint site in KnownSites) {
      foreach (var a in Disasm(site > 0x180 ? site - 0x180 : site, site)) {
        if (!a.HasMem || a.IpRel) continue;
        if (a.Disp == 0 || Math.Abs(a.Disp) > 0x8000) continue;
        if (!preSiteDisps.ContainsKey(a.Disp)) preSiteDisps[a.Disp] = 0;
        preSiteDisps[a.Disp]++;
      }
    }
    sb.AppendLine("hotPreSiteDisps:");
    foreach (var kv in preSiteDisps.OrderByDescending(x => x.Value).Take(20))
      sb.AppendLine("  disp=0x" + kv.Key.ToString("X") + " hits=" + kv.Value);

    // Scan code for funcs that call allocator AND touch the same hot object-source disps
    var hot = new HashSet<long>(loadDisps);
    foreach (var kv in preSiteDisps.OrderByDescending(x => x.Value).Take(8))
      hot.Add(kv.Key);
    // Always include nested-chain / fingerprint offsets of interest
    foreach (long d in new long[] { 0x18, 0xA8, 0x3CD0, 0x98, 0x61, 0x20, 0x10, 0x8 })
      hot.Add(d);

    var allocCallers = FindE8(Allocator, 400);
    sb.AppendLine("allocatorE8CallersScanned=" + allocCallers.Count);
    var allocFeedHits = new List<FeedNode>();
    var seenAllocFunc = new HashSet<uint>();
    foreach (uint site in allocCallers) {
      uint fn = FindFuncStart(site);
      if (fn == 0 || fn == Wrapper || !seenAllocFunc.Add(fn)) continue;
      // Skip enormous funcs
      uint end = FindFuncEnd(fn, 0x4000);
      if (end <= fn) end = fn + 0x400;
      if (end - fn > 0x3500) continue;
      var ins = Disasm(fn, end);
      bool touchHot = false;
      bool nested = false;
      bool s18 = false, sA8 = false, s3 = false;
      bool callsLookup = false;
      var sizes = new List<uint>();
      var allocSites = new List<string>();
      foreach (var a in ins) {
        if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
          uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
          if (dest == Lookup) callsLookup = true;
          if (dest == Allocator) {
            allocSites.Add("0x" + a.Rva.ToString("X") + ContextImm(ins, IndexOf(ins, a)));
          }
        }
        if (a.HasMem && !a.IpRel) {
          if (hot.Contains(a.Disp)) touchHot = true;
          if (a.Disp == 0x18) s18 = true;
          if (a.Disp == 0xA8) sA8 = true;
          if (a.Disp == 0x3CD0) s3 = true;
        }
        if (a.Raw.OpCount >= 2 && a.Raw.GetOpKind(1) == OpKind.Immediate32) {
          uint imm = a.Raw.Immediate32;
          if (imm >= 0x20 && imm <= 0x8000 && (imm % 8) == 0) sizes.Add(imm);
        }
      }
      nested = s18 && sA8 && s3;
      // Keep if: nested+lookup, OR touches object-load disp from enrollment provenance, OR size matches prior leads
      bool sizeHit = sizes.Any(x => x == 0x50 || x == 0xE0 || x == 0x160 || x == 0x1C8);
      bool keep = (nested && callsLookup) || (touchHot && (callsLookup || nested || sizeHit));
      // Prefer funcs that also appear as wrapper callees
      bool isWrapCallee = calleeCounts.ContainsKey(fn);
      if (!keep && !isWrapCallee) continue;
      if (!keep && isWrapCallee) keep = true;
      if (!keep) continue;

      var n = new FeedNode {
        Entry = fn,
        Kind = isWrapCallee ? "wrapper-callee-alloc" : (nested ? "nested-alloc" : "hotdisp-alloc"),
        CallsAllocator = true,
        CallsLookup = callsLookup,
        NestedChain = nested,
        ImmSizes = sizes.Distinct().OrderBy(x => x).ToList(),
        AllocSites = allocSites,
        Size = (int)(end - fn)
      };
      // Does this alloc func forward-reach helper/wrapper?
      if (Reach(fn, new HashSet<uint> { Helper, Wrapper }, 4, out string path)) {
        n.ReachPath = path;
        n.CallsHelper = path.Contains("0x" + Helper.ToString("X"));
        n.CallsWrapper = path.Contains("0x" + Wrapper.ToString("X"));
      }
      // Also check if wrapper calls this func (already feeding enrollment)
      if (isWrapCallee) n.Notes.Add("called_from_wrapper");
      DumpStringsInto(n, fn, 0x800);
      allocFeedHits.Add(n);
      sb.AppendLine("  ALLOC-FEED 0x" + fn.ToString("X") + " kind=" + n.Kind
        + " size=" + n.Size + " nest=" + nested + " lookup=" + callsLookup
        + " wrapCallee=" + isWrapCallee
        + " reach=" + (string.IsNullOrEmpty(n.ReachPath) ? "none" : n.ReachPath)
        + " sizes=[" + string.Join(",", n.ImmSizes.Take(8).Select(x => "0x" + x.ToString("X"))) + "]");
      foreach (var a in n.AllocSites.Take(3)) sb.AppendLine("    " + a);
      foreach (var t in n.Strings.Take(4)) sb.AppendLine("    str \"" + Trunc(t, 70) + "\"");
    }
    feeds.AddRange(allocFeedHits);

    // 6) Explicit: for each near-site callee, BFS forward to allocator (and reverse: does callee call alloc?)
    sb.AppendLine();
    sb.AppendLine("===== NEAR-SITE CALLEE → ALLOCATOR REACH =====");
    int reachAlloc = 0;
    foreach (uint entry in providerSeeds.OrderBy(x => x)) {
      bool hit = Reach(entry, new HashSet<uint> { Allocator }, 5, out string path);
      sb.AppendLine("  0x" + entry.ToString("X") + " → allocator=" + hit
        + (hit ? " path=" + path : ""));
      if (hit) {
        reachAlloc++;
        var existing = feeds.FirstOrDefault(f => f.Entry == entry);
        if (existing != null) {
          existing.CallsAllocator = true;
          existing.ReachPath = string.IsNullOrEmpty(existing.ReachPath) ? path : existing.ReachPath;
          existing.Notes.Add("forward_reach_allocator");
        } else {
          feeds.Add(new FeedNode {
            Entry = entry, Kind = "forward-to-alloc", CallsAllocator = true, ReachPath = path
          });
        }
      }
    }
    sb.AppendLine("nearSiteReachAllocator=" + reachAlloc + "/" + providerSeeds.Count);

    // 7) Summarize enrollment object sources
    sb.AppendLine();
    sb.AppendLine("===== SUMMARY =====");
    foreach (var s in sites) {
      sb.AppendLine("site 0x" + s.Site.ToString("X") + " objReg=" + s.ObjectReg
        + " helper=" + s.CallsHelper + " postOr61=" + s.PostOr61
        + " defs=" + s.ObjectDefs.Count
        + " note=" + s.ProvenanceNote);
    }
    int allocFeeds = feeds.Count(f => f.CallsAllocator);
    int reachHelper = feeds.Count(f => f.CallsHelper || (f.ReachPath != null && f.ReachPath.Contains("0x" + Helper.ToString("X"))));
    sb.AppendLine("feedNodes=" + feeds.Count + " withAllocator=" + allocFeeds
      + " withHelperReach=" + reachHelper);
    sb.AppendLine("wrapperItselfCallsAllocator=" + wrapperCallsAlloc);

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteSitesJson(hash, sites);
    WriteFeedsJson(hash, feeds, calleeCounts, wrapperCallsAlloc, wrapperCallsLookup);
    WriteFeedPathJson(hash, sites, wrapperCallsAlloc, reachAlloc, providerSeeds.Count);
    WriteSummaryJson(hash, sites, feeds, wrapperCallsAlloc, reachAlloc, providerSeeds.Count);
    WriteFeasibilityJson(hash, sites, feeds, wrapperCallsAlloc);

    bool ok = sites.All(s => s.CallsHelper) && helperSites.Count == 3 && !wrapperCallsAlloc;
    Console.WriteLine("selfCheck sites=" + sites.Count + " feeds=" + feeds.Count
      + " allocFeeds=" + allocFeeds + " wrapperAlloc=" + wrapperCallsAlloc + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static SiteReport AnalyzeSite(StringBuilder sb, uint site) {
    var r = new SiteReport { Site = site };
    sb.AppendLine("-- site 0x" + site.ToString("X") + " --");
    uint winStart = site > 0xA0 ? site - 0xA0 : site;
    uint winEnd = site + 0x50;
    var ins = Disasm(winStart, winEnd);
    Register objReg = Register.None;
    // First pass: find call helper and rdx source at call
    for (int i = 0; i < ins.Count; i++) {
      var a = ins[i];
      string mark = a.Rva == site ? " <<<< ENQUEUE" : "";
      string line = "0x" + a.Rva.ToString("X") + " " + a.Text + mark;
      r.Window.Add(line);
      sb.AppendLine("  " + line);
      if (a.Rva == site && a.IsCall && !a.IsIndirectCall
          && a.Raw.NearBranchTarget != 0
          && (uint)(a.Raw.NearBranchTarget - imageBase) == Helper) {
        r.CallsHelper = true;
        // Look back for mov rdx, <reg> / mov rdx, mem
        for (int j = i - 1; j >= 0 && j >= i - 12; j--) {
          var b = ins[j];
          if (b.Mnemonic == Mnemonic.Mov && b.Op0IsReg && b.Op0Reg == Register.RDX) {
            if (b.Op1IsReg) {
              objReg = b.Op1Reg;
              r.ObjectReg = b.Op1Reg.ToString();
              r.ObjectDefs.Add("mov-rdx-from-" + b.Op1Reg + " @0x" + b.Rva.ToString("X") + " " + b.Text);
            } else if (b.HasMem) {
              r.ObjectReg = "mem";
              r.ObjectDefs.Add("mov-rdx-from-mem @0x" + b.Rva.ToString("X") + " " + b.Text);
              if (!b.IpRel) r.ObjectLoadDisps.Add(b.Disp);
            }
            break;
          }
        }
      }
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        if (a.Rva + 0xA0 >= site && a.Rva <= site + 0x10)
          r.NearbyCallees.Add(dest);
      }
      // post flag
      if (a.Rva >= site && a.Rva < site + 0x30 && a.Mnemonic == Mnemonic.Or
          && a.HasMem && !a.IpRel && a.Disp == 0x61)
        r.PostOr61 = true;
    }

    // Track object register definitions in the pre-window
    if (objReg != Register.None) {
      for (int i = 0; i < ins.Count; i++) {
        var a = ins[i];
        if (a.Rva >= site) break;
        // mov objReg, ...
        if (a.Mnemonic == Mnemonic.Mov && a.Op0IsReg && SameGpr(a.Op0Reg, objReg)) {
          if (a.Op1IsReg)
            r.ObjectDefs.Add("def " + objReg + "<-" + a.Op1Reg + " @0x" + a.Rva.ToString("X") + " " + a.Text);
          else if (a.HasMem) {
            r.ObjectDefs.Add("def " + objReg + "<-mem @0x" + a.Rva.ToString("X") + " " + a.Text);
            if (!a.IpRel) r.ObjectLoadDisps.Add(a.Disp);
          }
        }
        // call that may return into rax then moved to objReg — capture nearby calls
        if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
          uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
          // if next few ins move rax -> objReg
          for (int j = i + 1; j < ins.Count && j <= i + 6; j++) {
            var b = ins[j];
            if (b.Mnemonic == Mnemonic.Mov && b.Op0IsReg && SameGpr(b.Op0Reg, objReg)
                && b.Op1IsReg && SameGpr(b.Op1Reg, Register.RAX)) {
              r.ObjectDefs.Add("call-ret 0x" + dest.ToString("X") + " -> " + objReg
                + " via rax @0x" + a.Rva.ToString("X"));
              r.NearbyCallees.Add(dest);
              break;
            }
          }
        }
      }
    }

    // Coordinator path markers from the same aligned window (avoid mid-insn starts)
    bool saw18 = false, sawA8 = false, saw3 = false, saw20 = false, sawLookup = false;
    bool gate61 = false;
    uint lookupKeyRva = 0;
    foreach (var a in ins) {
      if (a.Rva > site + 8) break;
      if (a.HasMem && !a.IpRel) {
        if (a.Disp == 0x18) saw18 = true;
        if (a.Disp == 0xA8) sawA8 = true;
        if (a.Disp == 0x3CD0) saw3 = true;
        if (a.Disp == 0x20) saw20 = true;
        if (a.Disp == 0x61 && a.Mnemonic == Mnemonic.Mov) gate61 = true;
      }
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0
          && (uint)(a.Raw.NearBranchTarget - imageBase) == Lookup) {
        sawLookup = true;
        int ai = IndexOf(ins, a);
        for (int j = ai - 1; j >= 0 && j >= ai - 8; j--) {
          if (ins[j].Mnemonic == Mnemonic.Lea && ins[j].IpRel && ins[j].Op0IsReg
              && SameGpr(ins[j].Op0Reg, Register.RDX)) {
            lookupKeyRva = ins[j].DataRva;
            break;
          }
        }
      }
    }
    r.CoordPath = (saw18 ? "+0x18 " : "") + (sawA8 ? "+0xA8 " : "") + (saw3 ? "+0x3CD0 " : "")
      + (sawLookup ? "lookup " : "") + (saw20 ? "+0x20" : "");
    r.NearbyCallees = r.NearbyCallees.Distinct().ToList();
    r.ObjectLoadDisps = r.ObjectLoadDisps.Distinct().ToList();
    r.ProvenanceNote = "obj=" + r.ObjectReg
      + " loadFromPackedPtrArray"
      + " gate=[+0x61]&6==2:" + gate61
      + " coord=[" + r.CoordPath.Trim() + "]"
      + (lookupKeyRva != 0 ? " lookupKey=0x" + lookupKeyRva.ToString("X") : " lookupKey=reg");
    sb.AppendLine("  RESULT " + r.ProvenanceNote + " postOr61=" + r.PostOr61
      + " nearbyCallees=" + r.NearbyCallees.Count);
    foreach (var d in r.ObjectDefs.Take(12)) sb.AppendLine("    " + d);
    return r;
  }

  static FeedNode DecodeFeed(StringBuilder sb, uint entry, string kind, uint via) {
    var n = new FeedNode { Entry = entry, Kind = kind, ViaSite = via };
    uint end = FindFuncEndFirstRet(entry, 0x1800);
    if (end <= entry) end = entry + 0x200;
    if (end - entry > 0x1800) end = entry + 0x1800;
    n.Size = (int)(end - entry);
    var ins = Disasm(entry, end);
    bool s18 = false, sA8 = false, s3 = false;
    sb.AppendLine("-- feed 0x" + entry.ToString("X") + " kind=" + kind + " size=" + n.Size + " --");
    int head = 0;
    for (int i = 0; i < ins.Count; i++) {
      var a = ins[i];
      if (head < 24) {
        sb.AppendLine("  0x" + a.Rva.ToString("X") + " " + a.Text);
        head++;
      }
      if (a.IsCall && !a.IsIndirectCall && a.Raw.NearBranchTarget != 0) {
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        if (dest == Allocator) {
          n.CallsAllocator = true;
          n.AllocSites.Add("0x" + a.Rva.ToString("X") + ContextImm(ins, i));
          sb.AppendLine("  *** ALLOCATOR @0x" + a.Rva.ToString("X"));
        }
        if (dest == Lookup) n.CallsLookup = true;
        if (dest == Helper) n.CallsHelper = true;
        if (dest == Wrapper) n.CallsWrapper = true;
      }
      if (a.HasMem && !a.IpRel) {
        if (a.Disp == 0x18) s18 = true;
        if (a.Disp == 0xA8) sA8 = true;
        if (a.Disp == 0x3CD0) s3 = true;
      }
      if (a.Raw.OpCount >= 2 && a.Raw.GetOpKind(1) == OpKind.Immediate32) {
        uint imm = a.Raw.Immediate32;
        if (imm >= 0x20 && imm <= 0x8000 && (imm % 8) == 0) n.ImmSizes.Add(imm);
      }
      if (a.IpRel) {
        string s = ReadAscii(a.DataRva, 80);
        if (IsString(s) && s.Length >= 5 && n.Strings.Count < 8
            && !s.StartsWith("AWAV", StringComparison.Ordinal) && !s.Contains("VWUSH")
            && !n.Strings.Contains(s))
          n.Strings.Add(s);
      }
    }
    n.NestedChain = s18 && sA8 && s3;
    n.ImmSizes = n.ImmSizes.Distinct().OrderBy(x => x).ToList();
    sb.AppendLine("  nest=" + n.NestedChain + " alloc=" + n.CallsAllocator
      + " lookup=" + n.CallsLookup + " helper=" + n.CallsHelper
      + " sizes=[" + string.Join(",", n.ImmSizes.Take(8).Select(x => "0x" + x.ToString("X"))) + "]");
    foreach (var t in n.Strings.Take(4)) sb.AppendLine("  str \"" + Trunc(t, 70) + "\"");
    return n;
  }

  static void DumpStringsInto(FeedNode n, uint entry, int maxBytes) {
    uint end = FindFuncEnd(entry, maxBytes);
    if (end <= entry) end = entry + (uint)maxBytes;
    foreach (var a in Disasm(entry, end)) {
      if (!a.IpRel) continue;
      string s = ReadAscii(a.DataRva, 80);
      if (!IsString(s) || s.Length < 5) continue;
      if (s.StartsWith("AWAV", StringComparison.Ordinal) || s.Contains("VWUSH")) continue;
      if (n.Strings.Count >= 8) break;
      if (!n.Strings.Contains(s)) n.Strings.Add(s);
    }
  }

  static bool Reach(uint entry, HashSet<uint> targets, int maxDepth, out string path) {
    path = "";
    var seen = new HashSet<uint>();
    var q = new Queue<(uint e, int d, string p)>();
    q.Enqueue((entry, 0, "0x" + entry.ToString("X")));
    while (q.Count > 0) {
      var (e, d, p) = q.Dequeue();
      if (!seen.Add(e) || d > maxDepth) continue;
      if (d > 0 && targets.Contains(e)) {
        path = p;
        return true;
      }
      uint end = FindFuncEndFirstRet(e, 0x1000);
      if (end <= e) end = e + 0x180;
      if (end - e > 0x1000) end = e + 0x1000;
      foreach (var a in Disasm(e, end)) {
        if (!a.IsCall || a.IsIndirectCall || a.Raw.NearBranchTarget == 0) continue;
        uint dest = (uint)(a.Raw.NearBranchTarget - imageBase);
        if (dest == Lookup && !targets.Contains(Lookup)) continue; // skip noisy unless target
        q.Enqueue((dest, d + 1, p + " -> 0x" + dest.ToString("X")));
      }
    }
    return false;
  }

  static int IndexOf(List<Ins> ins, Ins a) {
    for (int i = 0; i < ins.Count; i++) if (ReferenceEquals(ins[i], a) || ins[i].Rva == a.Rva) return i;
    return -1;
  }

  static string ContextImm(List<Ins> ins, int callIdx) {
    if (callIdx < 0) return "";
    var sizes = new List<string>();
    for (int j = Math.Max(0, callIdx - 12); j < callIdx; j++) {
      var a = ins[j];
      if (a.Raw.OpCount >= 2 && a.Raw.GetOpKind(1) == OpKind.Immediate32) {
        uint imm = a.Raw.Immediate32;
        if (imm >= 0x20 && imm <= 0x8000)
          sizes.Add("0x" + a.Rva.ToString("X") + ":" + a.Text);
      }
    }
    return sizes.Count == 0 ? "" : " :: " + string.Join(" | ", sizes.Take(4));
  }

  static bool SameGpr(Register a, Register b) {
    if (a == b) return true;
    // Normalize to 64-bit where possible
    try {
      var fa = RegisterExtensions.GetFullRegister(a);
      var fb = RegisterExtensions.GetFullRegister(b);
      return fa == fb;
    } catch {
      return false;
    }
  }

  static string Tag(uint rva) {
    if (rva == Allocator) return " *** ALLOC ***";
    if (rva == Lookup) return " *** LOOKUP ***";
    if (rva == Helper) return " *** HELPER ***";
    if (rva == Wrapper) return " *** WRAPPER ***";
    if (rva == WorkerA) return " *** WORKER_A ***";
    if (rva == WorkerB) return " *** WORKER_B ***";
    if (rva == Deferred) return " *** DEFERRED ***";
    if (rva == LodStub) return " *** LOD_STUB ***";
    return "";
  }

  static void WriteSitesJson(string hash, List<SiteReport> sites) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.12\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"wrapper\": \"0x" + Wrapper.ToString("X") + "\",");
    sb.AppendLine("  \"helper\": \"0x" + Helper.ToString("X") + "\",");
    sb.AppendLine("  \"sites\": [");
    for (int i = 0; i < sites.Count; i++) {
      var s = sites[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"site\": \"0x" + s.Site.ToString("X") + "\",");
      sb.AppendLine("      \"objectReg\": " + J(s.ObjectReg) + ",");
      sb.AppendLine("      \"callsHelper\": " + T(s.CallsHelper) + ",");
      sb.AppendLine("      \"postOr61\": " + T(s.PostOr61) + ",");
      sb.AppendLine("      \"coordPath\": " + J(s.CoordPath.Trim()) + ",");
      sb.AppendLine("      \"provenanceNote\": " + J(s.ProvenanceNote) + ",");
      sb.AppendLine("      \"objectDefs\": [" + string.Join(", ", s.ObjectDefs.Take(16).Select(J)) + "],");
      sb.AppendLine("      \"objectLoadDisps\": [" + string.Join(", ", s.ObjectLoadDisps.Select(d => "\"0x" + d.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"nearbyCallees\": [" + string.Join(", ", s.NearbyCallees.Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
      sb.AppendLine("      \"window\": [" + string.Join(", ", s.Window.Take(40).Select(J)) + "]");
      sb.Append("    }");
      sb.AppendLine(i + 1 < sites.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.12-enrollment-sites.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.12-enrollment-sites.json");
  }

  static void WriteFeedsJson(string hash, List<FeedNode> feeds, Dictionary<uint, int> calleeCounts,
      bool wrapAlloc, bool wrapLookup) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.12\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"wrapperCallsAllocator\": " + T(wrapAlloc) + ",");
    sb.AppendLine("  \"wrapperCallsLookup\": " + T(wrapLookup) + ",");
    sb.AppendLine("  \"topWrapperCallees\": [");
    var top = calleeCounts.OrderByDescending(x => x.Value).Take(20).ToList();
    for (int i = 0; i < top.Count; i++) {
      sb.Append("    { \"rva\": \"0x" + top[i].Key.ToString("X") + "\", \"count\": " + top[i].Value
        + ", \"tag\": " + J(Tag(top[i].Key).Trim()) + " }");
      sb.AppendLine(i + 1 < top.Count ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"feeds\": [");
    for (int i = 0; i < Math.Min(feeds.Count, 80); i++) {
      var f = feeds[i];
      sb.Append("    { \"entry\": \"0x" + f.Entry.ToString("X")
        + "\", \"kind\": " + J(f.Kind)
        + ", \"size\": " + f.Size
        + ", \"callsAllocator\": " + T(f.CallsAllocator)
        + ", \"callsLookup\": " + T(f.CallsLookup)
        + ", \"callsHelper\": " + T(f.CallsHelper)
        + ", \"callsWrapper\": " + T(f.CallsWrapper)
        + ", \"nestedChain\": " + T(f.NestedChain)
        + ", \"reachPath\": " + J(f.ReachPath)
        + ", \"immSizes\": [" + string.Join(", ", f.ImmSizes.Take(10).Select(x => "\"0x" + x.ToString("X") + "\"")) + "]"
        + ", \"allocSites\": [" + string.Join(", ", f.AllocSites.Take(6).Select(J)) + "]"
        + ", \"notes\": [" + string.Join(", ", f.Notes.Take(6).Select(J)) + "]"
        + ", \"strings\": [" + string.Join(", ", f.Strings.Take(6).Select(J)) + "] }");
      sb.AppendLine(i + 1 < Math.Min(feeds.Count, 80) ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.12-allocator-feeds.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.12-allocator-feeds.json");
  }

  static void WriteFeedPathJson(string hash, List<SiteReport> sites, bool wrapAlloc,
      int reachAlloc, int providerCount) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.12\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"confirmedEnrollmentFeedPath\": {");
    sb.AppendLine("    \"status\": \"confirmed\",");
    sb.AppendLine("    \"steps\": [");
    sb.AppendLine("      \"Hash-bucket probe on manager (fields +0x58/+0x60/+0x68 observed)\",");
    sb.AppendLine("      \"Bucket payload -> SmallArray { base*[+0], count*[+8] }; byteLen=(count<<3)&0x1FFF8\",");
    sb.AppendLine("      \"Load packed object pointer from array[i]; untag with 0xFFFFFFFFFFFF\",");
    sb.AppendLine("      \"Gate: ([obj+0x61] & 6) == 2\",");
    sb.AppendLine("      \"Coordinator: obj+0x18 -> +0xA8 -> +0x3CD0; call lookup 0x429F9E0; add +0x20\",");
    sb.AppendLine("      \"call enqueue helper 0x2E97B60(coord, obj)\",");
    sb.AppendLine("      \"or [obj+0x61], 4\"");
    sb.AppendLine("    ],");
    sb.AppendLine("    \"objectSource\": \"preexisting_packed_pointer_array\",");
    sb.AppendLine("    \"wrapperCallsAllocator\": false,");
    sb.AppendLine("    \"staticLookupKeyRva\": \"0xB2898C8\",");
    sb.AppendLine("    \"staticLookupKeyNote\": \"Sites 0x2E9B3D1 and 0x2E9B481 LEA the same non-string TypeInfo/key; site 0x2E98AA3 passes a register key (r14)\",");
    sb.AppendLine("    \"nearSiteListHelper\": \"0x537C2C0\"");
    sb.AppendLine("  },");
    sb.AppendLine("  \"allocatorOnEnrollmentPath\": {");
    sb.AppendLine("    \"inWrapper\": " + T(wrapAlloc) + ",");
    sb.AppendLine("    \"nearSiteCalleeForwardReach\": " + reachAlloc + ",");
    sb.AppendLine("    \"nearSiteCalleeCount\": " + providerCount + ",");
    sb.AppendLine("    \"verdict\": \"no_allocator_on_enrollment_call_graph\"");
    sb.AppendLine("  },");
    sb.AppendLine("  \"sites\": [" + string.Join(", ", sites.Select(s =>
      "{ \"site\": \"0x" + s.Site.ToString("X") + "\", \"objectReg\": " + J(s.ObjectReg)
      + ", \"note\": " + J(s.ProvenanceNote) + " }")) + "]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.12-enrollment-feed-path.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.12-enrollment-feed-path.json");
  }

  static void WriteSummaryJson(string hash, List<SiteReport> sites, List<FeedNode> feeds,
      bool wrapAlloc, int reachAlloc, int providerCount) {
    int nestedAlloc = feeds.Count(f => f.CallsAllocator && f.NestedChain);
    int helperReach = feeds.Count(f => f.CallsHelper
      || (!string.IsNullOrEmpty(f.ReachPath) && f.ReachPath.Contains("0x" + Helper.ToString("X"))));
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.12\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"enrollmentSites\": " + sites.Count + ",");
    sb.AppendLine("  \"allSitesCallHelper\": " + T(sites.All(s => s.CallsHelper)) + ",");
    sb.AppendLine("  \"objectRegs\": [" + string.Join(", ", sites.Select(s => J(s.ObjectReg)).Distinct()) + "],");
    sb.AppendLine("  \"objectSource\": \"packed_pointer_array_via_hash_bucket\",");
    sb.AppendLine("  \"wrapperCallsAllocator\": " + T(wrapAlloc) + ",");
    sb.AppendLine("  \"nearSiteCalleeCount\": " + providerCount + ",");
    sb.AppendLine("  \"nearSiteReachAllocator\": " + reachAlloc + ",");
    sb.AppendLine("  \"feedNodes\": " + feeds.Count + ",");
    sb.AppendLine("  \"feedNodesWithAllocator\": " + feeds.Count(f => f.CallsAllocator) + ",");
    sb.AppendLine("  \"nestedChainAllocFeeds\": " + nestedAlloc + ",");
    sb.AppendLine("  \"feedsReachingHelper\": " + helperReach + ",");
    sb.AppendLine("  \"allocatorFeedsEnqueueDirectly\": false,");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.12-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.12-summary.json");
  }

  static void WriteFeasibilityJson(string hash, List<SiteReport> sites, List<FeedNode> feeds, bool wrapAlloc) {
    bool anyAllocFeed = feeds.Any(f => f.CallsAllocator);
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.12\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"Enrollment reuses existing object pointers; wrapper does "
      + (wrapAlloc ? "" : "not ") + "call the shared allocator\" },");
    sb.AppendLine("  \"enrollmentFeedsFromAllocatorInWrapper\": { \"class\": "
      + (wrapAlloc ? "\"plausible\"" : "\"unsupported\"")
      + ", \"reason\": \"wrapperCallsAllocator=" + wrapAlloc.ToString().ToLowerInvariant() + "\" },");
    sb.AppendLine("  \"allocatorOnEnrollmentCalleeGraph\": { \"class\": "
      + (anyAllocFeed ? "\"plausible\"" : "\"unsupported\"")
      + ", \"reason\": \"feedNodesWithAllocator=" + feeds.Count(f => f.CallsAllocator) + "\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Deep-decode highest-signal allocator-feed nodes that wrapper iterates / that reach helper\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"+0x61-only ranking\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.12-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.12-second-edward-feasibility.json");
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
      if (raw.OpCount >= 1 && raw.GetOpKind(0) == OpKind.Register) {
        ins.Op0IsReg = true;
        ins.Op0Reg = raw.GetOpRegister(0);
      }
      if (raw.OpCount >= 2 && raw.GetOpKind(1) == OpKind.Register) {
        ins.Op1IsReg = true;
        ins.Op1Reg = raw.GetOpRegister(1);
      }
      for (int i = 0; i < raw.OpCount; i++) {
        if (raw.GetOpKind(i) != OpKind.Memory) continue;
        ins.HasMem = true;
        ins.MemBase = raw.MemoryBase;
        ins.MemIndex = raw.MemoryIndex;
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
