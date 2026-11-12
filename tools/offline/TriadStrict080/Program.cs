// v0.8.0 — Strict C2 triad filter after TriadHunt080 false sandwiches.
// Require last-def arg values, freestanding End, and Begin leaves that
// write TLS (gs:) and/or RIP-rel globals. Offline PE only.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;

internal static class Program {
  const string Expected = "19920F34BB2FAC814023EE3C27F0CECA1872E80A2AAFB37C092C419FFF77CC0D";
  static byte[] pe; static ulong ib; static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(new FormatterOptions { RipRelativeAddresses = true }, null, null);
  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }

  sealed class Site {
    public uint BeginCall, BeginCallee, DupCall, DupCallee, EndCall, EndCallee, BuildCall, BuildCallee, Func;
    public string BeginKind; public int BeginSize; public bool BeginTls, BeginRipStore, BeginRetAl;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha(pe);
    if (!hash.Equals(Expected, StringComparison.OrdinalIgnoreCase)) { Console.Error.WriteLine("hash mismatch"); return 2; }
    Parse();
    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 C2 TRIAD STRICT (last-def + BeginTLS) =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("callEngine=off");

    Console.WriteLine("Pass A: strict Begin(1,0) last-def...");
    var begins = FindStrictBegin10(max: 4000);
    sb.AppendLine("strictBegin10=" + begins.Count);

    Console.WriteLine("Classifying Begin callees (TLS / RIP-store / size)...");
    var beginProf = new Dictionary<uint, string>();
    foreach (var b in begins.Select(x => x.callee).Distinct()) {
      var p = ProfileLeaf(b);
      beginProf[b] = "size=" + p.size + " tls=" + p.tls + " ripStore=" + p.ripStore + " retAl=" + p.retAl
        + " ripTargets=" + string.Join("|", p.rips.Take(4).Select(x => "0x" + x.ToString("X")));
    }
    var arming = begins.Where(b => {
      var p = ProfileLeaf(b.callee);
      return p.tls || p.ripStore;
    }).ToList();
    sb.AppendLine("beginArmingTlsOrRip=" + arming.Count);
    sb.AppendLine("uniqueBeginCallees=" + begins.Select(x => x.callee).Distinct().Count());
    sb.AppendLine();
    sb.AppendLine("===== BEGIN CALLEE PROFILES (arming first) =====");
    foreach (var kv in beginProf.OrderByDescending(k => k.Value.Contains("tls=True") || k.Value.Contains("ripStore=True"))
             .ThenBy(k => k.Key).Take(40)) {
      int n = begins.Count(b => b.callee == kv.Key);
      sb.AppendLine("beginCallee=0x" + kv.Key.ToString("X") + " n=" + n + " " + kv.Value);
    }

    Console.WriteLine("Pass B: expand sandwiches with last-def Dup(0,0) + freestanding End...");
    var sandwiches = new List<Site>();
    foreach (var b in begins) {
      var s = ExpandStrict(b.site, b.callee);
      if (s != null) sandwiches.Add(s);
    }
    var full = sandwiches.Where(s => s.DupCall != 0 && s.EndCall != 0 && s.BuildCall != 0).ToList();
    var almost = sandwiches.Where(s => s.DupCall != 0 && s.EndCall != 0).ToList();
    var armSand = sandwiches.Where(s => s.BeginTls || s.BeginRipStore).ToList();
    sb.AppendLine();
    sb.AppendLine("strictSandwich=" + sandwiches.Count);
    sb.AppendLine("strictBeginDupEnd=" + almost.Count);
    sb.AppendLine("strictFullTriad=" + full.Count);
    sb.AppendLine("armingSandwich=" + armSand.Count);

    sb.AppendLine();
    sb.AppendLine("===== STRICT FULL TRIAD =====");
    foreach (var s in full.Take(20)) { sb.AppendLine(Format(s)); Dump(sb, s.BeginCall, 0x18, 0xA0, "full"); }

    sb.AppendLine();
    sb.AppendLine("===== STRICT BEGIN+DUP+END =====");
    foreach (var s in almost.Take(24)) { sb.AppendLine(Format(s)); Dump(sb, s.BeginCall, 0x10, 0x70, "bde"); }

    sb.AppendLine();
    sb.AppendLine("===== ARMING BEGIN SANDWICHES =====");
    foreach (var s in armSand.Take(24)) {
      sb.AppendLine(Format(s) + " beginKind=" + s.BeginKind + " size=" + s.BeginSize);
      Dump(sb, s.BeginCallee, 0, Math.Min(0x80, s.BeginSize + 8), "beginLeaf");
    }

    Console.WriteLine("Pass C: invert from strict Dup(0,0) last-def → nearby Begin/End/Build...");
    var inverted = InvertFromDup(max: 3000);
    sb.AppendLine();
    sb.AppendLine("===== INVERT FROM STRICT DUP(0,0) =====");
    sb.AppendLine("strictDup00=" + inverted.dupCount);
    sb.AppendLine("dupWithBuild=" + inverted.withBuild);
    sb.AppendLine("dupWithBegin=" + inverted.withBegin);
    sb.AppendLine("dupWithEnd=" + inverted.withEnd);
    sb.AppendLine("dupFullShape=" + inverted.full.Count);
    foreach (var line in inverted.samples.Take(40)) sb.AppendLine(line);
    foreach (var s in inverted.full.Take(12)) {
      sb.AppendLine(Format(s));
      Dump(sb, s.DupCall, 0x40, 0x80, "invFull");
    }

    // Rank frequent Dup callees with true (0,0) last-def — likely RowSelector::Duplicate
    sb.AppendLine();
    sb.AppendLine("===== TOP STRICT DUP CALLEES =====");
    foreach (var g in inverted.dupCallees.OrderByDescending(kv => kv.Value).Take(20))
      sb.AppendLine("dupCallee=0x" + g.Key.ToString("X") + " n=" + g.Value + " " + LeafSummary(g.Key));

    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    bool proven = false;
    sb.AppendLine("c2Proven=" + proven);
    sb.AppendLine("callEngine=off");
    if (full.Count > 0 || inverted.full.Count > 0) {
      sb.AppendLine("decision=strict-shaped-triad-candidates — identity still unproven");
      sb.AppendLine("next=Deep-disasm Begin/Dup/End/Build callees; prove selector/builder this;");
    } else if (almost.Count > 0 || armSand.Count > 0) {
      sb.AppendLine("decision=strict Begin+Dup+End without Build shape yet");
      sb.AppendLine("next=At survivors, find post-End consumer of Duplicate return (lea rdx + call).");
    } else if (inverted.withBuild > 0) {
      sb.AppendLine("decision=strict Dup(0,0)+Build pairs exist; Begin/End link missing under freestanding filter");
      sb.AppendLine("next=Widen Begin window; allow End via register-indirect; profile Dup callees for scope reads.");
    } else if (arming.Count > 0) {
      sb.AppendLine("decision=arming Begin leaves found but no strict sandwich");
      sb.AppendLine("next=Disasm top arming Begin callees; find callers that also call Duplicate.");
    } else {
      sb.AppendLine("decision=no-strict-triad-under-last-def-filters");
      sb.AppendLine("next=Ask Agent1 for x64 Begin/End ABI (cdecl→rcx/rdx?) and whether End is leaf vs virtual.");
    }

    string dir = Path.Combine(root, "reports", "v080-triad-strict-raw");
    Directory.CreateDirectory(dir);
    File.WriteAllText(Path.Combine(dir, "evidence.txt"), sb.ToString());
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-triad-strict.json"),
      "{\n  \"schemaVersion\": 1,\n  \"contract\": \"C2\",\n  \"exeSha256\": \"" + hash + "\",\n" +
      "  \"strictBegin10\": " + begins.Count + ",\n  \"beginArming\": " + arming.Count + ",\n" +
      "  \"strictSandwich\": " + sandwiches.Count + ",\n  \"strictBeginDupEnd\": " + almost.Count + ",\n" +
      "  \"strictFullTriad\": " + full.Count + ",\n  \"strictDup00\": " + inverted.dupCount + ",\n" +
      "  \"dupWithBuild\": " + inverted.withBuild + ",\n  \"dupFullShape\": " + inverted.full.Count + ",\n" +
      "  \"c2Proven\": false,\n  \"callEngine\": false\n}\n");
    Console.WriteLine(string.Join("\n", sb.ToString().Split('\n').Take(45)));
    Console.WriteLine("WROTE reports/v080-triad-strict-raw/evidence.txt");
    return 0;
  }

  struct BeginHit { public uint site, callee; }

  // Last-def: final write to ecx/cl must be 1; final write to edx/dl must be 0; no rcx=this from mem preferred.
  static List<BeginHit> FindStrictBegin10(int max) {
    var list = new List<BeginHit>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0x20; i + 5 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        // cheap prefilter
        bool maybe1 = false, maybe0 = false;
        for (uint j = i - 0x20; j < i; j++) {
          if (pe[s.Ptr + j] == 0xB1 && j + 1 < i && pe[s.Ptr + j + 1] == 1) maybe1 = true;
          if (pe[s.Ptr + j] == 0xB9 && j + 4 < i && pe[s.Ptr + j + 1] == 1 && pe[s.Ptr + j + 2] == 0) maybe1 = true;
          if ((pe[s.Ptr + j] == 0x31 || pe[s.Ptr + j] == 0x33) && j + 1 < i && pe[s.Ptr + j + 1] == 0xD2) maybe0 = true;
        }
        if (!maybe1 || !maybe0) continue;
        uint site = s.Va + i;
        if (!LastDefIs(site, "ecx", 1) || !LastDefIs(site, "edx", 0)) continue;
        // Reject if last rcx write looks like this-pointer from register/mem (not imm 1)
        if (LastRcxLooksLikeThis(site)) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        uint callee = unchecked((uint)(site + 5 + rel));
        list.Add(new BeginHit { site = site, callee = callee });
      }
    }
    return list;
  }

  static bool LastRcxLooksLikeThis(uint callSite) {
    string last = null;
    foreach (var ins in Disasm(callSite > 0x28 ? callSite - 0x28 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("movrcx,") || t.StartsWith("learcx,") || t.StartsWith("movecx,") || t.StartsWith("movcl,"))
        last = t;
    }
    if (last == null) return false;
    if (last == "movecx,1" || last == "movcl,1" || last == "movrcx,1") return false;
    // anything else setting rcx is suspicious for freestanding Begin
    return true;
  }

  static bool LastDefIs(uint callSite, string reg, int want) {
    // Track last write affecting ecx/cl or edx/dl.
    string last = null;
    uint start = callSite > 0x30 ? callSite - 0x30 : 0;
    foreach (var ins in Disasm(start, callSite)) {
      string t = Norm(ins.text);
      if (reg == "ecx") {
        if (t.StartsWith("movecx,") || t.StartsWith("movcl,") || t.StartsWith("xorecx,ecx") || t.StartsWith("xorcl,cl")
            || t.StartsWith("movrcx,") || t.StartsWith("xorrcx,rcx") || t.StartsWith("learcx,"))
          last = t;
      } else if (reg == "edx") {
        if (t.StartsWith("movedx,") || t.StartsWith("movdl,") || t.StartsWith("xoredx,edx") || t.StartsWith("xordl,dl")
            || t.StartsWith("movrdx,") || t.StartsWith("xorrdx,rdx") || t.StartsWith("leardx,"))
          last = t;
      } else if (reg == "r8") {
        if (t.StartsWith("movr8") || t.StartsWith("xorr8") || t.StartsWith("lear8"))
          last = t;
      }
    }
    if (last == null) return false;
    if (want == 0) {
      return last.Contains("xor") && (last.Contains(reg) || last.Contains(reg.Replace("e", "")) || last.Contains("r8"))
        || last.EndsWith(",0") || last.EndsWith(",0h");
    }
    if (want == 1) {
      return last.EndsWith(",1") || last.EndsWith(",1h");
    }
    return false;
  }

  static bool LastDefDup00(uint callSite) {
    // edx/dl last-def 0 AND r8/r8d/r8b last-def 0 AND rcx set (this)
    string lastEdx = null, lastR8 = null; bool hasRcx = false;
    foreach (var ins in Disasm(callSite > 0x30 ? callSite - 0x30 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("movedx,") || t.StartsWith("movdl,") || t.StartsWith("xoredx,edx") || t.StartsWith("xordl,dl")
          || t.StartsWith("movrdx,") || t.StartsWith("xorrdx,rdx")) lastEdx = t;
      if (t.StartsWith("movr8") || t.StartsWith("xorr8") || t.StartsWith("lear8")) lastR8 = t;
      if (t.StartsWith("movrcx,") || t.StartsWith("learcx,")) hasRcx = true;
    }
    if (!hasRcx || lastEdx == null || lastR8 == null) return false;
    bool zEdx = lastEdx.Contains("xor") || lastEdx.EndsWith(",0") || lastEdx.EndsWith(",0h");
    bool zR8 = lastR8.Contains("xor") || lastR8.EndsWith(",0") || lastR8.EndsWith(",0h");
    // reject non-zero immediates as last def
    if (lastEdx.Contains(",1") || lastR8.Contains(",1")) return false;
    return zEdx && zR8;
  }

  static bool LooksLikeFreestandingEnd(uint callSite) {
    // No rcx/ecx write in prior 0x14 bytes (0-arg freestanding).
    foreach (var ins in Disasm(callSite > 0x14 ? callSite - 0x14 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("movrcx,") || t.StartsWith("movecx,") || t.StartsWith("movcl,") || t.StartsWith("learcx,"))
        return false;
      if (t.StartsWith("movedx,") || t.StartsWith("movdl,") || t.StartsWith("movr8"))
        return false;
    }
    return true;
  }

  static bool LooksLikeBuild(uint callSite) {
    bool leaRdx = false, hasR8 = false, hasRcx = false;
    foreach (var ins in Disasm(callSite > 0x30 ? callSite - 0x30 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("leardx,[rsp") || t.StartsWith("leardx,[rbp")) leaRdx = true;
      if (t.StartsWith("movr8,") || t.StartsWith("movr8d,")) hasR8 = true;
      if (t.StartsWith("movrcx,")) hasRcx = true;
    }
    return leaRdx && hasR8 && hasRcx;
  }

  static Site ExpandStrict(uint beginSite, uint beginCallee) {
    var p = ProfileLeaf(beginCallee);
    var c = new Site {
      BeginCall = beginSite, BeginCallee = beginCallee, Func = FuncStart(beginSite),
      BeginSize = p.size, BeginTls = p.tls, BeginRipStore = p.ripStore, BeginRetAl = p.retAl,
      BeginKind = p.tls ? "tls" : (p.ripStore ? "ripStore" : "other")
    };
    foreach (var ins in Disasm(beginSite + 5, beginSite + 0x140)) {
      if (ins.mnem == Mnemonic.Int3 && ins.rva > beginSite + 8) break;
      if (ins.mnem == Mnemonic.Ret) break;
      if (!ins.isCall || ins.target == 0) continue;
      if (c.DupCall == 0 && LastDefDup00(ins.rva)) {
        c.DupCall = ins.rva; c.DupCallee = ins.target; continue;
      }
      if (c.DupCall != 0 && c.EndCall == 0 && LooksLikeFreestandingEnd(ins.rva)) {
        c.EndCall = ins.rva; c.EndCallee = ins.target; continue;
      }
      if (c.DupCall != 0 && c.BuildCall == 0 && LooksLikeBuild(ins.rva)) {
        c.BuildCall = ins.rva; c.BuildCallee = ins.target;
      }
    }
    if (c.DupCall == 0) return null;
    return c;
  }

  sealed class InvertResult {
    public int dupCount, withBuild, withBegin, withEnd;
    public List<Site> full = new List<Site>();
    public List<string> samples = new List<string>();
    public Dictionary<uint, int> dupCallees = new Dictionary<uint, int>();
  }

  static InvertResult InvertFromDup(int max) {
    var r = new InvertResult();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0x30; i + 5 <= lim && r.dupCount < max; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        bool zEdx = false, zR8 = false;
        for (uint j = i - 0x28; j + 2 < i; j++) {
          byte a = pe[s.Ptr + j], b = pe[s.Ptr + j + 1];
          if ((a == 0x33 || a == 0x31) && b == 0xD2) zEdx = true;
          if (a == 0x45 && (b == 0x33 || b == 0x31) && j + 2 < i && pe[s.Ptr + j + 2] == 0xC0) zR8 = true;
        }
        if (!zEdx || !zR8) continue;
        uint dupSite = s.Va + i;
        if (!LastDefDup00(dupSite)) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        uint dupCallee = unchecked((uint)(dupSite + 5 + rel));
        r.dupCount++;
        if (!r.dupCallees.ContainsKey(dupCallee)) r.dupCallees[dupCallee] = 0;
        r.dupCallees[dupCallee]++;

        uint beginCall = 0, beginCallee = 0, endCall = 0, endCallee = 0, buildCall = 0, buildCallee = 0;
        // look BACK for Begin(1,0)
        var back = Disasm(dupSite > 0x80 ? dupSite - 0x80 : 0, dupSite);
        for (int bi = back.Count - 1; bi >= 0; bi--) {
          var ins = back[bi];
          if (!ins.isCall || ins.target == 0) continue;
          if (LastDefIs(ins.rva, "ecx", 1) && LastDefIs(ins.rva, "edx", 0) && !LastRcxLooksLikeThis(ins.rva)) {
            beginCall = ins.rva; beginCallee = ins.target; break;
          }
        }
        // look FORWARD for End + Build
        foreach (var ins in Disasm(dupSite + 5, dupSite + 0xA0)) {
          if (!ins.isCall || ins.target == 0) continue;
          if (endCall == 0 && LooksLikeFreestandingEnd(ins.rva)) { endCall = ins.rva; endCallee = ins.target; continue; }
          if (buildCall == 0 && LooksLikeBuild(ins.rva)) { buildCall = ins.rva; buildCallee = ins.target; }
        }
        if (beginCall != 0) r.withBegin++;
        if (endCall != 0) r.withEnd++;
        if (buildCall != 0) r.withBuild++;
        if (r.samples.Count < 60) {
          r.samples.Add("dup=0x" + dupSite.ToString("X") + "->0x" + dupCallee.ToString("X")
            + " begin=" + (beginCall == 0 ? "0" : "0x" + beginCall.ToString("X") + "->0x" + beginCallee.ToString("X"))
            + " end=" + (endCall == 0 ? "0" : "0x" + endCall.ToString("X") + "->0x" + endCallee.ToString("X"))
            + " build=" + (buildCall == 0 ? "0" : "0x" + buildCall.ToString("X") + "->0x" + buildCallee.ToString("X"))
            + " func=0x" + FuncStart(dupSite).ToString("X"));
        }
        if (beginCall != 0 && endCall != 0 && buildCall != 0) {
          var site = new Site {
            BeginCall = beginCall, BeginCallee = beginCallee, DupCall = dupSite, DupCallee = dupCallee,
            EndCall = endCall, EndCallee = endCallee, BuildCall = buildCall, BuildCallee = buildCallee,
            Func = FuncStart(dupSite)
          };
          var bp = ProfileLeaf(beginCallee);
          site.BeginTls = bp.tls; site.BeginRipStore = bp.ripStore; site.BeginSize = bp.size;
          site.BeginKind = bp.tls ? "tls" : (bp.ripStore ? "ripStore" : "other");
          r.full.Add(site);
        }
      }
    }
    return r;
  }

  struct LeafProf { public int size; public bool tls, ripStore, retAl; public List<uint> rips; }

  static LeafProf ProfileLeaf(uint rva) {
    var p = new LeafProf { rips = new List<uint>() };
    uint end = rva + 0x200;
    int n = 0;
    foreach (var ins in Disasm(rva, end)) {
      n++;
      if (ins.mnem == Mnemonic.Ret || ins.mnem == Mnemonic.Int3) { p.size = (int)(ins.rva - rva) + 1; break; }
      string t = Norm(ins.text);
      if (t.Contains("gs:[") || t.Contains("gs:")) p.tls = true;
      // RIP-rel store: mov [rip+..], reg
      if ((t.StartsWith("mov[") || t.StartsWith("movbyteptr[") || t.StartsWith("movdwordptr[") || t.StartsWith("movqwordptr["))
          && t.Contains("rip")) {
        p.ripStore = true;
        uint tgt = RipTarget(ins);
        if (tgt != 0) p.rips.Add(tgt);
      }
      if (t.StartsWith("moval,") || t == "seteal" || t == "setneal" || t.StartsWith("movzxeax,")) p.retAl = true;
      if (n > 120) { p.size = (int)(ins.rva - rva); break; }
    }
    if (p.size == 0) p.size = n * 4;
    return p;
  }

  static uint RipTarget(Ins ins) {
    // parse ;data= from our Dump style — here decode memory disp via iced
    int fo = RvaToFile(ins.rva); if (fo < 0) return 0;
    var reader = new ByteArrayCodeReader(pe); reader.Position = fo;
    var dec = Decoder.Create(64, reader); dec.IP = ib + ins.rva;
    var raw = dec.Decode();
    if (raw.IsIPRelativeMemoryOperand) return (uint)(raw.IPRelativeMemoryAddress - ib);
    return 0;
  }

  static string LeafSummary(uint rva) {
    var p = ProfileLeaf(rva);
    return "size≈" + p.size + " tls=" + p.tls + " ripStore=" + p.ripStore;
  }

  static string Format(Site s) {
    return "func=0x" + s.Func.ToString("X")
      + " begin=0x" + s.BeginCall.ToString("X") + "->0x" + s.BeginCallee.ToString("X")
      + " dup=0x" + s.DupCall.ToString("X") + "->0x" + s.DupCallee.ToString("X")
      + " end=0x" + (s.EndCall == 0 ? "0" : s.EndCall.ToString("X")) + "->0x" + s.EndCallee.ToString("X")
      + " build=0x" + (s.BuildCall == 0 ? "0" : s.BuildCall.ToString("X")) + "->0x" + s.BuildCallee.ToString("X")
      + (s.BeginKind != null ? " kind=" + s.BeginKind : "");
  }

  static string Norm(string s) => s.Replace(" ", "").Replace("ptr", "").ToLowerInvariant();

  struct Ins {
    public uint rva, target; public string text; public Mnemonic mnem; public bool isCall;
  }

  static List<Ins> Disasm(uint start, uint endEx) {
    var list = new List<Ins>();
    int fo = RvaToFile(start);
    if (fo < 0) return list;
    var reader = new ByteArrayCodeReader(pe); reader.Position = fo;
    var dec = Decoder.Create(64, reader); dec.IP = ib + start;
    ulong lim = ib + endEx; int g = 0;
    while (dec.IP < lim && g++ < 600) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      var o = new StringOutput(); Fmt.Format(raw, o);
      var ins = new Ins { rva = (uint)(raw.IP - ib), text = o.ToString(), mnem = raw.Mnemonic };
      if (raw.FlowControl == FlowControl.Call && raw.NearBranchTarget != 0 && raw.NearBranchTarget >= ib) {
        ins.isCall = true; ins.target = (uint)(raw.NearBranchTarget - ib);
      }
      list.Add(ins);
      if (ins.mnem == Mnemonic.Int3) break;
    }
    return list;
  }

  static void Dump(StringBuilder sb, uint center, int before, int after, string label) {
    uint start = center > (uint)before ? center - (uint)before : center;
    sb.AppendLine("--- " + label + " @0x" + center.ToString("X") + " ---");
    foreach (var ins in Disasm(start, center + (uint)after).Take(40)) {
      string ex = ins.isCall ? "  ;call=0x" + ins.target.ToString("X") : "";
      string t = Trunc(ins.text, 96);
      if (ins.text.Contains("rip") && RipTarget(ins) != 0) ex += " ;data=0x" + RipTarget(ins).ToString("X");
      sb.AppendLine("0x" + ins.rva.ToString("X") + " " + t + ex);
    }
  }

  static IEnumerable<Sec> CodeSecs() {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      if ((s.Char & 0x20000000) != 0 || s.Name.Contains("impdata") || s.Name.Contains("code"))
        yield return s;
    }
  }
  static uint FuncStart(uint site) {
    int fo = RvaToFile(site); if (fo < 0) return 0;
    int back = Math.Min(fo, 0x2000), pad = -1;
    for (int i = 1; i < back; i++) if (pe[fo - i] == 0xCC && i + 1 < back && pe[fo - i - 1] == 0xCC) { pad = i; break; }
    if (pad < 0) return site > 0x20 ? site - 0x20 : site;
    uint rva = site - (uint)pad; int p = RvaToFile(rva);
    while (p >= 0 && p < pe.Length && pe[p] == 0xCC) { rva++; p++; }
    return rva;
  }
  static string Trunc(string s, int n) => s.Length <= n ? s : s.Substring(0, n);
  static int RvaToFile(uint rva) {
    foreach (var s in secs) {
      uint sp = Math.Max(s.VSize, s.Raw);
      if (rva >= s.Va && rva < s.Va + sp && s.Ptr > 0) return (int)s.Ptr + (int)(rva - s.Va);
    }
    return -1;
  }
  static void Parse() {
    int e = BitConverter.ToInt32(pe, 0x3C); ib = BitConverter.ToUInt64(pe, e + 48);
    ushort n = BitConverter.ToUInt16(pe, e + 6), o = BitConverter.ToUInt16(pe, e + 20);
    int sec = e + 24 + o; secs = new List<Sec>();
    for (int i = 0; i < n; i++) {
      int p = sec + i * 40;
      secs.Add(new Sec {
        Name = Encoding.ASCII.GetString(pe, p, 8).TrimEnd('\0'),
        VSize = BitConverter.ToUInt32(pe, p + 8), Va = BitConverter.ToUInt32(pe, p + 12),
        Raw = BitConverter.ToUInt32(pe, p + 16), Ptr = BitConverter.ToUInt32(pe, p + 20),
        Char = BitConverter.ToUInt32(pe, p + 36)
      });
    }
  }
  static string Sha(byte[] d) {
    using (var s = SHA256.Create()) {
      var h = s.ComputeHash(d); var sb = new StringBuilder();
      foreach (byte b in h) sb.Append(b.ToString("X2")); return sb.ToString();
    }
  }
}
