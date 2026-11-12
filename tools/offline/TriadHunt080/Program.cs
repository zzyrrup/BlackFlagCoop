// v0.8.0 — Agent1 string-free C2 triad hunt:
//   Begin(1,0) -> Duplicate(sel,0,0)->new* -> End() -> Build(builder, &out, new*)
// Prefer Build-shaped thiscalls; also invert from Begin(1,0)/End sandwiches.
// Ignore Havok/ObjectID strings and Entity::Duplicate. Read-only PE.
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

  sealed class Cand {
    public uint BeginCall, DupCall, EndCall, BuildCall;
    public uint BeginCallee, DupCallee, EndCallee, BuildCallee;
    public uint Func;
    public string Kind;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha(pe);
    if (!hash.Equals(Expected, StringComparison.OrdinalIgnoreCase)) { Console.Error.WriteLine("hash mismatch"); return 2; }
    Parse();
    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 C2 TRIAD HUNT (Agent1 string-free) =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("triad=Begin(1,0) -> Duplicate(sel,0,0)->new* -> End() -> Build(builder,&out,dup)");
    sb.AppendLine("callEngine=off");

    Console.WriteLine("Scanning Begin(1,0)-shaped freestanding calls...");
    var begins = FindBegin10(max: 8000);
    sb.AppendLine("begin10Candidates=" + begins.Count);
    Console.WriteLine("begin10=" + begins.Count);

    var cands = new List<Cand>();
    Console.WriteLine("Expanding sandwiches...");
    foreach (var b in begins) {
      var c = ExpandSandwich(b.site, b.callee);
      if (c != null) cands.Add(c);
    }
    sb.AppendLine("sandwichCandidates=" + cands.Count);

    // Rank: prefer those with Dup + End + Build all found
    var full = cands.Where(c => c.DupCall != 0 && c.EndCall != 0 && c.BuildCall != 0).ToList();
    var almost = cands.Where(c => c.DupCall != 0 && c.EndCall != 0).ToList();
    sb.AppendLine("fullTriad=" + full.Count);
    sb.AppendLine("beginDupEnd=" + almost.Count);

    sb.AppendLine();
    sb.AppendLine("===== FULL TRIAD SITES =====");
    foreach (var c in full.Take(24)) {
      sb.AppendLine(Format(c));
      Dump(sb, c.BeginCall, 0x10, 0xA0, "triad");
    }

    sb.AppendLine();
    sb.AppendLine("===== BEGIN+DUP+END (no Build yet) =====");
    foreach (var c in almost.Where(x => x.BuildCall == 0).Take(24)) {
      sb.AppendLine(Format(c));
      Dump(sb, c.BeginCall, 0x10, 0x80, "begindupend");
    }

    // Also: Build-first heuristic — lea rdx,[rsp+..] then call with r8 set from prior call
    Console.WriteLine("Scanning Build-shaped (lea rdx,[rsp] + call) near Duplicate(0,0)...");
    var builds = FindBuildNearDup(max: 4000);
    sb.AppendLine();
    sb.AppendLine("===== BUILD-SHAPED NEAR DUP(0,0) =====");
    sb.AppendLine("buildNearDup=" + builds.Count);
    foreach (var line in builds.Take(30)) sb.AppendLine(line);

    // Aggregate unique Begin/Dup/End/Build callees
    sb.AppendLine();
    sb.AppendLine("===== UNIQUE CALLEES =====");
    sb.AppendLine("BeginCallees=" + string.Join(",", almost.Select(c => c.BeginCallee).Distinct().Take(12).Select(x => "0x" + x.ToString("X"))));
    sb.AppendLine("DupCallees=" + string.Join(",", almost.Select(c => c.DupCallee).Where(x => x != 0).Distinct().Take(12).Select(x => "0x" + x.ToString("X"))));
    sb.AppendLine("EndCallees=" + string.Join(",", almost.Select(c => c.EndCallee).Where(x => x != 0).Distinct().Take(12).Select(x => "0x" + x.ToString("X"))));
    sb.AppendLine("BuildCallees=" + string.Join(",", full.Select(c => c.BuildCallee).Where(x => x != 0).Distinct().Take(12).Select(x => "0x" + x.ToString("X"))));

    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    sb.AppendLine("c1Proven=false");
    sb.AppendLine("c2Proven=" + (full.Count > 0 ? "candidate-sites-unconfirmed" : "false"));
    sb.AppendLine("callEngine=off");
    if (full.Count > 0) {
      sb.AppendLine("decision=full-triad-shaped-sites-found-identity-unproven");
      sb.AppendLine("next=Disasm top Begin/Dup/End/Build callees; prove selector this + builder this + out Entity**;");
      sb.AppendLine("     then backtrace selector/builder sources to C1 cache slots.");
    } else if (almost.Count > 0) {
      sb.AppendLine("decision=Begin+Dup+End sandwiches found — Build link missing or different shape");
      sb.AppendLine("next=At sandwich sites, find post-End consumer of Duplicate return (Build or enroll).");
    } else if (begins.Count > 0) {
      sb.AppendLine("decision=Begin(1,0)-shaped calls found but no Dup/End sandwich");
      sb.AppendLine("next=Widen window; allow Begin(1,0) with different imm encoding; virtual Duplicate.");
    } else {
      sb.AppendLine("decision=no-Begin(1,0)-shaped freestanding calls under current heuristic");
      sb.AppendLine("next=Try char-sized cl=1; or invert from frequent End-like epilogues; Ask Agent1 x64 arg pass.");
    }

    string dir = Path.Combine(root, "reports", "v080-triad-raw");
    Directory.CreateDirectory(dir);
    File.WriteAllText(Path.Combine(dir, "evidence.txt"), sb.ToString());
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-triad-hunt.json"),
      "{\n  \"schemaVersion\": 1,\n  \"contract\": \"C2\",\n  \"exeSha256\": \"" + hash + "\",\n" +
      "  \"begin10\": " + begins.Count + ",\n  \"sandwich\": " + cands.Count + ",\n" +
      "  \"fullTriad\": " + full.Count + ",\n  \"beginDupEnd\": " + almost.Count + ",\n" +
      "  \"buildNearDup\": " + builds.Count + ",\n  \"c2Proven\": false,\n  \"callEngine\": false\n}\n");
    Console.WriteLine(string.Join("\n", sb.ToString().Split('\n').Take(35)));
    Console.WriteLine("WROTE reports/v080-triad-raw/evidence.txt");
    return 0;
  }

  struct BeginHit { public uint site, callee; }

  static List<BeginHit> FindBegin10(int max) {
    // Look for E8 where preceding ~0x18 bytes set ecx/rcx to 1 and edx/rdx to 0.
    var list = new List<BeginHit>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0x18; i + 5 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        // Prefilter bytes for imm1 and xor-zero of edx
        bool has1 = false, has0 = false;
        for (uint j = i - 0x18; j < i; j++) {
          // mov ecx,1 = B9 01 00 00 00; mov cl,1 = B1 01; mov edx,1 similarly less relevant
          if (pe[s.Ptr + j] == 0xB9 && j + 4 < i && pe[s.Ptr + j + 1] == 1 && pe[s.Ptr + j + 2] == 0 && pe[s.Ptr + j + 3] == 0 && pe[s.Ptr + j + 4] == 0) has1 = true;
          if (pe[s.Ptr + j] == 0xB1 && j + 1 < i && pe[s.Ptr + j + 1] == 1) has1 = true;
          // mov ecx,1 via C7 C1 01 00 00 00 rare
          // xor edx,edx = 31 D2 / 33 D2
          if ((pe[s.Ptr + j] == 0x31 || pe[s.Ptr + j] == 0x33) && j + 1 < i && pe[s.Ptr + j + 1] == 0xD2) has0 = true;
          // xor rdx,rdx = 48 31 D2
          if (pe[s.Ptr + j] == 0x48 && j + 2 < i && (pe[s.Ptr + j + 1] == 0x31 || pe[s.Ptr + j + 1] == 0x33) && pe[s.Ptr + j + 2] == 0xD2) has0 = true;
        }
        if (!has1 || !has0) continue;
        uint site = s.Va + i;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        uint callee = unchecked((uint)(site + 5 + rel));
        // Confirm via decode that this looks like freestanding Begin (no prior mov rcx from mem as this)
        if (!ConfirmBeginWindow(site)) continue;
        list.Add(new BeginHit { site = site, callee = callee });
      }
    }
    return list;
  }

  static bool ConfirmBeginWindow(uint callSite) {
    uint start = callSite > 0x20 ? callSite - 0x20 : callSite;
    bool saw1 = false, saw0 = false;
    foreach (var ins in Disasm(start, callSite)) {
      string t = ins.text.Replace(" ", "").ToLowerInvariant();
      if (t == "moveecx,1" || t == "movecx,1" || t == "movcl,1" || t == "movrcx,1") saw1 = true;
      if (t == "xoredx,edx" || t == "xorrdx,rdx" || t == "movedx,0" || t == "movrdx,0") saw0 = true;
    }
    return saw1 && saw0;
  }

  static Cand ExpandSandwich(uint beginSite, uint beginCallee) {
    // Decode forward up to 0x120 looking for Duplicate(0,0) call and End() call and Build.
    var c = new Cand {
      BeginCall = beginSite, BeginCallee = beginCallee,
      Func = FuncStart(beginSite), Kind = "sandwich"
    };
    uint end = beginSite + 0x120;
    uint dupRetRegWindow = 0;
    foreach (var ins in Disasm(beginSite + 5, end)) {
      if (ins.mnem == Mnemonic.Int3 && ins.rva > beginSite + 8) break;
      if (ins.mnem == Mnemonic.Ret) break;
      if (!ins.isCall || ins.target == 0) continue;
      // Duplicate: xor edx/r8d zeroed in previous ~0x20 and rcx set
      if (c.DupCall == 0 && LooksLikeDup00(ins.rva, ins.target)) {
        c.DupCall = ins.rva; c.DupCallee = ins.target;
        dupRetRegWindow = ins.rva;
        continue;
      }
      // End: call with no obvious arg setup in prior 8 bytes (heuristic)
      if (c.DupCall != 0 && c.EndCall == 0 && LooksLikeEnd(ins.rva, ins.target)) {
        c.EndCall = ins.rva; c.EndCallee = ins.target;
        continue;
      }
      // Build: after End (or after Dup), lea rdx,[rsp+..] and call
      if (c.DupCall != 0 && c.BuildCall == 0 && LooksLikeBuild(ins.rva, ins.target)) {
        c.BuildCall = ins.rva; c.BuildCallee = ins.target;
      }
    }
    if (c.DupCall == 0) return null; // need at least Dup to be interesting
    return c;
  }

  static bool LooksLikeDup00(uint callSite, uint callee) {
    uint start = callSite > 0x28 ? callSite - 0x28 : callSite;
    bool zEdx = false, zR8 = false, hasRcx = false;
    foreach (var ins in Disasm(start, callSite)) {
      string t = ins.text.Replace(" ", "").ToLowerInvariant();
      if (t == "xoredx,edx" || t == "movedx,0") zEdx = true;
      if (t == "xorr8d,r8d" || t == "movr8d,0" || t == "xorr8,r8") zR8 = true;
      if (t.StartsWith("movrcx,") || t.StartsWith("learcx,")) hasRcx = true;
    }
    return zEdx && zR8 && hasRcx && callee != 0;
  }

  static bool LooksLikeEnd(uint callSite, uint callee) {
    // End has 0 args — reject if prior instruction sets ecx/edx to immediates
    uint start = callSite > 0x10 ? callSite - 0x10 : callSite;
    foreach (var ins in Disasm(start, callSite)) {
      string t = ins.text.Replace(" ", "").ToLowerInvariant();
      if (t.StartsWith("movecx,") || t.StartsWith("movedx,") || t.StartsWith("movcl,") || t.StartsWith("movrcx,"))
        return false;
    }
    // Prefer small leaf callees later; accept for now
    return callee != 0;
  }

  static bool LooksLikeBuild(uint callSite, uint callee) {
    uint start = callSite > 0x30 ? callSite - 0x30 : callSite;
    bool leaRdx = false, hasR8 = false, hasRcx = false;
    foreach (var ins in Disasm(start, callSite)) {
      string t = ins.text.Replace(" ", "").ToLowerInvariant();
      if (t.StartsWith("leardx,[rsp") || t.StartsWith("leardx,[rbp")) leaRdx = true;
      if (t.StartsWith("movr8,") || t.StartsWith("movr8d,")) hasR8 = true;
      if (t.StartsWith("movrcx,")) hasRcx = true;
    }
    return leaRdx && hasR8 && hasRcx && callee != 0;
  }

  static List<string> FindBuildNearDup(int max) {
    var lines = new List<string>();
    // Reuse RoleHunt-style: E8 with xor edx+r8d and rcx, then within +0x40 a lea rdx,[rsp] call
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0x30; i + 5 <= lim && lines.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        bool zEdx = false, zR8 = false;
        for (uint j = i - 0x28; j + 2 < i; j++) {
          byte a = pe[s.Ptr + j], b = pe[s.Ptr + j + 1];
          if ((a == 0x33 || a == 0x31) && b == 0xD2) zEdx = true;
          if (a == 0x45 && (b == 0x33 || b == 0x31) && pe[s.Ptr + j + 2] == 0xC0) zR8 = true;
        }
        if (!zEdx || !zR8) continue;
        uint dupSite = s.Va + i;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        uint dupCallee = unchecked((uint)(dupSite + 5 + rel));
        if (!LooksLikeDup00(dupSite, dupCallee)) continue;
        // look forward for build
        foreach (var ins in Disasm(dupSite + 5, dupSite + 0x60)) {
          if (!ins.isCall || ins.target == 0) continue;
          if (LooksLikeBuild(ins.rva, ins.target)) {
            lines.Add("dup=0x" + dupSite.ToString("X") + " dupCallee=0x" + dupCallee.ToString("X")
              + " build=0x" + ins.rva.ToString("X") + " buildCallee=0x" + ins.target.ToString("X")
              + " func=0x" + FuncStart(dupSite).ToString("X"));
            break;
          }
        }
      }
    }
    return lines;
  }

  static string Format(Cand c) {
    return "func=0x" + c.Func.ToString("X")
      + " begin=0x" + c.BeginCall.ToString("X") + "->0x" + c.BeginCallee.ToString("X")
      + " dup=0x" + c.DupCall.ToString("X") + "->0x" + c.DupCallee.ToString("X")
      + " end=0x" + (c.EndCall == 0 ? "0" : c.EndCall.ToString("X")) + "->0x" + c.EndCallee.ToString("X")
      + " build=0x" + (c.BuildCall == 0 ? "0" : c.BuildCall.ToString("X")) + "->0x" + c.BuildCallee.ToString("X");
  }

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
    while (dec.IP < lim && g++ < 500) {
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
    foreach (var ins in Disasm(start, center + (uint)after).Take(36)) {
      string ex = ins.isCall ? "  ;call=0x" + ins.target.ToString("X") : "";
      sb.AppendLine("0x" + ins.rva.ToString("X") + " " + Trunc(ins.text, 90) + ex);
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
    foreach (var s in secs) { uint sp = Math.Max(s.VSize, s.Raw); if (rva >= s.Va && rva < s.Va + sp && s.Ptr > 0) return (int)s.Ptr + (int)(rva - s.Va); }
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
  static string Sha(byte[] d) { using (var s = SHA256.Create()) { var h = s.ComputeHash(d); var sb = new StringBuilder(); foreach (byte b in h) sb.Append(b.ToString("X2")); return sb.ToString(); } }
}
