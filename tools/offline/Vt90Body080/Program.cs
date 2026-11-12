// Resolve Agent1 next xref: body at vt+0x90 for site 0x1F75EA7 / sibling 0x44A8A5.
// Offline: (1) profile 0xBF3100 (return consumer, not factory),
// (2) hunt vt+0x90 (0,0) callers whose saved rax is r8 of 3-arg Build (no r9),
// (3) scan .rdata candidate vtables' slot +0x90 for alloc/return-new bodies.
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
  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; public bool IsCode, IsData; }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha(pe);
    if (!hash.Equals(Expected, StringComparison.OrdinalIgnoreCase)) { Console.Error.WriteLine("hash mismatch"); return 2; }
    Parse();
    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 Agent1 vt+0x90 body xref =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("primary=0x1F75EA7 sibling=0x44A8A5 loadAt=0x1F75E9F");
    sb.AppendLine("callEngine=off");

    sb.AppendLine();
    sb.AppendLine("===== PRIMARY WINDOW (aligned) =====");
    Dump(sb, 0x1F75E70, 0x1F75F10, 48);
    sb.AppendLine("===== SIBLING WINDOW =====");
    Dump(sb, 0x44A880, 0x44A910, 40);

    sb.AppendLine();
    sb.AppendLine("===== 0xBF3100 (return consumer; not factory) =====");
    ProfileLeaf(sb, 0xBF3100, "BF3100");

    Console.WriteLine("Scanning vt+0x90 (0,0) for rax→r8 Build (3-arg, no r9)...");
    var buildHits = FindVt90ToBuild();
    sb.AppendLine();
    sb.AppendLine("===== vt+0x90 SAVED-RAX → Build r8 (3-arg, no r9) =====");
    sb.AppendLine("hits=" + buildHits.Count);
    foreach (var h in buildHits.Take(40)) {
      sb.AppendLine(h);
    }

    Console.WriteLine("Scanning rdata candidate vtables for slot +0x90 bodies...");
    var bodies = ScanVtblSlot90(maxVtbl: 8000, maxBodies: 80);
    sb.AppendLine();
    sb.AppendLine("===== CANDIDATE vt+0x90 BODIES (rdata) =====");
    sb.AppendLine("vtablesScanned=" + bodies.scanned + " uniqueSlot90=" + bodies.bodies.Count);
    int allocish = 0;
    foreach (var b in bodies.bodies.OrderByDescending(x => x.score).Take(40)) {
      sb.AppendLine("body=0x" + b.rva.ToString("X") + " score=" + b.score + " size=" + b.size
        + " alloc=" + b.alloc + " retRax=" + b.retRax + " uses0=" + b.usesZeroArgs
        + " nVtbl=" + b.nVtbl + " sampleVtbl=0x" + b.sampleVtbl.ToString("X"));
      if (b.score >= 3) {
        allocish++;
        Dump(sb, b.rva, b.rva + (uint)Math.Min(b.size + 8, 0xA0), 36);
      }
    }
    sb.AppendLine("allocishBodies=" + allocish);

    // Rank bodies that appear AND have a build-hit calling through some vt (can't prove same vt offline)
    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    bool bodyResolved = false; // we don't claim a unique body for the live object
    sb.AppendLine("slotBodyUniqueResolved=" + bodyResolved);
    sb.AppendLine("buildConsumerHits=" + buildHits.Count);
    sb.AppendLine("c2Proven=false");
    sb.AppendLine("callEngine=off");
    if (buildHits.Count > 0) {
      sb.AppendLine("decision=found vt+0x90 callers whose saved rax is Build r8 — Duplicate→Build candidate edge");
      sb.AppendLine("next=At those sites, prove Begin/End scope; resolve concrete slot body if possible; backtrace C1.");
    } else if (allocish > 0) {
      sb.AppendLine("decision=no Build-r8 consumer yet; some rdata vt+0x90 bodies look alloc/return-new");
      sb.AppendLine("next=Match an allocish body to the object type at 0x1F75E9F path, or keep hunting Build consumers.");
    } else {
      sb.AppendLine("decision=cannot uniquely resolve slot body offline; no Build-r8 consumer found");
      sb.AppendLine("next=Widen Build consumer window; or ask Agent1 for RTTI/type of [wrapper+0] object.");
    }

    string dir = Path.Combine(root, "reports", "v080-vt90-body-raw");
    Directory.CreateDirectory(dir);
    File.WriteAllText(Path.Combine(dir, "evidence.txt"), sb.ToString());
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-vt90-body.json"),
      "{\n  \"schemaVersion\": 1,\n  \"primary\": \"0x1F75EA7\",\n  \"sibling\": \"0x44A8A5\",\n" +
      "  \"buildConsumerHits\": " + buildHits.Count + ",\n  \"uniqueSlot90Bodies\": " + bodies.bodies.Count + ",\n" +
      "  \"allocishBodies\": " + allocish + ",\n  \"slotBodyUniqueResolved\": false,\n" +
      "  \"c2Proven\": false,\n  \"callEngine\": false\n}\n");
    Console.WriteLine(string.Join("\n", sb.ToString().Split('\n').Take(55)));
    Console.WriteLine("WROTE reports/v080-vt90-body-raw/evidence.txt");
    return 0;
  }

  static List<string> FindVt90ToBuild() {
    var hits = new List<string>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      uint i = 0;
      while (i + 8 < lim && hits.Count < 200) {
        int fo = (int)(s.Ptr + i);
        var reader = new ByteArrayCodeReader(pe); reader.Position = fo;
        var dec = Decoder.Create(64, reader); dec.IP = ib + s.Va + i;
        var raw = dec.Decode();
        if (raw.Length == 0 || raw.Code == Code.INVALID) { i++; continue; }
        uint site = (uint)(raw.IP - ib);
        if (raw.Mnemonic == Mnemonic.Call && raw.IsCallNearIndirect && MemDisp(raw) == 0x90 && LastDefDup00(site)) {
          string line = FollowSavedRaxToBuild(site);
          if (line != null) hits.Add(line);
        }
        i += (uint)Math.Max(1, raw.Length);
      }
    }
    return hits;
  }

  // After call: test rax / je; mov REG,rax; ... later call with mov r8,REG, lea rdx,[rsp], mov rcx,?, and NO mov r9
  static string FollowSavedRaxToBuild(uint dupSite) {
    string ret = null;
    var after = Disasm(dupSite + 2, dupSite + 0x100);
    int idx = 0;
    for (; idx < after.Count; idx++) {
      string t = Norm(after[idx].text);
      if (ret == null) {
        if (t.StartsWith("testrax") || t.StartsWith("je") || t.StartsWith("jne") || t.StartsWith("jz") || t.StartsWith("jnz") || t.StartsWith("nop")) continue;
        if (IsMovFromRax(t, out ret)) continue;
        return null;
      }
      break;
    }
    if (ret == null) return null;
    bool killed = false; string lastR8 = null; bool sawR9 = false;
    for (; idx < after.Count; idx++) {
      var ins = after[idx];
      string t = Norm(ins.text);
      if (IsWriteTo(t, ret) && t != "mov" + ret + ",rax") killed = true;
      if (t.StartsWith("movr8,") || t.StartsWith("movr8d,") || t.StartsWith("lear8,")) lastR8 = t;
      if (t.StartsWith("movr9,") || t.StartsWith("movr9d,") || t.StartsWith("lear9,") || t.StartsWith("xorr9")) sawR9 = true;
      if (ins.isCall) {
        if (!killed && lastR8 != null && (lastR8 == "movr8," + ret || lastR8 == "movr8d," + ret)
            && LooksBuildLea(ins.rva) && !HasR9Before(ins.rva)) {
          return "dup=0x" + dupSite.ToString("X") + " ret=" + ret + " build=0x" + ins.rva.ToString("X")
            + "->0x" + ins.target.ToString("X") + " func=0x" + FuncStart(dupSite).ToString("X");
        }
        // reset r9 tracking after unrelated calls carefully — if call before build, r9 from before may be stale
        if (ins.rva != dupSite) { /* keep lastR8 */ }
      }
      if (ins.mnem == Mnemonic.Ret || ins.mnem == Mnemonic.Int3) break;
    }
    return null;
  }

  static bool HasR9Before(uint callSite) {
    foreach (var ins in Disasm(callSite > 0x30 ? callSite - 0x30 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("movr9,") || t.StartsWith("movr9d,") || t.StartsWith("lear9,") || t.StartsWith("movr9b,")) return true;
    }
    return false;
  }
  static bool LooksBuildLea(uint callSite) {
    bool lea = false, rcx = false;
    foreach (var ins in Disasm(callSite > 0x40 ? callSite - 0x40 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("leardx,[rsp") || t.StartsWith("leardx,[rbp")) lea = true;
      if (t.StartsWith("movrcx,")) rcx = true;
    }
    return lea && rcx;
  }

  sealed class Body {
    public uint rva, sampleVtbl; public int score, size, nVtbl;
    public bool alloc, retRax, usesZeroArgs;
  }
  sealed class BodyScan { public int scanned; public List<Body> bodies = new List<Body>(); }

  static BodyScan ScanVtblSlot90(int maxVtbl, int maxBodies) {
    var res = new BodyScan();
    var byBody = new Dictionary<uint, Body>();
    // Scan data sections for runs of code pointers (candidate vtables)
    foreach (var s in secs) {
      if (!s.IsData || s.Ptr == 0 || s.Raw < 0xA0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw) & ~7u;
      for (uint off = 0; off + 0x98 <= lim && res.scanned < maxVtbl; off += 8) {
        // Heuristic: [0] and [8] and [0x90] are all code pointers
        uint p0 = ReadU32CodePtr(s, off);
        uint p8 = ReadU32CodePtr(s, off + 8);
        uint p90 = ReadU32CodePtr(s, off + 0x90);
        if (p0 == 0 || p8 == 0 || p90 == 0) continue;
        if (!IsCode(p0) || !IsCode(p8) || !IsCode(p90)) continue;
        // also [0x10] preferably code
        uint p10 = ReadU32CodePtr(s, off + 0x10);
        if (p10 == 0 || !IsCode(p10)) continue;
        res.scanned++;
        uint vt = s.Va + off;
        if (!byBody.TryGetValue(p90, out var b)) {
          b = ProfileBody(p90);
          b.rva = p90; b.sampleVtbl = vt; b.nVtbl = 0;
          byBody[p90] = b;
          if (byBody.Count >= maxBodies * 4) break;
        }
        b.nVtbl++;
      }
    }
    res.bodies = byBody.Values.ToList();
    return res;
  }

  static Body ProfileBody(uint rva) {
    var b = new Body { rva = rva };
    int n = 0;
    bool sawRet = false;
    foreach (var ins in Disasm(rva, rva + 0x180)) {
      n++;
      string t = Norm(ins.text);
      if (t.Contains("gs:[58]") || t.Contains("gs:[30]")) { /* tls */ }
      // alloc-ish: call then mov reg,rax then stores into new object
      if (ins.isCall && ins.target != 0) {
        // common allocator sizes / names unknown — look for call then use of rax as base for stores
      }
      if (t.StartsWith("mov[rax") || t.StartsWith("movqwordptr[rax") || t.StartsWith("mov[rbx") && t.Contains(",rax"))
        b.alloc = true; // weak
      // stronger: call; mov rbx,rax; mov [rbx], rip-rel vtable
      if (t.Contains("[rax],") && t.Contains("rip")) b.alloc = true;
      if (t.Contains("[rbx],") && t.Contains("rip")) b.alloc = true;
      if (t.StartsWith("xoredx,edx") || t.StartsWith("xorr8d,r8d") || t.StartsWith("testdl") || t.StartsWith("testr8"))
        b.usesZeroArgs = true;
      if (ins.mnem == Mnemonic.Ret) {
        sawRet = true; b.size = (int)(ins.rva - rva) + 1;
        // look back for mov rax
        break;
      }
      if (ins.mnem == Mnemonic.Int3) { b.size = (int)(ins.rva - rva); break; }
      if (n > 120) { b.size = (int)(ins.rva - rva); break; }
    }
    // check if returns rax: last movs to rax before ret
    if (sawRet) {
      foreach (var ins in Disasm(rva, rva + (uint)b.size)) {
        string t = Norm(ins.text);
        if (t.StartsWith("movrax,") || t.StartsWith("learax,") || t == "xorrax,rax") b.retRax = true;
      }
    }
    b.score = (b.alloc ? 2 : 0) + (b.retRax ? 2 : 0) + (b.usesZeroArgs ? 1 : 0) + Math.Min(b.nVtbl, 3);
    return b;
  }

  static void ProfileLeaf(StringBuilder sb, uint rva, string label) {
    Dump(sb, rva, rva + 0x80, 40);
    var b = ProfileBody(rva);
    sb.AppendLine(label + " size=" + b.size + " alloc=" + b.alloc + " retRax=" + b.retRax);
  }

  static uint ReadU32CodePtr(Sec s, uint off) {
    // read 8-byte VA, convert to RVA if in image
    if (s.Ptr + off + 8 > pe.Length) return 0;
    ulong va = BitConverter.ToUInt64(pe, (int)(s.Ptr + off));
    if (va < ib || va > ib + 0x20000000) return 0;
    return (uint)(va - ib);
  }
  static bool IsCode(uint rva) {
    foreach (var s in secs) {
      if (!s.IsCode) continue;
      uint sp = Math.Max(s.VSize, s.Raw);
      if (rva >= s.Va && rva < s.Va + sp) return true;
    }
    return false;
  }

  static bool LastDefDup00(uint callSite) {
    string lastEdx = null, lastR8 = null; bool hasRcx = false;
    foreach (var ins in Disasm(callSite > 0x30 ? callSite - 0x30 : 0, callSite)) {
      string t = Norm(ins.text);
      if (t.StartsWith("movedx,") || t.StartsWith("movdl,") || t.StartsWith("xoredx,edx") || t.StartsWith("movrdx,") || t.StartsWith("xorrdx,rdx")) lastEdx = t;
      if (t.StartsWith("movr8") || t.StartsWith("xorr8") || t.StartsWith("lear8")) lastR8 = t;
      if (t.StartsWith("movrcx,") || t.StartsWith("learcx,")) hasRcx = true;
    }
    if (!hasRcx || lastEdx == null || lastR8 == null) return false;
    if (lastEdx.Contains(",1") || lastR8.Contains(",1")) return false;
    return (lastEdx.Contains("xor") || lastEdx.EndsWith(",0")) && (lastR8.Contains("xor") || lastR8.EndsWith(",0"));
  }
  static int MemDisp(Instruction raw) {
    try { if (raw.MemoryBase != Register.None) return (int)raw.MemoryDisplacement64; } catch { }
    return -1;
  }
  static bool IsMovFromRax(string t, out string dest) {
    dest = null;
    foreach (var r in new[] { "rcx","rbx","rsi","rdi","rbp","r12","r13","r14","r15","r8","r9","rax" }) {
      if (t == "mov" + r + ",rax") { dest = r; return true; }
    }
    return false;
  }
  static bool IsWriteTo(string t, string reg) {
    return t.StartsWith("mov" + reg + ",") || t.StartsWith("lea" + reg + ",") || t.StartsWith("xor" + reg + ",")
      || t.StartsWith("or" + reg + ",") || t.StartsWith("and" + reg + ",") || t.StartsWith("add" + reg + ",")
      || t.StartsWith("sub" + reg + ",") || t.StartsWith("pop" + reg);
  }
  static string Norm(string s) => s.Replace(" ", "").Replace("ptr", "").ToLowerInvariant();

  struct Ins { public uint rva, target; public string text; public Mnemonic mnem; public bool isCall; }
  static List<Ins> Disasm(uint start, uint endEx) {
    var list = new List<Ins>();
    int fo = RvaToFile(start); if (fo < 0) return list;
    var reader = new ByteArrayCodeReader(pe); reader.Position = fo;
    var dec = Decoder.Create(64, reader); dec.IP = ib + start;
    ulong lim = ib + endEx; int g = 0;
    while (dec.IP < lim && g++ < 700) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      var o = new StringOutput(); Fmt.Format(raw, o);
      var ins = new Ins { rva = (uint)(raw.IP - ib), text = o.ToString(), mnem = raw.Mnemonic };
      if (raw.FlowControl == FlowControl.Call) {
        if (raw.NearBranchTarget != 0 && raw.NearBranchTarget >= ib) { ins.isCall = true; ins.target = (uint)(raw.NearBranchTarget - ib); }
        else if (raw.IsCallNearIndirect) ins.isCall = true;
      }
      list.Add(ins);
      if (ins.mnem == Mnemonic.Int3) break;
    }
    return list;
  }
  static void Dump(StringBuilder sb, uint st, uint en, int max) {
    foreach (var ins in Disasm(st, en).Take(max)) {
      string ex = ins.isCall ? (ins.target != 0 ? "  ;call=0x" + ins.target.ToString("X") : "  ;call=mem") : "";
      sb.AppendLine("0x" + ins.rva.ToString("X") + " " + Trunc(ins.text, 100) + ex);
    }
  }
  static IEnumerable<Sec> CodeSecs() => secs.Where(s => s.IsCode && s.Ptr > 0 && s.Raw > 0);
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
      var s = new Sec {
        Name = Encoding.ASCII.GetString(pe, p, 8).TrimEnd('\0'),
        VSize = BitConverter.ToUInt32(pe, p + 8), Va = BitConverter.ToUInt32(pe, p + 12),
        Raw = BitConverter.ToUInt32(pe, p + 16), Ptr = BitConverter.ToUInt32(pe, p + 20),
        Char = BitConverter.ToUInt32(pe, p + 36)
      };
      s.IsCode = (s.Char & 0x20000000) != 0 || s.Name.Contains("impdata") || s.Name.Contains("code");
      s.IsData = !s.IsCode && (s.Name.Contains("data") || s.Name.Contains("rdata") || s.Name.Contains("trace") || (s.Char & 0x40000000) != 0);
      secs.Add(s);
    }
  }
  static string Sha(byte[] d) { using (var s = SHA256.Create()) { var h = s.ComputeHash(d); var sb = new StringBuilder(); foreach (byte b in h) sb.Append(b.ToString("X2")); return sb.ToString(); } }
}
