// v0.8.0 — Offline: are SpawnCharacterParams / SpawnEntityParams /
// SpawnEntityBuilderParams a native character factory, or schema visitors?
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

  // Schema visitors recovered from the Spawn*Params name sites.
  const uint SpawnCharacterParams = 0x80F2330;
  const uint SpawnEntityParams = 0x8DFFB90;
  const uint SpawnEntityBuilderParams = 0x8E02960;
  // Type-name registrar used by those visitors (name in rdx, hash in r9).
  const uint SchemaRegister = 0x4572C60;
  const uint Allocator = 0x426EE50;

  static readonly uint[] Visitors = {
    SpawnCharacterParams, SpawnEntityParams, SpawnEntityBuilderParams
  };

  static readonly string[] Needles = {
    "SpawnCharacterParams",
    "SpawnEntityParams",
    "SpawnEntityBuilderParams",
    "SpawnCharacter",
    "SpawnEntity",
    "CreateEntity",
    "EntityBuilder"
  };

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);

  sealed class Sec { public string Name; public uint Va, VSize, Raw, Ptr, Char; }
  sealed class Ins {
    public uint Rva; public string Text; public Mnemonic Mnemonic;
    public bool IpRel; public uint DataRva; public bool IsCall, IsIndirectCall, IsRet;
    public uint NearTarget; public int Length; public bool HasImm; public ulong Imm;
  }
  sealed class FuncRep {
    public uint Entry;
    public string Klass;
    public bool CallsSchema, CallsAlloc, CallsVisitor, LeasParams;
    public List<uint> Callees = new List<uint>();
    public List<string> Strings = new List<string>();
    public List<string> Head = new List<string>();
    public int Size;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0
      ? args[0]
      : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1
      ? args[1]
      : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha256Hex(pe);
    Console.WriteLine("exeSha256=" + hash);
    if (!hash.Equals(ExpectedExeSha, StringComparison.OrdinalIgnoreCase)) {
      Console.Error.WriteLine("REFUSING: EXE hash mismatch.");
      return 2;
    }
    ParsePe();
    string rawDir = Path.Combine(root, "reports", "v080-spawn-raw");
    Directory.CreateDirectory(rawDir);
    Directory.CreateDirectory(Path.Combine(root, "reports"));

    var sb = new StringBuilder();
    sb.AppendLine("===== v0.8.0 SPAWN PARAM CALLERS =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("imageBase=0x" + imageBase.ToString("X"));

    var stringHits = FindNeedles();
    sb.AppendLine();
    sb.AppendLine("===== STRING HITS =====");
    foreach (var hit in stringHits)
      sb.AppendLine(hit.Needle + " rva=0x" + hit.Rva.ToString("X") + " text=" + Trunc(hit.Text, 80));

    var leaSites = new List<Tuple<string, uint, uint>>();
    sb.AppendLine();
    sb.AppendLine("===== STRING LEA SITES =====");
    foreach (var hit in stringHits) {
      var leas = FindLeaTo(hit.Rva, 24);
      sb.AppendLine("LEA " + hit.Needle + " @0x" + hit.Rva.ToString("X") + " count=" + leas.Count);
      foreach (uint site in leas) {
        uint fs = FindFuncStart(site);
        leaSites.Add(Tuple.Create(hit.Needle, site, fs));
        sb.AppendLine("  site=0x" + site.ToString("X") + " func=0x" + fs.ToString("X"));
      }
    }

    var callerFuncs = new HashSet<uint>();
    sb.AppendLine();
    sb.AppendLine("===== VISITOR E8 CALLERS =====");
    foreach (uint dest in Visitors) {
      var e8 = FindE8(dest, 40);
      sb.AppendLine("E8 -> 0x" + dest.ToString("X") + " count=" + e8.Count);
      foreach (uint site in e8) {
        uint fs = FindFuncStart(site);
        callerFuncs.Add(fs);
        sb.AppendLine("  site=0x" + site.ToString("X") + " func=0x" + fs.ToString("X"));
      }
    }
    foreach (var site in leaSites)
      callerFuncs.Add(site.Item3);
    foreach (uint v in Visitors)
      callerFuncs.Add(v);

    var reps = new List<FuncRep>();
    sb.AppendLine();
    sb.AppendLine("===== FUNCTIONS =====");
    foreach (uint fs in callerFuncs.Where(x => x != 0).OrderBy(x => x).Take(48)) {
      var rep = Analyze(fs);
      reps.Add(rep);
      sb.AppendLine("0x" + rep.Entry.ToString("X")
        + " class=" + rep.Klass
        + " size=" + rep.Size
        + " schema=" + rep.CallsSchema
        + " alloc=" + rep.CallsAlloc
        + " visitor=" + rep.CallsVisitor
        + " paramsLea=" + rep.LeasParams
        + " callees=" + string.Join(",", rep.Callees.Distinct().Take(12).Select(c => "0x" + c.ToString("X"))));
      foreach (string line in rep.Head.Take(18))
        sb.AppendLine("    " + line);
    }

    var tables = MapTables(sb);
    int schemaVisitors = 0;
    foreach (uint v in Visitors) {
      var rep = reps.FirstOrDefault(r => r.Entry == v);
      bool ok = rep != null && rep.CallsSchema && rep.Klass == "schema-visitor";
      if (ok) schemaVisitors++;
      sb.AppendLine("SELF " + (ok ? "PASS" : "FAIL") + " visitor 0x" + v.ToString("X")
        + " class=" + (rep == null ? "missing" : rep.Klass));
    }

    var factories = reps.Where(r => r.Klass == "factory-candidate").ToList();
    sb.AppendLine("factoryCandidates=" + factories.Count);
    sb.AppendLine("decision=" + (factories.Count == 0
      ? "native-spawn-not-confirmed"
      : "factory-candidate-present"));
    sb.AppendLine("missingLink=caller that fills SpawnEntityBuilderParams and invokes entity creation; the three *Params functions only register schema names via 0x4572C60");

    string evidence = sb.ToString();
    File.WriteAllText(Path.Combine(rawDir, "evidence.txt"), evidence);
    WriteTables(root, tables);
    WriteJson(root, hash, stringHits, leaSites, reps, factories, schemaVisitors);
    Console.WriteLine(evidence);
    Console.WriteLine("schemaVisitors=" + schemaVisitors + "/3 factoryCandidates=" + factories.Count);
    if (schemaVisitors != 3) return 3;
    return 0;
  }

  sealed class Slot {
    public int Index; public uint Rva; public string Klass; public bool CallsAlloc; public bool CallsSchema;
  }
  sealed class Table {
    public uint Visitor; public uint SlotRva; public uint Base; public int Index;
    public List<Slot> Slots = new List<Slot>();
  }

  static List<Table> MapTables(StringBuilder sb) {
    var tables = new List<Table>();
    sb.AppendLine();
    sb.AppendLine("===== PARAM VT SLOTS =====");
    foreach (uint visitor in Visitors) {
      var embeds = FindQword(visitor, 8);
      sb.AppendLine("QWORD 0x" + visitor.ToString("X") + " embeds=" + embeds.Count);
      foreach (uint slot in embeds) {
        uint basis = slot;
        int back = 0;
        while (back < 48) {
          uint prev = basis >= 8 ? basis - 8 : 0;
          if (prev == 0) break;
          uint ptr = ReadQwordRva(prev);
          if (!IsCode(ptr)) break;
          basis = prev;
          back++;
        }
        int index = (int)((slot - basis) / 8);
        var table = new Table { Visitor = visitor, SlotRva = slot, Base = basis, Index = index };
        sb.AppendLine("  slot=0x" + slot.ToString("X") + " base=0x" + basis.ToString("X") + " index=" + index);
        for (int i = 0; i < 12; i++) {
          uint ptr = ReadQwordRva(basis + (uint)(i * 8));
          if (!IsCode(ptr)) {
            sb.AppendLine("    [" + i + "] 0x" + ptr.ToString("X") + " not-code");
            break;
          }
          var rep = Analyze(ptr);
          table.Slots.Add(new Slot {
            Index = i, Rva = ptr, Klass = rep.Klass,
            CallsAlloc = rep.CallsAlloc, CallsSchema = rep.CallsSchema
          });
          sb.AppendLine("    [" + i + "] 0x" + ptr.ToString("X")
            + " class=" + rep.Klass + " alloc=" + rep.CallsAlloc + " schema=" + rep.CallsSchema);
          if (rep.CallsAlloc && !rep.CallsSchema) {
            foreach (string line in rep.Head.Take(22))
              sb.AppendLine("      " + line);
          }
        }
        tables.Add(table);
      }
    }
    int allocSiblings = tables.SelectMany(t => t.Slots).Count(s => s.CallsAlloc && !s.CallsSchema);
    sb.AppendLine("allocSiblingsOutsideSchema=" + allocSiblings);
    return tables;
  }

  static void WriteTables(string root, List<Table> tables) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.8.0\",");
    sb.AppendLine("  \"tables\": [");
    for (int i = 0; i < tables.Count; i++) {
      var t = tables[i];
      sb.AppendLine("    {");
      sb.AppendLine("      \"visitor\": \"0x" + t.Visitor.ToString("X") + "\",");
      sb.AppendLine("      \"base\": \"0x" + t.Base.ToString("X") + "\",");
      sb.AppendLine("      \"index\": " + t.Index + ",");
      sb.Append("      \"slots\": [" + string.Join(", ", t.Slots.Select(s =>
        "{\"index\": " + s.Index + ", \"rva\": \"0x" + s.Rva.ToString("X") + "\", \"class\": " + J(s.Klass)
        + ", \"callsAlloc\": " + T(s.CallsAlloc) + "}")) + "]");
      sb.AppendLine();
      sb.Append("    }");
      sb.AppendLine(i + 1 < tables.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-param-vtables.json"), sb.ToString());
  }

  static uint ReadQwordRva(uint rva) {
    int fo = RvaToFile(rva);
    if (fo < 0 || fo + 8 > pe.Length) return 0;
    ulong va = BitConverter.ToUInt64(pe, fo);
    if (va < imageBase) return 0;
    ulong r = va - imageBase;
    if (r > uint.MaxValue) return 0;
    return (uint)r;
  }

  static List<uint> FindQword(uint rva, int max) {
    var list = new List<uint>();
    ulong va = imageBase + rva;
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      if ((s.Char & 0x20000000) != 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 8 <= lim && list.Count < max; i += 8) {
        if (BitConverter.ToUInt64(pe, (int)(s.Ptr + i)) == va)
          list.Add(s.Va + i);
      }
    }
    return list;
  }

  static bool IsCode(uint rva) {
    if (rva < 0x10000) return false;
    foreach (var s in CodeSecs()) {
      uint span = Math.Max(s.VSize, s.Raw);
      if (rva >= s.Va && rva < s.Va + span) return true;
    }
    return false;
  }

  sealed class Hit { public string Needle; public uint Rva; public string Text; }

  static List<Hit> FindNeedles() {
    var hits = new List<Hit>();
    foreach (string needle in Needles) {
      byte[] pat = Encoding.ASCII.GetBytes(needle);
      int from = 0;
      int guard = 0;
      while (from < pe.Length && guard++ < 64) {
        int at = IndexOf(pe, pat, from);
        if (at < 0) break;
        if (at > 0) {
          byte prev = pe[at - 1];
          if (prev != 0 && prev >= 32 && prev < 127) {
            from = at + 1;
            continue;
          }
        }
        uint rva = FileToRva(at);
        string text = ReadAscii((uint)Math.Max(0, rva), 96);
        if (rva != 0 && IsString(text))
          hits.Add(new Hit { Needle = needle, Rva = rva, Text = text });
        from = at + pat.Length;
      }
    }
    return hits
      .GroupBy(h => h.Rva)
      .Select(g => g.OrderByDescending(h => h.Needle.Length).First())
      .OrderBy(h => h.Rva)
      .ToList();
  }

  static int IndexOf(byte[] data, byte[] pat, int start) {
    int at = data.AsSpan(start).IndexOf(pat);
    return at < 0 ? -1 : at + start;
  }

  static FuncRep Analyze(uint entry) {
    var rep = new FuncRep { Entry = entry, Klass = "unclassified" };
    uint end = FindFuncEnd(entry, 0x600);
    var insns = DisasmRaw(entry, end);
    rep.Size = insns.Count == 0 ? 0 : (int)(insns[insns.Count - 1].Rva + insns[insns.Count - 1].Length - entry);
    foreach (var ins in insns) {
      if (rep.Head.Count < 24)
        rep.Head.Add("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 96));
      if (ins.IsCall && ins.NearTarget != 0) {
        rep.Callees.Add(ins.NearTarget);
        if (ins.NearTarget == SchemaRegister) rep.CallsSchema = true;
        if (ins.NearTarget == Allocator) rep.CallsAlloc = true;
        if (Visitors.Contains(ins.NearTarget)) rep.CallsVisitor = true;
      }
      if (ins.IpRel && ins.DataRva != 0) {
        string s = ReadAscii(ins.DataRva, 80);
        if (IsString(s) && (s.IndexOf("Spawn", StringComparison.Ordinal) >= 0
            || s.IndexOf("Entity", StringComparison.Ordinal) >= 0)) {
          rep.Strings.Add(s);
          if (s.IndexOf("Params", StringComparison.Ordinal) >= 0) rep.LeasParams = true;
        }
      }
    }
    bool isVisitor = Visitors.Contains(entry);
    if (isVisitor && rep.CallsSchema) rep.Klass = "schema-visitor";
    else if (rep.CallsSchema) rep.Klass = "schema-caller";
    else if (rep.CallsAlloc && (rep.CallsVisitor || rep.LeasParams)) rep.Klass = "factory-candidate";
    else if (rep.CallsVisitor) rep.Klass = "visitor-caller";
    else if (rep.LeasParams) rep.Klass = "params-name-user";
    else rep.Klass = "unrelated";
    return rep;
  }

  static void WriteJson(string root, string hash, List<Hit> hits,
      List<Tuple<string, uint, uint>> leas, List<FuncRep> reps, List<FuncRep> factories,
      int schemaVisitors) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.8.0\",");
    sb.AppendLine("  \"mode\": \"offline-pe-readonly\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"nativeSpawnConfirmed\": false,");
    sb.AppendLine("  \"schemaVisitorsConfirmed\": " + schemaVisitors + ",");
    sb.AppendLine("  \"factoryCandidateCount\": " + factories.Count + ",");
    sb.AppendLine("  \"missingLink\": \"A caller that fills SpawnEntityBuilderParams and invokes entity creation. The three *Params functions register schema names through 0x4572C60 and are not character factories.\",");
    sb.AppendLine("  \"excludedAsFactory\": [");
    sb.AppendLine("    {\"rva\": \"0x1AC380\", \"reason\": \"deferred queue drain\"},");
    sb.AppendLine("    {\"rva\": \"0x2E97B60\", \"reason\": \"LOD enqueue helper\"},");
    sb.AppendLine("    {\"rva\": \"0x2E97FC0\", \"reason\": \"LOD enqueue wrapper\"},");
    sb.AppendLine("    {\"rva\": \"0xE95E80\", \"reason\": \"side-block allocator\"},");
    sb.AppendLine("    {\"rva\": \"0x426EE50\", \"reason\": \"generic allocator\"},");
    sb.AppendLine("    {\"rva\": \"0x80F2330\", \"reason\": \"SpawnCharacterParams schema visitor\"},");
    sb.AppendLine("    {\"rva\": \"0x8DFFB90\", \"reason\": \"SpawnEntityParams schema visitor\"},");
    sb.AppendLine("    {\"rva\": \"0x8E02960\", \"reason\": \"SpawnEntityBuilderParams schema visitor\"}");
    sb.AppendLine("  ],");
    sb.AppendLine("  \"strings\": [" + string.Join(", ", hits.Select(h =>
      "{\"needle\": " + J(h.Needle) + ", \"rva\": \"0x" + h.Rva.ToString("X") + "\", \"text\": " + J(Trunc(h.Text, 72)) + "}")) + "],");
    sb.AppendLine("  \"leaSites\": [" + string.Join(", ", leas.Take(40).Select(s =>
      "{\"needle\": " + J(s.Item1) + ", \"site\": \"0x" + s.Item2.ToString("X") + "\", \"func\": \"0x" + s.Item3.ToString("X") + "\"}")) + "],");
    sb.AppendLine("  \"functions\": [");
    for (int i = 0; i < reps.Count; i++) {
      var r = reps[i];
      sb.AppendLine("    {\"entry\": \"0x" + r.Entry.ToString("X") + "\", \"class\": " + J(r.Klass)
        + ", \"callsSchema\": " + T(r.CallsSchema)
        + ", \"callsAlloc\": " + T(r.CallsAlloc)
        + ", \"callsVisitor\": " + T(r.CallsVisitor)
        + ", \"leasParams\": " + T(r.LeasParams)
        + ", \"strings\": [" + string.Join(", ", r.Strings.Distinct().Take(6).Select(J)) + "]"
        + ", \"callees\": [" + string.Join(", ", r.Callees.Distinct().Take(16).Select(c => "\"0x" + c.ToString("X") + "\"")) + "]}");
      if (i + 1 < reps.Count) { /* comma already not needed if we add it */ }
    }
    // Fix trailing commas by rewriting simply: the loop above omitted commas between objects.
    // Emit a compact valid array instead.
    sb.Clear();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.8.0\",");
    sb.AppendLine("  \"mode\": \"offline-pe-readonly\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"nativeSpawnConfirmed\": false,");
    sb.AppendLine("  \"schemaVisitorsConfirmed\": " + schemaVisitors + ",");
    sb.AppendLine("  \"factoryCandidateCount\": " + factories.Count + ",");
    sb.AppendLine("  \"missingLink\": " + J("A caller that fills SpawnEntityBuilderParams and invokes entity creation. The three *Params functions register schema names through 0x4572C60 and are not character factories.") + ",");
    sb.AppendLine("  \"excludedAsFactory\": [");
    string[] excl = {
      "0x1AC380|deferred queue drain",
      "0x2E97B60|LOD enqueue helper",
      "0x2E97FC0|LOD enqueue wrapper",
      "0xE95E80|side-block allocator",
      "0x426EE50|generic allocator",
      "0x80F2330|SpawnCharacterParams schema visitor",
      "0x8DFFB90|SpawnEntityParams schema visitor",
      "0x8E02960|SpawnEntityBuilderParams schema visitor"
    };
    for (int i = 0; i < excl.Length; i++) {
      var parts = excl[i].Split('|');
      sb.Append("    {\"rva\": \"" + parts[0] + "\", \"reason\": " + J(parts[1]) + "}");
      sb.AppendLine(i + 1 < excl.Length ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"strings\": [");
    for (int i = 0; i < hits.Count; i++) {
      var h = hits[i];
      sb.Append("    {\"needle\": " + J(h.Needle) + ", \"rva\": \"0x" + h.Rva.ToString("X")
        + "\", \"text\": " + J(Trunc(h.Text, 72)) + "}");
      sb.AppendLine(i + 1 < hits.Count ? "," : "");
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"functions\": [");
    for (int i = 0; i < reps.Count; i++) {
      var r = reps[i];
      sb.Append("    {\"entry\": \"0x" + r.Entry.ToString("X") + "\", \"class\": " + J(r.Klass)
        + ", \"callsSchema\": " + T(r.CallsSchema)
        + ", \"callsAlloc\": " + T(r.CallsAlloc)
        + ", \"callsVisitor\": " + T(r.CallsVisitor)
        + ", \"leasParams\": " + T(r.LeasParams)
        + ", \"strings\": [" + string.Join(", ", r.Strings.Distinct().Take(6).Select(J)) + "]"
        + ", \"callees\": [" + string.Join(", ", r.Callees.Distinct().Take(16).Select(c => "\"0x" + c.ToString("X") + "\"")) + "]}");
      sb.AppendLine(i + 1 < reps.Count ? "," : "");
    }
    sb.AppendLine("  ]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-spawn-callers.json"), sb.ToString());
    Console.WriteLine("WROTE reports/v0.8.0-spawn-callers.json");
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
    while (dec.IP < limit && guard++ < 2000) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      if (raw.IP < imageBase) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      var ins = new Ins {
        Rva = (uint)(raw.IP - imageBase), Text = o.ToString(),
        Mnemonic = raw.Mnemonic, Length = raw.Length,
        IsCall = raw.FlowControl == FlowControl.Call || raw.FlowControl == FlowControl.IndirectCall,
        IsIndirectCall = raw.FlowControl == FlowControl.IndirectCall,
        IsRet = raw.Mnemonic == Mnemonic.Ret
      };
      if (ins.IsCall && !ins.IsIndirectCall && raw.NearBranchTarget != 0 && raw.NearBranchTarget >= imageBase)
        ins.NearTarget = (uint)(raw.NearBranchTarget - imageBase);
      for (int oi = 0; oi < raw.OpCount; oi++) {
        var kind = raw.GetOpKind(oi);
        if (kind == OpKind.Immediate8 || kind == OpKind.Immediate8to32 || kind == OpKind.Immediate32
            || kind == OpKind.Immediate32to64 || kind == OpKind.Immediate64 || kind == OpKind.Immediate8to64
            || kind == OpKind.Immediate16 || kind == OpKind.Immediate8to16) {
          ins.HasImm = true;
          try { ins.Imm = raw.GetImmediate(oi); } catch { }
        }
        if (kind != OpKind.Memory || !raw.IsIPRelativeMemoryOperand) continue;
        ins.IpRel = true;
        ulong va = raw.IPRelativeMemoryAddress;
        if (va >= imageBase) ins.DataRva = (uint)(va - imageBase);
      }
      list.Add(ins);
      if (ins.Mnemonic == Mnemonic.Int3) break;
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
    return list.Count > 0 ? list[list.Count - 1].Rva + (uint)list[list.Count - 1].Length : entry + 0x20;
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
        if (pe[s.Ptr + i + off] != 0x8D) continue;
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
        || s.Name.IndexOf("text", StringComparison.OrdinalIgnoreCase) >= 0
        || s.Name.IndexOf("code", StringComparison.OrdinalIgnoreCase) >= 0;
      if (ok) yield return s;
    }
  }

  static uint FindFuncStart(uint site) {
    int fo = RvaToFile(site);
    if (fo < 0) return 0;
    int back = Math.Min(fo, 0x4000);
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

  static uint FileToRva(int fileOff) {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      if (fileOff >= s.Ptr && fileOff < s.Ptr + s.Raw)
        return s.Va + (uint)(fileOff - s.Ptr);
    }
    return 0;
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
