// v0.6.6 — Offline scan for deferred-queue producers (stores into +0xAC0 / +0xAC8).
// Read-only PE analysis. No launch, inject, hook, or game writes.
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;

internal static class Program {
  const string ExpectedExeSha =
    "19920F34BB2FAC814023EE3C27F0CECA1872E80A2AAFB37C092C419FFF77CC0D";
  const uint Handler = 0x1AC380;
  const uint HandlerEnd = 0x1AC61F;
  const int OffArray = 0xAC0;
  const int OffCount = 0xAC8;
  const string ReportsRoot = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports";

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);

  sealed class Sec {
    public string Name;
    public uint Va, VSize, Raw, Ptr, Char;
  }

  sealed class Hit {
    public uint Rva;
    public string How;
    public int Disp;
    public string Field;
    public string Text;
    public uint FuncStart;
    public string Section;
    public bool InHandler;
    public List<string> Context = new List<string>();
    public List<string> NearbyStrings = new List<string>();
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v066-raw");
    pe = File.ReadAllBytes(exe);
    string hash = Sha256Hex(pe);
    Console.WriteLine("exeSha256=" + hash);
    if (!hash.Equals(ExpectedExeSha, StringComparison.OrdinalIgnoreCase)) {
      Console.Error.WriteLine("REFUSING: EXE hash mismatch.");
      return 2;
    }
    ParsePe();
    Directory.CreateDirectory(outDir);

    var hits = ScanByDispPattern();
    Console.WriteLine("verifiedHits=" + hits.Count);

    int handlerLoads = 0;
    foreach (var h in hits) if (h.InHandler && h.How == "load") handlerLoads++;
    Console.WriteLine("handlerLoadHits=" + handlerLoads);
    if (handlerLoads < 2) {
      Console.Error.WriteLine("Self-test failed: expected handler loads of +AC0/+AC8.");
      return 4;
    }

    var stores = Filter(hits, "store");
    var leas = Filter(hits, "lea");
    var loads = Filter(hits, "load");
    var outsideLoads = new List<Hit>();
    foreach (var h in loads) if (!h.InHandler) outsideLoads.Add(h);
    Console.WriteLine("stores=" + stores.Count + " leas=" + leas.Count
      + " loads=" + loads.Count + " outsideLoads=" + outsideLoads.Count);

    Enrich(stores);
    Enrich(leas);
    Enrich(outsideLoads, 60);

    var sb = new StringBuilder();
    sb.AppendLine("===== v0.6.6 QUEUE PRODUCER SCAN =====");
    sb.AppendLine("exeSha256=" + hash);
    sb.AppendLine("imageBase=0x" + imageBase.ToString("X"));
    sb.AppendLine("handler=[0x" + Handler.ToString("X") + ",0x" + HandlerEnd.ToString("X") + ")");
    sb.AppendLine("method=disp32_pattern_then_iced_verify");
    sb.AppendLine("verifiedHits=" + hits.Count + " stores=" + stores.Count
      + " leas=" + leas.Count + " loads=" + loads.Count);
    sb.AppendLine();
    sb.AppendLine("===== STORES to +0xAC0 / +0xAC8 =====");
    DumpHits(sb, stores);
    sb.AppendLine();
    sb.AppendLine("===== LEAs of +0xAC0 / +0xAC8 =====");
    DumpHits(sb, leas);
    sb.AppendLine();
    sb.AppendLine("===== NON-HANDLER LOADS =====");
    DumpHits(sb, outsideLoads);
    sb.AppendLine();
    sb.AppendLine("===== STRING XREFS =====");
    WriteStringLeads(sb, "CreateActorsDeferredSingleThreaded");

    string path = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path + " chars=" + sb.Length);
    WriteSummaryJson(Path.Combine(ReportsRoot, "v0.6.6-producer-scan-summary.json"),
      hash, stores, leas, outsideLoads);
    return 0;
  }

  static List<Hit> Filter(List<Hit> hits, string how) {
    var list = new List<Hit>();
    foreach (var h in hits) if (h.How == how) list.Add(h);
    return list;
  }

  static void DumpHits(StringBuilder sb, List<Hit> hits) {
    if (hits.Count == 0) { sb.AppendLine("(none)"); return; }
    foreach (var h in hits) {
      sb.AppendLine("HIT 0x" + h.Rva.ToString("X")
        + " " + h.How + " field=" + h.Field + " disp=0x" + h.Disp.ToString("X")
        + " func=0x" + h.FuncStart.ToString("X")
        + " sec=" + h.Section
        + (h.InHandler ? " IN_HANDLER" : "")
        + " :: " + h.Text);
      foreach (var c in h.Context) sb.AppendLine("  | " + c);
      foreach (var s in h.NearbyStrings) sb.AppendLine("  str " + s);
    }
  }

  // Find little-endian 0x00000AC0 / 0x00000AC8 as disp32, then verify with Iced
  // by trying instruction starts a few bytes before the displacement.
  static List<Hit> ScanByDispPattern() {
    var list = new List<Hit>();
    var seen = new HashSet<uint>();
    byte[][] needles = {
      new byte[] { 0xC0, 0x0A, 0x00, 0x00 }, // 0xAC0
      new byte[] { 0xC8, 0x0A, 0x00, 0x00 }  // 0xAC8
    };
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 4; i + 4 <= lim; i++) {
        int which = -1;
        for (int n = 0; n < needles.Length; n++) {
          bool ok = true;
          for (int k = 0; k < 4; k++) if (pe[s.Ptr + i + k] != needles[n][k]) { ok = false; break; }
          if (ok) { which = n; break; }
        }
        if (which < 0) continue;

        // ModRM should sit immediately before disp32 for mod=10 encodings.
        // Try instruction starts from disp-1-15 .. disp-1 (prefixes/REX/opcode/modrm).
        uint dispRva = s.Va + i;
        for (int back = 1; back <= 16; back++) {
          if (i < (uint)back) break;
          uint tryRva = dispRva - (uint)back;
          if (!seen.Add(tryRva)) continue;
          if (!TryDecodeAt(tryRva, out Hit hit)) { seen.Remove(tryRva); continue; }
          if (hit.Disp != OffArray && hit.Disp != OffCount) { seen.Remove(tryRva); continue; }
          // Ensure this decode actually consumed the disp bytes we found.
          if (hit.Rva + EstimateLen(tryRva) < dispRva + 4 && hit.Rva > dispRva) {
            seen.Remove(tryRva); continue;
          }
          hit.Section = s.Name;
          hit.InHandler = hit.Rva >= Handler && hit.Rva < HandlerEnd;
          hit.Field = hit.Disp == OffArray ? "arrayBase" : "count";
          list.Add(hit);
          break;
        }
      }
    }
    list.Sort((a, b) => a.Rva.CompareTo(b.Rva));
    return Dedup(list);
  }

  static List<Hit> Dedup(List<Hit> hits) {
    var outList = new List<Hit>();
    var keys = new HashSet<string>();
    foreach (var h in hits) {
      string k = h.Rva.ToString("X") + ":" + h.How + ":" + h.Disp.ToString("X");
      if (keys.Add(k)) outList.Add(h);
    }
    return outList;
  }

  static int EstimateLen(uint rva) {
    int fo = RvaToFile(rva);
    if (fo < 0) return 0;
    var reader = new ByteArrayCodeReader(pe);
    reader.Position = fo;
    var dec = Decoder.Create(64, reader);
    dec.IP = imageBase + rva;
    var raw = dec.Decode();
    return raw.Length;
  }

  static bool TryDecodeAt(uint rva, out Hit hit) {
    hit = null;
    int fo = RvaToFile(rva);
    if (fo < 0) return false;
    var reader = new ByteArrayCodeReader(pe);
    reader.Position = fo;
    var dec = Decoder.Create(64, reader);
    dec.IP = imageBase + rva;
    var raw = dec.Decode();
    if (raw.Length == 0 || raw.Code == Code.INVALID) return false;
    if ((uint)(raw.IP - imageBase) != rva) return false;
    if (!TryMemDisp(raw, out int disp, out int memOp)) return false;
    if (disp != OffArray && disp != OffCount) return false;

    var o = new StringOutput();
    Fmt.Format(raw, o);
    hit = new Hit {
      Rva = rva,
      How = Classify(raw, memOp),
      Disp = disp,
      Text = o.ToString()
    };
    return true;
  }

  static bool TryMemDisp(Instruction raw, out int disp, out int memOp) {
    disp = 0; memOp = -1;
    for (int i = 0; i < raw.OpCount; i++) {
      if (raw.GetOpKind(i) != OpKind.Memory) continue;
      if (raw.IsIPRelativeMemoryOperand) continue;
      long d;
      int sz = raw.MemoryDisplSize;
      if (sz == 1) d = unchecked((sbyte)raw.MemoryDisplacement32);
      else if (sz == 2) d = unchecked((short)raw.MemoryDisplacement32);
      else if (sz == 4) d = unchecked((int)raw.MemoryDisplacement32);
      else if (sz == 8) d = unchecked((long)raw.MemoryDisplacement64);
      else continue;
      if (d != OffArray && d != OffCount) continue;
      // Prefer encodings that actually use a base register (not absolute).
      if (raw.MemoryBase == Register.None && raw.MemoryIndex == Register.None) continue;
      disp = (int)d;
      memOp = i;
      return true;
    }
    return false;
  }

  static string Classify(Instruction raw, int memOp) {
    if (raw.Mnemonic == Mnemonic.Lea) return "lea";
    if (raw.Mnemonic == Mnemonic.Cmp || raw.Mnemonic == Mnemonic.Test) return "cmp";
    if (memOp == 0) return "store";
    return "load";
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

  static void Enrich(List<Hit> hits, int max = int.MaxValue) {
    int n = 0;
    foreach (var h in hits) {
      if (n++ >= max) break;
      h.FuncStart = FindFuncStart(h.Rva);
      h.Context = Window(h.FuncStart == 0 ? (h.Rva > 40 ? h.Rva - 40 : h.Rva) : h.FuncStart, h.Rva, 12, 10);
      h.NearbyStrings = NearbyStrings(h.FuncStart == 0 ? h.Rva : h.FuncStart, 0xA00);
    }
  }

  static List<string> Window(uint start, uint focus, int before, int after) {
    var list = new List<string>();
    // Decode from a nearby pad-aligned start when possible.
    uint decodeFrom = focus > 0x80 ? focus - 0x80 : focus;
    if (start != 0 && start < focus && focus - start < 0x2000) decodeFrom = start;
    var ins = DisasmRange(decodeFrom, focus + 0x50);
    int idx = -1;
    for (int i = 0; i < ins.Count; i++) if (ins[i].Item1 == focus) { idx = i; break; }
    if (idx < 0) {
      // Fall back: decode exactly at focus for one insn.
      int fo = RvaToFile(focus);
      if (fo >= 0) {
        var reader = new ByteArrayCodeReader(pe);
        reader.Position = fo;
        var dec = Decoder.Create(64, reader);
        dec.IP = imageBase + focus;
        var raw = dec.Decode();
        var o = new StringOutput();
        Fmt.Format(raw, o);
        list.Add(">> 0x" + focus.ToString("X") + " " + o);
      }
      return list;
    }
    int from = Math.Max(0, idx - before);
    int to = Math.Min(ins.Count, idx + after + 1);
    for (int i = from; i < to; i++) {
      string mark = ins[i].Item1 == focus ? ">> " : "   ";
      list.Add(mark + "0x" + ins[i].Item1.ToString("X") + " " + ins[i].Item2);
    }
    return list;
  }

  static List<string> NearbyStrings(uint entry, int maxBytes) {
    var found = new List<string>();
    int fo = RvaToFile(entry);
    if (fo < 0) return found;
    var reader = new ByteArrayCodeReader(pe);
    reader.Position = fo;
    var dec = Decoder.Create(64, reader);
    dec.IP = imageBase + entry;
    ulong limit = imageBase + entry + (uint)maxBytes;
    int guard = 0;
    while (dec.IP < limit && guard++ < 5000 && found.Count < 10) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      if (!raw.IsIPRelativeMemoryOperand) continue;
      ulong va = raw.IPRelativeMemoryAddress;
      if (va < imageBase) continue;
      uint dr = (uint)(va - imageBase);
      string s = ReadAscii(dr, 72);
      if (!IsString(s)) continue;
      string line = "0x" + ((uint)(raw.IP - imageBase)).ToString("X") + " \"" + Trunc(s, 70) + "\"";
      if (!found.Contains(line)) found.Add(line);
    }
    return found;
  }

  static List<(uint, string)> DisasmRange(uint start, uint endExclusive) {
    var list = new List<(uint, string)>();
    int fo = RvaToFile(start);
    if (fo < 0) return list;
    var reader = new ByteArrayCodeReader(pe);
    reader.Position = fo;
    var dec = Decoder.Create(64, reader);
    dec.IP = imageBase + start;
    ulong limit = imageBase + endExclusive;
    int guard = 0;
    while (dec.IP < limit && guard++ < 30000) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      if (raw.IP < imageBase) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      list.Add(((uint)(raw.IP - imageBase), o.ToString()));
      if (raw.Mnemonic == Mnemonic.Int3 && list.Count > 1) break;
    }
    return list;
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

  static void WriteStringLeads(StringBuilder sb, string needle) {
    var sites = FindAscii(needle, 10);
    sb.AppendLine("ascii \"" + Trunc(needle, 50) + "\" hits=" + sites.Count);
    foreach (var rva in sites) {
      sb.AppendLine("  str@0x" + rva.ToString("X") + " sec=" + SecName(rva));
      foreach (var c in FindLeaToData(rva, 20)) {
        sb.AppendLine("    lea/code 0x" + c.ToString("X") + " func=0x" + FindFuncStart(c).ToString("X")
          + " sec=" + SecName(c));
      }
    }
  }

  static List<uint> FindAscii(string s, int max) {
    var list = new List<uint>();
    byte[] n = Encoding.ASCII.GetBytes(s);
    foreach (var sec in secs) {
      if (sec.Ptr == 0) continue;
      uint lim = Math.Min(sec.Raw, sec.VSize > 0 ? sec.VSize : sec.Raw);
      for (uint i = 0; i + (uint)n.Length <= lim && list.Count < max; i++) {
        bool ok = true;
        for (int k = 0; k < n.Length; k++) if (pe[sec.Ptr + i + k] != n[k]) { ok = false; break; }
        if (ok) list.Add(sec.Va + i);
      }
    }
    return list;
  }

  static List<uint> FindLeaToData(uint target, int max) {
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
        uint tgt = unchecked((uint)(site + len + disp));
        if (tgt == target) list.Add(site);
      }
    }
    return list;
  }

  static void WriteSummaryJson(string path, string hash, List<Hit> stores, List<Hit> leas, List<Hit> loads) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.6\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"method\": \"disp32_pattern_then_iced_verify\",");
    sb.AppendLine("  \"storeCount\": " + stores.Count + ",");
    sb.AppendLine("  \"leaCount\": " + leas.Count + ",");
    sb.AppendLine("  \"outsideLoadCount\": " + loads.Count + ",");
    AppendHitArray(sb, "stores", stores);
    sb.AppendLine(",");
    AppendHitArray(sb, "leas", leas);
    sb.AppendLine(",");
    AppendHitArray(sb, "outsideLoads", loads);
    sb.AppendLine();
    sb.AppendLine("}");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path);
  }

  static void AppendHitArray(StringBuilder sb, string name, List<Hit> hits) {
    sb.AppendLine("  \"" + name + "\": [");
    for (int i = 0; i < hits.Count; i++) {
      var h = hits[i];
      sb.Append("    { \"rva\": \"0x" + h.Rva.ToString("X")
        + "\", \"field\": \"" + h.Field
        + "\", \"func\": \"0x" + h.FuncStart.ToString("X")
        + "\", \"inHandler\": " + (h.InHandler ? "true" : "false")
        + ", \"text\": " + JsonStr(h.Text) + " }");
      sb.AppendLine(i + 1 < hits.Count ? "," : "");
    }
    sb.Append("  ]");
  }

  static string JsonStr(string s) {
    if (s == null) return "null";
    return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
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

  static string Trunc(string s, int n) {
    if (s == null) return "";
    return s.Length <= n ? s : s.Substring(0, n);
  }

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
