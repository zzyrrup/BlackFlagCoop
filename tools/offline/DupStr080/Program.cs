// Follow Duplicate / ObjectID string LEAs for C1 role proof.
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

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string root = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn";
    pe = File.ReadAllBytes(exe);
    string hash = Sha(pe);
    if (!hash.Equals(Expected, StringComparison.OrdinalIgnoreCase)) { Console.Error.WriteLine("hash mismatch"); return 2; }
    Parse();
    var sb = new StringBuilder();
    sb.AppendLine("===== Duplicate / ObjectID string LEA hunt =====");
    sb.AppendLine("exeSha256=" + hash);

    foreach (string needle in new[] { "Duplicate", "ObjectID", "ObjectId", "objectId" }) {
      var hits = Find(needle);
      sb.AppendLine();
      sb.AppendLine("## needle=" + needle + " hits=" + hits.Count);
      foreach (uint rva in hits) {
        string text = Asc(rva, 96);
        sb.AppendLine("str=0x" + rva.ToString("X") + " text=" + Trunc(text, 96));
        var leas = FindLea(rva, 24);
        sb.AppendLine("  leaCount=" + leas.Count);
        foreach (uint site in leas) {
          uint fs = FuncStart(site);
          sb.AppendLine("  lea=0x" + site.ToString("X") + " func=0x" + fs.ToString("X"));
          Dump(sb, site, 0x40, 0x80, "lea");
          // E8 callers of func
          var callers = FindE8(fs, 12);
          sb.AppendLine("  E8_callers=" + callers.Count);
          foreach (uint c in callers.Take(6))
            sb.AppendLine("    callerSite=0x" + c.ToString("X") + " callerFunc=0x" + FuncStart(c).ToString("X"));
        }
      }
    }

    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    sb.AppendLine("c1Proven=false");
    sb.AppendLine("callEngine=off");
    sb.AppendLine("note=Duplicate string present; classify LEA funcs as type-name vs method vs UI");
    string dir = Path.Combine(root, "reports", "v080-role-hunt-raw");
    Directory.CreateDirectory(dir);
    File.WriteAllText(Path.Combine(dir, "dup-strings.txt"), sb.ToString());
    Console.WriteLine(sb.ToString());
    return 0;
  }

  static List<uint> Find(string n) {
    var list = new List<uint>();
    byte[] pat = Encoding.ASCII.GetBytes(n);
    int from = 0, g = 0;
    while (from < pe.Length && g++ < 64) {
      int at = pe.AsSpan(from).IndexOf(pat);
      if (at < 0) break;
      at += from;
      if (at > 0) { byte p = pe[at - 1]; if (p != 0 && p >= 32 && p < 127) { from = at + 1; continue; } }
      // Prefer whole-ish tokens: next char not letter for exact "Duplicate" role names
      uint rva = FileToRva(at);
      if (rva != 0) list.Add(rva);
      from = at + pat.Length;
    }
    return list;
  }

  static List<uint> FindLea(uint target, int max) {
    var list = new List<uint>();
    foreach (var s in CodeSecs()) {
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim && list.Count < max; i++) {
        int off = 0;
        byte b0 = pe[s.Ptr + i];
        if (b0 == 0x48 || b0 == 0x4C || b0 == 0x49 || b0 == 0x4D) off = 1;
        if (pe[s.Ptr + i + off] != 0x8D) continue;
        if ((pe[s.Ptr + i + off + 1] & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + off + 2));
        uint site = s.Va + i;
        uint len = (uint)(off + 6);
        if (unchecked((uint)(site + len + disp)) == target) list.Add(site);
      }
    }
    return list;
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

  static void Dump(StringBuilder sb, uint center, int before, int after, string label) {
    uint start = center > (uint)before ? center - (uint)before : center;
    sb.AppendLine("  --- " + label + " @0x" + center.ToString("X") + " ---");
    int fo = RvaToFile(start);
    if (fo < 0) return;
    var reader = new ByteArrayCodeReader(pe); reader.Position = fo;
    var dec = Decoder.Create(64, reader); dec.IP = ib + start;
    ulong lim = ib + center + (uint)after; int g = 0;
    while (dec.IP < lim && g++ < 40) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      var o = new StringOutput(); Fmt.Format(raw, o);
      uint rva = (uint)(raw.IP - ib);
      string ex = "";
      for (int oi = 0; oi < raw.OpCount; oi++) {
        if (raw.GetOpKind(oi) != OpKind.Memory || !raw.IsIPRelativeMemoryOperand) continue;
        ulong va = raw.IPRelativeMemoryAddress;
        if (va >= ib) {
          uint dr = (uint)(va - ib);
          string s = Asc(dr, 48);
          ex = s.Length >= 4 ? "  ;str=" + Trunc(s, 48) : "  ;data=0x" + dr.ToString("X");
        }
      }
      if (raw.FlowControl == FlowControl.Call && raw.NearBranchTarget != 0)
        ex += "  ;call=0x" + ((uint)(raw.NearBranchTarget - ib)).ToString("X");
      sb.AppendLine("  0x" + rva.ToString("X") + " " + Trunc(o.ToString(), 90) + ex);
      if (raw.Mnemonic == Mnemonic.Int3 || raw.Mnemonic == Mnemonic.Ret) break;
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
  static string Asc(uint rva, int max) {
    int fo = RvaToFile(rva); if (fo < 0) return "";
    var sb = new StringBuilder();
    for (int i = 0; i < max && fo + i < pe.Length; i++) {
      byte b = pe[fo + i]; if (b == 0) break;
      if (b >= 32 && b < 127) sb.Append((char)b); else return sb.Length >= 4 ? sb.ToString() : "";
    }
    return sb.ToString();
  }
  static string Trunc(string s, int n) => s.Length <= n ? s : s.Substring(0, n);
  static int RvaToFile(uint rva) {
    foreach (var s in secs) { uint sp = Math.Max(s.VSize, s.Raw); if (rva >= s.Va && rva < s.Va + sp && s.Ptr > 0) return (int)s.Ptr + (int)(rva - s.Va); }
    return -1;
  }
  static uint FileToRva(int fo) {
    foreach (var s in secs) if (s.Ptr > 0 && fo >= s.Ptr && fo < s.Ptr + s.Raw) return s.Va + (uint)(fo - s.Ptr);
    return 0;
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
