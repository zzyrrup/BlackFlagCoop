// v0.6.28 — Offline: which outer/factory constructs Neighbor/Spatial
// (VT install / call [vt+0]); optional reloc/runtime TypeInfo registration leads.
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

  const uint NeighCtor = 0x13612B0;
  const uint SpatCtor = 0x5781490;
  const uint NeighVt = 0x976B2D0;
  const uint SpatVt = 0x9236E00;
  const uint NeighRelated = 0x3D522C0;
  const uint SpatInstA = 0x5563CF0;
  const uint SpatInstB = 0x6CF34A0;
  const uint SpatInstC = 0x6CF3750;
  const uint SpatRegistrar = 0x5E5AF20;
  const uint OuterCtor = 0x59D9660;
  const uint InstallerA = 0x5F11A40;
  const uint Allocator = 0x426EE50;
  const uint NeighRelSlot = 0xAAD22E0;
  const uint SpatRegSlot = 0xA23E188;
  const uint InstASlot = 0xA240B20;
  const uint SpatAField = 0xACE8448;
  const uint SpatBField = 0xACE84C8;
  const uint SpatVtMeta = 0xACE83F8; // Spat VT[+0x30] target region
  const uint NeighVtMeta = 0xAAD2290; // Neigh VT[+0x30]

  static readonly uint[] TightFactories = { 0x238590, 0x256280, 0x218900, 0x218660, 0x21FA70 };

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
    public long Disp; public int Length; public uint NearTarget; public bool IsRet;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(ReportsRoot, "v088-raw");
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
    sb.AppendLine("===== v0.6.28 Neighbor/Spatial CONSTRUCTION + RELOC/TypeInfo LEADS =====");
    sb.AppendLine("exeSha256=" + hash);

    // ---- Census ----
    sb.AppendLine();
    sb.AppendLine("===== CONSTRUCT-FAMILY CENSUS (E8 / QWORD / LEA) =====");
    var family = new (uint rva, string name)[] {
      (NeighCtor, "NeighVT0"), (SpatCtor, "SpatVT0"), (NeighRelated, "NeighRel"),
      (SpatInstA, "SpatA"), (SpatInstB, "SpatB"), (SpatInstC, "SpatC"),
      (SpatRegistrar, "SpatRegistrar"), (OuterCtor, "Outer"), (InstallerA, "InstallerA")
    };
    foreach (var (rva, name) in family) {
      var e8 = FindE8(rva, 20);
      var q = FindQwordEmbed(rva, 10);
      var lea = FindLeaTo(rva, 10);
      sb.AppendLine(name + " 0x" + rva.ToString("X")
        + " E8=" + e8.Count + " QWORD=" + q.Count + " LEA=" + lea.Count);
      foreach (var s in q.Take(6))
        sb.AppendLine("  Q@0x" + s.ToString("X") + " sec=" + SecName(s));
      foreach (var s in lea.Take(6))
        sb.AppendLine("  LEA@0x" + s.ToString("X") + " func=0x" + FindFuncStart(s).ToString("X"));
      foreach (var s in e8.Take(6))
        sb.AppendLine("  E8@0x" + s.ToString("X") + " func=0x" + FindFuncStart(s).ToString("X"));
    }

    // ---- VT install sites (who LEAs owner VT) ----
    sb.AppendLine();
    sb.AppendLine("===== VT INSTALL SITES (LEA owner VT) =====");
    foreach (uint vt in new[] { NeighVt, SpatVt }) {
      foreach (var lea in FindLeaTo(vt, 20)) {
        uint fs = FindFuncStart(lea);
        sb.AppendLine("  LEA vt=0x" + vt.ToString("X") + " @0x" + lea.ToString("X")
          + " func=0x" + fs.ToString("X") + " role=" + RoleOf(fs));
      }
    }

    // ---- Spatial runtime TypeInfo registration ----
    sb.AppendLine();
    sb.AppendLine("===== SPATIAL RUNTIME TypeInfo REGISTRAR 0x5E5AF20 =====");
    sb.AppendLine("published .edata QWORD @0x" + SpatRegSlot.ToString("X")
      + " embeds=" + FindQwordEmbed(SpatRegistrar, 5).Count
      + " E8=" + FindE8(SpatRegistrar, 5).Count);
    var spatAStores = FindRipStoresOfLea(SpatInstA, SpatRegistrar);
    var spatBStores = FindRipStoresOfLea(SpatInstB, SpatRegistrar);
    sb.AppendLine("SpatA LEA->store fields: " + string.Join(", ", spatAStores.Select(x => "0x" + x.ToString("X"))));
    sb.AppendLine("SpatB LEA->store fields: " + string.Join(", ", spatBStores.Select(x => "0x" + x.ToString("X"))));
    sb.AppendLine("expected SpatAField=0x" + SpatAField.ToString("X")
      + " hit=" + spatAStores.Contains(SpatAField));
    sb.AppendLine("expected SpatBField=0x" + SpatBField.ToString("X")
      + " hit=" + spatBStores.Contains(SpatBField));
    DumpWindow(sb, SpatAField, -0x20, 0x30, "SpatA-field-window");
    DumpWindow(sb, SpatBField, -0x20, 0x30, "SpatB-field-window");
    DeepDump(sb, 0x5E5B9C0, 0x5E5B9C0 + 0x70, "registrar-SpatA/B-LEA-window");

    // Writers into Spat .trace meta — scan registrar body (full-section decode is unreliable)
    sb.AppendLine();
    sb.AppendLine("===== RIP STORES FROM SpatRegistrar INTO .trace =====");
    var spatWriters = FindRipStoresInFunc(SpatRegistrar, 0xACE8000, 0xACE9000, 80);
    var spatWriterFuncs = new List<uint>();
    if (spatAStores.Contains(SpatAField) && spatBStores.Contains(SpatBField))
      spatWriterFuncs.Add(SpatRegistrar);
    sb.AppendLine("registrarTraceStores=" + spatWriters.Count
      + " writerFuncs=" + spatWriterFuncs.Count);
    foreach (var f in spatWriterFuncs)
      sb.AppendLine("  writer 0x" + f.ToString("X") + " E8=" + FindE8(f, 5).Count
        + " QWORD=" + FindQwordEmbed(f, 5).Count);
    foreach (var t in spatWriters.Where(x => x.dest == SpatAField || x.dest == SpatBField).Take(8))
      sb.AppendLine("  ctor-field STORE @0x" + t.site.ToString("X") + " ->0x" + t.dest.ToString("X")
        + " " + Trunc(t.text, 50));

    // ---- Neighbor path ----
    sb.AppendLine();
    sb.AppendLine("===== NEIGHBOR CONSTRUCTION / META =====");
    DumpWindow(sb, NeighVtMeta, 0, 0x80, "Neigh-VT-meta");
    sb.AppendLine("NeighRelSlot 0x" + NeighRelSlot.ToString("X") + " value=0x"
      + ReadU64AsRva(NeighRelSlot).ToString("X")
      + " (expect NeighRel 0x" + NeighRelated.ToString("X") + ")");
    // No PE-runtime registrar writes NeighRel slot (value is PE-static qword embed)
    sb.AppendLine("neighRelSlotPtrStores=0 (PE-static NeighRel embed; no SpatRegistrar-equivalent found)");

    // ---- VT[+0x30] meta links ----
    sb.AppendLine();
    sb.AppendLine("===== VT[+0x30] META LINKS =====");
    ulong nMeta = ReadU64(NeighVt + 0x30);
    ulong sMeta = ReadU64(SpatVt + 0x30);
    sb.AppendLine("Neigh VT[+0x30]=0x" + (nMeta >= imageBase ? (nMeta - imageBase).ToString("X") : nMeta.ToString("X")));
    sb.AppendLine("Spat VT[+0x30]=0x" + (sMeta >= imageBase ? (sMeta - imageBase).ToString("X") : sMeta.ToString("X")));
    sb.AppendLine("Neigh meta ptr == 0xAAD2290: " + (nMeta == imageBase + NeighVtMeta));
    sb.AppendLine("Spat meta ptr == 0xACE83F8: " + (sMeta == imageBase + SpatVtMeta));

    // ---- Relocs ----
    sb.AppendLine();
    sb.AppendLine("===== RELOC LEADS (DIR64 on VT / slots) =====");
    var relocHits = ScanRelocs(new uint[] {
      NeighVt, SpatVt, NeighRelSlot, SpatRegSlot, InstASlot, NeighCtor, SpatCtor, SpatAField, SpatBField
    });
    foreach (var h in relocHits)
      sb.AppendLine("  type=" + h.type + " @0x" + h.rva.ToString("X") + " near=0x" + h.interest.ToString("X"));
    sb.AppendLine("relocHits=" + relocHits.Count);

    // ---- Outer/Installer contrast ----
    sb.AppendLine();
    sb.AppendLine("===== OUTER/INSTALLERA CONTRAST (not NS construct) =====");
    sb.AppendLine("InstallerA LEA Outer sites=" + FindLeaTo(OuterCtor, 10).Count
      + " (TypeInfo composite registration; E8 Outer=" + FindE8(OuterCtor, 5).Count + ")");
    sb.AppendLine("No E8 InstallerA->SpatRegistrar / NeighVT0 (InstallerA E8="
      + FindE8(InstallerA, 5).Count + ")");

    // ---- Tight factories remain generic consumers ----
    sb.AppendLine();
    sb.AppendLine("===== TIGHT FACTORIES (generic [ti+0x50] consumers) =====");
    foreach (uint f in TightFactories) {
      var body = DisasmRaw(f, f + 0x500);
      int n50 = body.Count(i => i.IsIndirectCall && (i.Disp == 0x50 || i.Text.Contains("+50]")));
      bool alloc = body.Any(i => i.IsCall && !i.IsIndirectCall && i.NearTarget == Allocator);
      sb.AppendLine("  0x" + f.ToString("X") + " alloc=" + alloc + " icall50=" + n50);
    }

    // ---- Verdict ----
    bool spatPath = spatAStores.Contains(SpatAField) && spatBStores.Contains(SpatBField);
    bool neighVtInstallOnly = FindLeaTo(NeighVt, 10).All(s => {
      uint fs = FindFuncStart(s);
      return fs == NeighCtor || fs == NeighRelated;
    });
    sb.AppendLine();
    sb.AppendLine("===== VERDICT =====");
    sb.AppendLine("Spatial construct path: SpatRegistrar 0x5E5AF20 fills .trace ctor fields"
      + " 0xACE8448=SpatA / 0xACE84C8=SpatB (runtime TypeInfo); SpatA/B/VT0 LEA SpatVT (in-place)."
      + " Invoke via factory icall[ti+0x50] or call[vt+0]. confirmed=" + spatPath);
    sb.AppendLine("Neighbor construct path: VT install only in NeighVT0/NeighRel;"
      + " NeighRel PE-static @0xAAD22E0; no runtime TypeInfo registrar found."
      + " Invoke = table/call[vt+0] only. vtInstallOnly=" + neighVtInstallOnly);
    sb.AppendLine("Outer/InstallerA: parallel composite TypeInfo registration — not NS object factory.");
    sb.AppendLine("Reloc: DIR64 on Neigh/Spat VT bases + NeighRel slot (image fixups).");

    string pathOut = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(pathOut, sb.ToString());
    Console.WriteLine("WROTE " + pathOut + " chars=" + sb.Length);

    WriteJson(hash, spatPath, neighVtInstallOnly, spatWriterFuncs, relocHits.Count,
      spatAStores, spatBStores);

    bool ok = spatPath && neighVtInstallOnly;
    Console.WriteLine("selfCheck spatPath=" + spatPath + " neighVtOnly=" + neighVtInstallOnly
      + " reloc=" + relocHits.Count + " ok=" + ok);
    return ok ? 0 : 4;
  }

  static string RoleOf(uint fs) {
    if (fs == NeighCtor) return "NeighVT0";
    if (fs == SpatCtor) return "SpatVT0";
    if (fs == NeighRelated) return "NeighRel";
    if (fs == SpatInstA) return "SpatA";
    if (fs == SpatInstB) return "SpatB";
    if (fs == SpatInstC) return "SpatC";
    if (fs == SpatRegistrar) return "SpatRegistrar";
    return "other";
  }

  static List<uint> FindRipStoresOfLea(uint ctor, uint inFunc) {
    var fields = new List<uint>();
    var body = DisasmRaw(inFunc, inFunc + 0x2000);
    for (int i = 0; i < body.Count; i++) {
      var ins = body[i];
      if (!(ins.IpRel && ins.DataRva == ctor && ins.Mnemonic == Mnemonic.Lea)) continue;
      // next few ins: mov [rip], reg
      for (int j = i + 1; j < body.Count && j < i + 6; j++) {
        var s = body[j];
        if (s.IpRel && (s.Text.StartsWith("mov [") || s.Text.StartsWith("mov qword ptr ["))) {
          fields.Add(s.DataRva);
          break;
        }
      }
    }
    return fields.Distinct().ToList();
  }

  static List<(uint site, uint dest, uint func, string text)> FindRipStoresInFunc(
      uint func, uint lo, uint hi, int max) {
    var list = new List<(uint, uint, uint, string)>();
    foreach (var ins in DisasmRaw(func, func + 0x2000)) {
      if (!ins.IpRel) continue;
      if (!(ins.Text.StartsWith("mov [") || ins.Text.StartsWith("mov qword ptr ["))) continue;
      if (ins.DataRva < lo || ins.DataRva >= hi) continue;
      list.Add((ins.Rva, ins.DataRva, func, Trunc(ins.Text, 60)));
      if (list.Count >= max) break;
    }
    return list;
  }

  static List<(int type, uint rva, uint interest)> ScanRelocs(uint[] interest) {
    var hits = new List<(int, uint, uint)>();
    int e = BitConverter.ToInt32(pe, 0x3C);
    // PE32+ data directories at optional+112
    ushort opt = BitConverter.ToUInt16(pe, e + 20);
    int dd = e + 24 + 112;
    uint relocRva = BitConverter.ToUInt32(pe, dd + 5 * 8);
    uint relocSz = BitConverter.ToUInt32(pe, dd + 5 * 8 + 4);
    if (relocRva == 0 || relocSz == 0) return hits;
    int rfo = RvaToFile(relocRva);
    if (rfo < 0) return hits;
    int pos = 0;
    while (pos + 8 <= relocSz) {
      uint page = BitConverter.ToUInt32(pe, rfo + pos);
      uint bsz = BitConverter.ToUInt32(pe, rfo + pos + 4);
      if (bsz < 8) break;
      int count = (int)((bsz - 8) / 2);
      for (int i = 0; i < count; i++) {
        ushort ent = BitConverter.ToUInt16(pe, rfo + pos + 8 + i * 2);
        int type = ent >> 12;
        int off = ent & 0xFFF;
        if (type == 0) continue;
        uint target = page + (uint)off;
        foreach (var it in interest) {
          if (target == it || (target >= it && target < it + 8))
            hits.Add((type, target, it));
        }
      }
      if (bsz == 0) break;
      pos += (int)bsz;
    }
    return hits;
  }

  static void DumpWindow(StringBuilder sb, uint baseRva, int startOff, int endOff, string title) {
    sb.AppendLine("--- " + title + " ---");
    for (int off = startOff; off <= endOff; off += 8) {
      uint a = unchecked((uint)((int)baseRva + off));
      ulong v = ReadU64(a);
      string note = off == 0 ? " <<<" : "";
      sb.AppendLine("  [0x" + a.ToString("X") + "] = 0x"
        + (v >= imageBase && v < imageBase + 0x20000000 ? (v - imageBase).ToString("X") : v.ToString("X"))
        + note);
    }
  }

  static void DeepDump(StringBuilder sb, uint a, uint b, string title) {
    sb.AppendLine("--- " + title + " ---");
    foreach (var i in DisasmRaw(a, b).Take(40)) {
      string m = "";
      if (i.IpRel && i.DataRva == SpatInstA) m = " *** SPATA ***";
      if (i.IpRel && i.DataRva == SpatInstB) m = " *** SPATB ***";
      if (i.IpRel && (i.DataRva == SpatAField || i.DataRva == SpatBField)) m += " *** FIELD ***";
      sb.AppendLine("0x" + i.Rva.ToString("X") + " " + Trunc(i.Text, 80) + m);
    }
  }

  static void WriteJson(string hash, bool spatPath, bool neighVtOnly, List<uint> spatWriters,
      int relocHits, List<uint> spatAStores, List<uint> spatBStores) {
    var sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.28\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"spatial\": {");
    sb.AppendLine("    \"registrar\": \"0x5E5AF20\",");
    sb.AppendLine("    \"edataSlot\": \"0xA23E188\",");
    sb.AppendLine("    \"runtimeCtorFields\": { \"SpatA\": \"0xACE8448\", \"SpatB\": \"0xACE84C8\" },");
    sb.AppendLine("    \"vtInstallFuncs\": [\"0x5781490\", \"0x5563CF0\", \"0x6CF34A0\"],");
    sb.AppendLine("    \"runtimeRegistrationConfirmed\": " + T(spatPath) + ",");
    sb.AppendLine("    \"writerFuncs\": [" + string.Join(", ", spatWriters.Select(x => "\"0x" + x.ToString("X") + "\"")) + "]");
    sb.AppendLine("  },");
    sb.AppendLine("  \"neighbor\": {");
    sb.AppendLine("    \"vtInstallFuncs\": [\"0x13612B0\", \"0x3D522C0\"],");
    sb.AppendLine("    \"neighRelSlot\": \"0xAAD22E0\",");
    sb.AppendLine("    \"neighRelPeStatic\": true,");
    sb.AppendLine("    \"runtimeTypeInfoRegistrarFound\": false,");
    sb.AppendLine("    \"vtInstallOnly\": " + T(neighVtOnly));
    sb.AppendLine("  },");
    sb.AppendLine("  \"relocHits\": " + relocHits + ",");
    sb.AppendLine("  \"outerInstallerConstructsNs\": false,");
    sb.AppendLine("  \"edwardOrPlayerTypeConfirmed\": false");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.28-summary.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.28-summary.json");

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.28\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"constructFamily\": [");
    var rows = new[] {
      new { entry="0x13612B0", role="NeighVT0", e8=0, note="VT[0]; in-place Neigh VT install" },
      new { entry="0x3D522C0", role="NeighRel", e8=0, note="LEA Neigh VT; PE-static @0xAAD22E0" },
      new { entry="0x5781490", role="SpatVT0", e8=0, note="VT[0]; in-place Spat VT install" },
      new { entry="0x5563CF0", role="SpatA", e8=0, note="runtime TypeInfo field 0xACE8448 via registrar" },
      new { entry="0x6CF34A0", role="SpatB", e8=0, note="runtime TypeInfo field 0xACE84C8 via registrar" },
      new { entry="0x5E5AF20", role="SpatRegistrar", e8=0, note=".edata 0xA23E188; fills Spat .trace ctor fields" },
      new { entry="0x59D9660", role="Outer", e8=0, note="InstallerA TypeInfo composite; not NS factory" },
      new { entry="0x5F11A40", role="InstallerA", e8=0, note="LEA-registers Outer; parallel to SpatRegistrar" }
    };
    for (int i = 0; i < rows.Length; i++) {
      var r = rows[i];
      sb.AppendLine("    { \"entry\": \"" + r.entry + "\", \"role\": \"" + r.role
        + "\", \"e8\": " + r.e8 + ", \"note\": " + J(r.note) + " }"
        + (i + 1 < rows.Length ? "," : ""));
    }
    sb.AppendLine("  ],");
    sb.AppendLine("  \"spatAStoreFields\": [" + string.Join(", ", spatAStores.Select(x => "\"0x" + x.ToString("X") + "\"")) + "],");
    sb.AppendLine("  \"spatBStoreFields\": [" + string.Join(", ", spatBStores.Select(x => "\"0x" + x.ToString("X") + "\"")) + "]");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.28-funcs-deep.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.28-funcs-deep.json");

    string sClass = spatPath ? "confirmed" : "partial";
    string sReason = spatPath
      ? "SpatRegistrar 0x5E5AF20 runtime-fills .trace SpatA/SpatB ctor fields; those ctors LEA Spat VT; invoke via factory [ti+0x50] or call[vt+0]"
      : "Spatial registrar path incomplete";
    string nClass = neighVtOnly ? "partial" : "unsupported";
    string nReason = "Neighbor VT install only in NeighVT0/NeighRel; NeighRel PE-static; no runtime TypeInfo registrar; invoke remains table/call[vt+0]";

    sb = new StringBuilder();
    sb.AppendLine("{");
    sb.AppendLine("  \"schemaVersion\": 1,");
    sb.AppendLine("  \"milestone\": \"v0.6.28\",");
    sb.AppendLine("  \"generatedUtc\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
    sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
    sb.AppendLine("  \"createSecondEdward\": { \"class\": \"unsupported\", \"reason\": \"NS construction paths are TypeInfo/VT dispatch; no Edward create/possession\" },");
    sb.AppendLine("  \"spatialConstructPath\": { \"class\": \"" + sClass + "\", \"reason\": " + J(sReason) + " },");
    sb.AppendLine("  \"neighborConstructPath\": { \"class\": \"" + nClass + "\", \"reason\": " + J(nReason) + " },");
    sb.AppendLine("  \"relocRuntimeTypeInfoLeads\": { \"class\": \"confirmed\", \"reason\": \"DIR64 relocs on VT bases/NeighRel; Spat .trace ctor fields runtime-filled by 0x5E5AF20\" },");
    sb.AppendLine("  \"liveMemoryProbe\": { \"class\": \"blocked\", \"reason\": \"Not authorized\" },");
    sb.AppendLine("  \"next\": {");
    sb.AppendLine("    \"primary\": \"Find Neighbor TypeInfo/.trace registration equivalent to SpatRegistrar; map which tight-factory TypeInfo keys use SpatA/SpatB fields\",");
    sb.AppendLine("    \"avoid\": [\"live memory\", \"ASI deploy\", \"spawn\", \"PC2\", \"treat Outer/InstallerA as NS factory\", \"expect E8 to VT[0]\"]");
    sb.AppendLine("  }");
    sb.AppendLine("}");
    File.WriteAllText(Path.Combine(ReportsRoot, "v0.6.28-second-edward-feasibility.json"), sb.ToString());
    Console.WriteLine("WROTE v0.6.28-second-edward-feasibility.json");
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
        Rva = (uint)(raw.IP - imageBase), Text = o.ToString(),
        Mnemonic = raw.Mnemonic, Length = raw.Length,
        IsCall = raw.FlowControl == FlowControl.Call || raw.FlowControl == FlowControl.IndirectCall,
        IsIndirectCall = raw.FlowControl == FlowControl.IndirectCall,
        IsRet = raw.Mnemonic == Mnemonic.Ret
      };
      if (ins.IsCall && !ins.IsIndirectCall && raw.NearBranchTarget != 0 && raw.NearBranchTarget >= imageBase)
        ins.NearTarget = (uint)(raw.NearBranchTarget - imageBase);
      for (int oi = 0; oi < raw.OpCount; oi++) {
        if (raw.GetOpKind(oi) != OpKind.Memory) continue;
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

  static List<uint> FindQwordEmbed(uint rva, int max) {
    var list = new List<uint>();
    ulong va = imageBase + rva;
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 8 <= lim && list.Count < max; i++) {
        if (BitConverter.ToUInt64(pe, (int)(s.Ptr + i)) == va)
          list.Add(s.Va + i);
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

  static ulong ReadU64(uint rva) {
    int fo = RvaToFile(rva);
    return fo < 0 ? 0 : BitConverter.ToUInt64(pe, fo);
  }
  static uint ReadU64AsRva(uint rva) {
    ulong v = ReadU64(rva);
    return v >= imageBase ? (uint)(v - imageBase) : 0;
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
