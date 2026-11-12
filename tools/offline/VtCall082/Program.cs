// v0.8.0 follow-up — resolve virtual calls in 0x33591C0 after SpawnNPCParams type attach.
// Read-only. No launch, inject, or deploy.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;

internal static class Program {
  const uint kHost = 0x33591C0;
  const uint kTypeAttach = 0x137AE80;
  const uint kNodeAlloc = 0x156B20;
  const uint kNpcType = 0xB5378F0;

  static byte[] pe;
  static List<Sec> secs;
  static ulong imageBase;
  static readonly NasmFormatter Fmt = new NasmFormatter();

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080\reports";
    pe = File.ReadAllBytes(exe);
    ParsePe();
    Directory.CreateDirectory(outDir);
    Console.WriteLine("imageBase=" + H(imageBase));

    var sb = new StringBuilder();
    sb.Append("{\n  \"schemaVersion\": 1,\n  \"milestone\": \"v0.8.0-vtcall\",\n");

    sb.Append("  \"host\": ").Append(FuncJson(kHost, 140)).Append(",\n");
    sb.Append("  \"typeAttach\": ").Append(FuncJson(kTypeAttach, 120)).Append(",\n");
    sb.Append("  \"nodeAlloc\": ").Append(FuncJson(kNodeAlloc, 80)).Append(",\n");

    // Helpers the host and attach use.
    uint[] helpers = new uint[] {
      0x1332060, 0x137AC40, 0x492BFF0, 0x4B0E00, 0x156B20, 0x4265F00, 0x42EB100
    };
    sb.Append("  \"helpers\": [\n");
    for (int i = 0; i < helpers.Length; i++) {
      if (i > 0) sb.Append(",\n");
      uint entry = helpers[i];
      // Follow a single unconditional jmp if present.
      uint resolved = FollowJmp(entry);
      sb.Append("    {\"entry\":\"").Append(H(entry));
      sb.Append("\",\"resolved\":\"").Append(H(resolved));
      sb.Append("\",\"body\":").Append(FuncJson(resolved, 48)).Append('}');
      Console.WriteLine("helper " + H(entry) + " -> " + H(resolved));
    }
    sb.Append("\n  ],\n");

    // Who E8-calls typeAttach / nodeAlloc.
    var callMap = FindE8(new uint[] { kTypeAttach, kNodeAlloc, 0x137AC40 }, 200);
    sb.Append("  \"directCallers\": {\n");
    AppendCallerList(sb, callMap, kTypeAttach);
    sb.Append(",\n");
    AppendCallerList(sb, callMap, kNodeAlloc);
    sb.Append(",\n");
    AppendCallerList(sb, callMap, 0x137AC40);
    sb.Append("\n  },\n");

    // From nodeAlloc / typeAttach: recover absolute vtable LEAs and their +0xC0 / +0x20 slots.
    var leaVts = CollectVtableLeas(new uint[] { kTypeAttach, kNodeAlloc, 0x137AC40, kHost }, 24);
    sb.Append("  \"installedVtables\": [\n");
    for (int i = 0; i < leaVts.Count; i++) {
      if (i > 0) sb.Append(",\n");
      var vt = leaVts[i];
      sb.Append("    {\"leaSite\":\"").Append(H(vt.LeaSite));
      sb.Append("\",\"inFunc\":\"").Append(H(vt.InFunc));
      sb.Append("\",\"base\":\"").Append(H(vt.Base));
      sb.Append("\",\"slot20\":\"").Append(H(vt.Slot20));
      sb.Append("\",\"slot58\":\"").Append(H(vt.Slot58));
      sb.Append("\",\"slotC0\":\"").Append(H(vt.SlotC0));
      sb.Append("\",\"slot20Decode\":").Append(J(vt.Slot20 == 0 ? "" : Join(Disasm(vt.Slot20, 20), 20)));
      sb.Append(",\"slot58Decode\":").Append(J(vt.Slot58 == 0 ? "" : Join(Disasm(vt.Slot58, 20), 20)));
      sb.Append(",\"slotC0Decode\":").Append(J(vt.SlotC0 == 0 ? "" : Join(Disasm(vt.SlotC0, 28), 28)));
      sb.Append('}');
      Console.WriteLine("lea-vt " + H(vt.Base) + " from " + H(vt.InFunc) + " C0=" + H(vt.SlotC0));
    }
    sb.Append("\n  ],\n");

    // Absolute qword hits for the NPC type global itself (who stores / publishes it).
    var typePtrs = FindU64(imageBase + kNpcType, 12);
    sb.Append("  \"npcTypeAbsolute\": [");
    for (int i = 0; i < typePtrs.Count; i++) {
      if (i > 0) sb.Append(',');
      long fo = typePtrs[i];
      sb.Append("{\"rva\":\"").Append(H(FileToRva(fo)));
      sb.Append("\",\"section\":").Append(J(SecName(fo))).Append('}');
    }
    sb.Append("],\n");

    // Strings near host for context.
    sb.Append("  \"hostNearbyStrings\": [\n");
    var near = NearbyStrings(0x3359000, 0x335B000, 24);
    for (int i = 0; i < near.Count; i++) {
      if (i > 0) sb.Append(",\n");
      sb.Append("    {\"rva\":\"").Append(H(near[i].Rva));
      sb.Append("\",\"text\":").Append(J(near[i].Text)).Append('}');
    }
    sb.Append("\n  ],\n");

    // Type-object field stores: who writes [B5378F0 + offs]?
    uint[] typeObjs = new uint[] { 0xB5378F0, 0xB537FC8, 0xB5377F8 };
    sb.Append("  \"typeFieldStores\": [\n");
    int written = 0;
    foreach (uint typeObj in typeObjs) {
      var stores = FindRipStoresTo(typeObj, 0x100, 40);
      Console.WriteLine("stores " + H(typeObj) + "=" + stores.Count);
      foreach (var st in stores) {
        if (written++ > 0) sb.Append(",\n");
        sb.Append("    {\"type\":\"").Append(H(typeObj));
        sb.Append("\",\"site\":\"").Append(H(st.Site));
        sb.Append("\",\"func\":\"").Append(H(st.Func));
        sb.Append("\",\"fieldOff\":\"").Append(H(st.FieldOff));
        sb.Append("\",\"valueRva\":\"").Append(H(st.ValueRva));
        sb.Append("\",\"kind\":").Append(J(st.Kind)).Append('}');
      }
    }
    sb.Append("\n  ],\n");

    // Decode methods at +0x50 of type objects if we recovered them, else decode lea targets written near +0x50.
    sb.Append("  \"plus50Candidates\": [\n");
    var plus50 = new List<uint>();
    foreach (uint typeObj in typeObjs) {
      uint direct = ReadCodePtr(typeObj + 0x50);
      if (direct != 0) plus50.Add(direct);
    }
    // Also gather valueRvas written with fieldOff==0x50 from stores above by rescanning briefly.
    foreach (uint typeObj in typeObjs) {
      var stores = FindRipStoresTo(typeObj, 0x100, 40);
      foreach (var st in stores) if (st.FieldOff == 0x50 && st.ValueRva != 0) plus50.Add(st.ValueRva);
    }
    var seen50 = new HashSet<uint>();
    int p50 = 0;
    foreach (uint fn in plus50) {
      if (!seen50.Add(fn)) continue;
      if (p50++ > 0) sb.Append(",\n");
      var lea = CollectVtableLeas(new uint[] { fn }, 8);
      sb.Append("    {\"ctor\":\"").Append(H(fn));
      sb.Append("\",\"decode\":").Append(J(Join(Disasm(fn, 40), 40)));
      sb.Append(",\"vtables\":[");
      for (int i = 0; i < lea.Count; i++) {
        if (i > 0) sb.Append(',');
        sb.Append("{\"base\":\"").Append(H(lea[i].Base));
        sb.Append("\",\"slotC0\":\"").Append(H(lea[i].SlotC0));
        sb.Append("\",\"slotC0Decode\":").Append(J(lea[i].SlotC0 == 0 ? "" : Join(Disasm(lea[i].SlotC0, 24), 24)));
        sb.Append('}');
      }
      sb.Append("]}");
      Console.WriteLine("plus50 " + H(fn) + " vts=" + lea.Count);
    }
    sb.Append("\n  ],\n");

    // Sibling host functions that also call typeAttach.
    sb.Append("  \"siblingHosts\": [\n");
    uint[] siblings = new uint[] { 0x3358F10, 0x3359FC0, 0x1924620, 0x286F290 };
    for (int i = 0; i < siblings.Length; i++) {
      if (i > 0) sb.Append(",\n");
      sb.Append("    ").Append(FuncJson(siblings[i], 60));
    }
    sb.Append("\n  ]\n}\n");

    string path = Path.Combine(outDir, "v0.8.0-vtcall-resolve.json");
    File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
    Console.WriteLine("WROTE " + path);
    return 0;
  }

  sealed class FieldStore {
    public uint Site; public uint Func; public uint FieldOff; public uint ValueRva; public string Kind;
  }

  static List<FieldStore> FindRipStoresTo(uint typeObj, uint maxField, int maxHits) {
    var list = new List<FieldStore>();
    // Match: lea reg, [rip+typeObj] then later mov [reg+off], ...
    // Also match: mov [rip+typeObj+off], reg / lea value then store.
    foreach (var s in secs) {
      if (!IsExec(s)) continue;
      int size = (int)s.Raw;
      for (int i = 0; i + 7 <= size; i++) {
        byte b0 = pe[s.Ptr + i], b1 = pe[s.Ptr + i + 1], b2 = pe[s.Ptr + i + 2];
        // lea r64, [rip+disp]
        if ((b0 == 0x48 || b0 == 0x4C) && b1 == 0x8D && (b2 & 0xC7) == 0x05) {
          int disp = BitConverter.ToInt32(pe, (int)s.Ptr + i + 3);
          uint site = s.VA + (uint)i;
          uint tgt = unchecked((uint)(site + 7 + disp));
          if (tgt != typeObj) continue;
          // Look ahead 0x40 bytes for mov [reg+imm], r64 or lea of a value stored.
          int look = Math.Min(0x60, size - (i + 7));
          for (int j = 7; j + 7 < look; j++) {
            // mov [rip+disp32], r64  — absolute store into type field if target in [typeObj, typeObj+maxField]
            byte c0 = pe[s.Ptr + i + j], c1 = pe[s.Ptr + i + j + 1], c2 = pe[s.Ptr + i + j + 2];
            if ((c0 == 0x48 || c0 == 0x4C) && c1 == 0x89 && (c2 & 0xC7) == 0x05) {
              int d2 = BitConverter.ToInt32(pe, (int)s.Ptr + i + j + 3);
              uint storeSite = s.VA + (uint)(i + j);
              uint storeTgt = unchecked((uint)(storeSite + 7 + d2));
              if (storeTgt >= typeObj && storeTgt < typeObj + maxField && ((storeTgt - typeObj) % 8) == 0) {
                list.Add(new FieldStore {
                  Site = storeSite, Func = FindFunc(storeSite), FieldOff = storeTgt - typeObj,
                  ValueRva = 0, Kind = "mov_rip_after_lea_type"
                });
                if (list.Count >= maxHits) return list;
              }
            }
          }
        }
        // Direct rip-relative store into typeObj+field
        if ((b0 == 0x48 || b0 == 0x4C) && b1 == 0x89 && (b2 & 0xC7) == 0x05) {
          int disp = BitConverter.ToInt32(pe, (int)s.Ptr + i + 3);
          uint site = s.VA + (uint)i;
          uint tgt = unchecked((uint)(site + 7 + disp));
          if (tgt >= typeObj && tgt < typeObj + maxField && ((tgt - typeObj) % 8) == 0) {
            // Look backward for lea of a code pointer into the source register.
            uint value = 0;
            for (int back = 1; back < 0x30 && i >= back + 7; back++) {
              int k = i - back;
              byte d0 = pe[s.Ptr + k], d1 = pe[s.Ptr + k + 1], d2 = pe[s.Ptr + k + 2];
              if ((d0 == 0x48 || d0 == 0x4C) && d1 == 0x8D && (d2 & 0xC7) == 0x05) {
                int d = BitConverter.ToInt32(pe, (int)s.Ptr + k + 3);
                uint leaSite = s.VA + (uint)k;
                uint leaTgt = unchecked((uint)(leaSite + 7 + d));
                if (IsCodeRva(leaTgt)) { value = leaTgt; break; }
              }
            }
            list.Add(new FieldStore {
              Site = site, Func = FindFunc(site), FieldOff = tgt - typeObj,
              ValueRva = value, Kind = "mov_rip_field"
            });
            if (list.Count >= maxHits) return list;
          }
        }
      }
    }
    return list;
  }

  sealed class Sec { public string Name; public uint VA, VS, Raw, Ptr, Char; }
  sealed class Ins { public uint Rva; public string Text; public uint Call; public bool Ret; public bool IndirectCall; public int MemDisp; public bool HasMem; }
  sealed class StrHit { public uint Rva; public string Text; }
  sealed class LeaVt {
    public uint LeaSite; public uint InFunc; public uint Base; public uint Slot20; public uint Slot58; public uint SlotC0;
  }

  static void ParsePe() {
    int e = BitConverter.ToInt32(pe, 0x3C);
    ushort num = BitConverter.ToUInt16(pe, e + 6);
    ushort opt = BitConverter.ToUInt16(pe, e + 20);
    ushort magic = BitConverter.ToUInt16(pe, e + 0x18);
    imageBase = magic == 0x20B
      ? BitConverter.ToUInt64(pe, e + 0x18 + 24)
      : BitConverter.ToUInt32(pe, e + 0x18 + 28);
    int secOff = e + 24 + opt;
    secs = new List<Sec>();
    for (int i = 0; i < num; i++) {
      int o = secOff + i * 40;
      var s = new Sec();
      s.Name = Encoding.ASCII.GetString(pe, o, 8).TrimEnd('\0');
      s.VS = BitConverter.ToUInt32(pe, o + 8);
      s.VA = BitConverter.ToUInt32(pe, o + 12);
      s.Raw = BitConverter.ToUInt32(pe, o + 16);
      s.Ptr = BitConverter.ToUInt32(pe, o + 20);
      s.Char = BitConverter.ToUInt32(pe, o + 36);
      secs.Add(s);
    }
  }

  static bool IsExec(Sec s) { return s.Ptr != 0 && (s.Char & 0x20000000) != 0; }
  static string H(uint v) { return "0x" + v.ToString("X"); }
  static string H(ulong v) { return "0x" + v.ToString("X"); }
  static string J(string s) {
    if (s == null) return "null";
    var sb = new StringBuilder(s.Length + 2);
    sb.Append('"');
    foreach (char c in s) {
      if (c == '\\' || c == '"') sb.Append('\\').Append(c);
      else if (c < 32 || c > 126) sb.Append(' ');
      else sb.Append(c);
    }
    return sb.Append('"').ToString();
  }

  static long RvaToFile(uint rva) {
    foreach (var s in secs) {
      if (s.Ptr == 0 || s.Raw == 0) continue;
      if (rva >= s.VA && rva < s.VA + s.Raw) return s.Ptr + (rva - s.VA);
    }
    return -1;
  }
  static uint FileToRva(long fo) {
    foreach (var s in secs) {
      if (s.Ptr != 0 && fo >= s.Ptr && fo < s.Ptr + s.Raw)
        return s.VA + (uint)(fo - s.Ptr);
    }
    return 0;
  }
  static string SecName(long fo) {
    foreach (var s in secs)
      if (s.Ptr != 0 && fo >= s.Ptr && fo < s.Ptr + s.Raw) return s.Name;
    return "";
  }
  static bool IsCodeRva(uint rva) {
    long fo = RvaToFile(rva);
    if (fo < 0) return false;
    foreach (var s in secs) {
      if (s.Ptr != 0 && fo >= s.Ptr && fo < s.Ptr + s.Raw) return IsExec(s);
    }
    return false;
  }

  static string FuncJson(uint rva, int maxIns) {
    var ins = Disasm(rva, maxIns);
    var calls = new List<string>();
    var seen = new HashSet<uint>();
    foreach (var item in ins) {
      if (item.Call == 0 || !seen.Add(item.Call)) continue;
      calls.Add("{\"target\":\"" + H(item.Call) + "\",\"indirect\":" + (item.IndirectCall ? "true" : "false") + "}");
    }
    var sb = new StringBuilder();
    sb.Append("{\"entry\":\"").Append(H(rva)).Append("\",\"calls\":[");
    sb.Append(string.Join(",", calls));
    sb.Append("],\"text\":").Append(J(Join(ins, maxIns))).Append('}');
    return sb.ToString();
  }

  static void AppendCallerList(StringBuilder sb, Dictionary<uint, List<uint>> map, uint target) {
    List<uint> list;
    if (!map.TryGetValue(target, out list)) list = new List<uint>();
    sb.Append("    \"").Append(H(target)).Append("\": {\"sites\":").Append(list.Count).Append(",\"funcs\":[");
    var funcs = new HashSet<uint>();
    int n = 0;
    foreach (uint site in list) {
      uint fn = FindFunc(site);
      if (!funcs.Add(fn)) continue;
      if (n++ > 0) sb.Append(',');
      sb.Append("{\"site\":\"").Append(H(site)).Append("\",\"func\":\"").Append(H(fn)).Append("\"}");
      if (n >= 20) break;
    }
    sb.Append("]}");
    Console.WriteLine("e8 " + H(target) + "=" + list.Count);
  }

  static uint FollowJmp(uint rva) {
    long fo = RvaToFile(rva);
    if (fo < 0 || fo + 5 >= pe.Length) return rva;
    if (pe[fo] == 0xE9) {
      int disp = BitConverter.ToInt32(pe, (int)fo + 1);
      return unchecked((uint)(rva + 5 + disp));
    }
    return rva;
  }

  static Dictionary<uint, List<uint>> FindE8(uint[] targets, int maxTotal) {
    var want = new HashSet<uint>(targets);
    var map = new Dictionary<uint, List<uint>>();
    int total = 0;
    foreach (var s in secs) {
      if (!IsExec(s) || total >= maxTotal) break;
      int size = (int)s.Raw;
      for (int i = 0; i + 5 <= size; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        int disp = BitConverter.ToInt32(pe, (int)s.Ptr + i + 1);
        uint site = s.VA + (uint)i;
        uint tgt = unchecked((uint)(site + 5 + disp));
        if (!want.Contains(tgt)) continue;
        List<uint> list;
        if (!map.TryGetValue(tgt, out list)) {
          list = new List<uint>();
          map[tgt] = list;
        }
        list.Add(site);
        if (++total >= maxTotal) break;
      }
    }
    return map;
  }

  static List<long> FindU64(ulong value, int max) {
    var list = new List<long>();
    byte[] pat = BitConverter.GetBytes(value);
    for (long i = 0; i + 8 <= pe.Length; i++) {
      bool ok = true;
      for (int j = 0; j < 8; j++) if (pe[i + j] != pat[j]) { ok = false; break; }
      if (!ok) continue;
      list.Add(i);
      if (list.Count >= max) break;
    }
    return list;
  }

  static List<LeaVt> CollectVtableLeas(uint[] funcs, int maxIns) {
    var list = new List<LeaVt>();
    var seen = new HashSet<uint>();
    foreach (uint fn in funcs) {
      long fo = RvaToFile(fn);
      if (fo < 0) continue;
      int len = (int)Math.Min(0x800, pe.Length - fo);
      for (int i = 0; i + 7 < len; i++) {
        byte b0 = pe[fo + i], b1 = pe[fo + i + 1], b2 = pe[fo + i + 2];
        if ((b0 != 0x48 && b0 != 0x4C) || b1 != 0x8D || (b2 & 0xC7) != 0x05) continue;
        uint site = fn + (uint)i;
        int disp = BitConverter.ToInt32(pe, (int)fo + i + 3);
        uint tgt = unchecked((uint)(site + 7 + disp));
        if (!seen.Add(tgt)) continue;
        // Require slot0 and at least one of +0x20/+0x58/+0xC0 to be code.
        uint s0 = ReadCodePtr(tgt);
        uint s20 = ReadCodePtr(tgt + 0x20);
        uint s58 = ReadCodePtr(tgt + 0x58);
        uint sC0 = ReadCodePtr(tgt + 0xC0);
        if (s0 == 0) continue;
        if (s20 == 0 && s58 == 0 && sC0 == 0) continue;
        list.Add(new LeaVt {
          LeaSite = site, InFunc = fn, Base = tgt, Slot20 = s20, Slot58 = s58, SlotC0 = sC0
        });
        if (list.Count >= maxIns) return list;
      }
    }
    return list;
  }

  static uint ReadCodePtr(uint rva) {
    long fo = RvaToFile(rva);
    if (fo < 0 || fo + 8 > pe.Length) return 0;
    ulong q = BitConverter.ToUInt64(pe, (int)fo);
    if (q < imageBase || q >= imageBase + 0x20000000) return 0;
    uint target = (uint)(q - imageBase);
    return IsCodeRva(target) ? target : 0;
  }

  static List<StrHit> NearbyStrings(uint begin, uint end, int max) {
    // Not nearby in VA of host — scan .edata for strings LEA'd from host range.
    var hits = new List<StrHit>();
    var rip = FindRipLeaInRange(begin, end, 40);
    foreach (uint site in rip) {
      long fo = RvaToFile(site);
      if (fo < 0 || fo + 7 >= pe.Length) continue;
      int disp = BitConverter.ToInt32(pe, (int)fo + 3);
      uint tgt = unchecked((uint)(site + 7 + disp));
      string text = ReadCString(tgt);
      if (text.Length < 4) continue;
      hits.Add(new StrHit { Rva = tgt, Text = text });
      if (hits.Count >= max) break;
    }
    return hits;
  }

  static List<uint> FindRipLeaInRange(uint begin, uint end, int max) {
    var list = new List<uint>();
    foreach (var s in secs) {
      if (!IsExec(s)) continue;
      uint from = Math.Max(s.VA, begin);
      uint to = Math.Min(s.VA + s.Raw, end);
      if (to <= from) continue;
      for (uint rva = from; rva + 7 <= to; rva++) {
        long fo = RvaToFile(rva);
        byte b0 = pe[fo], b1 = pe[fo + 1], b2 = pe[fo + 2];
        if ((b0 != 0x48 && b0 != 0x4C) || b1 != 0x8D || (b2 & 0xC7) != 0x05) continue;
        list.Add(rva);
        if (list.Count >= max) return list;
      }
    }
    return list;
  }

  static string ReadCString(uint rva) {
    long fo = RvaToFile(rva);
    if (fo < 0) return "";
    int n = 0;
    while (n < 96 && fo + n < pe.Length && pe[fo + n] >= 32 && pe[fo + n] < 127) n++;
    if (n == 0 || fo + n >= pe.Length || pe[fo + n] != 0) return "";
    return Encoding.ASCII.GetString(pe, (int)fo, n);
  }

  static uint FindFunc(uint site) {
    long fo = RvaToFile(site);
    if (fo < 0) return site;
    for (int back = 0; back < 0x2000; back++) {
      long pos = fo - back;
      if (pos < 1) break;
      byte prev = pe[pos - 1];
      if ((prev == 0xCC || prev == 0xC3) && LooksPrologue(pos)) return FileToRva(pos);
    }
    return site;
  }

  static bool LooksPrologue(long fo) {
    if (fo + 3 >= pe.Length) return false;
    byte b0 = pe[fo], b1 = pe[fo + 1], b2 = pe[fo + 2];
    if (b0 == 0x40 && (b1 == 0x53 || b1 == 0x55 || b1 == 0x56 || b1 == 0x57)) return true;
    if (b0 == 0x48 && b1 == 0x89) return true;
    if (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC) return true;
    if (b0 == 0x48 && b1 == 0x81 && b2 == 0xEC) return true;
    if (b0 == 0x55 || b0 == 0x53 || b0 == 0x56 || b0 == 0x57) return true;
    if (b0 == 0x41 && b1 >= 0x54 && b1 <= 0x57) return true;
    return false;
  }

  static List<Ins> Disasm(uint rva, int maxIns) {
    var list = new List<Ins>();
    long fo = RvaToFile(rva);
    if (fo < 0) return list;
    int len = (int)Math.Min(0x600, pe.Length - fo);
    var code = new byte[len];
    Buffer.BlockCopy(pe, (int)fo, code, 0, len);
    var dec = Decoder.Create(64, new ByteArrayCodeReader(code));
    dec.IP = imageBase + rva;
    int rets = 0;
    for (int n = 0; n < maxIns; n++) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      var o = new StringOutput();
      Fmt.Format(raw, o);
      var item = new Ins {
        Rva = (uint)(raw.IP - imageBase),
        Text = o.ToString(),
        Ret = raw.Mnemonic == Mnemonic.Ret,
        IndirectCall = raw.FlowControl == FlowControl.IndirectCall
      };
      if (raw.FlowControl == FlowControl.Call || raw.FlowControl == FlowControl.IndirectCall) {
        if (raw.NearBranchTarget >= imageBase)
          item.Call = (uint)(raw.NearBranchTarget - imageBase);
      }
      list.Add(item);
      if (item.Ret && ++rets >= 2 && n > 10) break;
      if (raw.Mnemonic == Mnemonic.Int3 && n > 4) break;
    }
    return list;
  }

  static string Join(List<Ins> ins, int max) {
    var sb = new StringBuilder();
    int n = Math.Min(max, ins.Count);
    for (int i = 0; i < n; i++) {
      if (i > 0) sb.Append(" | ");
      sb.Append(H(ins[i].Rva)).Append(' ').Append(ins[i].Text);
    }
    if (sb.Length > 2200) return sb.ToString(0, 2200);
    return sb.ToString();
  }
}
