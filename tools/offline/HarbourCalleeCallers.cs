using System; using System.IO; using System.Text;
class Y {
  static void Main() {
    byte[] pe = File.ReadAllBytes(@"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe");
    int e = BitConverter.ToInt32(pe, 0x3C);
    ushort num = BitConverter.ToUInt16(pe, e + 6);
    ushort opt = BitConverter.ToUInt16(pe, e + 20);
    int secOff = e + 24 + opt;
    uint[] tg = new uint[] { 0x69296F0, 0x692E820, 0x692E550, 0x692E3C0, 0x5014570, 0x6929650, 0x6929450 };
    string[] tn = new string[] { "ClearUnsafe", "Find", "DumpTo", "LoadFrom", "Shared5014570", "ClearInner9650", "ClearJmp9450" };
    int[] counts = new int[tg.Length];
    StringBuilder samples = new StringBuilder();
    for (int si = 0; si < num; si++) {
      int o = secOff + si * 40;
      string name = Encoding.ASCII.GetString(pe, o, 8).TrimEnd('\0');
      uint va = BitConverter.ToUInt32(pe, o + 12);
      uint raw = BitConverter.ToUInt32(pe, o + 16);
      uint ptr = BitConverter.ToUInt32(pe, o + 20);
      uint ch = BitConverter.ToUInt32(pe, o + 36);
      if ((ch & 0x20000000) == 0 || ptr == 0 || raw == 0 || ptr + raw > pe.Length) continue;
      for (int i = 0; i + 5 <= (int)raw; i++) {
        byte op = pe[ptr + i];
        if (op != 0xE8 && op != 0xE9) continue;
        int rel = BitConverter.ToInt32(pe, (int)(ptr + i + 1));
        uint site = va + (uint)i;
        uint dest = unchecked((uint)(site + 5 + rel));
        for (int t = 0; t < tg.Length; t++) {
          if (dest != tg[t]) continue;
          counts[t]++;
          if (counts[t] <= 8) {
            samples.Append("{\"target\":\"").Append(tn[t]).Append("\",\"op\":\"").Append(op == 0xE8 ? "E8" : "E9")
              .Append("\",\"siteRva\":\"0x").Append(site.ToString("X")).Append("\",\"section\":\"").Append(name).Append("\"},\n");
          }
        }
      }
    }
    // helper prologue
    long helperFo = -1;
    for (int si = 0; si < num; si++) {
      int o = secOff + si * 40;
      uint va = BitConverter.ToUInt32(pe, o + 12);
      uint vsz = BitConverter.ToUInt32(pe, o + 8);
      uint raw = BitConverter.ToUInt32(pe, o + 16);
      uint ptr = BitConverter.ToUInt32(pe, o + 20);
      uint span = Math.Max(vsz, raw);
      if (0x5014570u >= va && 0x5014570u < va + span && ptr > 0) { helperFo = ptr + (0x5014570 - va); break; }
    }
    StringBuilder sb = new StringBuilder();
    sb.Append("{\n  \"counts\":{\n");
    for (int t = 0; t < tg.Length; t++) {
      Console.WriteLine(tn[t] + "=" + counts[t]);
      sb.Append("    \"").Append(tn[t]).Append("\": ").Append(counts[t]);
      if (t + 1 < tg.Length) sb.Append(",");
      sb.Append("\n");
    }
    sb.Append("  },\n  \"samples\":[\n").Append(samples).Append("  ],\n");
    sb.Append("  \"sharedHelper\":{\"rva\":\"0x5014570\",\"fileOffset\":");
    if (helperFo >= 0) {
      sb.Append("\"0x").Append(helperFo.ToString("X")).Append("\",\"bytes\":\"");
      for (int i = 0; i < 24; i++) sb.Append(pe[helperFo + i].ToString("X2")).Append(i + 1 < 24 ? " " : "");
      sb.Append("\"");
    } else sb.Append("null");
    sb.Append("}\n}\n");
    File.WriteAllText(@"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports\v0.5.8-harbour-callee-callers.json", sb.ToString());
    Console.WriteLine("WROTE callee-callers");
  }
}
