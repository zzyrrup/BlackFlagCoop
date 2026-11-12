// Offline: do the AC4Coop source names exist as strings in the Resynced exe?
// Read-only. No launch.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

internal static class Program {
  const string Expected =
    "19920F34BB2FAC814023EE3C27F0CECA1872E80A2AAFB37C092C419FFF77CC0D";
  static readonly string[] Names = {
    "LoadEntityBuilderAndSelectorsForPlayer",
    "BuildEntityWithSelector",
    "EntityBuilder",
    "RowSelector",
    "DuplicationManager",
    "BhvAssassin",
    "GetUnusedPadID",
    "SetGlobalMatrixInternal",
    "SetTargetAction",
    "PlayerPadManager",
    "CharacterActionSet"
  };

  static int Main() {
    string exe = @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    byte[] pe = File.ReadAllBytes(exe);
    string hash;
    using (var sha = SHA256.Create()) {
      var sb = new StringBuilder();
      foreach (byte b in sha.ComputeHash(pe)) sb.Append(b.ToString("X2"));
      hash = sb.ToString();
    }
    Console.WriteLine("exeSha256=" + hash);
    if (!hash.Equals(Expected, StringComparison.OrdinalIgnoreCase)) return 2;
    var outSb = new StringBuilder();
    outSb.AppendLine("exeSha256=" + hash);
    foreach (string name in Names) {
      byte[] pat = Encoding.ASCII.GetBytes(name);
      int count = 0;
      int from = 0;
      while (from < pe.Length && count < 8) {
        int at = pe.AsSpan(from).IndexOf(pat);
        if (at < 0) break;
        count++;
        int abs = from + at;
        int start = abs;
        while (start > 0 && pe[start - 1] >= 32 && pe[start - 1] < 127) start--;
        int end = abs;
        while (end < pe.Length && pe[end] >= 32 && pe[end] < 127) end++;
        string text = Encoding.ASCII.GetString(pe, start, Math.Min(end - start, 96));
        string line = name + " hit=" + count + " text=" + text;
        Console.WriteLine(line);
        outSb.AppendLine(line);
        from = abs + pat.Length;
      }
      if (count == 0) {
        Console.WriteLine(name + " hit=0");
        outSb.AppendLine(name + " hit=0");
      }
    }
    string dir = @"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop-v080-spawn\reports";
    Directory.CreateDirectory(dir);
    File.WriteAllText(Path.Combine(dir, "v0.8.0-ac4-names.txt"), outSb.ToString());
    return 0;
  }
}
