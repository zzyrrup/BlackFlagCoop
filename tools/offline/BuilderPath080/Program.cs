// v0.8.0 — Offline: follow PlayerProgression / LoadingAdvisor / spawn-schema
 // strings toward the AC4Coop cached EntityBuilder + RowSelector path.
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
   const uint SchemaRegister = 0x4572C60;
   const uint Allocator = 0x426EE50;
   const uint CreateActorsDeferred = 0x1AC380;

   static readonly string[] Needles = {
     "PlayerProgression",
     "PlayerProgressions",
     "LoadingAdvisorUpdate",
     "SpawnPlayerBoatParams",
     "SpawnInventoryParams",
     "SpawnNPCParams",
     "SpawnEntityBuilderParams",
     "CreateActorsDeferredSingleThreaded",
     "Duplicated Request",
     "Duplicate reference to 0x%llx"
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
     public uint NearTarget; public int Length; public bool IsStore; public bool IsLoad;
   }
   sealed class Hit { public string Needle; public uint Rva; public string Text; }
   sealed class FuncRep {
     public uint Entry;
     public string Klass;
     public bool CallsSchema, CallsAlloc, CallsDeferred;
     public List<uint> Callees = new List<uint>();
     public List<string> Strings = new List<string>();
     public List<uint> DataLeas = new List<uint>();
     public List<uint> GlobalStores = new List<uint>();
     public List<uint> GlobalLoads = new List<uint>();
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
     string rawDir = Path.Combine(root, "reports", "v080-builder-raw");
     Directory.CreateDirectory(rawDir);
     Directory.CreateDirectory(Path.Combine(root, "reports"));

     var sb = new StringBuilder();
     sb.AppendLine("===== v0.8.0 BUILDER / PLAYERPROGRESSION PATH =====");
     sb.AppendLine("exeSha256=" + hash);
     sb.AppendLine("imageBase=0x" + imageBase.ToString("X"));
     sb.AppendLine("goal=locate Resynced equivalents of PlayerProgression cached");
     sb.AppendLine("      EntityBuilder handle + RowSelector (AC4Coop source path)");

     var hits = FindNeedles();
     sb.AppendLine();
     sb.AppendLine("===== STRING HITS =====");
     foreach (var hit in hits)
       sb.AppendLine(hit.Needle + " rva=0x" + hit.Rva.ToString("X") + " text=" + Trunc(hit.Text, 96));

     var leaSites = new List<Tuple<string, uint, uint>>();
     sb.AppendLine();
     sb.AppendLine("===== STRING LEA SITES =====");
     foreach (var hit in hits) {
       var leas = FindLeaTo(hit.Rva, 48);
       sb.AppendLine("LEA " + hit.Needle + " @0x" + hit.Rva.ToString("X") + " count=" + leas.Count);
       foreach (uint site in leas) {
         uint fs = FindFuncStart(site);
         leaSites.Add(Tuple.Create(hit.Needle, site, fs));
         sb.AppendLine("  site=0x" + site.ToString("X") + " func=0x" + fs.ToString("X"));
       }
     }

     var focus = new HashSet<uint>();
     foreach (var site in leaSites) {
       if (site.Item1.IndexOf("PlayerProgression", StringComparison.Ordinal) >= 0
           || site.Item1 == "LoadingAdvisorUpdate"
           || site.Item1 == "SpawnPlayerBoatParams"
           || site.Item1.StartsWith("Duplicate", StringComparison.Ordinal))
         focus.Add(site.Item3);
     }
     foreach (var site in leaSites)
       if (site.Item1 == "SpawnEntityBuilderParams" || site.Item1 == "SpawnNPCParams")
         focus.Add(site.Item3);

     var reps = new List<FuncRep>();
     sb.AppendLine();
     sb.AppendLine("===== FOCUS FUNCTIONS =====");
     foreach (uint fs in focus.Where(x => x != 0).OrderBy(x => x).Take(64)) {
       var rep = Analyze(fs);
       reps.Add(rep);
       EmitFunc(sb, rep);
       // One hop of E8 callers for PlayerProgression LEA funcs that are not pure schema.
       if (!rep.CallsSchema || rep.Strings.Any(s => s.IndexOf("PlayerProgression", StringComparison.Ordinal) >= 0)) {
         var callers = FindE8(fs, 24);
         sb.AppendLine("  E8_callers count=" + callers.Count);
         foreach (uint c in callers.Take(12)) {
           uint cfs = FindFuncStart(c);
           sb.AppendLine("    site=0x" + c.ToString("X") + " func=0x" + cfs.ToString("X"));
           if (cfs != 0 && focus.Add(cfs) && reps.Count < 96) {
             var crep = Analyze(cfs);
             reps.Add(crep);
             EmitFunc(sb, crep);
           }
         }
       }
     }

     // Re-analyze any newly added focus entries already covered above; summarize.
     int schemaOnly = reps.Count(r => r.CallsSchema && !r.CallsAlloc);
     int allocHits = reps.Count(r => r.CallsAlloc);
     int deferredHits = reps.Count(r => r.CallsDeferred);
     var cacheCandidates = reps
       .Where(r => r.GlobalStores.Count >= 2 && !r.CallsSchema)
       .OrderByDescending(r => r.GlobalStores.Count)
       .ToList();
     var progressionFuncs = reps
       .Where(r => r.Strings.Any(s => s.IndexOf("PlayerProgression", StringComparison.Ordinal) >= 0))
       .ToList();

     sb.AppendLine();
     sb.AppendLine("===== SUMMARY =====");
     sb.AppendLine("focusFuncs=" + reps.Select(r => r.Entry).Distinct().Count());
     sb.AppendLine("schemaOnly=" + schemaOnly);
     sb.AppendLine("allocHits=" + allocHits);
     sb.AppendLine("deferredHits=" + deferredHits);
     sb.AppendLine("playerProgressionFuncs=" + progressionFuncs.Count);
     foreach (var r in progressionFuncs)
       sb.AppendLine("  PP 0x" + r.Entry.ToString("X") + " class=" + r.Klass
         + " schema=" + r.CallsSchema + " alloc=" + r.CallsAlloc
         + " stores=" + r.GlobalStores.Count + " loads=" + r.GlobalLoads.Count
         + " strings=" + string.Join("|", r.Strings.Distinct().Take(4)));
     sb.AppendLine("cacheStoreCandidates=" + cacheCandidates.Count);
     foreach (var r in cacheCandidates.Take(12)) {
       sb.AppendLine("  CACHE 0x" + r.Entry.ToString("X") + " class=" + r.Klass
         + " stores=" + string.Join(",", r.GlobalStores.Distinct().Take(8).Select(x => "0x" + x.ToString("X")))
         + " loads=" + string.Join(",", r.GlobalLoads.Distinct().Take(8).Select(x => "0x" + x.ToString("X"))));
     }

     bool ppFound = hits.Any(h => h.Needle.IndexOf("PlayerProgression", StringComparison.Ordinal) >= 0);
     bool builderResolved = false; // never claim without BuildEntityWithSelector-equivalent proof
     sb.AppendLine("playerProgressionStringFound=" + ppFound);
     sb.AppendLine("cachedBuilderResolved=" + builderResolved);
     sb.AppendLine("decision=" + (ppFound
       ? "player-progression-string-found-builder-cache-unresolved"
       : "player-progression-absent"));
     sb.AppendLine("blocker=PlayerProgression name exists, but LoadEntityBuilderAndSelectorsForPlayer /");
     sb.AppendLine("        cached selector+builder handle globals are not yet identified.");

     string evidence = sb.ToString();
     File.WriteAllText(Path.Combine(rawDir, "evidence.txt"), evidence);
     WriteJson(root, hash, hits, leaSites, reps, progressionFuncs, cacheCandidates);
     Console.WriteLine(evidence);
     Console.WriteLine("playerProgressionFuncs=" + progressionFuncs.Count
       + " cacheStoreCandidates=" + cacheCandidates.Count);
     return ppFound ? 0 : 3;
   }

   static void EmitFunc(StringBuilder sb, FuncRep rep) {
     sb.AppendLine("0x" + rep.Entry.ToString("X")
       + " class=" + rep.Klass
       + " size=" + rep.Size
       + " schema=" + rep.CallsSchema
       + " alloc=" + rep.CallsAlloc
       + " deferred=" + rep.CallsDeferred
       + " stores=" + rep.GlobalStores.Count
       + " loads=" + rep.GlobalLoads.Count
       + " callees=" + string.Join(",", rep.Callees.Distinct().Take(14).Select(c => "0x" + c.ToString("X"))));
     foreach (string s in rep.Strings.Distinct().Take(8))
       sb.AppendLine("    str " + Trunc(s, 96));
     foreach (string line in rep.Head.Take(20))
       sb.AppendLine("    " + line);
     if (rep.GlobalStores.Count > 0)
       sb.AppendLine("    globalStores=" + string.Join(",", rep.GlobalStores.Distinct().Take(10).Select(x => "0x" + x.ToString("X"))));
     if (rep.GlobalLoads.Count > 0)
       sb.AppendLine("    globalLoads=" + string.Join(",", rep.GlobalLoads.Distinct().Take(10).Select(x => "0x" + x.ToString("X"))));
   }

   static FuncRep Analyze(uint entry) {
     var rep = new FuncRep { Entry = entry, Klass = "unclassified" };
     uint end = FindFuncEnd(entry, 0x900);
     var insns = DisasmRaw(entry, end);
     rep.Size = insns.Count == 0 ? 0 : (int)(insns[insns.Count - 1].Rva + insns[insns.Count - 1].Length - entry);
     foreach (var ins in insns) {
       if (rep.Head.Count < 28)
         rep.Head.Add("0x" + ins.Rva.ToString("X") + " " + Trunc(ins.Text, 100));
       if (ins.IsCall && ins.NearTarget != 0) {
         rep.Callees.Add(ins.NearTarget);
         if (ins.NearTarget == SchemaRegister) rep.CallsSchema = true;
         if (ins.NearTarget == Allocator) rep.CallsAlloc = true;
         if (ins.NearTarget == CreateActorsDeferred) rep.CallsDeferred = true;
       }
       if (ins.IpRel && ins.DataRva != 0) {
         string s = ReadAscii(ins.DataRva, 96);
         if (IsString(s)) {
           rep.Strings.Add(s);
           rep.DataLeas.Add(ins.DataRva);
         } else if (IsData(ins.DataRva)) {
           // Heuristic: RIP-relative mem ops against non-string data.
           if (ins.IsStore) rep.GlobalStores.Add(ins.DataRva);
           if (ins.IsLoad) rep.GlobalLoads.Add(ins.DataRva);
         }
       }
     }
     bool pp = rep.Strings.Any(s => s.IndexOf("PlayerProgression", StringComparison.Ordinal) >= 0);
     if (rep.CallsSchema) rep.Klass = pp ? "player-progression-schema" : "schema";
     else if (rep.CallsAlloc) rep.Klass = "alloc-user";
     else if (rep.GlobalStores.Count >= 2) rep.Klass = "multi-global-store";
     else if (pp) rep.Klass = "player-progression-ref";
     else if (rep.Strings.Count > 0) rep.Klass = "named-ref";
     else rep.Klass = "unrelated";
     return rep;
   }

   static void WriteJson(string root, string hash, List<Hit> hits,
       List<Tuple<string, uint, uint>> leas, List<FuncRep> reps,
       List<FuncRep> progression, List<FuncRep> cacheCandidates) {
     var sb = new StringBuilder();
     sb.AppendLine("{");
     sb.AppendLine("  \"schemaVersion\": 1,");
     sb.AppendLine("  \"milestone\": \"v0.8.0\",");
     sb.AppendLine("  \"mode\": \"offline-pe-readonly\",");
     sb.AppendLine("  \"exeSha256\": \"" + hash + "\",");
     bool ppFound = hits.Any(h => h.Needle.IndexOf("PlayerProgression", StringComparison.Ordinal) >= 0);
     sb.AppendLine("  \"playerProgressionStringFound\": " + T(ppFound) + ",");
     sb.AppendLine("  \"cachedBuilderResolved\": false,");
     sb.AppendLine("  \"spawnPlayerParamsVisitor\": \"0x80F2A20\",");
     sb.AppendLine("  \"playerProgressionRegistrar\": \"0x1C75AB0\",");
     sb.AppendLine("  \"decision\": " + J("player-progression-string-found-builder-cache-unresolved") + ",");
     sb.AppendLine("  \"blocker\": " + J("PlayerProgression name exists; cached selector+builder handle globals not identified") + ",");
     sb.AppendLine("  \"strings\": [");
     for (int i = 0; i < hits.Count; i++) {
       var h = hits[i];
       sb.Append("    {\"needle\": " + J(h.Needle) + ", \"rva\": \"0x" + h.Rva.ToString("X")
         + "\", \"text\": " + J(Trunc(h.Text, 80)) + "}");
       sb.AppendLine(i + 1 < hits.Count ? "," : "");
     }
     sb.AppendLine("  ],");
     sb.AppendLine("  \"leaSites\": [");
     for (int i = 0; i < Math.Min(leas.Count, 80); i++) {
       var s = leas[i];
       sb.Append("    {\"needle\": " + J(s.Item1) + ", \"site\": \"0x" + s.Item2.ToString("X")
         + "\", \"func\": \"0x" + s.Item3.ToString("X") + "\"}");
       sb.AppendLine(i + 1 < Math.Min(leas.Count, 80) ? "," : "");
     }
     sb.AppendLine("  ],");
     sb.AppendLine("  \"playerProgressionFuncs\": [");
     for (int i = 0; i < progression.Count; i++) {
       var r = progression[i];
       sb.Append("    {\"entry\": \"0x" + r.Entry.ToString("X") + "\", \"class\": " + J(r.Klass)
         + ", \"callsSchema\": " + T(r.CallsSchema)
         + ", \"callsAlloc\": " + T(r.CallsAlloc)
         + ", \"globalStores\": [" + string.Join(", ", r.GlobalStores.Distinct().Take(12).Select(x => "\"0x" + x.ToString("X") + "\"")) + "]"
         + ", \"globalLoads\": [" + string.Join(", ", r.GlobalLoads.Distinct().Take(12).Select(x => "\"0x" + x.ToString("X") + "\"")) + "]"
         + ", \"strings\": [" + string.Join(", ", r.Strings.Distinct().Take(8).Select(J)) + "]"
         + ", \"callees\": [" + string.Join(", ", r.Callees.Distinct().Take(16).Select(c => "\"0x" + c.ToString("X") + "\"")) + "]}");
       sb.AppendLine(i + 1 < progression.Count ? "," : "");
     }
     sb.AppendLine("  ],");
     sb.AppendLine("  \"cacheStoreCandidates\": [");
     for (int i = 0; i < Math.Min(cacheCandidates.Count, 24); i++) {
       var r = cacheCandidates[i];
       sb.Append("    {\"entry\": \"0x" + r.Entry.ToString("X") + "\", \"class\": " + J(r.Klass)
         + ", \"stores\": [" + string.Join(", ", r.GlobalStores.Distinct().Take(12).Select(x => "\"0x" + x.ToString("X") + "\"")) + "]"
         + ", \"loads\": [" + string.Join(", ", r.GlobalLoads.Distinct().Take(12).Select(x => "\"0x" + x.ToString("X") + "\"")) + "]}");
       sb.AppendLine(i + 1 < Math.Min(cacheCandidates.Count, 24) ? "," : "");
     }
     sb.AppendLine("  ],");
     sb.AppendLine("  \"functions\": [");
     var uniq = reps.GroupBy(r => r.Entry).Select(g => g.First()).OrderBy(r => r.Entry).ToList();
     for (int i = 0; i < uniq.Count; i++) {
       var r = uniq[i];
       sb.Append("    {\"entry\": \"0x" + r.Entry.ToString("X") + "\", \"class\": " + J(r.Klass)
         + ", \"callsSchema\": " + T(r.CallsSchema)
         + ", \"callsAlloc\": " + T(r.CallsAlloc)
         + ", \"size\": " + r.Size + "}");
       sb.AppendLine(i + 1 < uniq.Count ? "," : "");
     }
     sb.AppendLine("  ]");
     sb.AppendLine("}");
     File.WriteAllText(Path.Combine(root, "reports", "v0.8.0-builder-path.json"), sb.ToString());
     Console.WriteLine("WROTE reports/v0.8.0-builder-path.json");
   }

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
     while (dec.IP < limit && guard++ < 2800) {
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
         if (kind != OpKind.Memory || !raw.IsIPRelativeMemoryOperand) continue;
         ins.IpRel = true;
         ulong va = raw.IPRelativeMemoryAddress;
         if (va >= imageBase) ins.DataRva = (uint)(va - imageBase);
       }
       // Store vs load from formatted text (Iced does not expose write easily here).
       string t = ins.Text;
       int comma = t.IndexOf(',');
       if (comma > 0) {
         string left = t.Substring(0, comma);
         string right = t.Substring(comma + 1);
         if (left.IndexOf('[') >= 0) ins.IsStore = true;
         if (right.IndexOf('[') >= 0) ins.IsLoad = true;
       } else if (t.IndexOf('[') >= 0 &&
                  (ins.Mnemonic == Mnemonic.Inc || ins.Mnemonic == Mnemonic.Dec
                   || ins.Mnemonic == Mnemonic.Add || ins.Mnemonic == Mnemonic.Sub
                   || ins.Mnemonic == Mnemonic.Or || ins.Mnemonic == Mnemonic.And
                   || ins.Mnemonic == Mnemonic.Xor || ins.Mnemonic == Mnemonic.Xchg)) {
         ins.IsStore = true;
         ins.IsLoad = true;
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

   static bool IsData(uint rva) {
     foreach (var s in secs) {
       uint span = Math.Max(s.VSize, s.Raw);
       if (rva < s.Va || rva >= s.Va + span) continue;
       bool exec = (s.Char & 0x20000000) != 0
         || s.Name.IndexOf("text", StringComparison.OrdinalIgnoreCase) >= 0;
       return !exec;
     }
     return false;
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
   static string T(bool b) => b ? "true" : "false";
   static string J(string s) {
     if (s == null) return "null";
     return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
   }

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
