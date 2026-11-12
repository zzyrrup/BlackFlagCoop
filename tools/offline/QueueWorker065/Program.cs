// v0.6.5 — Offline decode of deferred-queue workers 0x725400 and 0xE95E80.
// Read-only PE analysis. Does not launch, inject, hook, or write the game.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;

internal static class Program {
  const string ExpectedExeSha =
    "19920F34BB2FAC814023EE3C27F0CECA1872E80A2AAFB37C092C419FFF77CC0D";
  const uint Handler = 0x1AC380;
  const uint WorkerA = 0x725400;
  const uint WorkerB = 0xE95E80;
  const uint CallSiteA = 0x1AC4D3;
  const uint CallSiteB = 0x1AC4DB;

  static byte[] pe;
  static ulong imageBase;
  static List<Sec> secs;
  static readonly MasmFormatter Fmt = new MasmFormatter(
    new FormatterOptions { RipRelativeAddresses = true }, null, null);
  static readonly InstructionInfoFactory InfoFactory = new InstructionInfoFactory();

  sealed class Sec {
    public string Name;
    public uint Va, VSize, Raw, Ptr, Char;
  }

  sealed class Ins {
    public uint Rva;
    public int Len;
    public string Text;
    public Mnemonic Mnemonic;
    public FlowControl Flow;
    public bool IsCall, IsRet, IsJmp, IsJcc, IsIndirectCall;
    public uint BranchRva;
    public bool HasBranch;
    public bool IpRel;
    public uint DataRva;
    public bool HasMem;
    public Register MemBase, MemIndex;
    public int Scale;
    public long Disp;
    public int MemWidth;
    public string MemSize;
    public Register Op0Reg, Op1Reg;
    public OpKind Op0Kind, Op1Kind;
    public bool HasImm;
    public long Imm;
    public int ImmOp;
    public Instruction Raw;
  }

  sealed class Fact {
    public string Kind = "unknown";
    public int Bias;
    public bool Indexed;
    public int FromOffset = int.MinValue;
    public int FromWidth;
    public long Imm;
    public string Note = "";
    public Fact Clone() {
      return new Fact {
        Kind = Kind, Bias = Bias, Indexed = Indexed,
        FromOffset = FromOffset, FromWidth = FromWidth,
        Imm = Imm, Note = Note
      };
    }
    public override string ToString() {
      var s = Kind;
      if (Kind == "imm" || Kind == "zero") s += " " + Imm.ToString("X", CultureInfo.InvariantCulture);
      else if (Bias != 0 || Kind == "elem" || Kind == "subj" || Kind == "arrayBase" || Kind == "coordinator")
        s += " bias=" + Bias.ToString("X", CultureInfo.InvariantCulture);
      if (FromOffset != int.MinValue) s += " from+" + FromOffset.ToString("X", CultureInfo.InvariantCulture);
      if (Indexed) s += " indexed";
      if (!string.IsNullOrEmpty(Note)) s += " (" + Note + ")";
      return s;
    }
  }

  sealed class Access {
    public uint Site;
    public string Space; // element, coordinator, deref, other
    public string How;
    public int Offset;
    public int Width;
    public string BaseKind;
    public bool Indexed;
    public string Text;
    public string Note;
  }

  sealed class CallEvt {
    public uint Site;
    public uint Dest;
    public bool Indirect;
    public string Rcx, Rdx, R8, R9;
    public string Text;
  }

  static int Main(string[] args) {
    string exe = args.Length > 0 ? args[0] : @"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe";
    string outDir = args.Length > 1 ? args[1] : Path.Combine(Path.GetTempPath(), "bfc-v065");
    pe = File.ReadAllBytes(exe);
    string hash = Sha256Hex(pe);
    Console.WriteLine("exeSha256=" + hash);
    if (!hash.Equals(ExpectedExeSha, StringComparison.OrdinalIgnoreCase)) {
      Console.Error.WriteLine("REFUSING: EXE hash does not match the v0.6.4 target.");
      return 2;
    }
    if (Register.ECX.GetFullRegister() != Register.RCX ||
        Register.R8D.GetFullRegister() != Register.R8 ||
        Register.SIL.GetFullRegister() != Register.RSI ||
        Register.R15D.GetFullRegister() != Register.R15) {
      Console.Error.WriteLine("REFUSING: Iced full-register mapping failed a sanity check.");
      return 3;
    }
    ParsePe();
    Directory.CreateDirectory(outDir);

    var handler = DisasmFunc(Handler, 0x8000, out uint handlerEnd, out string handlerBound);
    Console.WriteLine("handler insns=" + handler.Count + " end=0x" + handlerEnd.ToString("X") + " bound=" + handlerBound);
    bool hitA = false, hitB = false;
    foreach (var ins in handler) {
      if (ins.Rva == CallSiteA && ins.IsCall && ins.HasBranch && ins.BranchRva == WorkerA) hitA = true;
      if (ins.Rva == CallSiteB && ins.IsCall && ins.HasBranch && ins.BranchRva == WorkerB) hitB = true;
    }
    Console.WriteLine("selfTest callA=" + hitA + " callB=" + hitB + " endMatch=" + (handlerEnd == 0x1ACA4A));
    if (!hitA || !hitB) {
      DumpList(handler, Path.Combine(outDir, "handler-FAIL.txt"), 400);
      Console.Error.WriteLine("Decoder failed to land on the known v0.6.4 call sites.");
      return 4;
    }

    var sb = new StringBuilder();
    var handlerAcc = new List<Access>();
    var handlerCalls = new List<CallEvt>();
    sb.AppendLine("===== HANDLER 0x1AC380 =====");
    Track(handler, Seed("coordinator"), handlerAcc, handlerCalls, sb, "handler");
    sb.AppendLine();
    sb.AppendLine("-- handler element/coordinator accesses --");
    foreach (var a in handlerAcc) sb.AppendLine(FormatAccess(a));
    sb.AppendLine("-- handler calls --");
    foreach (var c in handlerCalls) sb.AppendLine(FormatCall(c));

    AnalyzeWorker("A_0x725400", WorkerA, sb);
    AnalyzeWorker("B_0xE95E80", WorkerB, sb);

    sb.AppendLine();
    sb.AppendLine("===== CALLERS =====");
    WriteCallers(sb, WorkerA, "0x725400");
    WriteCallers(sb, WorkerB, "0xE95E80");

    sb.AppendLine();
    sb.AppendLine("===== LEA / QWORD XREFS =====");
    WriteLeaXrefs(sb, WorkerA, "0x725400");
    WriteLeaXrefs(sb, WorkerB, "0xE95E80");
    WriteQwordXrefs(sb, WorkerA, "0x725400");
    WriteQwordXrefs(sb, WorkerB, "0xE95E80");

    Probe(sb);
    string path = Path.Combine(outDir, "evidence.txt");
    File.WriteAllText(path, sb.ToString());
    Console.WriteLine("WROTE " + path + " chars=" + sb.Length);
    return (!hitA || !hitB) ? 4 : 0;
  }

  static void AnalyzeWorker(string tag, uint entry, StringBuilder sb) {
    var insns = DisasmFunc(entry, 0x20000, out uint end, out string bound);
    sb.AppendLine();
    sb.AppendLine("===== WORKER " + tag + " =====");
    sb.AppendLine("entry=0x" + entry.ToString("X") + " end=0x" + end.ToString("X")
      + " size=" + (end > entry ? (end - entry).ToString() : "0")
      + " section=" + SecName(entry) + " bound=" + bound + " insns=" + insns.Count);
    sb.AppendLine("prologue=" + Hex(entry, 32));
    if (insns.Count == 1 && insns[0].IsJmp && insns[0].HasBranch) {
      sb.AppendLine("THUNK jmp -> 0x" + insns[0].BranchRva.ToString("X"));
    }
    long frame = 0;
    foreach (var ins in insns) {
      if (ins.Mnemonic == Mnemonic.Sub && ins.Op0Reg == Register.RSP && ins.HasImm) {
        frame = ins.Imm;
        break;
      }
      if (ins.Rva > entry + 0x40) break;
    }
    sb.AppendLine("stackSubRsp=" + frame.ToString("X"));

    var acc = new List<Access>();
    var calls = new List<CallEvt>();
    var local = new StringBuilder();
    var seed = SeedSubj();
    Track(insns, seed, acc, calls, local, tag);
    sb.Append(local);
    sb.AppendLine("-- accesses (rcx seeded as subj = queue[slot].ptr; handler-proven) --");
    foreach (var a in acc) sb.AppendLine(FormatAccess(a));
    sb.AppendLine("-- calls --");
    foreach (var c in calls) sb.AppendLine(FormatCall(c));

    var seen = new HashSet<uint>();
    foreach (var c in calls) {
      if (c.Indirect || c.Dest == 0 || !seen.Add(c.Dest)) continue;
      if (RvaToFile(c.Dest) < 0) continue;
      DescribeCallee(sb, c);
    }
  }

  static void DescribeCallee(StringBuilder sb, CallEvt c) {
    var insns = DisasmFunc(c.Dest, 0x6000, out uint end, out string bound);
    sb.AppendLine("CALLEE 0x" + c.Dest.ToString("X")
      + " size=" + (end > c.Dest ? (end - c.Dest).ToString() : "?")
      + " bound=" + bound + " insns=" + insns.Count
      + " atCall rcx=[" + c.Rcx + "] rdx=[" + c.Rdx + "] r8=[" + c.R8 + "] r9=[" + c.R9 + "]");
    int shown = 0;
    foreach (var ins in insns) {
      if (shown >= 6) break;
      sb.AppendLine("  | " + HexRva(ins.Rva) + " " + ins.Text);
      shown++;
    }
    var strings = new List<string>();
    var rttis = new List<string>();
    foreach (var ins in insns) {
      if (!ins.IpRel) continue;
      string s = ReadAscii(ins.DataRva, 80);
      if (IsString(s)) {
        string line = "0x" + ins.Rva.ToString("X") + " str " + Trunc(s, 70);
        if (strings.Count < 12 && !strings.Contains(line)) strings.Add(line);
      }
      string rtti = TryRttiName(ins.DataRva);
      if (rtti != null) {
        string line = "0x" + ins.Rva.ToString("X") + " rtti " + rtti;
        if (rttis.Count < 8 && !rttis.Contains(line)) rttis.Add(line);
      }
    }
    foreach (var s in strings) sb.AppendLine("  str " + s);
    foreach (var s in rttis) sb.AppendLine("  rtti " + s);

    bool passElem = ContainsKind(c.Rcx, "elem") || ContainsKind(c.Rcx, "subj") || ContainsKind(c.Rcx, "arrayBase")
      || ContainsKind(c.Rdx, "elem") || ContainsKind(c.Rdx, "subj") || ContainsKind(c.Rdx, "arrayBase")
      || ContainsKind(c.R8, "elem") || ContainsKind(c.R8, "subj") || ContainsKind(c.R8, "arrayBase")
      || ContainsKind(c.R9, "elem") || ContainsKind(c.R9, "subj") || ContainsKind(c.R9, "arrayBase");
    if (!passElem) return;

    var seed = new Dictionary<Register, Fact>();
    if (ContainsKind(c.Rcx, "elem") || ContainsKind(c.Rcx, "subj") || ContainsKind(c.Rcx, "arrayBase"))
      seed[Register.RCX] = new Fact { Kind = "elem", Note = "arg from caller" };
    if (ContainsKind(c.Rdx, "elem") || ContainsKind(c.Rdx, "subj") || ContainsKind(c.Rdx, "arrayBase"))
      seed[Register.RDX] = new Fact { Kind = "elem", Note = "arg from caller" };
    if (ContainsKind(c.R8, "elem") || ContainsKind(c.R8, "subj") || ContainsKind(c.R8, "arrayBase"))
      seed[Register.R8] = new Fact { Kind = "elem", Note = "arg from caller" };
    if (ContainsKind(c.R9, "elem") || ContainsKind(c.R9, "subj") || ContainsKind(c.R9, "arrayBase"))
      seed[Register.R9] = new Fact { Kind = "elem", Note = "arg from caller" };
    var acc = new List<Access>();
    var nested = new List<CallEvt>();
    var ignore = new StringBuilder();
    Track(insns, seed, acc, nested, ignore, "callee", logInsns: false);
    sb.AppendLine("  nested-elem-accesses=" + acc.Count);
    int n = 0;
    foreach (var a in acc) {
      if (n++ >= 40) { sb.AppendLine("  ..."); break; }
      sb.AppendLine("  acc " + FormatAccess(a));
    }
  }

  static bool ContainsKind(string fact, string kind) {
    return fact != null && fact.IndexOf(kind, StringComparison.Ordinal) >= 0;
  }

  static Dictionary<Register, Fact> Seed(string rcxKind) {
    return new Dictionary<Register, Fact> {
      { Register.RCX, new Fact { Kind = rcxKind, Note = "entry" } }
    };
  }

  // Workers receive the subject object pointer from queue slot+0 (not the 16-byte slot).
  static Dictionary<Register, Fact> SeedSubj() {
    return new Dictionary<Register, Fact> {
      { Register.RCX, new Fact { Kind = "subj", Note = "queue slot ptr arg" } }
    };
  }

  static void Track(List<Ins> insns, Dictionary<Register, Fact> seed,
      List<Access> acc, List<CallEvt> calls, StringBuilder log, string tag, bool logInsns = true) {
    var facts = new Dictionary<Register, Fact>();
    foreach (var kv in seed) facts[kv.Key] = kv.Value.Clone();
    var slots = new Dictionary<long, Fact>();
    long rsp = 0;
    foreach (var ins in insns) {
      if (logInsns) log.AppendLine(HexRva(ins.Rva) + " " + ins.Text);

      var baseReg = Full64(ins.MemBase);
      var indexReg = Full64(ins.MemIndex);
      Fact baseFact = null, indexFact = null;
      if (baseReg != Register.None) facts.TryGetValue(baseReg, out baseFact);
      if (indexReg != Register.None) facts.TryGetValue(indexReg, out indexFact);

      if (ins.HasMem && baseFact != null && IsPtrKind(baseFact.Kind)) {
        int off = baseFact.Bias + (int)ins.Disp;
        var a = new Access {
          Site = ins.Rva,
          How = HowOf(ins),
          Offset = off,
          Width = ins.MemWidth,
          BaseKind = baseFact.Kind,
          Indexed = ins.MemIndex != Register.None || baseFact.Indexed,
          Text = ins.Text,
          Note = baseFact.Note
        };
        if (baseFact.Kind == "coordinator" || baseFact.Kind == "addrOfCoord")
          a.Space = "coordinator";
        else if (baseFact.Kind == "loadedPtr")
          a.Space = "deref";
        else if (baseFact.Kind == "subj")
          a.Space = "subject";
        else
          a.Space = "element";
        acc.Add(a);
      } else if (ins.HasMem && baseFact != null && baseFact.Kind == "loadedPtr") {
        acc.Add(new Access {
          Site = ins.Rva,
          Space = "deref",
          How = HowOf(ins),
          Offset = baseFact.FromOffset,
          Width = ins.MemWidth,
          BaseKind = "loadedPtr",
          Indexed = ins.MemIndex != Register.None,
          Text = ins.Text,
          Note = "deref +" + ins.Disp.ToString("X") + " of field +" + baseFact.FromOffset.ToString("X")
        });
      }

      if (ins.IpRel && logInsns) {
        string s = ReadAscii(ins.DataRva, 72);
        string rtti = TryRttiName(ins.DataRva);
        if (rtti != null) log.AppendLine("    RTTI " + rtti);
        else if (IsString(s)) log.AppendLine("    STR \"" + Trunc(s, 90) + "\"");
      }

      if (ins.IsCall) {
        calls.Add(new CallEvt {
          Site = ins.Rva,
          Dest = ins.HasBranch ? ins.BranchRva : 0,
          Indirect = ins.IsIndirectCall,
          Rcx = Desc(facts, Register.RCX),
          Rdx = Desc(facts, Register.RDX),
          R8 = Desc(facts, Register.R8),
          R9 = Desc(facts, Register.R9),
          Text = ins.Text
        });
      }

      Apply(ins, facts, slots, ref rsp);
    }
  }

  static string HowOf(Ins ins) {
    if (ins.Mnemonic == Mnemonic.Lea) return "lea";
    if (ins.IsIndirectCall) return "indirect-call";
    if (ins.Mnemonic == Mnemonic.Cmp || ins.Mnemonic == Mnemonic.Test) return "cmp";
    if (ins.Op0Kind == OpKind.Memory) return "store";
    return "load";
  }

  static bool IsPtrKind(string k) {
    return k == "coordinator" || k == "elem" || k == "subj" || k == "arrayBase" || k == "addrOfCoord";
  }

  static void Apply(Ins ins, Dictionary<Register, Fact> facts, Dictionary<long, Fact> slots, ref long rsp) {
    var written = WrittenGprs(ins);

    if (ins.Mnemonic == Mnemonic.Push && ins.Op0Kind == OpKind.Register) {
      var r = Full64(ins.Op0Reg);
      rsp -= 8;
      Fact f;
      if (r != Register.None && facts.TryGetValue(r, out f)) slots[rsp] = f.Clone();
      return;
    }
    if (ins.Mnemonic == Mnemonic.Pop && ins.Op0Kind == OpKind.Register) {
      var r = Full64(ins.Op0Reg);
      Fact f;
      if (r != Register.None) {
        if (slots.TryGetValue(rsp, out f)) facts[r] = f.Clone();
        else facts.Remove(r);
      }
      rsp += 8;
      return;
    }
    if ((ins.Mnemonic == Mnemonic.Sub || ins.Mnemonic == Mnemonic.Add) &&
        ins.Op0Reg == Register.RSP && ins.HasImm) {
      rsp += ins.Mnemonic == Mnemonic.Sub ? -ins.Imm : ins.Imm;
      return;
    }

    var explicitSet = new HashSet<Register>();

    if (ins.Mnemonic == Mnemonic.Lea && ins.Op0Kind == OpKind.Register) {
      var dest = Full64(ins.Op0Reg);
      if (dest != Register.None) {
        facts[dest] = LeaFact(ins, facts);
        explicitSet.Add(dest);
      }
    } else if (ins.Mnemonic == Mnemonic.Mov || ins.Mnemonic == Mnemonic.Movzx || ins.Mnemonic == Mnemonic.Movsx ||
               ins.Mnemonic == Mnemonic.Movsxd) {
      ApplyMov(ins, facts, slots, rsp, explicitSet);
    } else if ((ins.Mnemonic == Mnemonic.Xor || ins.Mnemonic == Mnemonic.Sub || ins.Mnemonic == Mnemonic.Sbb) &&
               ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Register &&
               Full64(ins.Op0Reg) == Full64(ins.Op1Reg) && Full64(ins.Op0Reg) != Register.None) {
      var d = Full64(ins.Op0Reg);
      facts[d] = new Fact { Kind = "zero", Imm = 0 };
      explicitSet.Add(d);
    } else if ((ins.Mnemonic == Mnemonic.Add || ins.Mnemonic == Mnemonic.Sub) &&
               ins.Op0Kind == OpKind.Register && ins.HasImm) {
      var d = Full64(ins.Op0Reg);
      Fact cur;
      if (d != Register.None && facts.TryGetValue(d, out cur) && IsPtrKind(cur.Kind)) {
        var n = cur.Clone();
        int delta = (int)ins.Imm;
        if (ins.Mnemonic == Mnemonic.Sub) delta = -delta;
        n.Bias += delta;
        n.Note = "adj";
        facts[d] = n;
        explicitSet.Add(d);
      }
    } else if (ins.Mnemonic == Mnemonic.Shl && ins.Op0Kind == OpKind.Register && ins.HasImm && ins.Imm == 4) {
      var d = Full64(ins.Op0Reg);
      if (d != Register.None) {
        facts[d] = new Fact { Kind = "byteOffset", Note = "shl 4" };
        explicitSet.Add(d);
      }
    } else if (ins.Mnemonic == Mnemonic.Imul && ins.HasImm && (ins.Imm == 16 || ins.Imm == 0x10)) {
      var d = Full64(ins.Op0Reg);
      if (d != Register.None) {
        facts[d] = new Fact { Kind = "byteOffset", Note = "imul 16" };
        explicitSet.Add(d);
      }
    } else if (ins.Mnemonic == Mnemonic.And && ins.Op0Kind == OpKind.Register && ins.HasImm &&
               (ins.Imm & 0xFFFFFFFF) == 0x3FFF) {
      var d = Full64(ins.Op0Reg);
      if (d != Register.None) {
        facts[d] = new Fact { Kind = "count", Imm = 0x3FFF, Note = "mask 3FFF" };
        explicitSet.Add(d);
      }
    }

    foreach (var w in written) {
      if (explicitSet.Contains(w)) continue;
      if (w == Register.RSP) continue;
      facts.Remove(w);
    }

    if (ins.IsCall) {
      foreach (var v in new[] {
        Register.RAX, Register.RCX, Register.RDX, Register.R8, Register.R9, Register.R10, Register.R11 })
        facts.Remove(v);
    }
  }

  static void ApplyMov(Ins ins, Dictionary<Register, Fact> facts, Dictionary<long, Fact> slots,
      long rsp, HashSet<Register> explicitSet) {
    if (ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Register) {
      var d = Full64(ins.Op0Reg);
      var s = Full64(ins.Op1Reg);
      if (d == Register.None) return;
      Fact f;
      if (s != Register.None && facts.TryGetValue(s, out f)) facts[d] = f.Clone();
      else facts.Remove(d);
      explicitSet.Add(d);
      return;
    }
    if (ins.Op0Kind == OpKind.Register && ins.HasImm && ins.ImmOp == 1) {
      var d = Full64(ins.Op0Reg);
      if (d == Register.None) return;
      facts[d] = new Fact { Kind = ins.Imm == 0 ? "zero" : "imm", Imm = ins.Imm };
      explicitSet.Add(d);
      return;
    }
    if (ins.Op0Kind == OpKind.Register && ins.HasMem) {
      var d = Full64(ins.Op0Reg);
      if (d == Register.None) return;
      facts[d] = LoadFact(ins, facts, slots, rsp);
      explicitSet.Add(d);
      return;
    }
    if (ins.Op0Kind == OpKind.Memory && ins.Op1Kind == OpKind.Register) {
      var s = Full64(ins.Op1Reg);
      var b = Full64(ins.MemBase);
      if (b == Register.RSP || b == Register.RBP) {
        long key = rsp + ins.Disp;
        Fact f;
        if (s != Register.None && facts.TryGetValue(s, out f)) slots[key] = f.Clone();
        else slots.Remove(key);
      }
    }
  }

  static Fact LoadFact(Ins ins, Dictionary<Register, Fact> facts, Dictionary<long, Fact> slots, long rsp) {
    var b = Full64(ins.MemBase);
    Fact bf;
    facts.TryGetValue(b, out bf);
    if ((b == Register.RSP || b == Register.RBP) && ins.MemIndex == Register.None) {
      Fact slot;
      if (slots.TryGetValue(rsp + ins.Disp, out slot)) return slot.Clone();
    }
    if (bf == null) return new Fact { Kind = "unknown", Note = "load" };
    if ((bf.Kind == "coordinator" || bf.Kind == "addrOfCoord") && ins.MemWidth >= 8) {
      int field = bf.Bias + (int)ins.Disp;
      if (field == 0xAC0)
        return new Fact { Kind = "arrayBase", Note = "load coord+AC0" };
    }
    if ((bf.Kind == "elem" || bf.Kind == "arrayBase") && ins.MemWidth >= 8) {
      int off = bf.Bias + (int)ins.Disp;
      // Deferred queue slots are { ptr@+0, float@+8 }; indexed load from arrayBase+0
      // is the subject object pointer passed to workers (confirmed by handler sites).
      if (bf.Kind == "arrayBase" && off == 0)
        return new Fact {
          Kind = "subj",
          FromOffset = 0,
          FromWidth = ins.MemWidth,
          Indexed = ins.MemIndex != Register.None || bf.Indexed,
          Note = "load queue slot ptr"
        };
      return new Fact {
        Kind = "loadedPtr",
        FromOffset = off,
        FromWidth = ins.MemWidth,
        Indexed = ins.MemIndex != Register.None || bf.Indexed,
        Note = "load elem field"
      };
    }
    return new Fact { Kind = "unknown", Note = "load" };
  }

  static Fact LeaFact(Ins ins, Dictionary<Register, Fact> facts) {
    if (ins.IpRel) {
      string rtti = TryRttiName(ins.DataRva);
      if (rtti != null) return new Fact { Kind = "vtable", Note = rtti };
      string s = ReadAscii(ins.DataRva, 72);
      if (IsString(s)) return new Fact { Kind = "str", Note = Trunc(s, 60) };
      return new Fact { Kind = "addr", Imm = ins.DataRva, Note = "rva " + ins.DataRva.ToString("X") };
    }
    var b = Full64(ins.MemBase);
    var ix = Full64(ins.MemIndex);
    Fact bf, inf;
    facts.TryGetValue(b, out bf);
    facts.TryGetValue(ix, out inf);
    if (bf != null && bf.Kind == "coordinator") {
      return new Fact {
        Kind = "addrOfCoord",
        Bias = bf.Bias + (int)ins.Disp,
        Indexed = ix != Register.None,
        Note = "lea coord field"
      };
    }
    if (bf != null && (bf.Kind == "arrayBase" || bf.Kind == "elem" || bf.Kind == "subj")) {
      var n = new Fact {
        Kind = bf.Kind == "arrayBase" ? "elem" : bf.Kind,
        Bias = bf.Bias + (int)ins.Disp,
        Indexed = bf.Indexed || ix != Register.None,
        Note = "lea"
      };
      if (inf != null && inf.Kind == "byteOffset") n.Note = "lea + byteOffset";
      return n;
    }
    return new Fact { Kind = "unknown", Note = "lea" };
  }

  static List<Register> WrittenGprs(Ins ins) {
    var list = new List<Register>();
    var info = InfoFactory.GetInfo(ins.Raw);
    foreach (var u in info.GetUsedRegisters()) {
      if (u.Access != OpAccess.Write && u.Access != OpAccess.ReadWrite &&
          u.Access != OpAccess.CondWrite) continue;
      var f = Full64(u.Register);
      if (f == Register.None || f == Register.RSP) continue;
      if (!list.Contains(f)) list.Add(f);
    }
    return list;
  }

  static string Desc(Dictionary<Register, Fact> facts, Register r) {
    Fact f;
    return facts.TryGetValue(r, out f) ? f.ToString() : "-";
  }

  static string FormatAccess(Access a) {
    return HexRva(a.Site) + " " + a.Space + " " + a.How
      + " off=" + a.Offset.ToString("X")
      + " w=" + a.Width
      + (a.Indexed ? " indexed" : "")
      + " base=" + a.BaseKind
      + " :: " + a.Text
      + (string.IsNullOrEmpty(a.Note) ? "" : " :: " + a.Note);
  }

  static string FormatCall(CallEvt c) {
    string dest = c.Indirect ? "indirect" : "0x" + c.Dest.ToString("X");
    return HexRva(c.Site) + " call " + dest
      + " rcx=[" + c.Rcx + "] rdx=[" + c.Rdx + "] r8=[" + c.R8 + "] r9=[" + c.R9 + "]"
      + " :: " + c.Text;
  }

  static void WriteCallers(StringBuilder sb, uint target, string name) {
    var hits = FindE8Callers(target, 40);
    sb.AppendLine("E8 callers of " + name + " count=" + hits.Count);
    foreach (var site in hits) {
      bool boundary = NearBoundary(site);
      sb.AppendLine("  caller 0x" + site.ToString("X") + " boundary=" + boundary
        + " section=" + SecName(site));
      uint start = FindFuncStart(site);
      if (start != 0 && start < site) {
        var window = DisasmRange(start, site + 5);
        int from = Math.Max(0, window.Count - 8);
        for (int i = from; i < window.Count; i++) {
          var ins = window[i];
          if (ins.Rva + (uint)ins.Len < site - 24 && ins.Rva != site) continue;
          sb.AppendLine("    " + HexRva(ins.Rva) + " " + ins.Text);
        }
      }
    }
  }

  static void WriteLeaXrefs(StringBuilder sb, uint target, string name) {
    var hits = FindLeaTo(target, 30);
    sb.AppendLine("LEA xrefs to " + name + " count=" + hits.Count);
    foreach (var s in hits) sb.AppendLine("  lea 0x" + s.ToString("X"));
  }

  static void WriteQwordXrefs(StringBuilder sb, uint target, string name) {
    var hits = FindQword(target, 30);
    sb.AppendLine("Qword xrefs to " + name + " count=" + hits.Count);
    foreach (var s in hits) sb.AppendLine("  qw 0x" + s.ToString("X") + " section=" + SecName(s));
  }

  static List<Ins> DisasmFunc(uint entry, int maxBytes, out uint end, out string bound) {
    var list = DisasmRange(entry, entry + (uint)maxBytes);
    end = entry;
    bound = list.Count == 0 ? "unmapped_or_empty" : "maxscan";
    for (int i = 0; i < list.Count; i++) {
      var ins = list[i];
      if (ins.Mnemonic == Mnemonic.Int3) {
        list.RemoveRange(i, list.Count - i);
        end = ins.Rva;
        bound = "int3";
        break;
      }
      if (ins.IsRet) {
        uint next = ins.Rva + (uint)ins.Len;
        int fo = RvaToFile(next);
        if (fo >= 0 && fo < pe.Length && pe[fo] == 0xCC) {
          if (i + 1 < list.Count) list.RemoveRange(i + 1, list.Count - (i + 1));
          end = next;
          bound = "ret_then_int3";
          break;
        }
      }
    }
    if (bound == "maxscan" && list.Count > 0)
      end = list[list.Count - 1].Rva + (uint)list[list.Count - 1].Len;
    return list;
  }

  static List<Ins> DisasmRange(uint start, uint endExclusive) {
    var list = new List<Ins>();
    int file = RvaToFile(start);
    if (file < 0) return list;
    var reader = new ByteArrayCodeReader(pe);
    reader.Position = file;
    var dec = Decoder.Create(64, reader);
    dec.IP = imageBase + start;
    ulong limit = imageBase + endExclusive;
    int guard = 0;
    while (dec.IP < limit && guard++ < 50000) {
      var raw = dec.Decode();
      if (raw.Length == 0 || raw.Code == Code.INVALID) break;
      if (raw.IP < imageBase) break;
      list.Add(ToIns(raw));
      if (raw.Mnemonic == Mnemonic.Int3 && list.Count > 1) break;
    }
    return list;
  }

  static Ins ToIns(Instruction raw) {
    var o = new StringOutput();
    Fmt.Format(raw, o);
    var ins = new Ins();
    ins.Raw = raw;
    ins.Rva = (uint)(raw.IP - imageBase);
    ins.Len = raw.Length;
    ins.Text = o.ToString();
    ins.Mnemonic = raw.Mnemonic;
    ins.Flow = raw.FlowControl;
    ins.IsRet = raw.Mnemonic == Mnemonic.Ret || raw.Mnemonic == Mnemonic.Retf;
    ins.IsCall = raw.FlowControl == FlowControl.Call || raw.FlowControl == FlowControl.IndirectCall;
    ins.IsIndirectCall = raw.FlowControl == FlowControl.IndirectCall;
    ins.IsJmp = raw.FlowControl == FlowControl.UnconditionalBranch || raw.FlowControl == FlowControl.IndirectBranch;
    ins.IsJcc = raw.FlowControl == FlowControl.ConditionalBranch;
    if (raw.Op0Kind == OpKind.NearBranch64 || raw.Op0Kind == OpKind.NearBranch32) {
      ulong t = raw.NearBranchTarget;
      if (t >= imageBase) {
        ins.HasBranch = true;
        ins.BranchRva = (uint)(t - imageBase);
        ins.Text += " ; -> 0x" + ins.BranchRva.ToString("X");
      }
    }
    ins.Op0Kind = raw.Op0Kind;
    ins.Op1Kind = raw.Op1Kind;
    ins.Op0Reg = raw.Op0Kind == OpKind.Register ? raw.Op0Register : Register.None;
    ins.Op1Reg = raw.Op1Kind == OpKind.Register ? raw.Op1Register : Register.None;
    ins.HasMem = false;
    for (int i = 0; i < raw.OpCount; i++) {
      if (raw.GetOpKind(i) == OpKind.Memory) { ins.HasMem = true; break; }
    }
    if (ins.HasMem) {
      ins.MemBase = raw.MemoryBase;
      ins.MemIndex = raw.MemoryIndex;
      ins.Scale = raw.MemoryIndexScale;
      ins.MemWidth = raw.MemorySize.GetSize();
      ins.MemSize = raw.MemorySize.ToString();
      if (raw.IsIPRelativeMemoryOperand) {
        ins.IpRel = true;
        ulong va = raw.IPRelativeMemoryAddress;
        if (va >= imageBase) ins.DataRva = (uint)(va - imageBase);
        ins.Text += " ; data 0x" + ins.DataRva.ToString("X");
      } else {
        ins.Disp = SignedDisp(raw);
      }
    }
    ins.HasImm = false;
    for (int i = 0; i < raw.OpCount; i++) {
      long imm;
      if (TryImm(raw, i, out imm)) {
        ins.HasImm = true;
        ins.Imm = imm;
        ins.ImmOp = i;
        break;
      }
    }
    return ins;
  }

  static long SignedDisp(Instruction raw) {
    int sz = raw.MemoryDisplSize;
    if (sz == 1) return unchecked((sbyte)raw.MemoryDisplacement32);
    if (sz == 2) return unchecked((short)raw.MemoryDisplacement32);
    if (sz == 4) return unchecked((int)raw.MemoryDisplacement32);
    if (sz == 8) return unchecked((long)raw.MemoryDisplacement64);
    return 0;
  }

  static bool TryImm(Instruction raw, int op, out long imm) {
    var k = raw.GetOpKind(op);
    if (k == OpKind.Immediate8) { imm = raw.Immediate8; return true; }
    if (k == OpKind.Immediate8to32) { imm = raw.Immediate8to32; return true; }
    if (k == OpKind.Immediate8to64) { imm = unchecked((long)raw.Immediate8to64); return true; }
    if (k == OpKind.Immediate32) { imm = raw.Immediate32; return true; }
    if (k == OpKind.Immediate32to64) { imm = raw.Immediate32to64; return true; }
    if (k == OpKind.Immediate64) { imm = unchecked((long)raw.Immediate64); return true; }
    if (k == OpKind.Immediate16) { imm = raw.Immediate16; return true; }
    imm = 0;
    return false;
  }

  static Register Full64(Register r) {
    if (!r.IsGPR()) return Register.None;
    return r.GetFullRegister();
  }

  static bool NearBoundary(uint site) {
    uint start = FindFuncStart(site);
    if (start == 0 || start > site) return false;
    var list = DisasmRange(start, site + 8);
    foreach (var ins in list)
      if (ins.Rva == site && ins.IsCall) return true;
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
    if (pad < 0) return site > 0x80 ? site - 0x80 : site;
    uint rva = site - (uint)pad;
    int p = RvaToFile(rva);
    while (p >= 0 && p < pe.Length && pe[p] == 0xCC) { rva++; p++; }
    return rva;
  }

  static List<uint> FindE8Callers(uint dest, int max) {
    var list = new List<uint>();
    foreach (var s in secs) {
      if ((s.Char & 0x20000000) == 0 || s.Ptr == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 5 <= lim && list.Count < max; i++) {
        if (pe[s.Ptr + i] != 0xE8) continue;
        int rel = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 1));
        long site = (long)s.Va + i;
        long d = site + 5 + rel;
        if (d == dest) list.Add((uint)site);
      }
    }
    return list;
  }

  static List<uint> FindLeaTo(uint target, int max) {
    var list = new List<uint>();
    foreach (var s in secs) {
      if ((s.Char & 0x20000000) == 0 || s.Ptr == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 7 <= lim && list.Count < max; i++) {
        byte rex = pe[s.Ptr + i];
        if (rex != 0x48 && rex != 0x4C) continue;
        if (pe[s.Ptr + i + 1] != 0x8D) continue;
        if ((pe[s.Ptr + i + 2] & 0xC7) != 0x05) continue;
        int disp = BitConverter.ToInt32(pe, (int)(s.Ptr + i + 3));
        uint site = s.Va + i;
        uint tgt = unchecked((uint)(site + 7 + disp));
        if (tgt == target) list.Add(site);
      }
    }
    return list;
  }

  static List<uint> FindQword(uint destRva, int max) {
    var list = new List<uint>();
    ulong abs = imageBase + destRva;
    byte[] needle = BitConverter.GetBytes(abs);
    foreach (var s in secs) {
      if (s.Ptr == 0) continue;
      uint lim = Math.Min(s.Raw, s.VSize > 0 ? s.VSize : s.Raw);
      for (uint i = 0; i + 8 <= lim && list.Count < max; i++) {
        bool ok = true;
        for (int k = 0; k < 8; k++) if (pe[s.Ptr + i + k] != needle[k]) { ok = false; break; }
        if (ok) list.Add(s.Va + i);
      }
    }
    return list;
  }

  static string TryRttiName(uint maybeVtable) {
    if (maybeVtable < 8) return null;
    int fo = RvaToFile(maybeVtable - 8);
    if (fo < 0 || fo + 8 > pe.Length) return null;
    ulong colVa = BitConverter.ToUInt64(pe, fo);
    if (colVa < imageBase) return null;
    uint col = (uint)(colVa - imageBase);
    int cfo = RvaToFile(col);
    if (cfo < 0 || cfo + 0x18 > pe.Length) return null;
    uint sig = BitConverter.ToUInt32(pe, cfo);
    if (sig != 1) return null;
    uint self = BitConverter.ToUInt32(pe, cfo + 0x14);
    if (self != col) return null;
    uint td = BitConverter.ToUInt32(pe, cfo + 0x0C);
    string name = ReadAscii(td + 0x10, 96);
    if (name.Length < 6 || !name.StartsWith(".?A", StringComparison.Ordinal)) return null;
    return Demangle(name) + " [" + name + "]";
  }

  static string Demangle(string n) {
    string s = n;
    if (s.StartsWith(".?AV", StringComparison.Ordinal) || s.StartsWith(".?AU", StringComparison.Ordinal))
      s = s.Substring(4);
    int at = s.IndexOf("@@", StringComparison.Ordinal);
    if (at >= 0) s = s.Substring(0, at);
    return s;
  }

  static bool IsString(string s) {
    if (string.IsNullOrEmpty(s) || s.Length < 4) return false;
    int ok = 0;
    foreach (char c in s) if (c >= 32 && c < 127) ok++;
    return ok * 5 >= s.Length * 4;
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

  static string Hex(uint rva, int n) {
    int fo = RvaToFile(rva);
    if (fo < 0) return "UNMAPPED";
    var sb = new StringBuilder();
    for (int i = 0; i < n && fo + i < pe.Length; i++) {
      if (i > 0) sb.Append(' ');
      sb.Append(pe[fo + i].ToString("X2"));
    }
    return sb.ToString();
  }

  static string HexRva(uint rva) { return "0x" + rva.ToString("X"); }

  static string Trunc(string s, int n) {
    if (s == null) return "";
    return s.Length <= n ? s : s.Substring(0, n);
  }

  static void DumpList(List<Ins> list, string path, int max) {
    var sb = new StringBuilder();
    int n = Math.Min(list.Count, max);
    for (int i = 0; i < n; i++) sb.AppendLine(HexRva(list[i].Rva) + " " + list[i].Text);
    File.WriteAllText(path, sb.ToString());
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

  static void Probe(StringBuilder sb) {
    sb.AppendLine();
    sb.AppendLine("===== PROBE =====");
    sb.AppendLine("handlerTail " + Hex(0x1AC600, 64));
    sb.AppendLine("afterEnd " + Hex(0x1AC61F, 32));
    sb.AppendLine("float97C5C00 " + F32(0x97C5C00) + " raw " + Hex(0x97C5C00, 4));
    sb.AppendLine("u16_B2888BC " + U16(0xB2888BC) + " u16_B2888BE " + U16(0xB2888BE));
    sb.AppendLine("siteB2898C8 ascii=" + ReadAscii(0xB2898C8, 64));
    sb.AppendLine("siteB2898C8 hex=" + Hex(0xB2898C8, 32));
    sb.AppendLine("q919BCB8 " + Q(0x919BCB8) + " rtti=" + (TryRttiName(0x919BCB8) ?? "none") + " ascii=" + ReadAscii(0x919BCB8, 48));
    sb.AppendLine("q919BC98 " + Q(0x919BC98) + " rtti=" + (TryRttiName(0x919BC98) ?? "none") + " ascii=" + ReadAscii(0x919BC98, 48));
    sb.AppendLine("storedAF6FD48 " + Q(0xAF6FD48));
    sb.AppendLine("falseCaller " + Hex(0x129E51D0, 16));
    DumpShort(sb, "D530", 0xD530);
    DumpShort(sb, "7B02D70", 0x7B02D70);
    DumpShort(sb, "7B04200", 0x7B04200);
    DumpShort(sb, "2E9FA60", 0x2E9FA60);
    sb.AppendLine("ascii97B7430=" + ReadAscii(0x97B7430, 64));
    sb.AppendLine("hex7B04200 " + Hex(0x7B04200, 16));
    sb.AppendLine("hex2E9FA60 " + Hex(0x2E9FA60, 16));
    sb.AppendLine("nextFn " + Hex(0x1AC620, 16));
  }

  static void DumpShort(StringBuilder sb, string name, uint rva) {
    var ins = DisasmFunc(rva, 0x800, out uint end, out string bound);
    sb.AppendLine("fn " + name + " end=0x" + end.ToString("X") + " size=" + (end - rva) + " bound=" + bound + " insns=" + ins.Count);
    int n = Math.Min(ins.Count, 25);
    for (int i = 0; i < n; i++) sb.AppendLine("  " + HexRva(ins[i].Rva) + " " + ins[i].Text);
    foreach (var i in ins) {
      if (!i.IpRel) continue;
      string s = ReadAscii(i.DataRva, 64);
      string r = TryRttiName(i.DataRva);
      if (r != null) sb.AppendLine("  rtti " + r);
      else if (IsString(s) && s.IndexOf(' ') >= 0) sb.AppendLine("  str " + Trunc(s, 80));
    }
  }

  static string F32(uint rva) {
    int fo = RvaToFile(rva);
    if (fo < 0 || fo + 4 > pe.Length) return "unmapped";
    float f = BitConverter.ToSingle(pe, fo);
    return f.ToString("R", CultureInfo.InvariantCulture);
  }

  static int U16(uint rva) {
    int fo = RvaToFile(rva);
    if (fo < 0 || fo + 2 > pe.Length) return -1;
    return BitConverter.ToUInt16(pe, fo);
  }

  static string Q(uint rva) {
    int fo = RvaToFile(rva);
    if (fo < 0 || fo + 8 > pe.Length) return "unmapped";
    ulong q = BitConverter.ToUInt64(pe, fo);
    string s = "0x" + q.ToString("X");
    if (q >= imageBase) {
      uint rr = (uint)(q - imageBase);
      string rtti = TryRttiName(rr);
      if (rtti != null) s += " -> " + rtti;
      else s += " rva 0x" + rr.ToString("X") + " sec " + SecName(rr);
    }
    return s;
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
