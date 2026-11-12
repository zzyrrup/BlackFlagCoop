using System; using System.Collections.Generic; using System.IO; using System.Text;
class X {
  static void Main() {
    byte[] pe = File.ReadAllBytes(@"C:\Games\AC Black Flag Resynced\ACBlackFlag.exe");
    int e = BitConverter.ToInt32(pe, 0x3C);
    ushort num = BitConverter.ToUInt16(pe, e+6);
    ushort opt = BitConverter.ToUInt16(pe, e+20);
    ushort magic = BitConverter.ToUInt16(pe, e+0x18);
    ulong imageBase = magic==0x20B ? BitConverter.ToUInt64(pe, e+0x18+24) : BitConverter.ToUInt32(pe, e+0x18+28);
    int secOff = e+24+opt;
    var secs = new List<uint[]>(); // va, vsize, rawsize, ptr, chars
    var names = new List<string>();
    for(int i=0;i<num;i++){
      int o=secOff+i*40;
      names.Add(Encoding.ASCII.GetString(pe,o,8).TrimEnd('\0'));
      secs.Add(new uint[]{
        BitConverter.ToUInt32(pe,o+12), BitConverter.ToUInt32(pe,o+8),
        BitConverter.ToUInt32(pe,o+16), BitConverter.ToUInt32(pe,o+20),
        BitConverter.ToUInt32(pe,o+36)});
    }
    uint[] tgts = new uint[]{0x692E820,0x692E550,0x692E3C0,0x69296F0};
    string[] tnames = new string[]{"Find","DumpTo","LoadFrom","ClearUnsafe"};
    var sb = new StringBuilder();
    sb.Append("{\n  \"imageBase\":\""+("0x"+imageBase.ToString("X"))+"\",\n  \"targets\":[\n");
    for(int ti=0;ti<tgts.Length;ti++){
      uint rva=tgts[ti]; ulong va=imageBase+rva;
      int e9=0,e8=0,ptrHits=0;
      var samples=new List<string>();
      for(int si=0;si<secs.Count;si++){
        uint vaS=secs[si][0], raw=secs[si][2], ptr=secs[si][3], ch=secs[si][4];
        if(ptr==0||raw==0||ptr+raw>pe.Length) continue;
        bool exec=(ch&0x20000000)!=0;
        // pointer scan all non-discardable sections
        byte[] needle=BitConverter.GetBytes(va);
        for(int i=0;i+8<=(int)raw;i++){
          bool ok=true; for(int j=0;j<8;j++) if(pe[ptr+i+j]!=needle[j]){ok=false;break;}
          if(!ok) continue;
          ptrHits++;
          if(samples.Count<15) samples.Add("{\"kind\":\"abs_va_ptr\",\"fileOffset\":\"0x"+((ptr+i).ToString("X"))+"\",\"section\":\""+names[si]+"\",\"va\":\"0x"+va.ToString("X")+"\"}");
        }
        if(!exec) continue;
        for(int i=0;i+5<=(int)raw;i++){
          byte op=pe[ptr+i];
          if(op!=0xE8 && op!=0xE9) continue;
          int rel=BitConverter.ToInt32(pe,(int)(ptr+i+1));
          uint site=vaS+(uint)i;
          uint dest=unchecked((uint)(site+5+rel));
          if(dest!=rva) continue;
          if(op==0xE8) e8++; else e9++;
          if(samples.Count<15) samples.Add("{\"kind\":\""+(op==0xE8?"e8":"e9")+"\",\"callSiteRva\":\"0x"+site.ToString("X")+"\",\"section\":\""+names[si]+"\"}");
        }
      }
      Console.WriteLine(tnames[ti]+" e8="+e8+" e9="+e9+" absPtr="+ptrHits);
      sb.Append("    {\"name\":\""+tnames[ti]+"\",\"rva\":\"0x"+rva.ToString("X")+"\",\"e8\":"+e8+",\"e9\":"+e9+",\"absoluteVaPointerHits\":"+ptrHits+",\"samples\":["+string.Join(",",samples)+"]}");
      if(ti+1<tgts.Length) sb.Append(",");
      sb.Append("\n");
    }
    // ClearUnsafe first bytes analysis
    long fo=0x6928CF0;
    sb.Append("  ],\n  \"clearUnsafePrologue\":{\"fileOffset\":\"0x6928CF0\",\"bytes\":\"");
    for(int i=0;i<32;i++) sb.Append(pe[fo+i].ToString("X2")+(i+1<32?" ":""));
    // decode first call
    // 48 83 EC 28 E8 57 FF FF FF
    int rel2=BitConverter.ToInt32(pe,(int)(fo+5));
    uint site2=0x69296F0+4; // wait: offset of E8 is file fo+4, rva 0x69296F4
    uint callSiteRva=0x69296F4u;
    uint dest2=unchecked((uint)(callSiteRva+5+rel2));
    sb.Append("\",\"firstCallDestRva\":\"0x"+dest2.ToString("X")+"\",\"firstCallRel32\":"+rel2+"}\n}\n");
    File.WriteAllText(@"C:\Users\Frees\OneDrive\Documents\BlackFlagCoop\reports\v0.5.8-harbour-indirect-xrefs.json", sb.ToString());
    Console.WriteLine("ClearUnsafe first call dest RVA=0x"+dest2.ToString("X"));
    Console.WriteLine("WROTE indirect xrefs");
  }
}
