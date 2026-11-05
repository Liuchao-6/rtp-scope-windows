import com.liuchao.rtpscope.core.CaptureEngine;
import com.liuchao.rtpscope.core.CaptureEngine.Analysis;
import java.io.*;
import java.nio.file.Files;
import java.util.*;

/** Prefixes of real container fixtures exercise interruptions at headers, payloads and trailers. */
public final class PartialCaptureTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static Analysis read(byte[] bytes)throws IOException{return CaptureEngine.read(new ByteArrayInputStream(bytes));}
    private static long u32(byte[] b,int p,boolean le){long n=0;for(int i=0;i<4;i++)n=(n<<8)|(b[p+(le?3-i:i)]&255);return n;}
    public static int run(File fixtures)throws Exception {
        for(String name:new String[]{"demo.pcap","big-endian.pcap","nanoseconds.pcap","dynamic.pcapng","big-endian.pcapng","multi-section.pcapng"}) {
            byte[] full=Files.readAllBytes(new File(fixtures,name).toPath());boolean ng=name.endsWith("pcapng");
            List<Integer> ends=new ArrayList<>(),packetEnds=new ArrayList<>();Set<Integer> cuts=new TreeSet<>();int header=ng?28:24,p=ng?0:24;boolean le=ng||u32(full,0,false)==0xd4c3b2a1L||u32(full,0,false)==0x4d3cb2a1L;
            while(p<full.length) {
                int end,dataEnd=-1;
                if(ng){boolean section=u32(full,p,true)==0x0a0d0d0aL;if(section)le=u32(full,p+8,false)==0x4d3c2b1aL;int type=(int)u32(full,p,le);end=p+(int)u32(full,p+4,le);if(type==6||type==2)dataEnd=p+28+(int)u32(full,p+20,le);}
                else {end=p+16+(int)u32(full,p+8,le);dataEnd=end;}
                if(dataEnd>=0){ends.add(end);packetEnds.add(dataEnd);if(ends.size()<=6||end==full.length)for(int cut:new int[]{p,p+1,p+7,p+15,(p+end)/2,dataEnd-1,dataEnd,end-1,end})if(cut>=header&&cut<=full.length)cuts.add(cut);}
                p=end;
            }
            cuts.add(header);cuts.add(full.length);cuts.add(full.length-1);
            for(int cut:cuts){Analysis a=read(Arrays.copyOf(full,cut));int expected=0;for(int i=0;i<ends.size();i++)if(ends.get(i)<=cut||(ng&&packetEnds.get(i)<=cut))expected++;
                check(a.packets==expected,name+" cut="+cut+" keeps "+expected+" complete packet payloads, got "+a.packets);
                check(a.bytes==cut,name+" consumed byte count at "+cut);
                if(a.partial)check(!a.warnings.isEmpty(),name+" recovery coverage visible");
                if(cut==full.length)check(!a.partial,name+" complete capture remains complete");
            }
            for(int cut:new int[]{0,1,3,4,header-1})try{read(Arrays.copyOf(full,cut));throw new AssertionError("incomplete global header accepted: "+name+"/"+cut);}catch(IOException expected){checks++;}
        }
        byte[] ng=Files.readAllBytes(new File(fixtures,"dynamic.pcapng").toPath());List<Integer> packets=new ArrayList<>();
        for(int p=0;p<ng.length;p+=(int)u32(ng,p+4,true))if(u32(ng,p,true)==6)packets.add(p);
        byte[] broken=ng.clone();int middle=packets.get(1);for(int n=0;n<4;n++)broken[middle+8+n]=(byte)(n==0?99:0);
        Analysis skipped=read(broken),complete=read(ng);check(skipped.partial&&skipped.packets==complete.packets-1,"bad interface packet skipped using known block boundaries");check(skipped.lastUs==complete.lastUs,"valid packets after damaged packet still analyzed");
        byte[] pcap=Files.readAllBytes(new File(fixtures,"demo.pcap").toPath()),oversize=Arrays.copyOf(pcap,pcap.length+16);Arrays.fill(oversize,pcap.length+8,pcap.length+12,(byte)255);
        Analysis bounded=read(oversize);check(bounded.partial&&bounded.packets==read(pcap).packets,"oversized final record bounded without discarding existing data");
        try{CaptureEngine.read(new InputStream(){int at;public int read()throws IOException{if(at>=100)throw new IOException("storage read failed");return pcap[at++]&255;}});throw new AssertionError("storage failure swallowed");}catch(IOException expected){check(expected.getMessage().contains("storage read failed"),"real I/O errors propagate");}
        return checks;
    }
}
