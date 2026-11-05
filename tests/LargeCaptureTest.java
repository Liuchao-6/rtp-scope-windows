import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.Files;
import java.util.*;

/** Actual on-disk captures exceed both the old media and packet-count limits. */
public final class LargeCaptureTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static void le32(OutputStream out,long value)throws IOException{for(int n=0;n<4;n++)out.write((int)(value>>(8*n)));}
    private static int le(byte[] data,int at){return (data[at]&255)|((data[at+1]&255)<<8)|((data[at+2]&255)<<16)|((data[at+3]&255)<<24);}
    private static void be16(byte[] data,int at,int v){data[at]=(byte)(v>>8);data[at+1]=(byte)v;}
    private static void be32(byte[] data,int at,long v){for(int n=0;n<4;n++)data[at+n]=(byte)(v>>(24-8*n));}
    private static byte[] packet(int size){byte[] data=new byte[40+size];data[0]=0x45;be16(data,2,data.length);data[8]=64;data[9]=17;data[12]=(byte)192;data[14]=2;data[15]=10;data[16]=(byte)192;data[18]=2;data[19]=20;be16(data,20,6000);be16(data,22,6002);be16(data,24,20+size);data[28]=(byte)0x80;data[29]=96;be32(data,36,0x1234abcdL);for(int n=40;n<data.length;n++)data[n]=(byte)n;return data;}
    private static void record(OutputStream out,byte[] packet,int index)throws IOException{le32(out,1793664010L+index/50);le32(out,(index%50)*20000L);le32(out,packet.length);le32(out,packet.length);out.write(packet);}
    private static List<RtpStream> audio(Analysis a){List<RtpStream> out=new ArrayList<>();for(RtpStream s:a.streams)if(s.playable())out.add(s);return out;}
    public static void main(String[] args)throws Exception{
        File fixtures=new File(args[0]),out=new File(args[1]);boolean full=args.length>2&&args[2].equals("--one-gib");
        File capture=File.createTempFile("large-capture-",".pcap",out);File cacheDir=new File(out,"large-capture-cache");cacheDir.mkdirs();
        byte[] demo=Files.readAllBytes(new File(fixtures,"demo-analysis.pcap").toPath());check(le(demo,20)==101,"synthetic fixture uses raw IP");
        int last=24;for(int p=24;p<demo.length;p+=16+le(demo,p+8))last=p;byte[] tail=Arrays.copyOfRange(demo,last,demo.length);
        long start=System.nanoTime();Analysis large=null;
        try{
            try(OutputStream output=new BufferedOutputStream(new FileOutputStream(capture),262144)){
                output.write(demo);long size=demo.length;int index=0;
                byte[] packet=packet(65000);for(int n=0;n<1100;n++,index++){be16(packet,30,index);be32(packet,32,index*160L);record(output,packet,index);size+=16+packet.length;}
                packet=packet(160);for(int n=0;n<500100;n++,index++){be16(packet,30,index);be32(packet,32,index*160L);record(output,packet,index);size+=16+packet.length;}
                if(full){long remaining=CaptureEngine.MAX_DESKTOP_FILE-size-tail.length;byte[] padding=new byte[65536];while(remaining>=16){int length=(int)Math.min(padding.length,remaining-16);if(remaining-(length+16)>0&&remaining-(length+16)<16)length-=16-(remaining-(length+16));record(output,Arrays.copyOf(padding,length),index++);remaining-=16+length;}check(remaining==0,"full fixture fills exact size");}
                output.write(tail);
            }
            check(capture.length()>128L*1024*1024,"capture exceeds previous file limit");if(full)check(capture.length()==CaptureEngine.MAX_DESKTOP_FILE,"actual capture is exactly 1 GiB");
            final long[] progress={0};try(InputStream in=new FileInputStream(capture)){large=CaptureEngine.readLarge(in,cacheDir,(bytes,packets)->progress[0]=bytes);}
            check(large.bytes==capture.length()&&large.packets>500000,"entire large capture parsed beyond old packet count");check(progress[0]>128L*1024*1024,"progress reports beyond old limit");check(!large.partial&&large.calls.size()==1,"call signaling retained through end of file");
            RtpStream synthetic=large.streams.stream().filter(s->s.pt==96).findFirst().get();check(synthetic.packets.size()==501200,"all synthetic RTP packets are indexed");check(synthetic.quality.unique==501200&&synthetic.quality.lost==0,"streaming quality handles wraps and bounded-window flushing");
            for(int index:new int[]{0,1099,1100,250000,501199}){RtpPacket p=synthetic.packets.get(index);check(p.payload==null&&p.payloadSize()==(index<1100?65000:160),"payload stays on disk at "+index);byte[] bytes=p.payload();check(bytes.length==p.payloadSize()&&bytes[0]==40&&bytes[bytes.length-1]==(byte)(bytes.length+39),"disk payload random read correct at "+index);}
            Analysis original;try(InputStream in=new ByteArrayInputStream(demo)){original=CaptureEngine.read(in);}
            File reference=new File(out,"large-reference.wav"),actual=new File(out,"large-actual.wav");AudioRenderer.render(audio(original),reference);AudioRenderer.render(audio(large),actual);check(Arrays.equals(Files.readAllBytes(reference.toPath()),Files.readAllBytes(actual.toPath())),"disk-backed G711/G729 duplex audio is byte-identical");
            check(large.events.size()==original.events.size()&&large.events.get(0).key.equals("5"),"disk telephone events and audio detection preserved");File cache=large.mediaStore.file();large.close();check(!cache.exists(),"closing analysis deletes disk cache");large=null;
            try(InputStream in=new FileInputStream(capture)){CaptureEngine.read(in);throw new AssertionError("Android default limits changed");}catch(IOException expected){check(expected.getMessage().contains("64 MB"),"Android retains default media limit");}
            try{CaptureEngine.readLarge(new ByteArrayInputStream(new byte[]{1,2,3}),cacheDir,null);throw new AssertionError("bad capture accepted");}catch(IOException expected){check(cacheDir.list().length==0,"failed import removes disk cache");}
            for(String name:new String[]{"g729-reorder.pcap","truncated.pcap","dynamic.pcapng","big-endian.pcapng"}){Analysis disk;try(InputStream in=new FileInputStream(new File(fixtures,name))){disk=CaptureEngine.readLarge(in,cacheDir,null);}try{check(!disk.streams.isEmpty()||!disk.sip.isEmpty(),"disk parsing supports "+name);if(name.equals("g729-reorder.pcap")){Analysis normal;try(InputStream in=new FileInputStream(new File(fixtures,name))){normal=CaptureEngine.read(in);}AudioRenderer.render(audio(normal),reference);AudioRenderer.render(audio(disk),actual);check(Arrays.equals(Files.readAllBytes(reference.toPath()),Files.readAllBytes(actual.toPath())),"out-of-order metadata sorting preserves G729 decoding");}}finally{disk.close();}}
            System.out.println("PASS: "+checks+" large-capture assertions; bytes="+capture.length()+"; max_heap="+Runtime.getRuntime().maxMemory()+"; elapsed="+String.format(Locale.ROOT,"%.1f",(System.nanoTime()-start)/1e9)+"s");
        }finally{if(large!=null)large.close();if(!capture.delete())capture.deleteOnExit();}
    }
}
