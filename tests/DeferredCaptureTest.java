import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.lang.reflect.*;

/** Staged analysis must preserve the results of the original complete import. */
public final class DeferredCaptureTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static byte[] serialized(Object value)throws IOException{ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(ObjectOutputStream out=new ObjectOutputStream(bytes)){out.writeObject(value);}return bytes.toByteArray();}
    private static void describe(Object value,StringBuilder out)throws Exception{
        if(value==null||value instanceof String||value instanceof Number||value instanceof Boolean||value instanceof Enum){out.append(value).append('\n');return;}
        if(value instanceof byte[]){out.append(Arrays.toString((byte[])value)).append('\n');return;}
        if(value instanceof Map){for(Object key:((Map<?,?>)value).keySet()){describe(key,out);describe(((Map<?,?>)value).get(key),out);}return;}
        if(value instanceof Iterable){for(Object item:(Iterable<?>)value)describe(item,out);return;}
        if(value instanceof RtpPacket)describe(((RtpPacket)value).payload(),out);
        for(Field field:value.getClass().getFields())if(!Modifier.isStatic(field.getModifiers())&&!field.getName().equals("mediaStore")){out.append(field.getName()).append(':');describe(field.get(value),out);}
    }
    private static boolean equivalent(Analysis a,Analysis b)throws Exception{StringBuilder one=new StringBuilder(),two=new StringBuilder();describe(a,one);describe(b,two);return one.toString().equals(two.toString());}
    public static int run(File fixtures,File output)throws Exception{
        File directory=Files.createTempDirectory(output.toPath(),"staged-core-").toFile();
        try{
            for(String name:new String[]{"demo-analysis.pcap","key-modes.pcap","dtmf-multiplex.pcap","loss-wrap.pcap","quality.pcap","g729-reorder.pcap","opus-rtp.pcap","truncated.pcap","damaged.pcapng","dynamic.pcapng","sequence-reset.pcap","srtp.pcap","inband-negative.pcap","sip-websocket-deflate.pcap","tls13-websocket-opus.pcap"}){
                TlsKeyLog keys=TlsKeyLog.empty();File keyFile=new File(fixtures,name.replace(".pcap",".keys"));if(keyFile.isFile())try(InputStream in=new FileInputStream(keyFile)){keys=TlsKeyLog.read(in);}
                Analysis full;DeferredCapture staged;
                try(InputStream in=new FileInputStream(new File(fixtures,name))){full=CaptureEngine.readLarge(in,directory,null,keys);}
                try(InputStream in=new FileInputStream(new File(fixtures,name))){staged=CaptureEngine.readLargeSignaling(in,directory,null,keys,TlsRsaKeys.empty());}
                Analysis early=staged.signaling;
                try{
                    check(early.calls.size()==full.calls.size()&&early.sip.size()==full.sip.size()&&early.streams.size()==full.streams.size(),name+" signaling and association available early");
                    check(early.streams.stream().allMatch(s->s.quality==null),name+" no invented early quality result");
                    check(early.events.stream().noneMatch(e->e.type==DtmfParser.Type.IN_BAND),name+" audio detection deferred");
                    if(name.equals("key-modes.pcap"))check(early.events.size()==5,name+" RFC event and four INFO keys available early");
                    byte[] original=serialized(early);List<RtpStream> identities=new ArrayList<>(early.streams);List<String> stages=new ArrayList<>();
                    Analysis complete=staged.analyze(new CaptureEngine.Progress(){public void update(long b,long p){}public void stage(String text){stages.add(text);}});
                    check(Arrays.equals(original,serialized(early)),name+" background analysis never mutates visible metadata");
                    check(equivalent(full,complete),name+" complete metadata, quality, keys and packet payloads match original import");
                    check(!stages.isEmpty(),name+" reports media stages");
                    staged.apply(complete);check(equivalent(full,early),name+" applied result equals complete import");
                    check(early.streams.equals(identities),name+" preserves stream identities and selected streams");
                    byte[] applied=serialized(early);staged.apply(complete);check(Arrays.equals(applied,serialized(early)),name+" applying twice does not duplicate warnings or keys");
                    if(name.equals("key-modes.pcap")){
                        AnalysisCache cache=new AnalysisCache(directory);String key;try(InputStream in=new FileInputStream(new File(fixtures,name))){key=cache.key(in);}
                        final long[] progress={0};cache.save(key,complete,(b,p)->progress[0]=b);check(progress[0]>0,"index save has byte progress");Analysis restored=cache.load(key);
                        try{check(restored!=null&&equivalent(full,restored),"complete staged index restores quality and all key types");}finally{if(restored!=null)restored.close();}
                        Thread.currentThread().interrupt();try{cache.load(key);throw new AssertionError("interrupted index load accepted");}catch(InterruptedIOException expected){check(new File(directory,key+".index").isFile(),"cancelled restoration keeps valid previous index");}finally{Thread.interrupted();}
                        Thread.currentThread().interrupt();try{cache.save(key,complete);throw new AssertionError("interrupted index save accepted");}catch(InterruptedIOException expected){check(directory.list((d,n)->n.endsWith(".tmp")).length==0,"cancelled save removes partial index");}finally{Thread.interrupted();}
                        try{cache.save(key,complete,(b,p)->Thread.currentThread().interrupt());throw new AssertionError("cancellation during index output accepted");}catch(InterruptedIOException expected){check(directory.list((d,n)->n.endsWith(".tmp")).length==0,"cancellation after output starts removes partial index");}finally{Thread.interrupted();}
                        restored=cache.load(key);check(restored!=null,"cancelled save preserves previous complete index");if(restored!=null)restored.close();
                    }
                }finally{full.close();early.close();}
            }
            DeferredCapture staged;try(InputStream in=new FileInputStream(new File(fixtures,"demo-analysis.pcap"))){staged=CaptureEngine.readLargeSignaling(in,directory,null,TlsKeyLog.empty(),TlsRsaKeys.empty());}
            Analysis a=staged.signaling;File file=a.mediaStore.file();Closeable first=a.mediaStore.retain(),second=a.mediaStore.retain();a.close();a.close();
            check(file.isFile()&&a.streams.get(0).packets.get(0).payload().length>0,"background lease keeps disk payloads readable after owner closes");
            try{a.mediaStore.retain();throw new AssertionError("closed owner accepts lease");}catch(IOException expected){checks++;}
            first.close();first.close();check(file.isFile(),"one outstanding task retains cache");second.close();check(!file.exists(),"last task releases and deletes shared cache");
            System.out.println("PASS: "+checks+" staged-core checks; complete-result equivalence, index cancellation and packet leases");return checks;
        }finally{for(File file:directory.listFiles())file.delete();directory.delete();}
    }
}
