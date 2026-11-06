package com.liuchao.rtpscope.core;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Original packet export, streamed from the input; shared TCP connections are explicitly included. */
public final class CallExport {
    public interface Source {InputStream open()throws IOException;}
    private interface Writer {void write(File target)throws IOException;}
    public static final class Result {
        public final File directory;
        public final List<File> files=new ArrayList<>();
        public final Map<String,String> failures=new LinkedHashMap<>();
        public final List<String> notes=new ArrayList<>();
        Result(File dir){directory=dir;}
        public String summary(){StringBuilder s=new StringBuilder("导出成功 "+files.size()+" 项，失败 "+failures.size()+" 项\n");for(File f:files)s.append("成功 · ").append(f.getName()).append('\n');for(Map.Entry<String,String> e:failures.entrySet())s.append("失败 · ").append(e.getKey()).append("：").append(e.getValue()).append('\n');for(String note:notes)s.append("提示 · ").append(note).append('\n');return s.toString();}
    }
    /** Each artifact and audio direction is isolated. Cancellation still stops the entire job. */
    public static Result bundle(Source source,Analysis a,String id,File dir,boolean packets,boolean audio,boolean html,boolean redact)throws IOException{return bundle(source,a,id,dir,packets,audio,html,redact,redact);}
    public static Result bundle(Source source,Analysis a,String id,File dir,boolean packets,boolean audio,boolean html,boolean maskNumbers,boolean maskIps)throws IOException{
        if(!dir.isDirectory()&&!dir.mkdir())throw new IOException("无法建立导出目录");Result result=new Result(dir);
        if(packets)attempt(result,"call.pcapng",f->{try(InputStream in=source.open();OutputStream out=new FileOutputStream(f)){capture(in,a,id,out);}});
        if(audio)audio(a,id,dir,result);
        if(html)attempt(result,"report.html",f->{try(OutputStream out=new FileOutputStream(f)){report(a,id,maskNumbers,maskIps,out);}});
        if(!result.failures.isEmpty()||!result.notes.isEmpty()){
            File log=new File(dir,"导出结果.txt");try(java.io.Writer out=new OutputStreamWriter(new FileOutputStream(log),StandardCharsets.UTF_8)){out.write(result.summary());}catch(IOException e){result.notes.add("无法保存导出结果说明："+message(e));}
        }
        return result;
    }
    private static void cancel()throws InterruptedIOException{if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("导出已取消");}
    private static String message(Exception e){return e.getMessage()==null?e.getClass().getSimpleName():e.getMessage();}
    private static void attempt(Result result,String name,Writer writer)throws IOException{
        cancel();File target=new File(result.directory,name),temp=new File(result.directory,name+".part");
        try{writer.write(temp);cancel();if(!temp.renameTo(target))throw new IOException("无法保存文件");result.files.add(target);}
        catch(InterruptedIOException|java.util.concurrent.CancellationException e){throw e;}
        catch(IOException|RuntimeException e){result.failures.put(name,message(e));}
        finally{temp.delete();}
    }
    public static long capture(InputStream source,Analysis a,String callId,OutputStream target)throws IOException{
        Set<String> tcp=new HashSet<>();Set<String> media=new HashSet<>();
        for(SipMessage m:a.sip)if(callId.equals(m.callId)&&!m.transport.equals("UDP")){tcp.add(m.src+">"+m.dst);tcp.add(m.dst+">"+m.src);}
        for(RtpStream s:a.streams)if(callId.equals(s.callId))media.add(s.src+">"+s.dst+"/"+s.ssrc);
        final long[] count={0};Map<Integer,Integer> interfaces=new LinkedHashMap<>();
        // pcapng little-endian Section Header Block.
        ByteArrayOutputStream sh=new ByteArrayOutputStream();le(sh,0x1a2b3c4dL,4);le(sh,1,2);le(sh,0,2);le(sh,-1L,8);block(target,0x0a0d0d0a,sh.toByteArray());
        CaptureEngine.visitPackets(source,(packet,link,time,src,dst,protocol,payload)->{
            boolean selected=protocol==6&&tcp.contains(src+">"+dst);
            if(protocol==17){
                if(payload.length>=12&&(payload[0]&0xc0)==0x80){long ssrc=((payload[8]&255L)<<24)|((payload[9]&255L)<<16)|((payload[10]&255L)<<8)|(payload[11]&255L);selected=media.contains(src+">"+dst+"/"+ssrc);}
                if(!selected){String text=new String(payload,StandardCharsets.ISO_8859_1);for(String line:text.split("\\r?\\n")){int colon=line.indexOf(':');if(colon>0&&(line.substring(0,colon).equalsIgnoreCase("Call-ID")||line.substring(0,colon).equalsIgnoreCase("i"))&&line.substring(colon+1).trim().equals(callId)){selected=true;break;}}}
            }
            if(!selected)return;
            Integer iface=interfaces.get(link);if(iface==null){iface=interfaces.size();interfaces.put(link,iface);ByteArrayOutputStream b=new ByteArrayOutputStream();le(b,link,2);le(b,0,2);le(b,16*1024*1024,4);block(target,1,b.toByteArray());}
            ByteArrayOutputStream b=new ByteArrayOutputStream();le(b,iface,4);le(b,time>>>32,4);le(b,time,4);le(b,packet.length,4);le(b,packet.length,4);b.write(packet);while(b.size()%4!=0)b.write(0);block(target,6,b.toByteArray());count[0]++;
        });return count[0];
    }
    public static boolean includesSharedConnection(Analysis a,String id){for(SipMessage m:a.sip)if(m.callId.equals(id)&&!m.transport.equals("UDP"))return true;return false;}
    public static void report(Analysis a,String id,boolean redact,OutputStream out)throws IOException{report(a,id,redact,redact,out);}
    public static void report(Analysis a,String id,boolean maskNumbers,boolean maskIps,OutputStream out)throws IOException{out.write(CallHealth.inspect(a,id).html(maskNumbers,maskIps,false).getBytes(StandardCharsets.UTF_8));}
    public static List<File> audio(Analysis a,String id,File directory)throws IOException{
        Result result=new Result(directory);audio(a,id,directory,result);if(!result.failures.isEmpty())throw new IOException(result.summary());return result.files;
    }
    private static void audio(Analysis a,String id,File directory,Result result)throws IOException{
        Map<String,List<RtpStream>> groups=new LinkedHashMap<>();for(RtpStream s:a.streams)if(s.callId.equals(id)&&s.playable()&&!s.packets.isEmpty())groups.computeIfAbsent(s.src+" → "+s.dst,k->new ArrayList<>()).add(s);
        if(groups.isEmpty())result.failures.put("各方向 WAV","当前通话没有可解码的 RTP 媒体");
        int n=0;for(Map.Entry<String,List<RtpStream>> group:groups.entrySet()){
            String name="direction-"+(++n)+".wav";attempt(result,name,f->AudioRenderer.render(group.getValue(),f));
            result.notes.add(name+" · "+group.getKey());
            for(RtpStream stream:group.getValue()){long repairs=stream.quality==null?0:stream.quality.timestampResets;if(repairs>0)result.notes.add(name+" · RTP 时间轴衔接 "+repairs+" 处，原始抓包保留原始时间戳");}
        }
    }
    private static void block(OutputStream out,int type,byte[] body)throws IOException{le(out,type,4);le(out,body.length+12,4);out.write(body);le(out,body.length+12,4);}
    private static void le(OutputStream out,long v,int n)throws IOException{for(int i=0;i<n;i++)out.write((int)(v>>>(8*i)));}
}
