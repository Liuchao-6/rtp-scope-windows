package com.liuchao.rtpscope.core;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.util.*;

/** Platform AMR decode bridge. The common parser still reports unavailable decoders honestly. */
public final class CodecSupport {
    public interface Provider {boolean supports(String codec);File decode(File encoded,boolean wide,int rate)throws IOException;}
    public static volatile Provider provider;
    public static boolean amr(RtpStream s){return s.codec.equals("AMR")||s.codec.equals("AMR-WB");}
    public static boolean available(RtpStream s){return amr(s)&&AmrPayload.supported(s.fmtp)&&provider!=null&&provider.supports(s.codec);}
    public static File decode(RtpStream s,int rate)throws IOException{
        if(!available(s))throw new IOException("AMR 解码器或当前封装参数不可用");File encoded=File.createTempFile("huatan-amr-",s.codec.equals("AMR-WB")?".awb":".amr");
        try{
            boolean wide=s.codec.equals("AMR-WB");try(OutputStream out=new BufferedOutputStream(new FileOutputStream(encoded))){out.write((wide?"#!AMR-WB\n":"#!AMR\n").getBytes("US-ASCII"));
                RtpTimeline timeline=RtpTimeline.of(s);Set<String> seen=new HashSet<>();
                for(RtpTimeline.Frame frame:timeline.frames){if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("音频处理已取消");if(!seen.add(frame.identity()))continue;RtpPacket p=s.packets.get(frame.index);for(byte[] data:AmrPayload.frames(p.payload(),wide,AmrPayload.aligned(s.fmtp)))out.write(data);}

            }return provider.decode(encoded,wide,rate);
        }finally{encoded.delete();}
    }
}
