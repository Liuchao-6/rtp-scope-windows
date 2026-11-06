package com.liuchao.rtpscope.core;

import java.io.*;
import java.util.*;
import com.liuchao.rtpscope.core.CaptureEngine.RtpPacket;
import com.liuchao.rtpscope.core.CaptureEngine.RtpStream;
import org.concentus.OpusPacketInfo;

/** G.711 / G.729 -> PCM16 WAV, RTP timing and duplex mixing. */
public final class AudioRenderer {
    public static final int RATE=8000;
    public static final long MAX_SAMPLES=RATE*60L*60;
    public static int sampleCount(RtpStream stream,byte[] payload) {
        if(CodecSupport.amr(stream)){try{return AmrPayload.frames(payload,stream.codec.equals("AMR-WB"),AmrPayload.aligned(stream.fmtp)).size()*stream.clock/50;}catch(IOException e){return 0;}}
        if(stream.codec.equals("OPUS"))return Math.max(0,OpusPacketInfo.getNumSamples(payload,0,payload.length,48000));
        return sampleCount(stream,payload.length);
    }
    public static int sampleCount(RtpStream stream,RtpPacket packet){
        if(CodecSupport.amr(stream)){try{return sampleCount(stream,packet.payload());}catch(IOException e){throw new UncheckedIOException(e);}}
        if(!stream.codec.equals("OPUS"))return sampleCount(stream,packet.payloadSize());
        try{return Math.max(0,OpusPacketInfo.getNumSamples(packet.prefix(2),0,packet.payloadSize(),48000));}catch(IOException e){throw new UncheckedIOException(e);}
    }
    public static int sampleCount(RtpStream stream,int length) {
        if(stream.codec.equals("G729")||stream.codec.equals("G729A"))return (length/10+(length%10==2?1:0))*80;
        return length;
    }
    public static int decode(int value,boolean alaw) {
        if (alaw) {
            int a=value^0x55, t=(a&15)<<4, segment=(a&0x70)>>4;
            if (segment==0) t+=8;
            else if (segment==1) t+=0x108;
            else { t+=0x108; t<<=segment-1; }
            return (a&128)!=0?t:-t;
        }
        int u=(~value)&255, t=((u&15)<<3)+0x84;
        t<<=(u&0x70)>>4;
        return (u&128)!=0?0x84-t:t-0x84;
    }
    public static void render(List<RtpStream> streams,File target) throws IOException {
        if (streams.isEmpty() || streams.size()>8) throw new IOException("请选择 1 至 8 条可解码的媒体流");
        int outputRate=RATE;for(RtpStream s:streams){if(s.codec.equals("G722")||s.codec.equals("AMR-WB"))outputRate=Math.max(outputRate,16000);if(s.codec.equals("OPUS"))outputRate=48000;}
        long origin=Long.MAX_VALUE;
        for (RtpStream s:streams) {
            if (!s.playable()) throw new IOException("不支持播放 "+s.codec+"，或该流为加密媒体");
            if (!s.packets.isEmpty()) origin=Math.min(origin,s.firstUs());
        }
        if (origin==Long.MAX_VALUE) throw new IOException("没有可播放的 RTP 数据");
        long total=0;
        List<RtpTimeline> timelines=new ArrayList<>();List<Long> offsets=new ArrayList<>();
        for (RtpStream s:streams) {
            RtpTimeline timeline=RtpTimeline.of(s);timelines.add(timeline);
            long offset=Math.round((s.firstUs()-origin)*outputRate/1000000.0);offsets.add(offset);
            long end=offset+Math.round(timeline.samples*(double)outputRate/s.clock);
            if(offset<0||end>MAX_SAMPLES*outputRate/RATE)throw new IOException("音频时间轴超过 60 分钟");
            total=Math.max(total,end);
        }
        try (RandomAccessFile out=new RandomAccessFile(target,"rw")) {
            out.setLength(0); header(out,total,outputRate); out.setLength(44+total*2);
            for (int index=0;index<streams.size();index++) {
                RtpStream stream=streams.get(index);
                try(MediaDecoder decoder=new MediaDecoder(stream,outputRate)){
                Set<String> seen=new HashSet<>();long previousEnd=-1;
                for (RtpTimeline.Frame frame:timelines.get(index).frames) {
                    if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("音频任务已取消");
                    if(!seen.add(frame.identity()))continue;
                    RtpPacket p=stream.packets.get(frame.index);
                    long position=offsets.get(index)+Math.round(frame.ticks*(double)outputRate/stream.clock);
                    if(previousEnd>=0&&position>previousEnd)decoder.gap(position-previousEnd);
                    byte[] payload=p.payload();
                    short[] decoded=decoder.decode(payload);
                    int count=decoded.length;
                    byte[] pcm=new byte[count*2];
                    out.seek(44+position*2); out.readFully(pcm);
                    for (int i=0;i<count;i++) {
                        int previous=(short)((pcm[i*2]&255)|((pcm[i*2+1]&255)<<8));
                        int sample=decoded[i]/streams.size();
                        int mixed=Math.max(-32768,Math.min(32767,previous+sample));
                        pcm[i*2]=(byte)mixed; pcm[i*2+1]=(byte)(mixed>>8);
                    }
                    out.seek(44+position*2); out.write(pcm);
                    previousEnd=position+count;
                }}
            }
        } catch (IOException|RuntimeException e) {
            if (!target.delete()) target.deleteOnExit();
            throw e;
        }
    }
    private static void header(RandomAccessFile out,long samples,int rate) throws IOException {
        out.writeBytes("RIFF"); le32(out,36+samples*2); out.writeBytes("WAVEfmt "); le32(out,16);
        le16(out,1); le16(out,1); le32(out,rate); le32(out,rate*2); le16(out,2); le16(out,16);
        out.writeBytes("data"); le32(out,samples*2);
    }
    private static void le16(RandomAccessFile out,int value) throws IOException { out.write(value); out.write(value>>8); }
    private static void le32(RandomAccessFile out,long value) throws IOException { for(int i=0;i<4;i++) out.write((int)(value>>(i*8))); }
}
