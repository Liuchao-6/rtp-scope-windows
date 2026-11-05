package com.liuchao.rtpscope.core;

import java.io.*;
import java.util.*;
import com.liuchao.rtpscope.core.CaptureEngine.RtpPacket;
import com.liuchao.rtpscope.core.CaptureEngine.RtpStream;
import org.jitsi.impl.neomedia.codec.audio.g729.G729Codec;

/** G.711 / G.729 -> PCM16 WAV, RTP timing and duplex mixing. */
public final class AudioRenderer {
    public static final int RATE=8000;
    public static final long MAX_SAMPLES=RATE*60L*60;
    public static int sampleCount(RtpStream stream,byte[] payload) {
        if(stream.codec.equals("G729")||stream.codec.equals("G729A"))return (payload.length/10+(payload.length%10==2?1:0))*80;
        return payload.length;
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
        long origin=Long.MAX_VALUE;
        for (RtpStream s:streams) {
            if (!s.playable()) throw new IOException("不支持播放 "+s.codec+"，或该流为加密媒体");
            if (!s.packets.isEmpty()) origin=Math.min(origin,s.firstUs());
        }
        if (origin==Long.MAX_VALUE) throw new IOException("没有可播放的 RTP 数据");
        long total=0;
        List<Long> bases=new ArrayList<>(), offsets=new ArrayList<>();
        for (RtpStream s:streams) {
            long anchor=s.packets.get(0).timestamp, min=0;
            for (RtpPacket p:s.packets) min=Math.min(min,(int)(p.timestamp-anchor));
            long offset=Math.round((s.firstUs()-origin)*RATE/1000000.0);
            bases.add(anchor+min); offsets.add(offset);
            for (RtpPacket p:s.packets) {
                long position=offset+(int)(p.timestamp-(anchor+min));
                long end=position+sampleCount(s,p.payload);
                if (position<0 || end>MAX_SAMPLES) throw new IOException("音频时间轴超过 60 分钟或时间戳异常");
                total=Math.max(total,end);
            }
        }
        try (RandomAccessFile out=new RandomAccessFile(target,"rw")) {
            out.setLength(0); header(out,total); out.setLength(44+total*2);
            for (int index=0;index<streams.size();index++) {
                RtpStream stream=streams.get(index);
                G729Codec g729=stream.codec.startsWith("G729")?new G729Codec():null;
                Set<Long> seen=new HashSet<>(); long high=stream.packets.get(0).sequence;
                List<RtpPacket> ordered=new ArrayList<>(stream.packets);
                final long base=bases.get(index);
                ordered.sort((a,b)->Integer.compare((int)(a.timestamp-base),(int)(b.timestamp-base)));
                long previousEnd=-1;
                for (RtpPacket p:ordered) {
                    long sequence=high+(short)(p.sequence-(int)high); high=Math.max(high,sequence);
                    if (!seen.add(sequence)) continue;
                    long position=offsets.get(index)+(int)(p.timestamp-bases.get(index));
                    if(g729!=null&&previousEnd>=0&&position>previousEnd)g729.advanceLoss((int)Math.min(101,(position-previousEnd)/80));
                    short[] decoded=null;
                    if(g729!=null)decoded=g729.decode(p.payload);
                    int count=sampleCount(stream,p.payload);
                    byte[] pcm=new byte[count*2];
                    out.seek(44+position*2); out.readFully(pcm);
                    for (int i=0;i<count;i++) {
                        int previous=(short)((pcm[i*2]&255)|((pcm[i*2+1]&255)<<8));
                        int sample=(decoded==null?decode(p.payload[i]&255,stream.codec.equals("PCMA")):decoded[i])/streams.size();
                        int mixed=Math.max(-32768,Math.min(32767,previous+sample));
                        pcm[i*2]=(byte)mixed; pcm[i*2+1]=(byte)(mixed>>8);
                    }
                    out.seek(44+position*2); out.write(pcm);
                    previousEnd=position+count;
                }
            }
        } catch (IOException|RuntimeException e) {
            if (!target.delete()) target.deleteOnExit();
            throw e;
        }
    }
    private static void header(RandomAccessFile out,long samples) throws IOException {
        out.writeBytes("RIFF"); le32(out,36+samples*2); out.writeBytes("WAVEfmt "); le32(out,16);
        le16(out,1); le16(out,1); le32(out,RATE); le32(out,RATE*2); le16(out,2); le16(out,16);
        out.writeBytes("data"); le32(out,samples*2);
    }
    private static void le16(RandomAccessFile out,int value) throws IOException { out.write(value); out.write(value>>8); }
    private static void le32(RandomAccessFile out,long value) throws IOException { for(int i=0;i<4;i++) out.write((int)(value>>(i*8))); }
}
