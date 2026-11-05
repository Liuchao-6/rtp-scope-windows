package com.liuchao.rtpscope.core;

import java.util.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;

/** RFC 4733 telephone-event payloads; retransmitted end packets describe one key press. */
public final class DtmfParser {
    public enum Type { RTP_EVENT, SIP_INFO, IN_BAND }
    public static final class Event {
        public String src,dst,callId,key;
        public Type type=Type.RTP_EVENT;
        public String audioSrc="",audioDst="";
        public SipMessage signaling;
        public boolean durationKnown=true;
        public double levelDbfs=Double.NaN;
        public int number,volume,packets,clock;
        public long timestamp,firstSeenUs,lastSeenUs,durationTicks,ssrc;
        public boolean ended;
        public double durationMs() { return clock>0?durationTicks*1000.0/clock:0; }
        public String typeLabel(){return type==Type.SIP_INFO?"SIP INFO":type==Type.IN_BAND?"In-band DTMF":"RFC 2833 / 4733";}
        public String typeCode(){return type==Type.SIP_INFO?"INFO":type==Type.IN_BAND?"In-band":"2833";}
        public String durationText(){return durationKnown?String.format(Locale.ROOT,"%.1f ms",durationMs()):"未知";}
        public String stateText(){return type==Type.SIP_INFO?"INFO 请求":ended?"已结束":"未见结束";}
        public String detailText(){
            String common="类型："+typeLabel()+"\n持续："+durationText()+"\n状态："+stateText();
            if(type==Type.SIP_INFO)return common+"\n事务包数（含重传）："+packets+"\n音频方向："+(audioSrc.isEmpty()?"无法唯一确定":audioSrc+" → "+audioDst)+"\n\n"+(signaling==null?"":signaling.raw);
            String rtp=String.format(Locale.ROOT,"\nSSRC：%08X\nRTP 时间戳：%d",ssrc,timestamp);
            if(type==Type.IN_BAND)return common+String.format(Locale.ROOT,"\n检测音量：%.1f dBFS",levelDbfs)+rtp+"\n\n基于每个方向的解码音频检测；语音或噪声可能误判，建议定位试听。";
            return common+"\n音量：-"+volume+" dBm0\n事件包："+packets+rtp;
        }
        public String searchable() { return src+" "+dst+" "+callId+" "+key+" "+typeLabel()+" "+typeCode(); }
    }
    public static final class Result {
        public final List<Event> events=new ArrayList<>();
        public int malformed;
    }
    public static Result parse(RtpStream stream) throws java.io.IOException {
        Result result=new Result();
        if (stream.encrypted || !stream.isDtmf() || !stream.clockKnown || stream.clock<=0) return result;
        Map<String,Event> grouped=new LinkedHashMap<>();
        for (RtpPacket packet:stream.packets) {
            byte[] b=packet.payload;
            if (b.length==0 || b.length%4!=0) { result.malformed++; continue; }
            for (int off=0;off<b.length;off+=4) {
                if ((b[off+1]&64)!=0) { result.malformed++; continue; }
                int number=b[off]&255;
                String id=packet.timestamp+"/"+number;
                Event event=grouped.get(id);
                int duration=((b[off+2]&255)<<8)|(b[off+3]&255);
                if (event==null) {
                    if(result.events.size()>=30000)throw new java.io.IOException("电话事件超过 3 万条，请先拆分文件");
                    event=new Event(); event.src=stream.src;event.dst=stream.dst;event.callId=stream.callId;
                    event.number=number;event.key=key(number);event.timestamp=packet.timestamp;event.ssrc=stream.ssrc;
                    event.firstSeenUs=packet.timeUs;event.clock=stream.clock;event.durationTicks=duration;
                    grouped.put(id,event);result.events.add(event);
                }
                long extended=event.durationTicks+(short)(duration-(int)event.durationTicks);
                event.durationTicks=Math.max(event.durationTicks,extended);
                event.lastSeenUs=Math.max(event.lastSeenUs,packet.timeUs);event.packets++;
                event.volume=b[off+1]&63;event.ended|=(b[off+1]&128)!=0;
            }
        }
        return result;
    }
    public static boolean matches(Event e,RtpStream s){return e.type==Type.SIP_INFO?e.audioSrc.equals(s.src)&&e.audioDst.equals(s.dst)&&Objects.equals(e.callId,s.callId):Objects.equals(e.src,s.src)&&Objects.equals(e.dst,s.dst)&&e.ssrc==s.ssrc;}
    public static long mediaBase(RtpStream s){long anchor=s.packets.get(0).timestamp,min=0;for(RtpPacket p:s.packets)min=Math.min(min,(int)(p.timestamp-anchor));return anchor+min;}
    public static double audioStartMs(Event e,RtpStream s,long origin){return audioStartMs(e,s,origin,mediaBase(s));}
    public static double audioStartMs(Event e,RtpStream s,long origin,long base){return e.type!=Type.SIP_INFO&&e.clock==s.clock?(s.firstUs()-origin)/1000.0+(int)(e.timestamp-base)*1000.0/s.clock:(e.firstSeenUs-origin)/1000.0;}
    public static String key(int number) {
        if(number<=9)return String.valueOf(number);
        if(number==10)return "*";if(number==11)return "#";
        if(number>=12&&number<=15)return String.valueOf((char)('A'+number-12));
        return number==16?"Flash":"事件 "+number;
    }
}
