package com.liuchao.rtpscope.core;

import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.util.*;
import java.util.regex.*;

/** DTMF-bearing INFO requests; transaction retransmissions retain one event. */
public final class SipInfoDtmf {
    public static List<DtmfParser.Event> parse(Analysis analysis){
        Map<String,DtmfParser.Event> found=new LinkedHashMap<>();
        for(SipMessage m:analysis.sip){
            if(!m.firstLine.startsWith("INFO "))continue;String content=m.headers.getOrDefault("content-type","").split(";",2)[0].trim().toLowerCase(Locale.ROOT);
            if(!content.equals("application/dtmf-relay")&&!content.equals("application/dtmf"))continue;
            String body=m.body==null?"":m.body;Matcher signal=Pattern.compile("(?im)^\\s*Signal\\s*=\\s*([0-9A-Da-d*#]+)\\s*$").matcher(body);String value=signal.find()?signal.group(1):content.equals("application/dtmf")?body.trim():"";
            int number=-1;if(value.matches("[0-9]"))number=value.charAt(0)-'0';else if(value.equals("*"))number=10;else if(value.equals("#"))number=11;else if(value.matches("[A-Da-d]"))number=12+Character.toUpperCase(value.charAt(0))-'A';else try{int n=Integer.parseInt(value);if(n>=10&&n<=15)number=n;}catch(NumberFormatException ignored){}
            Matcher duration=Pattern.compile("(?im)^\\s*Duration\\s*=\\s*([^\\r\\n]+)\\s*$").matcher(body);long ms=0;boolean known=duration.find();
            if(known)try{ms=Long.parseLong(duration.group(1).trim());if(ms<=0||ms>60000)number=-1;}catch(NumberFormatException e){number=-1;}
            if(number<0){analysis.warn("SIP INFO 按键内容或持续时间无效");continue;}
            String id=m.src+">"+m.dst+"/"+m.callId+"/"+m.headers.getOrDefault("from","")+"/"+m.headers.getOrDefault("to","")+"/"+m.cseq+"/"+value;
            DtmfParser.Event event=found.get(id);
            if(event==null){event=new DtmfParser.Event();event.type=DtmfParser.Type.SIP_INFO;event.src=m.src;event.dst=m.dst;event.callId=m.callId;event.key=DtmfParser.key(number);event.number=number;event.clock=1000;event.durationTicks=ms;event.durationKnown=known;event.ended=true;event.firstSeenUs=m.timeUs;event.signaling=m;found.put(id,event);associate(event,analysis);}
            event.lastSeenUs=m.timeUs;event.packets++;
        }
        return new ArrayList<>(found.values());
    }
    private static void associate(DtmfParser.Event event,Analysis a){
        if(event.callId==null||event.callId.isEmpty())return;String src=CallFlow.Endpoint.parse(event.src).ip,dst=CallFlow.Endpoint.parse(event.dst).ip;int best=0;Set<String> matches=new LinkedHashSet<>();Map<String,RtpStream> directions=new HashMap<>();
        Set<String> offered=new HashSet<>();
        for(SipMessage m:a.sip)if(m.timeUs<=event.firstSeenUs&&Objects.equals(m.callId,event.callId)&&Objects.equals(m.src,event.src)&&m.body!=null&&m.headers.getOrDefault("content-type","").toLowerCase(Locale.ROOT).contains("application/sdp")){
            String sessionIp="",mediaIp="";int port=0;boolean inMedia=false,audio=false;
            for(String line:(m.body+"\r\nm=end").split("\\r?\\n")){
                line=line.trim();
                if(line.startsWith("m=")){
                    if(audio&&port>0&&!mediaIp.isEmpty())offered.add(endpoint(mediaIp,port));
                    inMedia=true;audio=line.startsWith("m=audio ");mediaIp=sessionIp;port=0;
                    if(audio)try{port=Integer.parseInt(line.split("\\s+")[1].split("/")[0]);}catch(RuntimeException ignored){}
                }else if(line.startsWith("c=IN IP")){
                    String[] parts=line.split("\\s+");if(parts.length>=3){String ip=parts[2].split("/")[0];if(inMedia)mediaIp=ip;else sessionIp=ip;}
                }
            }
        }
        for(RtpStream s:a.streams)if(s.playable()&&event.callId.equals(s.callId)){int score=offered.contains(s.src)?3:src.equals(s.srcIp)&&dst.equals(s.dstIp)?2:src.equals(s.srcIp)?1:0;if(score==0)continue;String key=s.src+">"+s.dst;directions.put(key,s);if(score>best){best=score;matches.clear();}if(score==best)matches.add(key);}
        if(matches.size()==1){RtpStream s=directions.get(matches.iterator().next());event.audioSrc=s.src;event.audioDst=s.dst;}
    }
    private static String endpoint(String ip,int port){return (ip.contains(":")?"["+ip+"]":ip)+":"+port;}
    private SipInfoDtmf(){}
}
