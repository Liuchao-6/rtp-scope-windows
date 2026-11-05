package com.liuchao.rtpscope.core;

import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.util.*;

/** Presentation model: one SIP message, media-stream summary or deduplicated key per row. */
public final class CallFlow {
    public static final class Endpoint {
        public final String ip, port;
        private Endpoint(String ip,String port){this.ip=ip;this.port=port;}
        public static Endpoint parse(String value) {
            if(value==null)return new Endpoint("?","");
            if(value.startsWith("[")) {
                int close=value.indexOf(']');
                if(close>0)return new Endpoint(value.substring(1,close),value.startsWith(":",close+1)?value.substring(close+2):"");
            }
            int colon=value.indexOf(':');
            if(colon>=0&&colon==value.lastIndexOf(':'))return new Endpoint(value.substring(0,colon),value.substring(colon+1));
            return new Endpoint(value,"");
        }
    }
    public static final class Entry {
        public final long timeUs;
        public final Endpoint src,dst;
        public final String title,detail;
        public final Object source;
        private Entry(long time,String from,String to,String title,String detail,Object source) {
            timeUs=time;src=Endpoint.parse(from);dst=Endpoint.parse(to);this.title=title;this.detail=detail;this.source=source;
        }
    }
    public final List<Entry> entries=new ArrayList<>();
    public final List<String> nodes=new ArrayList<>();
    public long originUs;

    public static CallFlow build(Analysis analysis,String callId,String search) {
        CallFlow flow=new CallFlow();if(analysis==null)return flow;
        String query=search==null?"":search.toLowerCase(Locale.ROOT);
        long origin=Long.MAX_VALUE;
        for(SipMessage m:analysis.sip)if(accept(callId,m.callId)) {
            origin=Math.min(origin,m.timeUs);
            if(matches(m.searchable(),query))flow.entries.add(new Entry(m.timeUs,m.src,m.dst,sipTitle(m),m.transport+" · CSeq "+m.cseq,m));
        }
        for(RtpStream s:analysis.streams)if(accept(callId,s.callId)&&!s.packets.isEmpty()) {
            long first=Long.MAX_VALUE,last=Long.MIN_VALUE;
            for(RtpPacket p:s.packets){first=Math.min(first,p.timeUs);last=Math.max(last,p.timeUs);}
            origin=Math.min(origin,first);
            if(s.isDtmf()&&!s.events.isEmpty())continue;
            if(matches(s.searchable(),query)) {
                String title=(s.encrypted?"SRTP":"RTP")+" · "+s.codec+" · "+s.packets.size()+" 包";
                String detail=String.format(Locale.ROOT,"PT %d · SSRC %08X · 到包跨度 %.3f s",s.pt,s.ssrc,(last-first)/1000000.0);
                flow.entries.add(new Entry(first,s.src,s.dst,title,detail,s));
            }
        }
        for(DtmfParser.Event e:analysis.events)if(accept(callId,e.callId)) {
            origin=Math.min(origin,e.firstSeenUs);
            if(matches(e.searchable(),query))flow.entries.add(new Entry(e.firstSeenUs,e.src,e.dst,"DTMF · 按键 "+e.key,
                e.typeLabel()+" · "+e.durationText()+" · "+e.stateText(),e));
        }
        // Stable sort retains packet order when timestamps tie (e.g. reassembled SIP).
        Collections.sort(flow.entries,Comparator.comparingLong(e->e.timeUs));
        LinkedHashSet<String> ips=new LinkedHashSet<>();
        for(Entry e:flow.entries){ips.add(e.src.ip);ips.add(e.dst.ip);}
        flow.nodes.addAll(ips);flow.originUs=origin==Long.MAX_VALUE?0:origin;
        return flow;
    }
    public static String sipTitle(SipMessage m) {
        String title=m.firstLine;
        if(!title.startsWith("SIP/")){int space=title.indexOf(' ');if(space>0)title=title.substring(0,space);}
        else if(title.startsWith("SIP/2.0 "))title=title.substring(8);
        if(m.body!=null&&m.body.trim().startsWith("v="))title+=" / SDP";
        return title;
    }
    private static boolean accept(String filter,String id){return filter==null||filter.isEmpty()||filter.equals(id);}
    private static boolean matches(String text,String query){return query.isEmpty()||text.toLowerCase(Locale.ROOT).contains(query);}
}
