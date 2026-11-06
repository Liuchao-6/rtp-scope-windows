package com.liuchao.rtpscope.core;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.util.*;

/** Match SIP transactions without hiding retransmissions; times retain both raw and corrected values. */
public final class CaptureComparison {
    public static final class Match {
        public final SipMessage reference,other;public final long deltaUs;
        Match(SipMessage a,SipMessage b,long offset){reference=a;other=b;deltaUs=a==null||b==null?Long.MIN_VALUE:b.timeUs+offset-a.timeUs;}
        public String state(){return reference==null?"仅对照抓包可见":other==null?"对照抓包未见":"已匹配";}
    }
    public static List<Match> compare(List<SipMessage> first,List<SipMessage> second,long offsetUs){
        Set<String> callIds=new HashSet<>();for(SipMessage m:first)callIds.add(m.callId);List<SipMessage> scoped=new ArrayList<>();for(SipMessage m:second)if(callIds.isEmpty()||callIds.contains(m.callId))scoped.add(m);second=scoped;
        Map<String,List<SipMessage>> indexed=new LinkedHashMap<>();for(SipMessage m:second)indexed.computeIfAbsent(key(m),k->new ArrayList<>()).add(m);
        Set<SipMessage> used=Collections.newSetFromMap(new IdentityHashMap<SipMessage,Boolean>());List<Match> out=new ArrayList<>();
        for(SipMessage m:first){SipMessage best=null;long distance=Long.MAX_VALUE;for(SipMessage n:indexed.getOrDefault(key(m),Collections.emptyList()))if(!used.contains(n)){
            long d=Math.abs(n.timeUs+offsetUs-m.timeUs);if(d<distance){distance=d;best=n;}}
            if(best!=null)used.add(best);out.add(new Match(m,best,offsetUs));
        }
        for(SipMessage m:second)if(!used.contains(m))out.add(new Match(null,m,offsetUs));return out;
    }
    // Proxy hops add Via headers and rewrite request URIs. Match the SIP transaction and dialog;
    // preserve each observation and retransmission rather than assuming identical packet bytes.
    private static String key(SipMessage m){return m.callId+"\n"+m.cseq.trim().toUpperCase(Locale.ROOT)+"\n"+(CallHealth.status(m)>0?String.valueOf(CallHealth.status(m)):CallHealth.method(m))+"\n"+CallHealth.tag(m.from)+"\n"+CallHealth.tag(m.to);}
    public static List<SipMessage> messages(Analysis a,String id){List<SipMessage> out=new ArrayList<>();for(SipMessage m:a.sip)if(id.isEmpty()||id.equals(m.callId))out.add(m);return out;}
}
