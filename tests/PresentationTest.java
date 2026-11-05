import java.util.*;
import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;

/** Regression tests for what the ladder and colored detail show from real parsed fixtures. */
public final class PresentationTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static boolean token(String raw,List<SipSyntax.Span> spans,String text,SipSyntax.Kind kind) {
        for(SipSyntax.Span span:spans)if(span.kind==kind&&raw.substring(span.start,span.end).trim().equals(text))return true;
        return false;
    }
    private static SipMessage sip(long time,String src,String dst,String id,String first) {
        SipMessage m=new SipMessage();m.timeUs=time;m.src=src;m.dst=dst;m.callId=id;m.firstLine=first;m.raw=first+"\r\nCall-ID: "+id+"\r\n\r\n";m.body="";m.cseq="1 INVITE";m.transport="UDP";return m;
    }
    public static int run(Analysis integrated,Analysis tcp,Analysis dtmf) {
        CallFlow flow=CallFlow.build(integrated,"","");
        check(flow.entries.size()==8,"ladder has five SIP messages, two audio streams, one deduplicated key");
        int sipCount=0,media=0,keys=0;long prior=Long.MIN_VALUE;
        for(CallFlow.Entry e:flow.entries) {
            check(e.timeUs>=prior,"chronological SIP media keys");prior=e.timeUs;
            if(e.source instanceof SipMessage)sipCount++;
            if(e.source instanceof RtpStream){media++;check(!((RtpStream)e.source).isDtmf(),"event stream not duplicated as media summary");}
            if(e.source instanceof DtmfParser.Event){keys++;check(e.title.contains("按键 5"),"key shown explicitly");}
        }
        check(sipCount==5&&media==2&&keys==1,"ladder sources remain available for details");
        check(flow.nodes.equals(Arrays.asList("10.0.0.1","10.0.0.2")),"IP lanes merge signaling and RTP ports");
        check(flow.entries.get(0).title.equals("INVITE / SDP"),"compact request and SDP summary");
        check(CallFlow.build(integrated,integrated.calls.get(0).id,"").entries.size()==8,"selected call retains its media and key");
        check(CallFlow.build(integrated,"unknown","").entries.isEmpty(),"unknown selected call shows no unrelated media");
        CallFlow found=CallFlow.build(integrated,"","g729");
        check(found.entries.stream().anyMatch(e->e.source instanceof RtpStream),"case insensitive codec search");
        check(found.originUs==flow.originUs,"search keeps relative times anchored to full selected call");
        check(CallFlow.build(integrated,"","no-such-value").nodes.isEmpty(),"no phantom lanes for empty search");
        check(CallFlow.build(null,"","").entries.isEmpty(),"empty analysis safe");
        check(CallFlow.build(dtmf,"","").entries.stream().filter(e->e.source instanceof DtmfParser.Event).count()==3,"repeated event endings stay deduplicated");
        CallFlow.Endpoint v6=CallFlow.Endpoint.parse("[2001:db8::1234]:5060");
        check(v6.ip.equals("2001:db8::1234")&&v6.port.equals("5060"),"IPv6 signaling endpoint");
        check(CallFlow.Endpoint.parse("2001:db8::1234").port.isEmpty(),"bare IPv6 does not invent a port");
        check(CallFlow.Endpoint.parse("[::1]").ip.equals("::1"),"bracketed IPv6 without port");
        Analysis topology=new Analysis();
        SipMessage request=sip(100,"[::1]:5060","[2001:db8::2]:9080","one","INVITE sip:b SIP/2.0");
        SipMessage response=sip(200,"[2001:db8::2]:9080","[::1]:5060","one","SIP/2.0 180 Ringing");
        SipMessage loop=sip(200,"[::1]:5080","[::1]:5060","one","ACK sip:b SIP/2.0");
        topology.sip.add(loop);topology.sip.add(request);topology.sip.add(response);topology.sip.add(sip(50,"x:1","y:2","two","OPTIONS sip:b SIP/2.0"));
        CallFlow selected=CallFlow.build(topology,"one","");
        check(selected.nodes.equals(Arrays.asList("::1","2001:db8::2")),"selected call excludes other topology");
        check(selected.originUs==100&&selected.entries.get(0).source==request,"order from capture time rather than input grouping");
        check(selected.entries.get(1).source==loop&&selected.entries.get(2).source==response,"equal timestamps stable");
        check(selected.entries.get(2).src.ip.equals(selected.entries.get(0).dst.ip),"response direction reversed");
        check(selected.entries.get(1).src.ip.equals(selected.entries.get(1).dst.ip)&&selected.entries.get(1).src.port.equals("5080"),"same IP different ports stays self loop");
        check(selected.entries.get(2).title.equals("180 Ringing"),"response status and reason visible");
        for(SipMessage m:tcp.sip)validateSpans(m.raw,SipSyntax.spans(m.raw));
        String raw="INVITE sip:135@test:7080 SIP/2.0\r\nVia: SIP/2.0/UDP host;branch=z9hG4bK-123\r\nFrom: \"中文\" <sip:100@test>;tag=abc\r\nTo: <sip:135@test>\r\nCall-ID: xyz-123@test\r\nCSeq: 12 INVITE\r\nAllow: INVITE, ACK, BYE\r\nContent-Type: application/sdp\r\n\r\nv=0\r\nm=audio 9000 RTP/AVP 18 110\r\na=rtpmap:110 telephone-event/8000\r\n";
        List<SipSyntax.Span> spans=SipSyntax.spans(raw);validateSpans(raw,spans);
        check(token(raw,spans,"INVITE",SipSyntax.Kind.METHOD),"method highlighted");
        check(token(raw,spans,"sip:135@test:7080",SipSyntax.Kind.URI),"request URI highlighted without trailing version");
        check(token(raw,spans,"Call-ID:",SipSyntax.Kind.HEADER),"header color includes colon");
        check(token(raw,spans,"xyz-123@test",SipSyntax.Kind.ID),"call ID highlighted");
        check(token(raw,spans,"abc",SipSyntax.Kind.ID)&&token(raw,spans,"z9hG4bK-123",SipSyntax.Kind.ID),"dialog tags and transaction branches");
        check(token(raw,spans,"\"中文\" <sip:100@test>;tag=abc",SipSyntax.Kind.ID),"Unicode display name part of intact From field");
        check(token(raw,spans,"a=rtpmap:",SipSyntax.Kind.SDP),"SDP attribute highlight");
        check(token(raw,spans,"m=",SipSyntax.Kind.SDP),"SDP media key highlight");
        String folded="BYE sip:b SIP/2.0\ni: compact-id\nf: <sips:a@test>\n\t;tag=folded\nCSeq: 8 BYE\n\nnon-sdp: body";
        List<SipSyntax.Span> foldedSpans=SipSyntax.spans(folded);validateSpans(folded,foldedSpans);
        check(token(folded,foldedSpans,"compact-id",SipSyntax.Kind.ID),"compact Call-ID");
        check(token(folded,foldedSpans,"sips:a@test",SipSyntax.Kind.URI),"secure URI");
        check(token(folded,foldedSpans,"folded",SipSyntax.Kind.ID),"folded header tag");
        check(!token(folded,foldedSpans,"non-sdp:",SipSyntax.Kind.HEADER),"message body not mistaken for header");
        for(String code:new String[]{"100 Trying","200 OK","302 Moved","404 Not Found","503 Unavailable","603 Decline"}) {
            String responseRaw="SIP/2.0 "+code+"\r\nCall-ID: INVITE\r\n\r\n";
            List<SipSyntax.Span> rs=SipSyntax.spans(responseRaw);validateSpans(responseRaw,rs);
            SipSyntax.Kind expected=code.startsWith("1")?SipSyntax.Kind.PROVISIONAL:code.startsWith("2")?SipSyntax.Kind.SUCCESS:SipSyntax.Kind.ERROR;
            check(token(responseRaw,rs,code,expected),"response class color "+code);
            check(!token(responseRaw,rs,"INVITE",SipSyntax.Kind.METHOD),"identifier named INVITE not mistaken for method");
        }
        for(String malformed:new String[]{"","\n","SIP/2.0 ","INVITE","INVITE sip:a SIP/2.0\r\nBroken header\r\n\r\n中文"})validateSpans(malformed,SipSyntax.spans(malformed));
        for(SipMessage m:integrated.sip) {
            String before=m.raw;validateSpans(m.raw,SipSyntax.spans(m.raw));
            check(before.equals(m.raw),"original raw message preserved for clipboard");
        }
        return checks;
    }
    private static void validateSpans(String raw,List<SipSyntax.Span> spans) {
        for(SipSyntax.Span span:spans){check(span.start>=0&&span.start<span.end&&span.end<=raw.length(),"syntax offsets in original text");check(raw.substring(span.start,span.end).indexOf('\n')<0&&raw.substring(span.start,span.end).indexOf('\r')<0,"span does not consume line endings");}
    }
}
