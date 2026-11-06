import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/** Behavioral checks for evidence boundaries, original packet export, persistent indexes and audio timestamps. */
public final class AdvancedFeatureTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    private static SipMessage sip(long time,String line,String cseq,String from,String to){SipMessage m=new SipMessage();m.timeUs=time;m.firstLine=line;m.cseq=cseq;m.from=from;m.to=to;m.src="192.0.2.1:5060";m.dst="198.51.100.2:5060";m.callId="test-call";m.transport="UDP";m.raw=line+"\r\nCall-ID: test-call\r\n";return m;}
    public static int run(File fixtures,File output)throws Exception{
        Analysis a=new Analysis();Call c=new Call();c.id="test-call";c.from="<sip:1001@a>;tag=a";c.to="<sip:1002@b>";a.calls.add(c);
        SipMessage invite=sip(1000000,"INVITE sip:1002@b SIP/2.0","1 INVITE",c.from,c.to);a.sip.add(invite);
        a.sip.add(sip(1100000,"SIP/2.0 200 OK","2 OPTIONS",c.from,c.to));
        check(CallHealth.inspect(a,c.id).answerUs<0,"OPTIONS 200 never counts as answer");
        SipMessage answer=sip(2000000,"SIP/2.0 200 OK","1 INVITE",c.from,c.to+";tag=b");a.sip.add(answer);
        CallHealth h=CallHealth.inspect(a,c.id);check(h.answerUs==2000000&&h.durationUs()<0&&h.endSide.equals("未知"),"incomplete call has unknown duration and ending side");
        SipMessage bye=sip(6000000,"BYE sip:1001@a SIP/2.0","5 BYE","<sip:1002@b>;tag=b",c.from);bye.src="203.0.113.5:5060";bye.headers.put("reason","Q.850;cause=16");a.sip.add(bye);h=CallHealth.inspect(a,c.id);
        check(h.durationUs()==4000000&&h.endSide.equals("被叫侧"),"dialog tags identify caller/callee despite changed proxy endpoint");
        check(h.reason.contains("cause=16"),"Q850 evidence preserved");check(!h.html(true).contains("203.0.113.5"),"report masks endpoint");
        DtmfParser.Event early=new DtmfParser.Event();early.callId=c.id;early.key="#";early.src="192.0.2.1:10000";early.dst="198.51.100.2:20000";early.firstSeenUs=3000000;early.clock=8000;early.durationTicks=640;
        DtmfParser.Event late=new DtmfParser.Event();late.callId=c.id;late.key="2";late.src="198.51.100.2:5060";late.dst="192.0.2.1:5060";late.firstSeenUs=4000000;late.type=DtmfParser.Type.SIP_INFO;late.durationKnown=false;
        DtmfParser.Event foreign=new DtmfParser.Event();foreign.callId="another-call";foreign.key="9";a.events.addAll(Arrays.asList(late,foreign,early));
        CallHealth.KeySummary keySummary=keys(CallHealth.inspect(a,c.id));check(keySummary.events.size()==2&&keySummary.events.get(0)==early&&keySummary.events.get(1)==late,"key evidence is scoped to the current call and sorted by source time");
        String keyText=keySummary.detailText();check(keyText.contains("按键 #")&&keyText.contains("按键 2")&&keyText.contains("SIP INFO")&&keyText.contains("RFC 2833 / 4733")&&!keyText.contains("按键 9"),"summary retains values and all key types without leaking other calls");
        check(keyText.contains("80.0 ms")&&keyText.contains("持续：未知")&&keyText.contains("192.0.2.1:10000"),"key summary retains duration and source direction");
        a.events.clear();check(keys(CallHealth.inspect(a,c.id)).detailText().contains("当前通话未检测到按键"),"zero keys still have an actionable summary");
        for(int i=0;i<201;i++){DtmfParser.Event e=new DtmfParser.Event();e.callId=c.id;e.key="1";e.src=early.src;e.dst=early.dst;e.type=DtmfParser.Type.IN_BAND;e.firstSeenUs=i;a.events.add(e);}
        keySummary=keys(CallHealth.inspect(a,c.id));check(keySummary.events.size()==201&&keySummary.detailText().contains("In-band DTMF")&&keySummary.detailText().contains("完整明细")&&!keySummary.detailText().contains("201. 按键"),"large summaries retain total count and bound rendered detail");a.events.clear();
        c.from="<img src=x onerror=bad>";check(h.html(false).contains("&lt;img"),"capture headers are escaped in HTML");c.from=invite.from;
        List<SipMessage> first=Arrays.asList(invite,invite),second=Collections.singletonList(invite);List<CaptureComparison.Match> compared=CaptureComparison.compare(first,second,1000);
        check(compared.size()==2&&compared.get(0).deltaUs==1000&&compared.get(1).other==null,"one message cannot satisfy two retransmissions");
        Call other=new Call();other.id="replaced";other.from=c.from;other.to=c.to;a.calls.add(other);bye.headers.put("replaces","replaced;to-tag=a;from-tag=b");CallRelations links=new CallRelations();
        check(links.find(a,c.id).stream().anyMatch(l->l.explicit&&l.kind.equals("replaces")),"Replaces evidence associates calls");links.confirm(c.id,other.id);check(links.find(a,c.id).stream().anyMatch(l->l.kind.equals("手动确认")),"manual association present");links.remove(c.id,other.id);check(links.find(a,c.id).stream().noneMatch(l->l.kind.equals("手动确认")),"manual association removed independently");
        try(InputStream in=new FileInputStream(new File(fixtures,"demo-analysis.pcap"));Analysis original=CaptureEngine.readLarge(in,output,null)){
            String id=original.calls.get(0).id;ByteArrayOutputStream filtered=new ByteArrayOutputStream();try(InputStream raw=new FileInputStream(new File(fixtures,"demo-analysis.pcap"))){long count=CallExport.capture(raw,original,id,filtered);check(count>0&&count<=original.packets,"export selects original capture packets");}
            try(Analysis restored=CaptureEngine.read(new ByteArrayInputStream(filtered.toByteArray()))){check(restored.sip.size()>0&&restored.streams.size()>0,"exported pcapng independently parses SIP and RTP");check(restored.calls.stream().anyMatch(x->x.id.equals(id)),"export retains original Call-ID");}
            AnalysisCache cache=new AnalysisCache(new File(output,"advanced-index"));String key;try(InputStream raw=new FileInputStream(new File(fixtures,"demo-analysis.pcap"))){key=cache.key(raw);}cache.save(key,original);try(Analysis restored=cache.load(key)){check(restored!=null&&restored.calls.size()==original.calls.size()&&restored.events.size()==original.events.size(),"index restores call and keypad graphs");check(restored.streams.get(0).packets.get(0).payload().length==original.streams.get(0).packets.get(0).payload().length,"index restores disk-backed RTP payload");}
            Files.write(new File(output,"advanced-index/"+key+".index").toPath(),new byte[]{1,2,3});check(cache.load(key)==null,"damaged index falls back to parsing");cache.clear();
        }
        RtpStream g722=new RtpStream();g722.codec="G722";g722.clock=8000;g722.clockKnown=true;RtpPacket p=new RtpPacket();p.payload=Files.readAllBytes(new File(fixtures,"g722-wideband.bin").toPath());g722.packets.add(p);File decoded=new File(output,"g722-decoded.wav");AudioRenderer.render(Collections.singletonList(g722),decoded);
        byte[] actual=Files.readAllBytes(decoded.toPath()),expected=Files.readAllBytes(new File(fixtures,"g722-reference.pcm").toPath());check(actual.length==expected.length+44,"G722 output uses 16 kHz audio with 8 kHz RTP clock");double error=0,signal=0;for(int i=0;i<expected.length;i+=2){int x=(short)((actual[i+44]&255)|(actual[i+45]<<8)),y=(short)((expected[i]&255)|(expected[i+1]<<8));error+=(x-y)*(double)(x-y);signal+=y*(double)y;}double snr=10*Math.log10(signal/Math.max(1,error));check(snr>60,"G722 independent wideband SNR");System.out.println("G722 independent reference SNR: "+snr+" dB");
        byte[] amr=new byte[14];amr[0]=(byte)0xf0;amr[1]=4;amr[2]=(byte)0x80;List<byte[]> unpacked=AmrPayload.frames(amr,false,true);check(unpacked.size()==1&&unpacked.get(0).length==13&&unpacked.get(0)[1]==(byte)0x80,"octet-aligned AMR maps speech bits");check(!AmrPayload.supported("octet-align=1;crc=1"),"unsupported AMR CRC is explicit");
        try{AmrPayload.frames(new byte[]{(byte)0xf0,4},false,true);throw new AssertionError("truncated AMR accepted");}catch(IOException ok){checks++;}
        File wav=new File(output,"resample-test.wav");float[] samples=new float[8000];for(int i=0;i<samples.length;i++)samples[i]=(float)Math.sin(i*.1)*.4f;PcmFile.write(wav,samples,8000);try(PcmFile pcm=new PcmFile(wav)){check(pcm.frames==8000&&pcm.channels==1,"PCM metadata decoded");check(pcm.read(500,100,0,16000).length==1600,"resampling preserves time offsets");}
        Transcript text=new Transcript();text.segments.add(new Transcript.Segment(65000,66200,"左声道","测试 <内容>"));ByteArrayOutputStream srt=new ByteArrayOutputStream();text.export(srt,true);check(srt.toString("UTF-8").contains("00:01:05,000 --> 00:01:06,200"),"SRT uses original recording timestamps");File saved=new File(output,"advanced-transcript.properties");text.save(saved);check(Transcript.load(saved).segments.get(0).text.equals("测试 <内容>"),"Chinese transcript round trip");
        ByteArrayOutputStream unsafe=new ByteArrayOutputStream();try(ZipOutputStream zip=new ZipOutputStream(unsafe)){zip.putNextEntry(new ZipEntry("../escape.onnx"));zip.write(1);zip.closeEntry();}try{SpeechModels.install(new ByteArrayInputStream(unsafe.toByteArray()),new File(output,"models"),"bad.zip");throw new AssertionError("model zip traversal accepted");}catch(IOException ok){checks++;}
        return checks;
    }
    private static CallHealth.KeySummary keys(CallHealth health){for(CallHealth.Finding f:health.findings)if(f.title.equals("按键")){if(!(f.evidence instanceof CallHealth.KeySummary))throw new AssertionError("Key summary missing");return (CallHealth.KeySummary)f.evidence;}throw new AssertionError("Key finding missing");}
    public static void main(String[] args)throws Exception{System.out.println("PASS: "+run(new File(args[0]),new File(args[1]))+" advanced feature checks");}
}
