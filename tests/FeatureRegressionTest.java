import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.util.*;

/** Cross-platform regressions for authenticated dialogs, proxy observations and audio routing. */
public final class FeatureRegressionTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    private static SipMessage sip(long time,String line,String cseq,String from,String to){SipMessage m=new SipMessage();m.timeUs=time;m.firstLine=line;m.cseq=cseq;m.from=from;m.to=to;m.src="192.0.2.1:5060";m.dst="198.51.100.2:5060";m.callId="auth-call";m.raw=line+"\r\n";m.transport="UDP";return m;}
    public static int run(File output)throws Exception{
        Analysis a=new Analysis();Call c=new Call();c.id="auth-call";c.from="<sip:1001@a>;tag=caller";c.to="<sip:1002@b>";a.calls.add(c);
        SipMessage first=sip(1000000,"INVITE sip:1002@b SIP/2.0","1 INVITE",c.from,c.to),auth=sip(1100000,"SIP/2.0 401 Unauthorized","1 INVITE",c.from,c.to+";tag=auth"),retry=sip(1200000,"INVITE sip:1002@b SIP/2.0","2 INVITE",c.from,c.to),answer=sip(2000000,"SIP/2.0 200 OK","2 INVITE",c.from,c.to+";tag=callee");
        a.sip.addAll(Arrays.asList(first,auth,retry,answer));check(CallHealth.inspect(a,c.id).answerUs==2000000,"authenticated initial INVITE can answer with a new CSeq");
        SipMessage wrongAck=sip(2100000,"ACK sip:1002@b SIP/2.0","99 ACK",c.from,answer.to);a.sip.add(wrongAck);check(CallHealth.inspect(a,c.id).findings.stream().anyMatch(f->f.title.equals("ACK 未捕获")),"unrelated ACK cannot satisfy the answer transaction");
        SipMessage ack=sip(2200000,"ACK sip:1002@b SIP/2.0","2 ACK",c.from,answer.to);a.sip.add(ack);check(CallHealth.inspect(a,c.id).findings.stream().noneMatch(f->f.title.equals("ACK 未捕获")),"dialog and CSeq ACK accepted");
        SipMessage forkBye=sip(3000000,"BYE sip:1001@a SIP/2.0","3 BYE","<sip:1002@b>;tag=other-branch",c.from);a.sip.add(forkBye);check(CallHealth.inspect(a,c.id).end==null,"another fork BYE does not end the selected answered dialog");
        SipMessage bye=sip(5000000,"BYE sip:1001@a SIP/2.0","4 BYE",answer.to,c.from);bye.headers.put("reason","Q.850;cause=16");a.sip.add(bye);CallHealth h=CallHealth.inspect(a,c.id);check(h.durationUs()==3000000&&h.endSide.equals("被叫侧"),"authenticated dialog duration and ending side");check(h.reason.contains("正常清除"),"Q850 reason has explanation");
        bye.headers.put("reason","Q.850;cause=999999999999999999999999");check(CallHealth.inspect(a,c.id).reason.contains("999999999999999999999999"),"out of range Q850 cause is retained without breaking call health");bye.headers.put("reason","Q.850;cause=16");
        ByteArrayOutputStream report=new ByteArrayOutputStream();CallExport.report(a,c.id,true,report);String html=report.toString("UTF-8");check(html.contains("#evidence0")&&html.contains("id='evidence0'")&&!html.contains("evidence:"),"standalone report evidence links resolve inside the report");check(!html.contains("192.0.2.1")&&!html.contains("1001@"),"report masks endpoints and URI numbers");
        a.sip.remove(answer);a.sip.remove(bye);a.sip.remove(forkBye);a.sip.add(sip(2500000,"CANCEL sip:1002@b SIP/2.0","2 CANCEL",c.from,c.to));a.sip.add(sip(2600000,"SIP/2.0 487 Request Terminated","2 INVITE",c.from,c.to));check(CallHealth.inspect(a,c.id).state.equals("已取消"),"487 after CANCEL retains cancellation state");
        SipMessage forwarded=sip(first.timeUs+2500,"INVITE sip:1002@rewritten-target SIP/2.0",first.cseq,first.from,first.to);forwarded.headers.put("via","SIP/2.0/UDP proxy;branch=other");SipMessage unrelated=sip(0,"OPTIONS sip:x@y SIP/2.0","2 OPTIONS",c.from,c.to);unrelated.callId="another-call";
        List<CaptureComparison.Match> matches=CaptureComparison.compare(Collections.singletonList(first),Arrays.asList(forwarded,unrelated),-1000);check(matches.size()==1&&matches.get(0).other==forwarded&&matches.get(0).deltaUs==1500,"proxy URI and Via rewrite match while unrelated calls are omitted");
        float[] signal=new float[48000];Arrays.fill(signal,.5f);File left=new File(output,"routing-left.wav"),right=new File(output,"routing-right.wav"),routed=new File(output,"routing-stereo.wav");PcmFile.write(left,signal,48000);PcmFile.write(right,signal,48000);
        PcmTracks.mix(Arrays.asList(left,right),Arrays.asList(0.0,.5),new boolean[]{false,true},true,routed);try(PcmFile pcm=new PcmFile(routed)){check(pcm.rate==48000&&pcm.channels==2&&pcm.frames==48024,"stereo keeps 48 kHz and half-millisecond offset");float[] l=pcm.read(0,20,0,48000),r=pcm.read(0,20,1,48000);check(l[100]==0&&r[0]==0&&r[23]==0&&r[24]>.49f,"muting and fractional direction offsets reach actual PCM samples");}
        PcmTracks.mix(Arrays.asList(left,right),Arrays.asList(0,0),new boolean[]{true,false},false,routed);try(PcmFile pcm=new PcmFile(routed)){check(pcm.read(0,20,0,48000)[100]>.49f,"independent listening is not attenuated by the muted direction");}
        float[] delayed=new float[67*8000];for(int i=65*8000;i<66*8000;i++)delayed[i]=(float)Math.sin(i*.1)*.2f;File delayedFile=new File(output,"voice-delayed.wav");PcmFile.write(delayedFile,delayed,8000);try(PcmFile pcm=new PcmFile(delayedFile)){List<VoiceSegments.Window> windows=VoiceSegments.find(pcm,0);check(windows.size()==1&&windows.get(0).startMs>=64800&&windows.get(0).endMs<=66200,"silence skipping retains the original recording time");}
        Transcript t=new Transcript();t.segments.add(new Transcript.Segment(100,200,"左声道","甲"));t.segments.add(new Transcript.Segment(300,400,"右声道","乙"));check(t.channels().size()==2&&t.channel("右声道").segments.size()==1,"transcripts can export each channel separately");
        return checks;
    }
}
