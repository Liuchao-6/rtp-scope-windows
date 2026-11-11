import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.desktop.AudioPreview;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/** End-to-end checks on the bundled, multi-call sample, independent of its generator. */
public final class DemoShowcaseTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    private static Call call(Analysis a,int number){String prefix=String.format(Locale.ROOT,"%02d-",number);for(Call c:a.calls)if(c.id.startsWith(prefix))return c;throw new AssertionError("Missing demo call "+number);}
    private static Analysis read(File file,TlsKeyLog keys,TlsRsaKeys rsa)throws Exception{try(InputStream in=new FileInputStream(file)){return CaptureEngine.read(in,keys,rsa);}}
    public static int run(File fixtures,File output)throws Exception{
        File source=new File(fixtures,"demo-showcase.pcap"),inputs=new File(fixtures,"demo-audio");
        check(source.length()<5*1024*1024,"showcase remains suitable for phone import");
        TlsRsaKeys rsa;TlsKeyLog keys;
        try(InputStream in=new FileInputStream(new File(inputs,"demo-rsa.key"))){rsa=TlsRsaKeys.read(in);}
        try(InputStream in=new FileInputStream(new File(inputs,"demo-tls.keys"))){keys=TlsKeyLog.read(in);}
        try(Analysis plain=read(source,TlsKeyLog.empty(),TlsRsaKeys.empty())){
            check(plain.calls.size()==21,"plain demo exposes 21 calls before importing keys");
            check(plain.calls.get(0).id.startsWith("01-g711@"),"first call is the basic duplex example");
        }
        try(Analysis onlyRsa=read(source,TlsKeyLog.empty(),rsa)){
            check(onlyRsa.calls.size()==22&&call(onlyRsa,22).streams.size()==2,"separate RSA import reveals only the RSA demo");
        }
        try(Analysis onlyLog=read(source,keys,TlsRsaKeys.empty())){
            check(onlyLog.calls.size()==22&&call(onlyLog,23).streams.size()==2,"separate key log import reveals only the WSS demo");
        }
        try(Analysis a=read(source,keys,rsa)){
            check(a.calls.size()==23,"both demo credentials reveal all 23 distinct calls");
            Set<String> codecs=new HashSet<>();for(RtpStream s:a.streams){codecs.add(s.codec);check(!s.callId.isEmpty(),"every demo stream associates with its own SIP call");}
            check(codecs.containsAll(Arrays.asList("PCMU","PCMA","G729","G729A","OPUS","G722","AMR","AMR-WB","TELEPHONE-EVENT","RTPEVENT")),"complete supported codec and event names");
            for(int number=1;number<=6;number++){
                Call c=call(a,number);check(c.streams.size()==2,"two directions per codec call "+number);
                for(RtpStream s:c.streams){check(s.quality.lost==0,"clean codec demo has no artificial packet loss "+number);check(Math.abs(s.seconds()-11)<.05,"codec demo retains the full conversation duration "+number);}
                if(number<=4){File wav=new File(output,"showcase-codec-"+number+".wav");try(AudioPreview preview=AudioPreview.render(c.streams,a.events,wav)){check(preview.tracks.size()==2,"decoded waveform has independent directions "+number);try(PcmFile pcm=new PcmFile(wav)){check(pcm.durationMs()>10900&&pcm.durationMs()<11200,"decoded speech length "+number);double power=0;for(float value:pcm.read(0,11000,-1,8000))power+=value*value;check(power>1,"decoded demo contains audible speech "+number);}if(number==1){File stereo=new File(output,"showcase-duplex.wav");preview.exportWav(stereo);try(PcmFile pcm=new PcmFile(stereo)){check(pcm.channels==2,"showcase exports two directions in one WAV file");}}}}
            }
            for(int number:new int[]{7,8,9}){
                Call c=call(a,number);DtmfParser.Type type=number==7?DtmfParser.Type.RTP_EVENT:number==8?DtmfParser.Type.SIP_INFO:DtmfParser.Type.IN_BAND;
                List<DtmfParser.Event> found=new ArrayList<>();for(DtmfParser.Event event:a.events)if(c.id.equals(event.callId)){found.add(event);check(event.type==type,"key mode separated by demo call "+number);}
                check(found.size()==(number==7?34:32),"all keys in both directions, without repeated end/request events "+number+" actual="+found.size());
                Map<String,Set<String>> directions=new HashMap<>();for(DtmfParser.Event event:found)directions.computeIfAbsent(event.src+">"+event.dst,k->new HashSet<>()).add(event.key);
                check(directions.size()==2,"both keypad directions "+number);
                for(Set<String> labels:directions.values())check(labels.containsAll(Arrays.asList("0","1","2","3","4","5","6","7","8","9","*","#","A","B","C","D")),"complete 16-key matrix "+number);
                if(number==7)for(DtmfParser.Event event:found)check(event.ended&&event.packets==5,"RFC end repeats collapse into one finished event");
                if(number==8)check(found.stream().anyMatch(e->e.packets==2)&&found.stream().anyMatch(e->!e.durationKnown),"INFO retransmission and absent duration examples");
            }
            RtpStream problem=call(a,10).streams.stream().filter(s->s.codec.equals("PCMU")).findFirst().get();
            check(problem.quality.lost==3&&problem.quality.duplicates==1&&problem.quality.reordered>0&&problem.quality.delaySpikes()>0,"quality scenario exposes exact loss plus duplicate reorder and delay evidence");
            File damaged=new File(output,"showcase-quality.wav");try(AudioPreview preview=AudioPreview.render(call(a,10).streams,a.events,damaged)){
            check(preview.mixed.markers.stream().anyMatch(m->m.kind.equals("LOSS"))&&preview.mixed.markers.stream().anyMatch(m->m.kind.equals("DELAY")),"waveform exposes loss and delay markers");}
            check(CallHealth.inspect(a,call(a,1).id).endSide.equals("主叫侧")&&CallHealth.inspect(a,call(a,2).id).endSide.equals("被叫侧"),"both hangup sides have valid SIP dialog evidence");
            check(CallHealth.inspect(a,call(a,14).id).state.equals("被拒接"),"busy call health");
            check(CallHealth.inspect(a,call(a,15).id).state.equals("已取消"),"cancelled call health");
            check(CallHealth.inspect(a,call(a,16).id).state.equals("响应超时"),"timeout call health");
            check(CallHealth.inspect(a,call(a,17).id).end==null&&call(a,17).streams.size()==1,"partial call keeps unknown termination and one media direction");
            check(a.sip.stream().anyMatch(m->m.callId.equals(call(a,11).id)&&m.body.contains("a=sendonly"))&&a.sip.stream().filter(m->m.callId.equals(call(a,11).id)&&m.firstLine.startsWith("INVITE ")).count()==3,"hold and resume SDP evidence");
            for(int number:new int[]{12,13,22,23})check(a.sip.stream().anyMatch(m->m.callId.equals(call(a,number).id)&&m.firstLine.startsWith("INVITE ")),"reassembled signaling transport "+number);
            check(new CallRelations().find(a,call(a,18).id).stream().anyMatch(l->l.explicit&&l.second.equals(call(a,19).id)||l.explicit&&l.first.equals(call(a,19).id)),"REFER/Replaces links the transfer call legs");
            for(RtpStream s:call(a,21).streams)check(s.quality.lost==0&&s.quality.delaySpikes()==0,"normal DTX gap is not a loss or stall");
            ByteArrayOutputStream selected=new ByteArrayOutputStream();try(InputStream in=new FileInputStream(source)){CallExport.capture(in,a,call(a,1).id,selected);}
            try(Analysis exported=CaptureEngine.read(new ByteArrayInputStream(selected.toByteArray()))){check(exported.calls.size()==1&&exported.calls.get(0).id.equals(call(a,1).id)&&exported.streams.size()==2,"call export isolates the selected conversation from the showcase");}
            ByteArrayOutputStream report=new ByteArrayOutputStream();CallExport.report(a,call(a,1).id,true,true,report);String html=report.toString("UTF-8");check(!html.contains("10001")&&!html.contains("192.0.2.1"),"demo report supports both privacy masks");
            for(RtpStream s:call(a,5).streams)for(RtpPacket p:s.packets)check(AmrPayload.frames(p.payload(),false,true).size()==1,"AMR-NB demo carries valid complete frames");
            for(RtpStream s:call(a,6).streams)for(RtpPacket p:s.packets)check(AmrPayload.frames(p.payload(),true,true).size()==1,"AMR-WB demo carries valid complete frames");
        }
        System.out.println("PASS: "+checks+" multi-call demo checks; codecs, full keypad matrices, TLS, call health and export");return checks;
    }
}
