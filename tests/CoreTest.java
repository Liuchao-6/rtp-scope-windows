import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;

public final class CoreTest {
    private static File fixtures,output;
    private static int checks;
    private static void check(boolean condition,String message) { checks++;if(!condition)throw new AssertionError(message); }
    private static Analysis read(String name) throws IOException {try(InputStream in=new FileInputStream(new File(fixtures,name))){return CaptureEngine.read(in);}}
    private static void bad(String name) throws IOException {
        try{read(name);throw new AssertionError("Must reject "+name);}catch(IOException expected){checks++;}
    }
    private static int sample(byte[] pcm,int offset){return (short)((pcm[offset]&255)|((pcm[offset+1]&255)<<8));}
    public static void main(String[] args) throws Exception {
        fixtures=new File(args[0]);output=new File(args[1]);
        for(boolean alaw:new boolean[]{false,true}) {
            byte[] oracle=Files.readAllBytes(new File(fixtures,alaw?"g711-pcma.pcm":"g711-pcmu.pcm").toPath());
            for(int i=0;i<256;i++)check(AudioRenderer.decode(i,alaw)==sample(oracle,i*2),"G711 reference "+alaw+" "+i);
        }
        Analysis demo=read("demo.pcap");
        check(demo.sip.size()==5,"five SIP messages");check(demo.calls.size()==1,"one call");check(demo.streams.size()==2,"duplex streams");
        check(demo.calls.get(0).streams.size()==2,"SDP associates both directions");check(demo.streams.get(0).packets.size()==300,"complete media");
        check(demo.streams.get(0).playable()&&demo.streams.get(1).playable(),"G711 playable");
        check(Math.abs(demo.streams.get(0).seconds()-6)<0.00001,"six second source");
        File mix=new File(output,"demo-duplex.wav");AudioRenderer.render(demo.streams,mix);
        check(mix.length()==44+48008*2,"duplex capture-time alignment");
        byte[] mixed=Files.readAllBytes(mix.toPath());
        byte[] mu=Files.readAllBytes(new File(fixtures,"g711-pcmu.pcm").toPath());
        byte[] alawRef=Files.readAllBytes(new File(fixtures,"g711-pcma.pcm").toPath());
        for(int pos:new int[]{1,37,101,3999,8001,8081,16003,23999,32007,40009,47999,48007}) {
            int expected=0;
            if(pos<48000) {RtpPacket p=demo.streams.get(0).packets.get(pos/160);expected+=sample(mu,(p.payload[pos%160]&255)*2)/2;}
            if(pos>=8&&pos<48008) {int j=pos-8;RtpPacket p=demo.streams.get(1).packets.get(j/160);expected+=sample(alawRef,(p.payload[j%160]&255)*2)/2;}
            check(sample(mixed,44+pos*2)==expected,"duplex PCM mix "+pos);
        }
        Analysis loss=read("loss-wrap.pcap");RtpStream stream=loss.streams.get(0);
        check(stream.lost==1,"one missing packet across sequence wrap");check(stream.duplicates==1,"duplicate recognized");
        check(stream.packets.get(0).payload.length==160,"RTP extension and padding stripped");
        File wav=new File(output,"loss-wrap.wav");AudioRenderer.render(loss.streams,wav);byte[] pcm=Files.readAllBytes(wav.toPath());
        check(pcm.length==44+800*2,"timestamp wrap and silence duration");
        for(int i=0;i<800;i++)check(sample(pcm,44+i*2)==(i>=480&&i<640?0:8),"reordering and missing audio sample "+i);
        for(String file:new String[]{"dynamic.pcapng","big-endian.pcapng","big-endian.pcap","nanoseconds.pcap"}) {
            Analysis a=read(file);check(a.sip.size()==1,file+" SIP");check(a.streams.size()==1,file+" RTP");
            check(a.streams.get(0).codec.equals("PCMU")&&a.streams.get(0).pt==96,file+" dynamic codec");
            check(a.firstUs==1793664000000000L,file+" time resolution");
        }
        check(read("multi-section.pcapng").sip.size()==2,"pcapng section byte-order and interface reset");
        Analysis tcp=read("tcp-reassembly.pcap");check(tcp.sip.size()==2,"TCP segmentation, overlap, reorder and retransmission");
        check(tcp.sip.get(0).body.contains("中文测试"),"SIP byte length and UTF-8 preserved");
        Analysis gap=read("tcp-gap.pcap");check(gap.sip.isEmpty(),"never join TCP gaps");check(!gap.warnings.isEmpty(),"gap coverage visible");
        Analysis secure=read("srtp.pcap");check(secure.streams.size()==1&&!secure.streams.get(0).playable(),"SRTP not decoded as audio");
        try{AudioRenderer.render(secure.streams,new File(output,"forbidden.wav"));throw new AssertionError("SRTP renderer refusal");}catch(IOException expected){checks++;}
        Analysis dtmf=read("dtmf.pcap");check(dtmf.streams.size()==1&&!dtmf.streams.get(0).playable(),"telephone-event not decoded as G711");
        for(String file:new String[]{"ethernet.pcap","vlan.pcap","sll.pcap","sll2.pcap","loopback.pcap","ipv6.pcap"}) {
            Analysis a=read(file);check(a.streams.size()==1,file+" supported link/IP");check(a.streams.get(0).packets.size()==3,file+" media packets");
        }
        check(read("truncated.pcap").partial,"truncated capture retains earlier packets");check(read("damaged.pcapng").partial,"damaged block retains earlier packets");bad("invalid.pcap");
        Analysis keys=read("dtmf-multiplex.pcap");
        check(keys.events.size()==3,"deduplicate repeated RFC4733 end packets");
        DtmfParser.Event digit=keys.events.get(0);
        check(digit.key.equals("1")&&digit.ended&&digit.packets==5,"one key with repeated ending");
        check(digit.durationMs()==60&&digit.volume==10,"DTMF duration and volume");
        check(keys.events.get(1).key.equals("#")&&keys.events.get(1).ended,"hash key");
        check(keys.events.get(2).key.equals("*")&&!keys.events.get(2).ended,"unfinished star key");
        check(keys.streams.get(0).quality.lost==0,"telephone-event does not cause false audio loss");
        check(keys.streams.get(0).quality.payloadTypes.contains(110),"dynamic event payload accounted for");
        check(!keys.warnings.isEmpty(),"malformed event coverage visible");
        Analysis quality=read("quality.pcap");QualityAnalyzer.Report report=quality.streams.get(0).quality;
        check(report.lost==1&&report.duplicates==1&&report.reordered==1,"SSRC loss duplicates reorder");
        check(report.delaySpikes()==1&&report.maxJitterMs>10,"arrival delay and RFC3550 jitter");
        check(report.payloadTypes.contains(13),"single comfort noise packet counted in sequence");
        QualityAnalyzer.Issue lossIssue=report.issues.stream().filter(i->i.kind.equals("LOSS")).findFirst().get();
        check(lossIssue.firstMissing==4&&lossIssue.lastMissing==4,"exact missing sequence range");
        check(lossIssue.startTimestamp==480&&lossIssue.endTimestamp==640,"RTP loss time interval");
        QualityAnalyzer.Report dtx=read("dtx.pcap").streams.get(0).quality;
        check(dtx.lost==0&&dtx.delaySpikes()==0&&dtx.maxArrivalGapMs==500,"DTX gap is not called a stall");
        WaveformData wave=WaveformData.load(wav,loss.streams);
        check(wave.samples==800&&wave.rate==8000,"waveform sample rate and duration");
        check(wave.minimum[500]==0&&wave.maximum[500]==0,"missing region is silent waveform");
        check(wave.maximum[100]==8,"waveform reflects decoded PCM");
        check(wave.markers.size()==1&&wave.markers.get(0).startMs==60&&wave.markers.get(0).endMs==80,"waveform exact loss marker interval");
        Analysis compressed=read("g729.pcap");RtpStream g729=compressed.streams.get(0);
        check(g729.codec.equals("G729")&&g729.playable()&&g729.seconds()==2,"G729 negotiated and 10-byte frames timed");
        File g729Wav=new File(output,"g729.wav");AudioRenderer.render(compressed.streams,g729Wav);
        byte[] decoded=Files.readAllBytes(g729Wav.toPath()),reference=Files.readAllBytes(new File(fixtures,"g729-reference.pcm").toPath());
        check(decoded.length==44+reference.length&&reference.length==32000,"G729 decoded duration matches FFmpeg");
        double signal=0,error=0;for(int i=0;i<reference.length;i+=2){double expected=sample(reference,i),actual=sample(decoded,44+i);signal+=expected*expected;error+=(expected-actual)*(expected-actual);}
        double snr=10*Math.log10(signal/Math.max(1,error));
        check(signal>1000000&&snr>18,"G729 independent FFmpeg reference SNR "+snr);
        System.out.println("G729 independent reference SNR: "+snr+" dB");
        org.jitsi.impl.neomedia.codec.audio.g729.G729Codec codec=new org.jitsi.impl.neomedia.codec.audio.g729.G729Codec();
        short[] sid=codec.decode(new byte[2]);check(sid.length==80&&sid[0]==0,"SID interval silent, not fake decoded noise");
        try{codec.decode(new byte[9]);throw new AssertionError("G729 malformed payload");}catch(IOException expected){checks++;}
        Analysis integrated=read("demo-analysis.pcap");check(integrated.calls.size()==1&&integrated.streams.size()==3&&integrated.events.size()==1,"integrated demo");
        check(integrated.events.get(0).key.equals("5")&&integrated.events.get(0).ended,"integrated key 5");
        RtpStream forward=integrated.streams.stream().filter(s->s.codec.equals("PCMU")).findFirst().get();
        check(forward.quality.lost==1&&forward.quality.delaySpikes()==1,"integrated loss and delay evidence");
        QualityAnalyzer.Report late=read("late-packet.pcap").streams.get(0).quality;
        check(late.lost==0&&late.reordered==1&&late.delaySpikes()==1,"late recovered packet still has delay risk");
        QualityAnalyzer.Report reset=read("sequence-reset.pcap").streams.get(0).quality;
        check(reset.lost==0&&reset.resets==1,"large sequence restart not counted as thousands of lost packets");
        Analysis reorderedG729=read("g729-reorder.pcap");File reorderedWav=new File(output,"g729-reordered.wav");AudioRenderer.render(reorderedG729.streams,reorderedWav);
        check(Arrays.equals(decoded,Files.readAllBytes(reorderedWav.toPath())),"G729 stateful decode uses RTP order and ignores retransmissions");
        RtpStream matrix=new RtpStream();matrix.codec="TELEPHONE-EVENT";matrix.clockKnown=true;matrix.src="a";matrix.dst="b";
        for(int number=0;number<16;number++){RtpPacket p=new RtpPacket();p.timestamp=number*160;p.timeUs=number*20000;p.payload=new byte[]{(byte)number,(byte)0xbf,0,(byte)160};matrix.packets.add(p);}
        DtmfParser.Result parsedKeys=DtmfParser.parse(matrix);
        String[] labels={"0","1","2","3","4","5","6","7","8","9","*","#","A","B","C","D"};
        check(parsedKeys.events.size()==16,"all RFC4733 DTMF events");
        for(int number=0;number<16;number++)check(parsedKeys.events.get(number).key.equals(labels[number]),"DTMF label "+number);
        matrix.encrypted=true;check(DtmfParser.parse(matrix).events.isEmpty(),"encrypted event not parsed");
        matrix.encrypted=false;matrix.codec="PT 101";check(DtmfParser.parse(matrix).events.isEmpty(),"PT101 alone does not prove telephone-event");
        checks+=AdvancedFeatureTest.run(fixtures,output);
        checks+=SpeechReportTest.run(output);
        checks+=ChannelAudioTest.run(fixtures,output);
        checks+=FeatureRegressionTest.run(output);
        checks+=RtpRecoveryTest.run(output);
        checks+=RtpClockSkewTest.run(output);
        checks+=CaptureWorkspaceTest.run();
        checks+=CallSearchTest.run(fixtures);
        checks+=SecureTransportTest.run(fixtures,output);
        checks+=RsaTransportTest.run(fixtures,output);
        checks+=PresentationTest.run(integrated,tcp,keys);
        checks+=PartialCaptureTest.run(fixtures);
        checks+=KeyModesTest.run(fixtures);
        checks+=DeferredCaptureTest.run(fixtures,output);
        System.out.println("PASS: "+checks+" assertions; codecs, captures, SIP ladder, syntax colors, RTP quality, waveform");
    }
}
