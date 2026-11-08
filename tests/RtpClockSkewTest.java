import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.Files;
import java.util.*;

/** Synthetic paused RTP clocks versus transient capture jitter; no private call data. */
public final class RtpClockSkewTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    private static RtpStream stream(String src){RtpStream s=new RtpStream();s.codec="PCMA";s.clock=8000;s.clockKnown=true;s.pt=8;s.src=src;s.dst="198.51.100.2:20000";s.ssrc=123;return s;}
    private static RtpPacket packet(RtpStream s,int n,long timeUs){RtpPacket p=new RtpPacket();p.sequence=(65500+n)&65535;p.timestamp=(0xfffff000L+n*160)&0xffffffffL;p.timeUs=timeUs;p.payload=new byte[160];for(int i=0;i<160;i++)p.payload[i]=(byte)(n+i);s.packets.add(p);return p;}
    private static long pausedUs(int n){return 1000000L+n*20000L+(n>=20?1020000:0)+(n>=60?160000:0)+(n>=100?(1+(n-100)/10)*20000:0);}
    private static int sample(byte[] b,long at){int offset=44+(int)at*2;return (short)((b[offset]&255)|(b[offset+1]<<8));}
    public static int run(File output)throws Exception{
        RtpStream paused=stream("192.0.2.1:10000");for(int n=0;n<160;n++)packet(paused,n,pausedUs(n));
        double expected=(pausedUs(159)-pausedUs(0))/1000000.0+.02;
        check(Math.abs(paused.seconds()-expected)<.000125,"consecutive sequence numbers retain repeated pauses missing from the RTP clock");
        RtpTimeline timeline=RtpTimeline.of(paused);check(timeline.repairs>1&&timeline.frames.size()==160,"persistent clock lag is repaired without dropping RTP packets");
        File wav=new File(output,"paused-clock.wav");AudioRenderer.render(Collections.singletonList(paused),wav);byte[] pcm=Files.readAllBytes(wav.toPath());
        check(pcm.length==44+Math.round(expected*8000)*2,"decoded WAV spans the real paused-clock recording");
        for(int n=0;n<160;n++){long position=(pausedUs(n)-pausedUs(0))*8000/1000000;RtpPacket p=paused.packets.get(n);for(int i=0;i<160;i++)check(sample(pcm,position+i)==AudioRenderer.decode(p.payload[i]&255,true),"all source samples survive at the correct capture-aligned position");}
        check(sample(pcm,3200)==0&&sample(pcm,11359)==0,"the first 1020 ms pause is represented by silence rather than removed");
        DtmfParser.Event key=new DtmfParser.Event();RtpPacket p=paused.packets.get(85);key.src=paused.src;key.dst=paused.dst;key.ssrc=paused.ssrc;key.clock=8000;key.timestamp=(p.timestamp+80)&0xffffffffL;key.firstSeenUs=p.timeUs+10000;key.durationTicks=160;key.key="5";
        double keyMs=(p.timeUs-paused.firstUs())/1000.0+10;
        check(Math.abs(DtmfParser.audioStartMs(key,paused,paused.firstUs(),timeline)-keyMs)<.001,"2833 events follow the repaired timeline after multiple pauses and timestamp wrap");
        paused.quality=QualityAnalyzer.analyze(Collections.singletonList(paused),true);WaveformData wave=WaveformData.load(wav,Collections.singletonList(paused));wave.addEvents(Collections.singletonList(key),Collections.singletonList(paused));
        check(paused.quality.lost==0&&paused.quality.delayCount>0,"playback repair leaves capture-side loss and delay evidence intact");
        check(Math.abs(wave.durationMs()-expected*1000)<.001&&wave.markers.stream().anyMatch(m->m.kind.equals("DTMF")&&Math.abs(m.startMs-keyMs)<.001),"waveform duration and key markers agree with the corrected PCM");
        check(wave.markers.stream().anyMatch(m->m.kind.equals("DELAY")&&Math.abs(m.startMs-400)<.001&&Math.abs(m.endMs-1420)<.001),"arrival-delay marker spans the restored silence gap");

        RtpStream jitter=stream("jitter");for(int n=0;n<100;n++){long us=n*20000L;if(n>=20&&n<30)us+=200000;else if(n>=30&&n<40)us=780000;packet(jitter,n,us);}
        RtpTimeline stable=RtpTimeline.of(jitter);check(stable.repairs==0&&Math.abs(jitter.seconds()-2)<.000001,"temporary 200 ms network delay followed by a burst does not stretch the recording");
        for(RtpTimeline.Frame f:stable.frames)check(f.ticks==f.index*160,"normal jitter retains the sender playback rhythm");
        RtpStream dtx=stream("dtx");for(int n=0;n<100;n++){RtpPacket q=packet(dtx,n,n*20000L+(n>=20?1020000:0));if(n>=20)q.timestamp=(q.timestamp+8160)&0xffffffffL;}
        check(RtpTimeline.of(dtx).repairs==0&&Math.abs(dtx.seconds()-3.02)<.000001,"silence already represented in RTP timestamps is never added twice");
        RtpStream unreliable=stream("unreliable");for(int n=0;n<100;n++)packet(unreliable,n,n*20000L+(n>=20?1020000:0));unreliable.quality=new QualityAnalyzer.Report();unreliable.quality.reliableTimestamps=false;
        check(RtpTimeline.of(unreliable).repairs==0&&Math.abs(unreliable.seconds()-2)<.000001,"unreliable capture timestamps cannot introduce inferred silence");
        RtpStream duplicate=stream("duplicate");for(int n=0;n<100;n++){packet(duplicate,n,n*20000L+(n>=20?1020000:0));if(n==20){RtpPacket old=duplicate.packets.get(19),copy=new RtpPacket();copy.sequence=old.sequence;copy.timestamp=old.timestamp;copy.payload=old.payload;copy.timeUs=duplicate.packets.get(20).timeUs+10000;duplicate.packets.add(copy);}}
        RtpTimeline copies=RtpTimeline.of(duplicate);Set<String> identities=new HashSet<>();for(RtpTimeline.Frame f:copies.frames)identities.add(f.identity());
        check(identities.size()==100&&Math.abs(duplicate.seconds()-3.02)<.000001,"a late duplicate across the restored gap remains a duplicate, including sequence wrap");
        RtpStream shortTail=stream("short-tail");packet(shortTail,0,0);packet(shortTail,1,1020000);
        check(RtpTimeline.of(shortTail).repairs==0&&Math.abs(shortTail.seconds()-.04)<.000001,"an isolated late last packet is insufficient evidence of a paused clock");
        RtpStream opus=stream("opus");opus.codec="OPUS";opus.clock=48000;
        for(int n=0;n<100;n++){RtpPacket q=packet(opus,n,n*20000L+(n>=20?1020000:0));q.timestamp=(0xfffff000L+n*960)&0xffffffffL;q.payload=new byte[]{(byte)0xf8,(byte)0xff,(byte)0xfe};}
        File wide=new File(output,"paused-clock-opus.wav");AudioRenderer.render(Collections.singletonList(opus),wide);
        try(PcmFile pcmOpus=new PcmFile(wide)){check(pcmOpus.rate==48000&&pcmOpus.frames==144960&&Math.abs(opus.seconds()-3.02)<.000001,"paused Opus clock is restored at 48 kHz without an 8 kHz timing assumption");}
        RtpStream g729=stream("g729");g729.codec="G729";
        for(int n=0;n<160;n++){RtpPacket q=packet(g729,n,n*10000L+(n>=20?1020000:0));q.timestamp=(1000+n*80)&0xffffffffL;q.payload=new byte[10];}
        check(Math.abs(g729.seconds()-2.62)<.000001,"10 ms G729 packets retain an omitted pause without assuming 20 ms packetization");
        File directory=new File(output,"paused-clock-cache");AnalysisCache cache=new AnalysisCache(directory);String cacheKey=cache.key(new ByteArrayInputStream(new byte[]{1,2,3}));
        try(ObjectOutputStream old=new ObjectOutputStream(new FileOutputStream(new File(directory,cacheKey+".index")))){old.writeUTF("huatan-index-3");old.writeObject(new Analysis());}
        check(cache.load(cacheKey)==null,"indexes containing keypad positions from the previous audio timeline are reparsed");
        return checks;
    }
}
