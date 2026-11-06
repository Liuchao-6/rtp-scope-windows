import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.Files;
import java.util.*;

/** Clock restart recovery and independent artifact failures, without private capture data. */
public final class RtpRecoveryTest {
    private static int checks;
    private static void check(boolean value,String name){checks++;if(!value)throw new AssertionError(name);}
    private static RtpStream stream(String direction){RtpStream s=new RtpStream();s.codec="PCMA";s.clock=8000;s.clockKnown=true;s.src=direction;s.dst="198.51.100.1:20000";s.callId="recovery-call";return s;}
    private static void packet(RtpStream s,int sequence,long timestamp,long us){RtpPacket p=new RtpPacket();p.sequence=sequence;p.timestamp=timestamp&0xffffffffL;p.timeUs=us;p.payload=new byte[160];Arrays.fill(p.payload,(byte)0xd5);s.packets.add(p);}
    private static int sample(byte[] b,int n){int at=44+2*n;return (short)((b[at]&255)|(b[at+1]<<8));}
    public static int run(File output)throws Exception{
        RtpStream jump=stream("192.0.2.1:10000");packet(jump,28935,14880,0);packet(jump,28936,776311752,660000);packet(jump,28937,776311912,680000);
        check(Math.abs(jump.seconds()-.7)<.000001,"forward clock restart follows 660 ms capture gap rather than 27 hour RTP span");
        File wav=new File(output,"timestamp-recovered.wav");AudioRenderer.render(Collections.singletonList(jump),wav);byte[] bytes=Files.readAllBytes(wav.toPath());
        check(bytes.length==44+5600*2&&sample(bytes,0)==8&&sample(bytes,159)==8&&sample(bytes,160)==0&&sample(bytes,5279)==0&&sample(bytes,5280)==8&&sample(bytes,5599)==8,"recovered PCM retains both segments and actual silence gap");
        QualityAnalyzer.Report quality=QualityAnalyzer.analyze(Collections.singletonList(jump),true);jump.quality=quality;
        check(quality.timestampResets==1&&quality.lost==0&&quality.delayCount==0&&quality.maxJitterMs<1,"timestamp restart is visible without becoming loss or hours of jitter");
        WaveformData wave=WaveformData.load(wav,Collections.singletonList(jump));check(wave.markers.stream().anyMatch(m->m.kind.equals("TIMESTAMP")&&Math.abs(m.startMs-660)<.001),"waveform marks clock recovery at the repaired audio location");
        DtmfParser.Event e=new DtmfParser.Event();e.src=jump.src;e.dst=jump.dst;e.ssrc=jump.ssrc;e.clock=8000;e.timestamp=776311832;e.firstSeenUs=690000;e.durationTicks=80;e.key="5";
        wave.addEvents(Collections.singletonList(e),Collections.singletonList(jump));check(wave.markers.stream().anyMatch(m->m.kind.equals("DTMF")&&Math.abs(m.startMs-670)<.001),"2833 key uses the correct clock segment after reset");
        RtpStream back=stream("192.0.2.2:10000");packet(back,28815,321024184,0);packet(back,28816,463840,180000);check(Math.abs(back.seconds()-.2)<.000001,"last-packet backward restart does not require a future packet to recover");
        AudioRenderer.render(Arrays.asList(jump,back),wav);check(wav.length()==44+5600*2,"duplex playback uses recovered clock spans");
        RtpStream wrap=stream("wrap");packet(wrap,65534,0xffffffa0L,0);packet(wrap,0,224,40000);packet(wrap,65535,64,50000);packet(wrap,0,224,60000);packet(wrap,1,384,70000);
        check(RtpTimeline.of(wrap).repairs==0&&Math.abs(wrap.seconds()-.08)<.000001,"sequence/timestamp wrap, reorder and duplicates remain normal");AudioRenderer.render(Collections.singletonList(wrap),wav);check(wav.length()==44+640*2,"normal wrapped/reordered packets retain original duration");
        RtpStream badDuplicate=stream("duplicate");packet(badDuplicate,1,1000,0);packet(badDuplicate,1,700000000,10000);packet(badDuplicate,2,1160,20000);check(Math.abs(badDuplicate.seconds()-.04)<.000001,"corrupt duplicate timestamp cannot inflate the audio span");
        RtpStream silence=stream("silence");packet(silence,1,1000,0);packet(silence,2,1000+8000*120,120000000);check(RtpTimeline.of(silence).repairs==0&&Math.abs(silence.seconds()-120.02)<.000001,"legitimate DTX silence matching capture time is preserved");
        RtpStream corrupt=stream("isolated");packet(corrupt,1,1000,0);packet(corrupt,2,700000000,20000);packet(corrupt,3,1320,40000);check(Math.abs(corrupt.seconds()-.06)<.000001&&RtpTimeline.of(corrupt).repairs==2,"isolated bad timestamp does not discard the following valid segment");
        RtpStream tooLong=stream("too-long");packet(tooLong,1,0,0);packet(tooLong,2,8000*3601L,3601000000L);File rejected=new File(output,"recovery-rejected.wav");try{AudioRenderer.render(Collections.singletonList(tooLong),rejected);throw new AssertionError("real long recording accepted");}catch(IOException expected){check(!rejected.exists(),"real 60-minute guard still applies");}
        // Decode a dual tone after a clock restart to exercise the importer, not just playback.
        RtpStream tone=stream("tone");packet(tone,1,0,0);for(int n=0;n<6;n++){packet(tone,2+n,700000000+n*160,20000+n*20000);byte[] payload=tone.packets.get(n+1).payload;for(int i=0;i<160;i++){int value=(int)(6000*(Math.sin(2*Math.PI*770*(n*160+i)/8000.0)+Math.sin(2*Math.PI*1336*(n*160+i)/8000.0)));int best=0,error=Integer.MAX_VALUE;for(int a=0;a<256;a++){int distance=Math.abs(AudioRenderer.decode(a,true)-value);if(distance<error){error=distance;best=a;}}payload[i]=(byte)best;}}
        List<DtmfParser.Event> detected=InbandDtmf.detect(Collections.singletonList(tone),new Analysis(),new long[]{80000});check(detected.stream().anyMatch(key->key.key.equals("5")&&key.type==DtmfParser.Type.IN_BAND&&key.firstSeenUs<50000&&key.timestamp>=700000000),"in-band scan continues beyond the timestamp discontinuity");
        Analysis analysis=new Analysis();analysis.streams.add(tooLong);analysis.streams.add(jump);Call c=new Call();c.id=jump.callId;c.streams.addAll(analysis.streams);analysis.calls.add(c);
        File directory=Files.createTempDirectory(output.toPath(),"export-recovery-").toFile();CallExport.Result result=CallExport.bundle(()->{throw new IOException("synthetic input failure");},analysis,c.id,directory,true,true,true,true);
        check(result.failures.containsKey("call.pcapng")&&result.failures.containsKey("direction-1.wav"),"packet failure and first-direction failure are independently recorded");
        check(new File(directory,"direction-2.wav").isFile()&&new File(directory,"report.html").isFile()&&result.files.size()==2,"later direction and HTML still export after prior failures");
        check(!new File(directory,"direction-1.wav").exists()&&!new File(directory,"call.pcapng").exists()&&Arrays.stream(directory.listFiles()).noneMatch(f->f.getName().endsWith(".part")),"failed artifacts leave no misleading partial files");
        check(new String(Files.readAllBytes(new File(directory,"导出结果.txt").toPath()),"UTF-8").contains("失败 2 项"),"export result explains partial completion");
        File cancelled=Files.createTempDirectory(output.toPath(),"export-cancel-").toFile();Thread.currentThread().interrupt();try{CallExport.bundle(()->null,analysis,c.id,cancelled,true,true,true,true);throw new AssertionError("cancel ignored");}catch(InterruptedIOException expected){checks++;}finally{Thread.interrupted();}
        check(cancelled.listFiles().length==0,"user cancellation does not start later export tasks");
        return checks;
    }
}
