package com.liuchao.rtpscope.desktop;
import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/** Real FFmpeg recording imports and AMR RTP-to-PCM bridge; no audio device playback. */
public final class NativeFeatureTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    public static int run(File output)throws Exception{
        NativeMedia.install();File source=new File(output,"native-source-stereo.wav"),left=new File(output,"native-tone-left.wav"),right=new File(output,"native-tone-right.wav");float[] tone=new float[48000];for(int n=0;n<tone.length;n++)tone[n]=(float)(.4*Math.sin(n*2*Math.PI*440/48000)*Math.pow(Math.sin(n*Math.PI/16000),2));PcmFile.write(left,tone,48000);for(int n=0;n<tone.length;n++)tone[n]=(float)(.35*Math.sin(n*2*Math.PI*660/48000)*Math.pow(Math.sin(n*Math.PI/24000),2));PcmFile.write(right,tone,48000);PcmTracks.mix(Arrays.asList(left,right),Arrays.asList(0,.5),new boolean[]{true,true},true,source);
        for(String extension:Arrays.asList("wav","mp3","m4a","aac","flac")){
            File encoded=new File(output,"recording-test."+extension),decoded=new File(output,"recording-decoded-"+extension+".wav");NativeMedia.run(Arrays.asList("-i",source.getAbsolutePath(),encoded.getAbsolutePath()));NativeMedia.recording(encoded,decoded);try(PcmFile pcm=new PcmFile(decoded)){check(pcm.channels==2&&Math.abs(pcm.durationMs()-1000.5)<120,"real "+extension+" import retains stereo and duration");}
        }
        for(boolean wide:new boolean[]{false,true}){
            RtpStream stream=new RtpStream();stream.codec=wide?"AMR-WB":"AMR";stream.clock=wide?16000:8000;stream.clockKnown=true;stream.fmtp="octet-align=1";stream.src="a";stream.dst="b";
            File storage=new File(output,wide?"reference.awb":"reference.amr");try(OutputStream out=new FileOutputStream(storage)){out.write((wide?"#!AMR-WB\n":"#!AMR\n").getBytes("US-ASCII"));for(int n=0;n<50;n++){RtpPacket p=new RtpPacket();p.sequence=n;p.timestamp=n*stream.clock/50;p.timeUs=n*20000;p.payload=new byte[wide?19:14];p.payload[0]=(byte)0xf0;p.payload[1]=4;stream.packets.add(p);for(byte[] frame:AmrPayload.frames(p.payload,wide,true))out.write(frame);}}
            File expected=new File(output,wide?"amr-wb-reference.pcm":"amr-nb-reference.pcm"),actual=new File(output,wide?"amr-wb.wav":"amr-nb.wav");NativeMedia.run(Arrays.asList("-i",storage.getAbsolutePath(),"-ac","1","-ar",String.valueOf(stream.clock),"-f","s16le",expected.getAbsolutePath()));AudioRenderer.render(Collections.singletonList(stream),actual);byte[] wav=Files.readAllBytes(actual.toPath());check(Arrays.equals(Arrays.copyOfRange(wav,44,wav.length),Files.readAllBytes(expected.toPath())),"AMR "+(wide?"WB":"NB")+" RTP output equals independent storage decode");check(wav.length==44+stream.clock*2,"AMR has 20 ms per frame");
        }
        try(InputStream in=NativeFeatureTest.class.getResourceAsStream("/demo-analysis.pcap");Analysis demo=CaptureEngine.read(in)){
            for(RtpStream stream:demo.streams)if(CodecSupport.amr(stream)){
                check(stream.playable(),"bundled AMR speech has a real native decoder");File wav=new File(output,"showcase-native-"+stream.codec+"-"+stream.ssrc+".wav");AudioRenderer.render(Collections.singletonList(stream),wav);
                try(PcmFile pcm=new PcmFile(wav)){double power=0;for(float sample:pcm.read(0,11000,-1,8000))power+=sample*sample;check(power>1&&Math.abs(pcm.durationMs()-11000)<100,"bundled "+stream.codec+" speech decodes with correct duration and audible content");}
            }
        }
        System.out.println("PASS: "+checks+" native recording and AMR checks");return checks;
    }
    public static void main(String[] args)throws Exception{run(new File(args[0]));}
}
