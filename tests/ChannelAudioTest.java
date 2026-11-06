import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.desktop.AudioPreview;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/** Independent lane samples, capture offsets and real RTP-to-multichannel export. */
public final class ChannelAudioTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    public static int run(File fixtures,File output)throws Exception{
        List<File> sources=new ArrayList<>();float[] amplitudes={.15f,-.3f,.5f,-.7f};int[] rates={8000,16000,48000,16000};List<Double> offsets=Arrays.asList(0.0,10.5,30.0,5.0);
        for(int c=0;c<4;c++){File f=new File(output,"channel-source-"+c+".wav");float[] data=new float[rates[c]/5];Arrays.fill(data,amplitudes[c]);PcmFile.write(f,data,rates[c]);sources.add(f);}
        for(int count=1;count<=4;count++){
            File f=new File(output,"channels-"+count+".wav");PcmTracks.separate(sources.subList(0,count),offsets.subList(0,count),f);
            try(PcmFile pcm=new PcmFile(f)){
                check(pcm.channels==count,"one media direction becomes exactly one channel, including three and four directions");
                check(pcm.offset==(count<=2?44:68)&&f.length()==pcm.offset+pcm.frames*count*2,"RIFF/data sizes match actual interleaved PCM");
                for(int c=0;c<count;c++){float[] values=pcm.read(70,10,c,pcm.rate);check(Math.abs(values[0]-amplitudes[c])<.0001,"channel amplitude stays isolated and is not averaged with other directions");if(c>0){values=pcm.read(0,1,c,pcm.rate);check(values[0]==0,"capture offset becomes leading silence on the corresponding channel");}}
                if(count==4)check(pcm.rate==48000&&pcm.frames==11040,"export retains highest sample rate and original direction offsets");
            }
            byte[] bytes=Files.readAllBytes(f.toPath());check((bytes[20]&255)==(count<=2?1:254),"multi-channel WAV uses standard extensible PCM format");
        }
        File left=new File(output,"tone-left.wav"),right=new File(output,"tone-right.wav"),routed=new File(output,"listening-stereo.wav");
        for(int c=0;c<2;c++){float[] data=new float[16000];for(int i=0;i<data.length;i++)data[i]=(float)Math.sin(2*Math.PI*(c==0?440:880)*i/16000)*.5f;PcmFile.write(c==0?left:right,data,16000);}
        PcmTracks.mix(Arrays.asList(left,right),Arrays.asList(0,0),new boolean[]{true,true},true,routed);
        try(PcmFile pcm=new PcmFile(routed)){float[] l=pcm.read(0,1000,0,16000),r=pcm.read(0,1000,1,16000);double same=0,wrong=0;for(int i=0;i<l.length;i++){same+=l[i]*Math.sin(2*Math.PI*440*i/16000);wrong+=r[i]*Math.sin(2*Math.PI*440*i/16000);}check(pcm.channels==2&&same>3900&&Math.abs(wrong)<1,"stereo listening contains 440 Hz only in left channel and 880 Hz in right");}
        PcmTracks.mix(Arrays.asList(left,right),Arrays.asList(0,0),new boolean[]{false,true},true,routed);
        try(PcmFile pcm=new PcmFile(routed)){float[] l=pcm.read(0,1000,0,16000);double power=0;for(float v:l)power+=v*v;check(power==0,"independent listening mutes the correct lane without folding the other lane into it");}
        File rejected=new File(output,"channel-cancel.wav");Thread.currentThread().interrupt();try{PcmTracks.separate(sources,offsets,rejected);throw new AssertionError("export cancellation ignored");}catch(InterruptedIOException expected){check(!rejected.exists(),"cancelled export removes incomplete WAV");}finally{Thread.interrupted();}
        try{PcmTracks.separate(sources,Arrays.asList(0,0,Double.NaN,0),rejected);throw new AssertionError("NaN offset accepted");}catch(IOException expected){check(!rejected.exists(),"invalid offsets cannot create misleading audio");}
        Analysis demo;try(InputStream in=new FileInputStream(new File(fixtures,"demo-analysis.pcap"))){demo=CaptureEngine.read(in);}
        List<RtpStream> streams=new ArrayList<>();for(RtpStream stream:demo.streams)if(stream.playable())streams.add(stream);
        File mixed=new File(output,"channel-preview-mixed.wav"),export=new File(output,"rtp-channels-2.wav");
        try(AudioPreview preview=AudioPreview.render(streams,demo.events,mixed)){preview.exportWav(export);try(PcmFile pcm=new PcmFile(export)){check(preview.tracks.size()==2&&pcm.channels==2,"player export uses direction tracks rather than its mono playback mix");for(int c=0;c<2;c++)try(PcmFile direction=new PcmFile(preview.tracks.get(c).audio)){long at=Math.round(preview.tracks.get(c).offsetMs*pcm.rate/1000);float[] lane=pcm.readFrames(at,300,c,pcm.rate),original=direction.readFrames(0,300,-1,pcm.rate);double difference=0;for(int n=0;n<Math.min(lane.length,original.length);n++)difference+=Math.abs(lane[n]-original[n]);check(difference<.03,"exported channel maps to the matching original RTP direction");}}}
        RtpStream third=new RtpStream(),source=streams.get(0);third.src="192.0.2.99:12000";third.dst=source.dst;third.codec=source.codec;third.clock=source.clock;third.clockKnown=source.clockKnown;third.packets.addAll(source.packets);streams.add(third);
        try(AudioPreview preview=AudioPreview.render(streams,demo.events,mixed)){preview.exportWav(new File(output,"rtp-channels-3.wav"));try(PcmFile pcm=new PcmFile(new File(output,"rtp-channels-3.wav"))){check(pcm.channels==3&&preview.tracks.size()==3,"three real media directions are not folded into two output channels");}}
        check(PcmFile.channelName(4,2).equals("声道 3")&&PcmFile.channelName(2,1).equals("右声道"),"reimported multi-channel audio keeps distinct channel labels");
        return checks;
    }
}
