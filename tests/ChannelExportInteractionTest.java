package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import javax.swing.*;
import java.io.*;
import java.nio.file.*;
import java.lang.reflect.Field;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/** Exercise the export action used after the native save dialog, including a failed overwrite. */
public final class ChannelExportInteractionTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    private static void set(Object target,String name,Object value)throws Exception{Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);f.set(target,value);}
    private static void idle(DesktopApp app)throws Exception{long until=System.nanoTime()+20_000_000_000L;AtomicReference<Boolean> busy=new AtomicReference<>(true);while(System.nanoTime()<until){SwingUtilities.invokeAndWait(()->busy.set(app.isBusy()));if(!busy.get())return;Thread.sleep(25);}throw new AssertionError("Desktop audio export task timed out");}
    public static int run(File fixtures,File output)throws Exception{
        Analysis demo;try(InputStream in=new FileInputStream(new File(fixtures,"demo-analysis.pcap"))){demo=CaptureEngine.read(in);}
        List<RtpStream> streams=new ArrayList<>();for(RtpStream s:demo.streams)if(s.playable())streams.add(s);
        AtomicReference<DesktopApp> ref=new AtomicReference<>();File dir=Files.createTempDirectory(output.toPath(),"channel-export-ui-").toFile();
        SwingUtilities.invokeAndWait(()->{DesktopApp app=new DesktopApp();ref.set(app);app.acceptAnalysis(demo,"synthetic export test");app.previewAudio(streams);});DesktopApp app=ref.get();
        try{
            idle(app);File mixed=app.renderedFile();byte[] original=Files.readAllBytes(mixed.toPath());try(PcmFile pcm=new PcmFile(mixed)){check(pcm.channels==1,"playback source remains a mono mix, so export must use the independent tracks");}
            File destination=new File(dir,"one-file.wav");SwingUtilities.invokeAndWait(()->app.exportWav(destination));idle(app);
            try(PcmFile pcm=new PcmFile(destination)){check(pcm.channels==2,"actual desktop export action produces two independent channels");check(Math.abs(pcm.durationMs()-app.waveform.preview().mixed.durationMs())<1,"export preserves source capture-time alignment and duration");}
            check(dir.list().length==1,"desktop action exports exactly one WAV file");byte[] separated=Files.readAllBytes(destination.toPath());
            File muted=new File(output,"ui-muted-listening.wav");PcmFile.write(muted,new float[8000],8000);
            SwingUtilities.invokeAndWait(()->{try{set(app,"routedWav",muted);set(app,"audible",new boolean[]{false,false});set(app,"playbackSpeed",2f);app.exportWav(destination);}catch(Exception e){throw new RuntimeException(e);}});idle(app);
            check(Arrays.equals(separated,Files.readAllBytes(destination.toPath())),"listening mute and playback speed do not alter exported source channels");check(Arrays.equals(original,Files.readAllBytes(mixed.toPath())),"export does not rewrite the rendered source WAV");
            File protectedFile=new File(dir,"preserve-existing.wav");byte[] marker="previous output must survive failure".getBytes("UTF-8");Files.write(protectedFile.toPath(),marker);AudioPreview.Track first=app.waveform.preview().tracks.get(0);File valid=first.audio;
            try{SwingUtilities.invokeAndWait(()->{first.audio=new File(dir,"missing-source.wav");app.exportWav(protectedFile);});idle(app);check(Arrays.equals(marker,Files.readAllBytes(protectedFile.toPath())),"failed export preserves an existing destination");check(Arrays.stream(dir.listFiles()).noneMatch(f->f.getName().endsWith(".part")),"failed export cleans temporary output");}
            finally{SwingUtilities.invokeAndWait(()->first.audio=valid);}
        }finally{SwingUtilities.invokeAndWait(app::shutdown);}
        return checks;
    }
}
