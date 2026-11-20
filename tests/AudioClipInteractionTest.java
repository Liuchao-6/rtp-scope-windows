package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/** Real excerpt-editor saves for RTP and imported MP3 without an ASR model or audio device. */
public final class AudioClipInteractionTest {
    private static int checks;
    private static void check(boolean ok,String text){checks++;if(!ok)throw new AssertionError(text);}
    private static Object field(Object target,String name)throws Exception{Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(target);}
    private static JButton find(Container root,String name){for(Component c:root.getComponents()){if(c instanceof JButton&&name.equals(c.getName()))return (JButton)c;if(c instanceof Container){JButton found=find((Container)c,name);if(found!=null)return found;}}return null;}
    private static void layout(Container root){root.doLayout();for(Component c:root.getComponents())if(c instanceof Container)layout((Container)c);}
    private static void image(JComponent panel,File target)throws Exception{layout(panel);layout(panel);BufferedImage image=new BufferedImage(panel.getWidth(),panel.getHeight(),BufferedImage.TYPE_INT_RGB);Graphics2D g=image.createGraphics();panel.printAll(g);g.dispose();javax.imageio.ImageIO.write(image,"png",target);}
    private static void idle(AudioClipPanel panel)throws Exception{long until=System.nanoTime()+20_000_000_000L;while(System.nanoTime()<until){AtomicReference<Boolean> ready=new AtomicReference<>();SwingUtilities.invokeAndWait(()->ready.set(panel.finished()&&(panel.statusText().startsWith("片段已保存")||panel.statusText().startsWith("保存未完成"))));if(ready.get())return;Thread.sleep(25);}throw new AssertionError("excerpt editor task timed out");}
    private static byte[] samples(File file)throws Exception{try(PcmFile pcm=new PcmFile(file);RandomAccessFile in=new RandomAccessFile(file,"r")){in.seek(pcm.offset);byte[] bytes=new byte[(int)(pcm.frames*pcm.channels*pcm.bits/8)];in.readFully(bytes);return bytes;}}
    public static int run(File fixtures,File output)throws Exception{
        File dir=new File(output,"audio-clip-ui");dir.mkdirs();Analysis demo;try(InputStream in=new FileInputStream(new File(fixtures,"demo-analysis.pcap"))){demo=CaptureEngine.read(in);}
        List<RtpStream> streams=new ArrayList<>();for(RtpStream stream:demo.streams)if(stream.playable())streams.add(stream);
        File mixed=new File(dir,"rtp-mixed.wav"),full=new File(dir,"full.wav"),target=new File(dir,"rtp-excerpt.wav"),reference=new File(dir,"reference.wav");
        try(AudioPreview preview=AudioPreview.render(streams,demo.events,mixed)){
            preview.exportWav(full);AtomicReference<AudioClipPanel> ref=new AtomicReference<>();
            SwingUtilities.invokeAndWait(()->{try{Ui.setup();ref.set(new AudioClipPanel(preview,mixed,false,"RTP 双向通话演示",0,preview.mixed.durationMs()));}catch(IOException e){throw new RuntimeException(e);}});AudioClipPanel panel=ref.get();
            try{
                double end=Math.min(700,preview.mixed.durationMs());SwingUtilities.invokeAndWait(()->{panel.setRange(100,end);panel.saveSelection(target);});idle(panel);AudioClip.save(full,reference,100,end);
                check(Arrays.equals(samples(target),samples(reference)),"actual RTP editor action retains every directional channel and original timeline interval");try(PcmFile pcm=new PcmFile(target)){check(pcm.channels==preview.tracks.size(),"RTP excerpt stays in one WAV with one channel per media direction");}
                SwingUtilities.invokeAndWait(()->{try{panel.setSize(960,560);image(panel,new File(output,"windows-audio-clip-rtp.png"));panel.setSize(820,480);image(panel,new File(output,"windows-audio-clip-compact.png"));check(panel.save.getBounds().width>0&&panel.save.isEnabled(),"save action is visible and available at compact width");panel.waveform.setSize(790,panel.waveform.getPreferredSize().height);panel.waveform.zoomBy(2);double from=panel.waveform.timeAt(100),to=panel.waveform.timeAt(450);panel.waveform.dispatchEvent(new MouseEvent(panel.waveform,MouseEvent.MOUSE_PRESSED,0,0,100,70,1,false,MouseEvent.BUTTON1));panel.waveform.dispatchEvent(new MouseEvent(panel.waveform,MouseEvent.MOUSE_DRAGGED,0,InputEvent.BUTTON1_DOWN_MASK,450,70,0,false,MouseEvent.NOBUTTON));panel.waveform.dispatchEvent(new MouseEvent(panel.waveform,MouseEvent.MOUSE_RELEASED,0,0,450,70,1,false,MouseEvent.BUTTON1));check(Math.abs(((Number)panel.start.getValue()).doubleValue()*1000-from)<.001&&Math.abs(((Number)panel.end.getValue()).doubleValue()*1000-to)<.001,"drag selection uses zoomed timeline and updates start/end controls");panel.setRange(300,200);check(!panel.save.isEnabled()&&!panel.listen.isEnabled(),"reversed range disables save and preview");panel.setRange(100,end);panel.saveSelection(mixed);}catch(Exception e){throw new RuntimeException(e);}});idle(panel);check(panel.statusText().contains("不能覆盖原音频"),"editor rejects overwriting its playback source");
            }finally{SwingUtilities.invokeAndWait(panel::close);}
        }
        NativeMedia.install();File mp3=new File(dir,"imported-stereo.mp3"),prepared=new File(dir,"imported-prepared.wav");NativeMedia.run(Arrays.asList("-i",full.getAbsolutePath(),"-c:a","libmp3lame",mp3.getAbsolutePath()));byte[] original=Files.readAllBytes(mp3.toPath());NativeMedia.recording(mp3,prepared);
        try(AudioPreview preview=AudioPreview.recording(prepared)){
            AtomicReference<AudioClipPanel> ref=new AtomicReference<>();SwingUtilities.invokeAndWait(()->{try{ref.set(new AudioClipPanel(preview,prepared,true,"单独导入的录音.mp3",50,450));}catch(IOException e){throw new RuntimeException(e);}});AudioClipPanel panel=ref.get();
            try{SwingUtilities.invokeAndWait(()->panel.saveSelection(target));idle(panel);AudioClip.save(prepared,reference,50,450);check(Arrays.equals(samples(target),samples(reference)),"imported MP3 excerpt saves decoded source channels directly, without waveform downsampling or an ASR model");try(PcmFile pcm=new PcmFile(target);PcmFile input=new PcmFile(prepared)){check(pcm.rate==input.rate&&pcm.channels==input.channels&&pcm.frames==Math.round(.4*input.rate),"recording editor preserves sample rate, channel count and selected duration");}SwingUtilities.invokeAndWait(()->{try{panel.setSize(960,560);image(panel,new File(output,"windows-audio-clip-recording.png"));}catch(Exception e){throw new RuntimeException(e);}});}finally{SwingUtilities.invokeAndWait(panel::close);}
        }
        check(Arrays.equals(original,Files.readAllBytes(mp3.toPath())),"original imported recording is unchanged");
        AtomicReference<DesktopApp> app=new AtomicReference<>();AtomicReference<RecordingPanel> recordings=new AtomicReference<>();SwingUtilities.invokeAndWait(()->{DesktopApp desktop=new DesktopApp();app.set(desktop);recordings.set(new RecordingPanel());check(!find(desktop,"clipRtpAudio").isEnabled(),"RTP excerpt entry is unavailable until audio is prepared");check(!find(recordings.get(),"clipRecordingAudio").isEnabled(),"recording excerpt entry is unavailable before importing audio");desktop.acceptAnalysis(demo,"synthetic excerpt test");desktop.previewAudio(streams);recordings.get().add(mp3);});
        try{long until=System.nanoTime()+30_000_000_000L;boolean ready=false;while(System.nanoTime()<until){AtomicReference<Boolean> value=new AtomicReference<>();SwingUtilities.invokeAndWait(()->value.set(find(app.get(),"clipRtpAudio").isEnabled()&&find(recordings.get(),"clipRecordingAudio").isEnabled()));if(value.get()){ready=true;break;}Thread.sleep(30);}check(ready,"both real workspace entries become available after RTP preparation and recording import, without transcription");SwingUtilities.invokeAndWait(()->{try{app.get().setSize(1040,760);image(app.get(),new File(output,"windows-audio-clip-entry.png"));recordings.get().setSize(1040,760);image(recordings.get(),new File(output,"windows-recording-clip-entry.png"));}catch(Exception e){throw new RuntimeException(e);}});}finally{SwingUtilities.invokeAndWait(()->{recordings.get().close();app.get().shutdown();});}
        System.out.println("PASS: "+checks+" audio excerpt UI checks; RTP, imported MP3, waveform selection and save actions");return checks;
    }
    public static void main(String[] args)throws Exception{run(new File(args[0]),new File(args[1]));}
}
