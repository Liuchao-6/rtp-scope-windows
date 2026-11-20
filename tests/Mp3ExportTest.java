package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Real encoding and re-import checks, including 267 ms telephone audio and UI save actions. */
public final class Mp3ExportTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static void clean(File dir){check(Arrays.stream(dir.listFiles()).noneMatch(f->f.getName().startsWith(".huatan-")||f.getName().endsWith(".part")),"temporary WAV and encoded output are cleaned");}
    private static File decode(File mp3,File output)throws Exception{File result=new File(output,mp3.getName()+"-decoded.wav");NativeMedia.recording(mp3,result);return result;}
    private static void compare(File original,File decoded)throws Exception{
        try(PcmFile a=new PcmFile(original);PcmFile b=new PcmFile(decoded)){
            check(a.channels==b.channels,"MP3 preserves mono/stereo channel count");check(a.rate==b.rate,"supported sample rate is retained");
            check(Math.abs(a.frames-b.frames)<=1,"gapless re-import preserves the selected sample count");
            for(int c=0;c<a.channels;c++){
                int size=(int)Math.min(a.frames,48000);float[] x=a.readFrames(0,size,c,a.rate),y=b.readFrames(0,size,c,b.rate);double xy=0,xx=0,yy=0;
                for(int i=0;i<Math.min(x.length,y.length);i++){xy+=x[i]*y[i];xx+=x[i]*x[i];yy+=y[i]*y[i];}
                check(xy/Math.sqrt(xx*yy)>.93,"decoded channel stays aligned with the same source direction");
            }
        }
    }
    private static void idle(AudioClipPanel panel)throws Exception{long until=System.nanoTime()+20_000_000_000L;while(System.nanoTime()<until){AtomicReference<Boolean> ready=new AtomicReference<>();SwingUtilities.invokeAndWait(()->ready.set(panel.finished()&&(panel.statusText().startsWith("片段已保存")||panel.statusText().startsWith("保存未完成"))));if(ready.get())return;Thread.sleep(25);}throw new AssertionError("excerpt export timed out");}
    private static void idle(DesktopApp app)throws Exception{long until=System.nanoTime()+20_000_000_000L;while(System.nanoTime()<until){AtomicReference<Boolean> ready=new AtomicReference<>();SwingUtilities.invokeAndWait(()->ready.set(!app.isBusy()));if(ready.get())return;Thread.sleep(25);}throw new AssertionError("player export timed out");}
    private static File tone(File dir,int rate,int channels)throws Exception{
        File first=new File(dir,"tone-"+rate+"-left.wav"),second=new File(dir,"tone-"+rate+"-right.wav"),source=new File(dir,"tone-"+rate+"-"+channels+"ch.wav");
        float[] x=new float[(int)Math.round(.267*rate)],y=new float[x.length];
        for(int i=0;i<x.length;i++){x[i]=(float)(.4*Math.sin(2*Math.PI*440*i/rate));y[i]=(float)(.35*Math.sin(2*Math.PI*697*i/rate));}
        PcmFile.write(first,x,rate);PcmFile.write(second,y,rate);
        List<File> files=new ArrayList<>();List<Double> offsets=new ArrayList<>();for(int c=0;c<channels;c++){files.add(c%2==0?first:second);offsets.add(0.0);}PcmTracks.separate(files,offsets,source);return source;
    }
    private static void layout(Container parent){parent.doLayout();for(Component c:parent.getComponents())if(c instanceof Container)layout((Container)c);}
    public static int run(File fixtures,File output)throws Exception{
        File dir=new File(output,"mp3-export");dir.mkdirs();NativeMedia.install();
        for(int rate:new int[]{8000,16000,44100,48000})for(int channels:new int[]{1,2}){
            File source=tone(dir,rate,channels),target=new File(dir,"encoded-"+rate+"-"+channels+"ch.mp3");byte[] input=Files.readAllBytes(source.toPath());
            AudioExport.save(target,AudioExport.Format.MP3,wav->Files.copy(source.toPath(),wav.toPath(),StandardCopyOption.REPLACE_EXISTING),NativeMedia::encodeMp3);
            String bytes=new String(Files.readAllBytes(target.toPath()),"ISO-8859-1");check(bytes.contains("Xing")||bytes.contains("Info"),"seekable output contains delay/padding metadata");
            compare(source,decode(target,dir));check(Arrays.equals(input,Files.readAllBytes(source.toPath())),"MP3 export leaves its WAV source unchanged");clean(dir);
        }
        File source=tone(dir,8000,1),protectedFile=new File(dir,"existing.mp3");byte[] old="existing audio".getBytes("UTF-8");Files.write(protectedFile.toPath(),old);
        AudioClip.Writer copy=wav->Files.copy(source.toPath(),wav.toPath(),StandardCopyOption.REPLACE_EXISTING);
        for(int mode=0;mode<4;mode++){
            final int selected=mode;
            try{if(mode==0)Thread.currentThread().interrupt();AudioExport.save(protectedFile,AudioExport.Format.MP3,copy,mode==1?null:(wav,target)->{Files.write(target.toPath(),new byte[]{1,2});if(selected==2)throw new IOException("synthetic encoding failure");Thread.currentThread().interrupt();});throw new AssertionError("invalid export was accepted");}
            catch(IOException expected){Thread.interrupted();check(Arrays.equals(old,Files.readAllBytes(protectedFile.toPath())),"cancelled, unavailable or failed encoder preserves an existing target");}
            finally{Thread.interrupted();}clean(dir);
        }
        File multichannel=tone(dir,8000,3);
        try{AudioExport.save(protectedFile,AudioExport.Format.MP3,wav->Files.copy(multichannel.toPath(),wav.toPath(),StandardCopyOption.REPLACE_EXISTING),NativeMedia::encodeMp3);throw new AssertionError("three channels silently downmixed");}catch(IOException expected){check(expected.getMessage().contains("两个声道"),"multi-channel MP3 is explicitly rejected");check(Arrays.equals(old,Files.readAllBytes(protectedFile.toPath())),"rejected multichannel export leaves existing audio intact");}clean(dir);
        SwingUtilities.invokeAndWait(()->{
            JFileChooser chooser=AudioSaveDialog.chooser("音频导出","example",2);check(chooser.getChoosableFileFilters().length==2,"player and clip save chooser offers WAV and MP3");
            chooser.setFileFilter(chooser.getChoosableFileFilters()[1]);check(chooser.getSelectedFile().getName().equals("example.mp3"),"switching format changes the default filename extension");
            chooser.setSelectedFile(new File("without-extension"));check(AudioSaveDialog.destination(chooser).getName().equals("without-extension.mp3"),"extensionless MP3 destination uses the chosen format");
            chooser.setSelectedFile(new File("explicit.WAV"));check(AudioSaveDialog.destination(chooser).getName().equals("explicit.WAV"),"explicit supported extension is respected");
            chooser.setFileFilter(chooser.getChoosableFileFilters()[0]);check(chooser.getSelectedFile().getName().equals("explicit.wav"),"switching back avoids a double extension");
            check(AudioSaveDialog.chooser("多声道","example",3).getChoosableFileFilters().length==1,"multichannel chooser retains WAV without silently merging directions");
        });
        try(AudioPreview preview=AudioPreview.recording(source)){
            AtomicReference<AudioClipPanel> ref=new AtomicReference<>();SwingUtilities.invokeAndWait(()->{try{ref.set(new AudioClipPanel(preview,source,true,"短录音.wav",0,267));}catch(IOException e){throw new RuntimeException(e);}});AudioClipPanel panel=ref.get();
            try{File mp3=new File(dir,"recording-clip.mp3");SwingUtilities.invokeAndWait(()->panel.saveSelection(mp3));idle(panel);compare(source,decode(mp3,dir));
                SwingUtilities.invokeAndWait(()->{try{panel.setSize(820,480);layout(panel);layout(panel);check(panel.save.getX()+panel.save.getWidth()<=panel.save.getParent().getWidth(),"format-neutral save action stays visible in the compact excerpt editor");BufferedImage image=new BufferedImage(820,480,BufferedImage.TYPE_INT_RGB);Graphics2D g=image.createGraphics();panel.printAll(g);g.dispose();javax.imageio.ImageIO.write(image,"png",new File(output,"windows-mp3-clip.png"));}catch(Exception e){throw new RuntimeException(e);}});
            }finally{SwingUtilities.invokeAndWait(panel::close);}
        }
        Analysis demo;try(InputStream in=new FileInputStream(new File(fixtures,"demo.pcap"))){demo=CaptureEngine.read(in);}
        File mixed=new File(dir,"rtp-mixed.wav"),full=new File(dir,"rtp-full.wav"),clip=new File(dir,"rtp-clip.mp3"),reference=new File(dir,"rtp-clip-reference.wav");
        try(AudioPreview preview=AudioPreview.render(demo.streams,demo.events,mixed)){
            preview.exportWav(full);AudioClip.save(full,reference,100,700);
            AtomicReference<AudioClipPanel> ref=new AtomicReference<>();SwingUtilities.invokeAndWait(()->{try{ref.set(new AudioClipPanel(preview,mixed,false,"RTP 通话",100,700));}catch(IOException e){throw new RuntimeException(e);}});AudioClipPanel panel=ref.get();
            try{SwingUtilities.invokeAndWait(()->panel.saveSelection(clip));idle(panel);compare(reference,decode(clip,dir));}finally{SwingUtilities.invokeAndWait(panel::close);}
        }
        AtomicReference<DesktopApp> ref=new AtomicReference<>();SwingUtilities.invokeAndWait(()->{DesktopApp app=new DesktopApp();ref.set(app);app.acceptAnalysis(demo,"MP3 export synthetic call");app.previewAudio(demo.streams);});DesktopApp app=ref.get();
        try{idle(app);File mp3=new File(dir,"player-full.mp3");SwingUtilities.invokeAndWait(()->app.exportWav(mp3));idle(app);compare(full,decode(mp3,dir));}finally{SwingUtilities.invokeAndWait(app::shutdown);}
        File bundleDir=Files.createTempDirectory(dir.toPath(),"bundle-").toFile();AtomicInteger attempted=new AtomicInteger();
        CallExport.Result result=CallExport.bundle(()->new FileInputStream(new File(fixtures,"demo.pcap")),demo,demo.calls.get(0).id,bundleDir,false,true,true,true,true,AudioExport.Format.MP3,(wav,target)->{if(attempted.getAndIncrement()==0)throw new IOException("synthetic first-direction failure");NativeMedia.encodeMp3(wav,target);});
        check(result.failures.containsKey("direction-1.mp3")&&result.files.size()==2,"MP3 bundle continues with later directions and HTML after one encoder failure");
        File direction=new File(bundleDir,"direction-2.mp3");check(direction.isFile()&&new File(bundleDir,"report.html").isFile(),"bundle writes the selected audio format and report");
        try(PcmFile pcm=new PcmFile(decode(direction,dir))){check(pcm.channels==1,"each call-bundle direction remains a mono file");}clean(bundleDir);clean(dir);
        System.out.println("PASS: "+checks+" MP3 export checks; gapless short audio, rates, channels, failure isolation, player and excerpt actions");return checks;
    }
    public static void main(String[] args)throws Exception{Ui.setup();run(new File(args[0]),new File(args[1]));}
}
