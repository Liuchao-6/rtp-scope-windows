package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.*;
import javax.imageio.ImageIO;

public final class WaveformTest {
    private static int checks;
    private static void check(boolean condition,String text){checks++;if(!condition)throw new AssertionError(text);}
    private static Analysis read(File file)throws IOException{try(InputStream in=new FileInputStream(file)){return CaptureEngine.read(in);}}
    public static int run(File fixtures,File output)throws Exception {
        Analysis demo=read(new File(fixtures,"demo.pcap"));File mixed=new File(output,"dual-preview.wav"),reference=new File(output,"dual-reference.wav");
        AudioPreview dual=AudioPreview.render(demo.streams,demo.events,mixed);AudioRenderer.render(demo.streams,reference);
        check(Arrays.equals(Files.readAllBytes(mixed.toPath()),Files.readAllBytes(reference.toPath())),"preview retains exact existing mixed audio");
        check(dual.tracks.size()==2,"one waveform per direction");check(dual.tracks.get(0).offsetMs==0&&dual.tracks.get(1).offsetMs==1,"duplex capture-time alignment");
        for(int n=0;n<2;n++) {
            File solo=new File(output,"direction-reference-"+n+".wav");AudioRenderer.render(Collections.singletonList(demo.streams.get(n)),solo);WaveformData expected=WaveformData.load(solo,Collections.singletonList(demo.streams.get(n)));
            AudioPreview.Track actual=dual.tracks.get(n);check(Arrays.equals(actual.waveform.minimum,expected.minimum)&&Arrays.equals(actual.waveform.maximum,expected.maximum),"direction "+n+" comes from its own decoded PCM");check(actual.label.contains(demo.streams.get(n).src)&&actual.label.contains(demo.streams.get(n).dst),"direction label endpoints");check(actual.waveform!=dual.mixed,"separate directions do not reuse mixed graph");
        }
        check(!Arrays.equals(dual.tracks.get(0).waveform.maximum,dual.tracks.get(1).waveform.maximum),"the two actual signals differ");check(!WaveformPanel.trackColor(0).equals(WaveformPanel.trackColor(1)),"direction colors distinct");
        Analysis integrated=read(new File(fixtures,"demo-analysis.pcap"));List<RtpStream> audio=new ArrayList<>();for(RtpStream s:integrated.streams)if(s.playable())audio.add(s);
        AudioPreview keys=AudioPreview.render(audio,integrated.events,new File(output,"keys-duplex.wav"));check(keys.keys.size()==1&&keys.keys.get(0).value.equals("5"),"parsed key retained in duplex preview");check(keys.keys.get(0).track==0&&keys.keys.get(0).event==integrated.events.get(0),"key retains direction and original event");check(keys.keys.get(0).durationMs==80,"key duration preserved");
        AudioPreview reverse=AudioPreview.render(Collections.singletonList(audio.get(1)),integrated.events,new File(output,"keys-reverse.wav"));check(reverse.keys.isEmpty(),"opposite direction does not inherit key");
        Analysis modes=read(new File(fixtures,"key-modes.pcap"));List<RtpStream> media=new ArrayList<>();for(RtpStream s:modes.streams)if(s.playable())media.add(s);AudioPreview typed=AudioPreview.render(media,modes.events,new File(output,"typed-desktop.wav"));check(typed.keys.size()==37,"all key types reach both directional waveforms");
        AtomicReference<Throwable> failure=new AtomicReference<>();
        SwingUtilities.invokeAndWait(()->{try {
            WaveformData longCall=new WaveformData();longCall.samples=137*8000;longCall.rate=8000;longCall.minimum=new short[1000];longCall.maximum=new short[1000];Arrays.fill(longCall.minimum,(short)-4500);Arrays.fill(longCall.maximum,(short)4500);
            for(int n=0;n<2;n++){WaveformData.Marker m=new WaveformData.Marker();m.kind="DTMF";m.label=n==0?"1":"#";m.startMs=32000+n*100;m.endMs=m.startMs+80;longCall.markers.add(m);}
            WaveformPanel panel=new WaveformPanel();panel.setSize(1000,200);panel.setData(longCall);panel.setSize(1000,panel.getPreferredSize().height);
            List<WaveformPanel.KeyBadge> badges=panel.keyBadges();check(badges.size()==2,"both subpixel-separated keys have visible labels");check(!badges.get(0).bounds.intersects(badges.get(1).bounds),"nearby keys stack without overlapping");check(badges.get(0).key.value.equals("1")&&badges.get(1).key.value.equals("#"),"key values visible as 1 and hash");
            AtomicReference<Double> seek=new AtomicReference<>();AtomicReference<AudioPreview.Key> clicked=new AtomicReference<>();panel.setSeekListener(seek::set);panel.setKeyListener(clicked::set);Rectangle first=badges.get(0).bounds;
            MouseEvent press=new MouseEvent(panel,MouseEvent.MOUSE_PRESSED,0,0,first.x+3,first.y+3,1,false);panel.dispatchEvent(press);check(seek.get()==32000&&clicked.get()==badges.get(0).key,"badge seeks exact event time rather than rounded pixel time");check(panel.getToolTipText(press).contains("按键 1")&&panel.getToolTipText(press).contains("80.0 ms"),"tooltip identifies key and duration");
            for(WaveformPanel.KeyBadge b:badges)check(b.bounds.x>=0&&b.bounds.y>=0&&b.bounds.x+b.bounds.width<=panel.getWidth()&&b.bounds.y+b.bounds.height<panel.getHeight(),"key label stays inside panel");
            BufferedImage image=new BufferedImage(panel.getWidth(),panel.getHeight(),BufferedImage.TYPE_INT_RGB);Graphics2D g=image.createGraphics();panel.printAll(g);g.dispose();ImageIO.write(image,"png",new File(output,"windows-close-keys.png"));
            panel.zoomBy(4);panel.panTo(20000);check(panel.viewport().zoom()==4&&panel.timeAt(14)==20000,"zoomed hit test uses visible start");
            check(panel.keyBadges().size()==2,"zoomed key labels remain visible");first=panel.keyBadges().get(0).bounds;panel.dispatchEvent(new MouseEvent(panel,MouseEvent.MOUSE_PRESSED,0,0,first.x+3,first.y+3,1,false));check(seek.get()==32000,"zoomed badge seeks original RTP time");
            double anchor=panel.timeAt(600);panel.dispatchEvent(new MouseWheelEvent(panel,MouseEvent.MOUSE_WHEEL,0,InputEvent.CTRL_DOWN_MASK,600,60,0,false,MouseWheelEvent.WHEEL_UNIT_SCROLL,1,-2));check(Math.abs(panel.timeAt(600)-anchor)<0.001&&panel.viewport().zoom()>4,"Ctrl wheel preserves mouse anchor");
            panel.panTo(100000);check(panel.keyBadges().isEmpty(),"offscreen keys do not stack at viewport edges");panel.revealPosition(32000);check(panel.viewport().contains(32000),"jump to key reveals its time");
            panel.setSize(1000,panel.getPreferredSize().height);image=new BufferedImage(panel.getWidth(),panel.getHeight(),BufferedImage.TYPE_INT_RGB);g=image.createGraphics();panel.printAll(g);g.dispose();ImageIO.write(image,"png",new File(output,"windows-zoom-keys.png"));
            panel.fit();check(panel.timeAt(14)==0&&panel.viewport().zoom()==1,"fit restores complete timeline");
            panel.setPreview(typed);panel.zoomBy(4);panel.panTo(200);panel.setSize(1000,panel.getPreferredSize().height);check(panel.keyBadges().stream().anyMatch(b->b.key.badgeText().contains("INFO")),"INFO badge visible in zoomed waveform");check(panel.keyBadges().stream().anyMatch(b->b.key.badgeText().contains("In-band")),"inband badge visible in zoomed waveform");image=new BufferedImage(panel.getWidth(),panel.getHeight(),BufferedImage.TYPE_INT_RGB);g=image.createGraphics();panel.printAll(g);g.dispose();ImageIO.write(image,"png",new File(output,"windows-typed-zoom.png"));
            WaveformPanel.KeyBadge unknown=panel.keyBadges().stream().filter(b->b.key.event!=null&&!b.key.event.durationKnown).findFirst().get();check(panel.getToolTipText(new MouseEvent(panel,MouseEvent.MOUSE_MOVED,0,0,unknown.bounds.x+2,unknown.bounds.y+2,0,false)).contains("未知"),"INFO tooltip does not invent a zero duration");
            for(SipSyntax.Kind kind:SipSyntax.Kind.values())check(contrast(Ui.syntaxColor(kind),Color.WHITE)>=4.5,"readable light theme syntax "+kind);
        }catch(Throwable e){failure.set(e);}});
        if(failure.get()!=null)throw new AssertionError("Waveform regressions",failure.get());return checks;
    }
    private static double luminance(Color c){double[] v={c.getRed()/255.0,c.getGreen()/255.0,c.getBlue()/255.0};for(int i=0;i<3;i++)v[i]=v[i]<=0.04045?v[i]/12.92:Math.pow((v[i]+0.055)/1.055,2.4);return 0.2126*v[0]+0.7152*v[1]+0.0722*v[2];}
    private static double contrast(Color a,Color b){double x=luminance(a),y=luminance(b);return (Math.max(x,y)+0.05)/(Math.min(x,y)+0.05);}
}
