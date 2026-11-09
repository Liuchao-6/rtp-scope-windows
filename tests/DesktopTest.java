package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;

public final class DesktopTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static Analysis read(File file)throws Exception{try(InputStream in=new FileInputStream(file)){return CaptureEngine.read(in);}}
    public static void main(String[] args)throws Exception {
        File fixtures=new File(args[0]),out=new File(args[1]);Analysis demo=read(new File(fixtures,"demo-analysis.pcap"));
        DesktopModel model=new DesktopModel();model.load(demo);check(model.flow().entries.size()==8,"desktop has complete integrated ladder");
        model.query="g729";check(model.streams().size()==1&&model.streams().get(0).codec.equals("G729"),"codec filter");
        model.query="INVITE";check(!model.messages().isEmpty()&&model.events().isEmpty(),"case insensitive signal search");
        model.query="";model.callId="missing";check(model.messages().isEmpty()&&model.streams().isEmpty()&&model.events().isEmpty(),"one call filter across tabs");model.callId="";
        for(RtpStream s:demo.streams)if(s.playable())model.selected.add(s);check(model.playbackSelection().size()==2,"duplex supported codecs");
        model.selected.add(demo.streams.stream().filter(s->s.isDtmf()).findFirst().get());try{model.playbackSelection();throw new AssertionError("event is not audio");}catch(IllegalArgumentException expected){checks++;}
        model.load(demo);check(model.selected.isEmpty()&&model.query.isEmpty()&&model.callId.isEmpty(),"new file clears stale selections");
        RtpStream first=new RtpStream(),second=new RtpStream();first.codec=second.codec="PCMU";first.callId="one";second.callId="two";model.selected.add(first);model.selected.add(second);try{model.playbackSelection();throw new AssertionError("different calls mixed");}catch(IllegalArgumentException expected){checks++;}
        List<String> command=CaptureSession.command(new File("C:/Program Files/Wireshark/tshark.exe"),"3",new File(out,"测试 & output.pcapng"));
        check(command.get(0).endsWith("tshark.exe")&&command.contains("3")&&command.contains("pcapng"),"tshark arguments structured");check(command.contains(new File(out,"测试 & output.pcapng").getAbsolutePath()),"capture output path one argument");
        File captured=new File(out,"capture-tail.pcapng");Path original=new File(fixtures,"multi-section.pcapng").toPath();Files.copy(original,captured.toPath(),StandardCopyOption.REPLACE_EXISTING);long length=captured.length();
        check(CaptureSession.finishFile(captured)==0&&captured.length()==length,"complete multiple-endian sections preserved");
        try(FileOutputStream append=new FileOutputStream(captured,true)){append.write(new byte[]{6,0,0,0,64});}
        check(CaptureSession.finishFile(captured)==0&&captured.length()==length+5,"interrupted partial block header retained");
        check(read(captured).sip.size()==2&&read(captured).partial,"interrupted capture directly readable");
        Files.copy(new File(fixtures,"dynamic.pcapng").toPath(),captured.toPath(),StandardCopyOption.REPLACE_EXISTING);length=captured.length();
        try(FileOutputStream append=new FileOutputStream(captured,true)){append.write(new byte[]{6,0,0,0,64,0,0,0,0,0,0,0,1,2,3,4});}
        check(CaptureSession.finishFile(captured)==0&&captured.length()==length+16,"partial block payload retained");
        File invalid=new File(out,"not-a-capture.pcapng");byte[] bad=new byte[20];Files.write(invalid.toPath(),bad);try{CaptureSession.finishFile(invalid);throw new AssertionError("invalid capture accepted");}catch(IOException expected){checks++;check(Arrays.equals(Files.readAllBytes(invalid.toPath()),bad),"invalid file never truncated");}
        Analysis loss=read(new File(fixtures,"loss-wrap.pcap"));RtpStream lossStream=loss.streams.get(0);QualityAnalyzer.Issue issue=lossStream.quality.issues.stream().filter(i->i.kind.equals("LOSS")).findFirst().get();
        check(DesktopApp.issueMillis(issue,lossStream,loss.streams)==60,"loss timestamp maps to audio after RTP wrap");
        AtomicReference<Throwable> failure=new AtomicReference<>();
        SwingUtilities.invokeAndWait(()->{DesktopApp app=null;try {
            Ui.setup();app=new DesktopApp();app.acceptAnalysis(demo,"演示 · G.711 / G.729 / 按键 / 丢包");app.setSize(Ui.u(1450),Ui.u(920));layout(app);
            check(!app.isPlayerExpanded(),"player starts collapsed for signaling analysis");int collapsedBody=rawHeight(app.detail);
            JButton visibility=findButton(app,"playerVisibility");check(visibility!=null&&visibility.getText().equals("展开播放器"),"expand switch remains visible when collapsed");visibility.doClick();layout(app);check(app.isPlayerExpanded()&&collapsedBody-rawHeight(app.detail)>=Ui.u(80),"expansion reserves player space and collapse gives it to SIP");visibility.doClick();layout(app);check(!app.isPlayerExpanded()&&rawHeight(app.detail)==collapsedBody,"collapse button restores SIP viewing area");
            check(app.callCount()==1,"call list receives parsed call");
            check(app.flow.data().entries.size()==8,"Swing receives complete timeline");
            app.flow.dispatchEvent(new MouseEvent(app.flow,MouseEvent.MOUSE_PRESSED,0,0,Ui.u(150),Ui.u(20),1,false));
            check(app.detail.original().equals(demo.sip.get(0).raw),"arrow click opens exact SIP raw");
            check(app.detail.document().getText(0,app.detail.document().getLength()).equals(demo.sip.get(0).raw),"styled document preserves CRLF and text");
            AttributeSet attrs=app.detail.document().getCharacterElement(0).getAttributes();check(StyleConstants.getForeground(attrs).equals(Ui.syntaxColor(SipSyntax.Kind.METHOD)),"method color applied to Swing document");check(StyleConstants.isBold(attrs),"method bold applied");
            check(UIManager.getLookAndFeel().getName().contains("FlatLaf"),"modern component theme loaded");
            check(Ui.font(13).canDisplayUpTo("超哥话探 通话波形按键详情")==-1,"UI font renders Chinese labels");
            image(app,new File(out,"windows-main.png"));
            app.setSearch("G729");check(app.model.streams().size()==1&&app.flow.data().entries.stream().anyMatch(e->e.source instanceof RtpStream),"search updates rendered flow and RTP model");
            app.setSearch("");app.openEntry(demo.events.get(0));check(app.detail.original().contains("80.0 ms"),"DTMF detail duration");
            app.openEntry(demo.sip.get(0));
            File wav=new File(out,"demo-desktop.wav");List<RtpStream> audio=new ArrayList<>();for(RtpStream s:demo.streams)if(s.playable())audio.add(s);AudioRenderer.render(audio,wav);WaveformData wave=WaveformData.load(wav,audio);wave.addEvents(demo.events,audio);
            app.setPlayerExpanded(true);app.waveform.setData(wave);app.waveform.setSize(Ui.u(1200),Ui.u(100));check(app.waveform.timeAt(0)==0&&Math.abs(app.waveform.timeAt(2000)-wave.durationMs())<0.001,"waveform seek clamp");
            AtomicReference<Double> position=new AtomicReference<>();app.waveform.setSeekListener(position::set);app.waveform.dispatchEvent(new MouseEvent(app.waveform,MouseEvent.MOUSE_PRESSED,0,0,Ui.u(600),Ui.u(35),1,false));check(position.get()!=null&&position.get()>0&&position.get()<wave.durationMs(),"waveform click emits seek");
            layout(app);image(app,new File(out,"windows-waveform.png"));
            app.setSearch("no-such-packet");check(app.flow.data().entries.isEmpty(),"empty filter safe");image(app,new File(out,"windows-empty.png"));
            SipMessage unicode=new SipMessage();unicode.timeUs=1;unicode.src="[::1]:5060";unicode.dst="[::2]:9080";unicode.transport="TCP";unicode.callId="中文-id";unicode.cseq="1 INVITE";unicode.firstLine="INVITE sip:用户@test SIP/2.0";unicode.raw=unicode.firstLine+"\r\nFrom: \"中文\" <sip:用户@test>;tag=一\r\nCall-ID: 中文-id\r\n\r\n";
            app.detail.showSip(unicode);check(app.detail.document().getText(0,app.detail.document().getLength()).equals(unicode.raw),"Chinese and Unicode offsets preserved in styled SIP");
            check(new Font(StyleConstants.getFontFamily(app.detail.document().getCharacterElement(0).getAttributes()),Font.PLAIN,13).canDisplayUpTo(unicode.raw)==-1,"SIP body font renders Chinese payload");
            app.setSearch("");app.setSize(Ui.u(1040),Ui.u(720));layout(app);image(app,new File(out,"windows-compact.png"));
            Analysis partial=read(new File(fixtures,"truncated.pcap"));app.acceptAnalysis(partial,"中断抓包.pcap");check(app.callCount()>0&&app.model.analysis.partial&&app.detail.original().contains("已保留可解析的包"),"partial capture enters the desktop workflow with coverage note");
            Analysis modes=read(new File(fixtures,"key-modes.pcap"));app.acceptAnalysis(modes,"三类按键示例.pcap");
            DtmfParser.Event info=modes.events.stream().filter(e->e.type==DtmfParser.Type.SIP_INFO).findFirst().get(),inband=modes.events.stream().filter(e->e.type==DtmfParser.Type.IN_BAND).findFirst().get();
            app.openEntry(info);check(app.detail.original().contains(info.signaling.raw)&&app.detail.original().contains("类型：SIP INFO"),"INFO UI preserves original signaling and type");
            app.openEntry(inband);check(app.detail.original().contains("In-band DTMF")&&app.detail.original().contains("dBFS"),"inband UI shows measured audio type and level");app.setSearch("SIP INFO");check(app.model.events().size()==4,"type search selects INFO events");app.setSearch("");layout(app);image(app,new File(out,"windows-keymodes-detail.png"));

        }catch(Throwable e){failure.set(e);}finally{if(app!=null)app.shutdown();}});
        if(failure.get()!=null)throw new AssertionError("Swing UI regression",failure.get());
        AtomicReference<DesktopApp> preview=new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(()->{DesktopApp app=new DesktopApp();preview.set(app);app.acceptAnalysis(demo,"演示 · 双向独立波形与按键");app.setSize(Ui.u(1450),Ui.u(920));layout(app);List<RtpStream> duplex=new ArrayList<>();for(RtpStream s:demo.streams)if(s.playable())duplex.add(s);app.previewAudio(duplex);check(app.isPlayerExpanded(),"explicit audio preview expands player");findButton(app,"playerVisibility").doClick();check(!app.isPlayerExpanded(),"user can collapse while audio renders");});
            AtomicReference<Boolean> ready=new AtomicReference<>(false);
            for(int n=0;n<200;n++){SwingUtilities.invokeAndWait(()->ready.set(!preview.get().isBusy()));if(ready.get())break;Thread.sleep(50);}
            check(ready.get(),"RTP preview background task finishes");
            SwingUtilities.invokeAndWait(()->{DesktopApp app=preview.get();check(!app.isPlayerExpanded(),"background render does not reopen a manually collapsed player");layout(app);File preserved=app.renderedFile();AudioPreview graph=app.waveform.preview();app.waveform.zoomBy(4);double zoom=app.waveform.viewport().zoom();try{image(app,new File(out,"windows-player-collapsed.png"));app.setSize(Ui.u(1040),Ui.u(760));layout(app);image(app,new File(out,"windows-player-collapsed-compact.png"));}catch(IOException e){throw new RuntimeException(e);}int collapsed=rawHeight(app.detail);JButton compact=findButton(app,"compactPlayback");check(compact!=null&&compact.isVisible()&&compact.isEnabled(),"collapsed player retains playback control");findButton(app,"playerVisibility").doClick();layout(app);check(app.isPlayerExpanded()&&collapsed-rawHeight(app.detail)>=Ui.u(180),"collapsing duplex waveforms recovers substantial SIP space");check(app.renderedFile()==preserved&&app.waveform.preview()==graph&&app.waveform.viewport().zoom()==zoom,"expand retains decoded audio, independent tracks and zoom");app.waveform.fit();check(app.renderedFile()!=null&&app.renderedFile().isFile(),"RTP selection produces playable WAV");check(app.waveform.data()!=null,"RTP selection delivers decoded waveform to Swing");check(app.waveform.data().markers.stream().anyMatch(m->m.kind.equals("LOSS")),"UI waveform loss marker");check(app.waveform.data().markers.stream().anyMatch(m->m.kind.equals("DELAY")),"UI waveform delay marker");check(app.waveform.data().markers.stream().anyMatch(m->m.kind.equals("DTMF")),"UI waveform key marker");check(app.waveform.preview().tracks.size()==2,"duplex UI has two independent tracks");check(app.waveformKeySummary().contains("5"),"key visible in persistent player summary");layout(app);WaveformPanel.KeyBadge badge=app.waveform.keyBadges().get(0);app.waveform.dispatchEvent(new MouseEvent(app.waveform,MouseEvent.MOUSE_PRESSED,0,0,badge.bounds.x+3,badge.bounds.y+3,1,false));check(app.detail.original().contains("80.0 ms"),"key badge opens original event detail");app.openEntry(demo.sip.get(0));layout(app);try{image(app,new File(out,"windows-ready.png"));app.setSize(Ui.u(1040),Ui.u(760));layout(app);image(app,new File(out,"windows-duplex-compact.png"));}catch(IOException e){throw new RuntimeException(e);}});
            SwingUtilities.invokeAndWait(()->check(rawHeight(preview.get().detail)>=Ui.u(40),"duplex compact window retains readable SIP body area"));
        }finally{if(preview.get()!=null)SwingUtilities.invokeAndWait(()->preview.get().shutdown());}
        File diagnostic=new File(out,"diagnostics-test.txt");DesktopApp.diagnostics(diagnostic);check(new String(Files.readAllBytes(diagnostic.toPath()),"UTF-8").contains("flow=8"),"bundled diagnostic exercises decode");
        checks+=MultiCaptureTest.run(fixtures,out);
        checks+=CallDiscoveryTest.run(fixtures,out);
        checks+=CallListRefreshTest.run();
        checks+=TlsImportTest.run(fixtures);
        checks+=WaveformTest.run(fixtures,out);
        checks+=WorkbenchTest.run(fixtures,out);
        checks+=CallHealthInteractionTest.run(fixtures,out);
        checks+=ChannelExportInteractionTest.run(fixtures,out);
        checks+=UpdateTest.run(out);
        System.out.println("PASS: "+checks+" desktop assertions; filtering, capture finalization, real Swing actions, syntax colors, waveform, diagnostic");
    }
    private static void layout(Container container){container.doLayout();for(Component child:container.getComponents())if(child instanceof Container)layout((Container)child);}
    private static JButton findButton(Container parent,String name){for(Component child:parent.getComponents()){if(child instanceof JButton&&name.equals(child.getName()))return (JButton)child;if(child instanceof Container){JButton result=findButton((Container)child,name);if(result!=null)return result;}}return null;}
    private static int rawHeight(SipDetailPanel panel){for(Component child:panel.getComponents())if(child instanceof JScrollPane)return ((JScrollPane)child).getViewport().getHeight();return 0;}
    private static void image(JComponent component,File file)throws IOException{BufferedImage image=new BufferedImage(component.getWidth(),component.getHeight(),BufferedImage.TYPE_INT_RGB);Graphics2D g=image.createGraphics();component.printAll(g);g.dispose();ImageIO.write(image,"png",file);}
}
