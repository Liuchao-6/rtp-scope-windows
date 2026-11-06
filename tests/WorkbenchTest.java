package com.liuchao.rtpscope.desktop;
import com.liuchao.rtpscope.core.*;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.util.concurrent.atomic.AtomicReference;

/** Real workspace controls, per-file settings and offscreen layouts at desktop and compact widths. */
public final class WorkbenchTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    private static String plain(Container pane){StringBuilder s=new StringBuilder();for(Component c:pane.getComponents()){if(c instanceof JLabel)s.append(((JLabel)c).getText());if(c instanceof JTextArea)s.append(((JTextArea)c).getText());if(c instanceof Container)s.append(plain((Container)c));}return s.toString();}
    private static Object field(Object target,String name)throws Exception{Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(target);}
    private static void waitFor(RecordingPanel panel)throws Exception{for(int i=0;i<300;i++){AtomicReference<Boolean> done=new AtomicReference<>();SwingUtilities.invokeAndWait(()->{try{SwingWorker<?,?> job=(SwingWorker<?,?>)field(panel,"job");done.set(job==null||job.isDone());}catch(Exception e){throw new RuntimeException(e);}});if(done.get()){SwingUtilities.invokeAndWait(()->{});Thread.sleep(80);return;}Thread.sleep(30);}throw new AssertionError("recording preparation timeout");}
    private static void layout(Container parent){parent.doLayout();for(Component c:parent.getComponents())if(c instanceof Container)layout((Container)c);}
    private static void image(JComponent component,File file)throws Exception{layout(component);layout(component);BufferedImage image=new BufferedImage(component.getWidth(),component.getHeight(),BufferedImage.TYPE_INT_RGB);Graphics2D g=image.createGraphics();component.printAll(g);g.dispose();javax.imageio.ImageIO.write(image,"png",file);}
    public static int run(File fixtures,File output)throws Exception{
        AtomicReference<DesktopApp> capture=new AtomicReference<>();AtomicReference<Workbench> workbench=new AtomicReference<>();AtomicReference<RecordingPanel> recordings=new AtomicReference<>();
        try{SwingUtilities.invokeAndWait(()->{try{Ui.setup();DesktopApp app=new DesktopApp();Workbench w=new Workbench(app);capture.set(app);workbench.set(w);recordings.set((RecordingPanel)field(w,"recording"));w.setSize(Ui.u(1450),Ui.u(960));try(InputStream in=new FileInputStream(new File(fixtures,"demo-analysis.pcap"))){app.acceptAnalysis(CaptureEngine.read(in),"合成演示抓包");}app.model.callId=app.model.analysis.calls.get(0).id;JTabbedPane tabs=(JTabbedPane)field(app,"tabs");tabs.setSelectedIndex(4);CallHealthView report=(CallHealthView)field(field(app,"callTools"),"report");check(plain(report).contains("呼叫开始")&&plain(report).contains("结束方"),"call health tab shows the selected call timing and ending side");image(w,new File(output,"windows-call-health.png"));w.setSize(Ui.u(1040),Ui.u(760));image(w,new File(output,"windows-call-health-compact.png"));check(report.getWidth()==report.getParent().getWidth(),"overview cards fit compact viewport without horizontal scrolling");w.setSize(Ui.u(1450),Ui.u(960));}catch(Exception e){throw new RuntimeException(e);}});
        }catch(Exception|Error error){if(capture.get()!=null)SwingUtilities.invokeAndWait(()->{if(workbench.get()!=null)workbench.get().close();capture.get().shutdown();});throw error;}
        RecordingPanel panel=recordings.get();File first=File.createTempFile("workspace-test-one-",".wav"),second=File.createTempFile("workspace-test-two-",".wav");Files.copy(new File(output,"native-source-stereo.wav").toPath(),first.toPath(),StandardCopyOption.REPLACE_EXISTING);Files.copy(first.toPath(),second.toPath(),StandardCopyOption.REPLACE_EXISTING);
        try{
            SwingUtilities.invokeAndWait(()->panel.addPrepared(first,"演示录音一.wav","呼叫侧","应答侧"));waitFor(panel);
            SwingUtilities.invokeAndWait(()->{try{((JComboBox<?>)field(panel,"language")).setSelectedIndex(1);((JCheckBox)field(panel,"separate")).setSelected(false);panel.addPrepared(second,"演示录音二.wav","左声道","右声道");}catch(Exception e){throw new RuntimeException(e);}});waitFor(panel);
            SwingUtilities.invokeAndWait(()->{try{((JList<?>)field(panel,"files")).setSelectedIndex(0);check(((JComboBox<?>)field(panel,"language")).getSelectedIndex()==1&&!((JCheckBox)field(panel,"separate")).isSelected(),"each recording restores language and channel mode");((JComboBox<?>)field(panel,"language")).setSelectedIndex(0);((JCheckBox)field(panel,"separate")).setSelected(true);Object active=field(panel,"active");Transcript text=(Transcript)field(active,"transcript");text.segments.add(new Transcript.Segment(100,500,"呼叫侧","你好，这里是演示录音。"));text.segments.add(new Transcript.Segment(550,950,"应答侧","可以，请继续测试。"));JTextField search=(JTextField)field(panel,"search");search.setText("测试");check(((JList<?>)field(panel,"text")).getModel().getSize()==1,"recording text search filters actual result list");search.setText("");JTabbedPane tabs=(JTabbedPane)field(workbench.get(),"workspaces");tabs.setSelectedIndex(1);image(workbench.get(),new File(output,"windows-recording-workspace.png"));workbench.get().setSize(Ui.u(1040),Ui.u(760));image(workbench.get(),new File(output,"windows-recording-compact.png"));check(panel.getHeight()>Ui.u(500),"recording workspace fits compact Windows layout");}catch(Exception e){throw new RuntimeException(e);}});
        }finally{SwingUtilities.invokeAndWait(()->{workbench.get().close();capture.get().shutdown();});first.delete();second.delete();}
        return checks;
    }
}
