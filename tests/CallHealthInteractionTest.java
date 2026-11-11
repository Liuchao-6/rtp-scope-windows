package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import javax.swing.*;
import javax.swing.event.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.lang.reflect.Field;
import java.util.*;

/** Exercises the actual health links, including replacement of stale SIP/event details. */
public final class CallHealthInteractionTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    private static Object field(Object value,String name)throws Exception{Field f=value.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(value);}
    private static void click(DesktopApp app,CallHealthView report,String title){
        CallHealth health=CallHealth.inspect(app.model.analysis,app.model.callId);
        for(int n=0;n<health.findings.size();n++)if(health.findings.get(n).title.equals(title)){
            JButton button=find(report,"healthEvidence"+n);if(button==null)throw new AssertionError("Visible evidence button missing");button.doClick();
            return;
        }
        throw new AssertionError("Health link missing: "+title);
    }
    private static JButton find(Container parent,String name){for(Component child:parent.getComponents()){if(child instanceof JButton&&name.equals(child.getName()))return (JButton)child;if(child instanceof Container){JButton found=find((Container)child,name);if(found!=null)return found;}}return null;}
    private static void layout(Container c){c.doLayout();for(Component child:c.getComponents())if(child instanceof Container)layout((Container)child);}
    public static int run(File fixtures,File output)throws Exception{
        try(InputStream input=new FileInputStream(new File(fixtures,"demo-analysis.pcap"));Analysis analysis=CaptureEngine.read(input)){
            SwingUtilities.invokeAndWait(()->{
                DesktopApp app=new DesktopApp();
                try{
                    app.acceptAnalysis(analysis,"合成演示 · 按键摘要检查");
                    ((JTabbedPane)field(app,"tabs")).setSelectedIndex(4);
                    CallToolsPanel tools=(CallToolsPanel)field(app,"callTools");CallHealthView report=(CallHealthView)field(tools,"report");
                    CallHealth health=CallHealth.inspect(analysis,app.model.callId);
                    check(!((JPanel)field(app,"detailRegion")).isVisible(),"overview initially gives full width to cards");
                    for(String title:new String[]{"接通状态","结束信令","接通等待"}){
                        click(app,report,title);check(app.detail.original().equals(title.equals("结束信令")?health.end.raw:health.answer.raw),"existing health evidence remains functional: "+title);
                    }
                    click(app,report,"按键");check(((JPanel)field(app,"detailRegion")).isVisible(),"evidence opens the details region");check(app.detail.original().contains("按键总数：1 次")&&app.detail.original().contains("按键 5")&&app.detail.original().contains("RFC 2833 / 4733"),"health key link opens current call summary instead of stale SIP detail");
                    check(app.detail.original().contains("时间：")&&app.detail.original().contains("方向：")&&app.detail.original().contains("持续："),"key summary includes time direction and duration");
                    JButton hide=find(app,"hideDetails");check(hide!=null,"detail region has a visible collapse control");hide.doClick();check(!((JPanel)field(app,"detailRegion")).isVisible(),"collapse returns space to overview");click(app,report,"按键");check(((JPanel)field(app,"detailRegion")).isVisible(),"evidence reopens details after manual collapse");
                    app.setSize(Ui.u(1450),Ui.u(920));layout(app);layout(app);if(report.getParent() instanceof JViewport)((JViewport)report.getParent()).setViewPosition(new Point(0,Math.max(0,report.getHeight()-report.getParent().getHeight())));
                    BufferedImage image=new BufferedImage(app.getWidth(),app.getHeight(),BufferedImage.TYPE_INT_RGB);Graphics2D g=image.createGraphics();app.printAll(g);g.dispose();javax.imageio.ImageIO.write(image,"png",new File(output,"windows-health-key-summary.png"));
                    java.util.List<DtmfParser.Event> saved=new ArrayList<>(analysis.events);
                    try{
                        analysis.events.clear();tools.refresh();app.openEntry(health.answer);click(app,report,"按键");
                        check(app.detail.original().contains("按键总数：0 次")&&app.detail.original().contains("当前通话未检测到按键"),"empty key summary replaces the prior detail");
                        check(!app.detail.original().contains(health.answer.raw),"empty summary does not leave stale SIP content");
                    }finally{analysis.events.addAll(saved);}
                }catch(Exception e){throw new RuntimeException(e);}finally{app.shutdown();}
            });
        }
        return checks;
    }
}
