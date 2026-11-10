package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.awt.*;
import java.io.*;
import java.util.*;
import javax.swing.*;

public final class CallDiscoveryTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static Component find(Container c,String name){for(Component child:c.getComponents()){if(name.equals(child.getName()))return child;if(child instanceof Container){Component result=find((Container)child,name);if(result!=null)return result;}}return null;}
    private static void ready(DesktopApp app)throws Exception{for(int i=0;i<300;i++){final boolean[] busy={false};SwingUtilities.invokeAndWait(()->busy[0]=(app.isBusy()||app.isBackgroundWorking()));if(!busy[0])return;Thread.sleep(30);}throw new AssertionError("Import timeout");}
    public static int run(File fixtures,File out)throws Exception{
        Analysis demo;try(InputStream in=new FileInputStream(new File(fixtures,"demo-analysis.pcap"))){demo=CaptureEngine.read(in);}
        final DesktopApp[] holder={null};SwingUtilities.invokeAndWait(()->{
            DesktopApp app=new DesktopApp();holder[0]=app;app.acceptAnalysis(demo,"演示");app.setSearch("no packet matches");CallSearch.Filter f=new CallSearch.Filter();f.caller="1001";f.callee="1002";f.ip="10.0.0.2";app.setCallSearch(f);
            check(app.callCount()==1&&app.model.messages().isEmpty(),"call discovery is independent of packet search");
            ((JList<?>)find(app,"calls")).setSelectedIndex(0);check(app.model.query.isEmpty()&&app.flow.data().entries.size()==8,"choosing a call restores the complete packet timeline");
            JTextField quick=(JTextField)find(app,"callQuickSearch");quick.setText("missing");check(app.callCount()==0,"real quick-search field filters all calls");quick.setText("1002");check(app.callCount()==1,"quick-search restores matching call");
            CallFilterPanel panel=new CallFilterPanel(f);((JTextField)find(panel,"start")).setText("25:99");try{panel.value();throw new AssertionError("invalid form accepted");}catch(IllegalArgumentException expected){checks++;}
            ((JTextField)find(panel,"start")).setText("");check(panel.value().callee.equals("1002"),"structured form retains fields");app.loadFiles(Arrays.asList(new File(fixtures,"demo-analysis.pcap"),new File(fixtures,"key-modes.pcap")));
        });DesktopApp app=holder[0];
        try{
            ready(app);final File[] cache={null};SwingUtilities.invokeAndWait(()->{cache[0]=app.model.analysis.mediaStore.file();check(cache[0].isFile(),"desktop import uses disk media cache");CallSearch.Filter f=new CallSearch.Filter();f.caller="1001";f.ip="10.0.0.2";app.setCallSearch(f);app.selectCapture(1);});
            ready(app);SwingUtilities.invokeAndWait(()->{check(!cache[0].exists(),"switching captures deletes old media cache");check(app.model.callSearch.empty(),"second capture has independent call filters");app.selectCapture(0);});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.model.callSearch.caller.equals("1001")&&app.model.callSearch.ip.equals("10.0.0.2"),"returning to capture restores structured call filter");cache[0]=app.model.analysis.mediaStore.file();});
            SwingUtilities.invokeAndWait(app::shutdown);check(!cache[0].exists(),"closing application deletes current media cache");
        }finally{SwingUtilities.invokeAndWait(app::shutdown);}
        return checks;
    }
}
