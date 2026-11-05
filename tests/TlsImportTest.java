package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import java.awt.*;
import java.io.*;
import java.util.*;
import javax.swing.*;

public final class TlsImportTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static Component find(Container root,String name){for(Component child:root.getComponents()){if(name.equals(child.getName()))return child;if(child instanceof Container){Component result=find((Container)child,name);if(result!=null)return result;}}return null;}
    private static void ready(DesktopApp app)throws Exception{for(int n=0;n<400;n++){boolean[] busy={false};SwingUtilities.invokeAndWait(()->busy[0]=app.isBusy());if(!busy[0])return;Thread.sleep(25);}throw new AssertionError("TLS import timeout");}
    public static int run(File fixtures)throws Exception {
        DesktopApp[] holder={null};SwingUtilities.invokeAndWait(()->{holder[0]=new DesktopApp();check(find(holder[0],"importTlsKeys") instanceof JButton,"independent TLS import action exists");holder[0].loadTlsKeyLog(new File(fixtures,"tls13-websocket.keys"));});DesktopApp app=holder[0];
        try{
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.tlsKeyCount()>0&&app.captureCount()==0,"key log imports before any PCAP and is not a capture entry");app.loadFiles(Arrays.asList(new File(fixtures,"tls13-websocket.pcap"),new File(fixtures,"tls12-gcm128.pcap")));});
            ready(app);final int[] count={0};SwingUtilities.invokeAndWait(()->{check(app.model.analysis.sip.size()==3,"previously imported key decrypts WSS after PCAP import");CallSearch.Filter filter=new CallSearch.Filter();filter.caller="1001";app.setCallSearch(filter);count[0]=app.tlsKeyCount();app.loadTlsKeyLog(new File(fixtures,"tls12-gcm128.keys"));});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.tlsKeyCount()>count[0]&&app.captureCount()==2,"later key log merges without altering PCAP file list");check(app.model.callSearch.caller.equals("1001")&&app.model.analysis.sip.size()==3,"adding keys reanalyzes active file and preserves call filters");app.selectCapture(1);});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.model.analysis.sip.size()==3,"merged keys also apply after changing captures");app.clearTlsKeys();});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.tlsKeyCount()==0&&app.model.analysis.sip.isEmpty(),"clearing keys reanalyzes capture without plaintext SIP");app.loadTlsKeyLog(new File(fixtures,"tls12-gcm128.keys"));});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.model.analysis.sip.size()==3,"key log added after PCAP restores decrypted SIP automatically");int previous=app.tlsKeyCount();app.loadTlsKeyLog(new File(fixtures,"tls12-gcm128.keys"));count[0]=previous;});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.tlsKeyCount()==count[0],"same key log can be imported again without duplicate entries");app.shutdown();check(app.tlsKeyCount()==0,"closing clears session key references");});
        }finally{SwingUtilities.invokeAndWait(app::shutdown);}
        return checks;
    }
}
