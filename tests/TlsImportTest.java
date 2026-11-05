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
        SwingUtilities.invokeAndWait(()->{holder[0]=new DesktopApp();holder[0].loadRsaKey(new File(fixtures,"rsa-synthetic-pkcs1.key"));});DesktopApp rsaApp=holder[0];
        try{
            ready(rsaApp);SwingUtilities.invokeAndWait(()->{check(rsaApp.rsaKeyCount()==1&&rsaApp.tlsKeyCount()==0&&rsaApp.captureCount()==0,"RSA private key imports independently before PCAP");rsaApp.loadFiles(Arrays.asList(new File(fixtures,"rsa-wss.pcap"),new File(fixtures,"rsa-tls12-gcm256.pcap")));});
            ready(rsaApp);SwingUtilities.invokeAndWait(()->{check(rsaApp.model.analysis.sip.size()==3,"RSA key imported first decrypts WSS after PCAP");CallSearch.Filter filter=new CallSearch.Filter();filter.caller="1001";rsaApp.setCallSearch(filter);rsaApp.loadRsaKey(new File(fixtures,"rsa-synthetic-pkcs8.der"));});
            ready(rsaApp);SwingUtilities.invokeAndWait(()->{check(rsaApp.rsaKeyCount()==1&&rsaApp.captureCount()==2,"RSA same key in different format deduplicates without capture entry");check(rsaApp.model.callSearch.caller.equals("1001")&&rsaApp.model.analysis.sip.size()==3,"RSA import preserves call filter and reanalyzes active capture");rsaApp.selectCapture(1);});
            ready(rsaApp);SwingUtilities.invokeAndWait(()->{check(rsaApp.model.analysis.sip.size()==3,"RSA key applies when switching independent PCAPs");rsaApp.clearRsaKeys();});
            ready(rsaApp);SwingUtilities.invokeAndWait(()->{check(rsaApp.rsaKeyCount()==0&&rsaApp.model.analysis.sip.isEmpty(),"clearing RSA keys removes decrypted SIP after reanalysis");rsaApp.loadRsaKey(new File(fixtures,"rsa-synthetic-pkcs1.key"));});
            ready(rsaApp);SwingUtilities.invokeAndWait(()->{check(rsaApp.model.analysis.sip.size()==3,"RSA key imported after PCAP automatically restores SIP");rsaApp.loadTlsKeyLog(new File(fixtures,"rsa-tls12-gcm256.keys"));});
            ready(rsaApp);SwingUtilities.invokeAndWait(()->{check(rsaApp.rsaKeyCount()==1&&rsaApp.tlsKeyCount()>0,"RSA private keys and NSS key logs coexist");rsaApp.clearRsaKeys();});
            ready(rsaApp);SwingUtilities.invokeAndWait(()->{check(rsaApp.model.analysis.sip.size()==3&&rsaApp.rsaKeyCount()==0,"clearing RSA retains independently imported NSS key log");rsaApp.loadRsaKey(new File(fixtures,"rsa-synthetic-wrong.key"));});
            ready(rsaApp);SwingUtilities.invokeAndWait(()->{check(rsaApp.rsaKeyCount()==1&&rsaApp.model.analysis.sip.size()==3,"key log takes priority over an unrelated RSA private key");rsaApp.clearTlsKeys();});
            ready(rsaApp);SwingUtilities.invokeAndWait(()->{check(rsaApp.tlsKeyCount()==0&&rsaApp.rsaKeyCount()==1&&rsaApp.model.analysis.sip.isEmpty(),"clearing key log retains RSA key and exposes certificate mismatch");rsaApp.loadRsaKey(new File(fixtures,"rsa-synthetic-pkcs8.key"));});
            ready(rsaApp);SwingUtilities.invokeAndWait(()->{check(rsaApp.rsaKeyCount()==2&&rsaApp.model.analysis.sip.size()==3,"appending correct RSA key restores captured SIP");JButton button=(JButton)find(rsaApp,"importTlsKeys");check(button.getText().contains("2")&&button.getToolTipText().contains("RSA 私钥 2")&&button.getToolTipText().contains("TLS key log 0"),"key action displays separate RSA and key-log counts");rsaApp.shutdown();check(rsaApp.rsaKeyCount()==0&&rsaApp.tlsKeyCount()==0,"shutdown clears both private and session key references");});
        }finally{SwingUtilities.invokeAndWait(rsaApp::shutdown);}
        return checks;
    }
}
