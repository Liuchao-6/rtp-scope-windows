package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import java.util.concurrent.TimeUnit;

/** Uses the real demo import and independent key loaders without modal dialogs. */
public final class DemoInteractionTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    private static void ready(DesktopApp app)throws Exception{
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(45);
        while(System.nanoTime()<until){boolean[] done={false};SwingUtilities.invokeAndWait(()->done[0]=!app.isBusy()&&!app.isBackgroundWorking());if(done[0])return;Thread.sleep(30);}
        throw new AssertionError("demo import/key analysis timeout");
    }
    public static int run()throws Exception{
        DesktopApp[] holder={null};SwingUtilities.invokeAndWait(()->{DesktopApp app=new DesktopApp();holder[0]=app;app.loadRsaKey(null);app.loadTlsKeyLog(null);check(app.rsaKeyCount()==0&&app.tlsKeyCount()==0,"demo keys unavailable outside demo capture");app.load(null);});DesktopApp app=holder[0];
        try{
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.model.analysis.calls.size()==21,"demo entry opens the complete multi-call asset");check(app.model.callId.startsWith("01-g711@"),"demo defaults to its first conversation");app.loadRsaKey(null);});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.rsaKeyCount()==1&&app.tlsKeyCount()==0&&app.model.analysis.calls.size()==22,"demo RSA loads separately and reanalyzes the current capture");check(app.model.callId.startsWith("01-g711@"),"RSA import retains call selection");app.loadTlsKeyLog(null);});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.rsaKeyCount()==1&&app.tlsKeyCount()>0&&app.model.analysis.calls.size()==23,"demo key log merges with RSA and reveals WSS");app.clearRsaKeys();});
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.rsaKeyCount()==0&&app.tlsKeyCount()>0&&app.model.analysis.calls.size()==22,"clearing RSA preserves independently imported key log");app.clearTlsKeys();});
            ready(app);SwingUtilities.invokeAndWait(()->check(app.model.analysis.calls.size()==21&&app.rsaKeyCount()==0&&app.tlsKeyCount()==0,"clearing both keys restores the encrypted demo view"));
        }finally{SwingUtilities.invokeAndWait(app::shutdown);}
        System.out.println("PASS: "+checks+" demo UI checks; bundled capture, selection and independent key loading");return checks;
    }
}
