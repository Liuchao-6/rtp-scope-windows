package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.awt.*;
import java.io.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import javax.swing.*;

/** Hold real media reads so early Swing interaction and cancellation are deterministic. */
public final class DeferredImportTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static Object field(Object object,String name)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}
    private static Component find(Container c,String name){for(Component child:c.getComponents()){if(name.equals(child.getName()))return child;if(child instanceof Container){Component found=find((Container)child,name);if(found!=null)return found;}}return null;}
    private static void waitFor(DesktopApp app,BooleanSupplier condition)throws Exception{long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);while(System.nanoTime()<until){AtomicBoolean ready=new AtomicBoolean();SwingUtilities.invokeAndWait(()->ready.set(condition.getAsBoolean()));if(ready.get())return;Thread.sleep(20);}throw new AssertionError("staged import timeout");}
    private static DeferredCapture read(File fixtures)throws IOException{try(InputStream in=new FileInputStream(new File(fixtures,"demo-analysis.pcap"))){return CaptureEngine.readLargeSignaling(in,null,null,TlsKeyLog.empty(),TlsRsaKeys.empty());}}
    private static void start(DesktopApp app,DeferredCapture capture){try{app.acceptAnalysis(capture.signaling,"后台分析示例");Method method=DesktopApp.class.getDeclaredMethod("startMediaAnalysis",DeferredCapture.class,AnalysisCache.class,String.class);method.setAccessible(true);method.invoke(app,capture,null,null);}catch(Exception e){throw new RuntimeException(e);}}
    private static final class Gate extends AbstractList<RtpPacket>{
        final List<RtpPacket> source;final CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
        Gate(RtpStream stream){source=stream.packets;stream.packets=this;}
        public int size(){return source.size();}
        public RtpPacket get(int n){if(!SwingUtilities.isEventDispatchThread()){entered.countDown();boolean interrupted=false;for(;;)try{release.await();break;}catch(InterruptedException e){interrupted=true;}if(interrupted)Thread.currentThread().interrupt();}return source.get(n);}
    }
    public static int run(File fixtures,File output)throws Exception{
        DesktopApp[] holder={null};SwingUtilities.invokeAndWait(()->holder[0]=new DesktopApp());DesktopApp app=holder[0];
        DeferredCapture capture=read(fixtures);Gate gate=new Gate(capture.signaling.streams.get(0));
        try{
            SwingUtilities.invokeAndWait(()->start(app,capture));check(gate.entered.await(5,TimeUnit.SECONDS),"media analysis actually running while signaling is shown");
            final RtpStream selected=capture.signaling.streams.get(0);
            SwingUtilities.invokeAndWait(()->{
                check(!app.isBusy()&&app.isBackgroundWorking()&&app.isMediaPending(),"foreground import is released before media completes");
                JTextField quick=(JTextField)find(app,"callQuickSearch");check(quick.isEnabled(),"call search enabled during media analysis");quick.setText("no-such-call");check(app.callCount()==0,"real quick search works before analysis completes");quick.setText("1001");check(app.callCount()==1,"real quick search finds the desired call");
                ((JList<?>)find(app,"calls")).setSelectedIndex(0);app.setSearch("INVITE");check(!app.model.messages().isEmpty(),"SIP selection and message filter work while media is blocked");
                app.model.selected.add(selected);app.openEntry(selected);check(app.detail.original().contains("待分析")&&!app.detail.original().contains("缺少 0"),"pending quality is explicit and does not claim zero loss");check(app.renderedFile()==null&&!app.isBusy(),"incomplete media cannot start playback or a second audio scan");
                try{JTable table=(JTable)field(app,"rtpTable");app.setSearch("");check(table.getValueAt(0,7).equals("待分析"),"RTP table shows unknown quality");app.setSearch("INVITE");}catch(Exception e){throw new RuntimeException(e);}
                JTabbedPane tabs=(JTabbedPane)find(app,"analysisTabs");check(!tabs.isEnabledAt(4),"call health waits for reliable media results");tabs.setSelectedIndex(1);
                try{JTable table=(JTable)field(app,"sipTable");table.getRowSorter().toggleSortOrder(0);table.setRowSelectionInterval(0,0);}catch(Exception e){throw new RuntimeException(e);}
            });
            gate.release.countDown();waitFor(app,()->!app.isBackgroundWorking());
            SwingUtilities.invokeAndWait(()->{check(!app.isMediaPending()&&selected.quality!=null&&selected.lost==1,"completed media results fill original stream");check(app.model.selected.contains(selected)&&app.model.callId.equals(capture.signaling.calls.get(0).id),"selected call and stream identity survive background completion");check(app.model.query.equals("INVITE")&&app.model.callSearch.keyword.equals("1001")&&((JTabbedPane)find(app,"analysisTabs")).getSelectedIndex()==1,"message query, call search and page survive completion");check(((JTabbedPane)find(app,"analysisTabs")).isEnabledAt(4),"media features become available after analysis");check(app.detail.original().equals(capture.signaling.sip.get(0).raw),"background result does not replace SIP detail the user is reading");try{JTable table=(JTable)field(app,"sipTable");check(table.getSelectedRow()==0&&!table.getRowSorter().getSortKeys().isEmpty(),"background result preserves selected SIP row and sorting");}catch(Exception e){throw new RuntimeException(e);}});
        }finally{gate.release.countDown();SwingUtilities.invokeAndWait(app::shutdown);}
        check(!capture.signaling.mediaStore.file().exists(),"normal shutdown releases background media cache");

        // Cancel while a decoder is still using the cache, then immediately open another capture.
        DeferredCapture old=read(fixtures);Gate blocked=new Gate(old.signaling.streams.get(0));File oldFile=old.signaling.mediaStore.file();
        SwingUtilities.invokeAndWait(()->{holder[0]=new DesktopApp();start(holder[0],old);});DesktopApp switching=holder[0];
        try{
            check(blocked.entered.await(5,TimeUnit.SECONDS),"old worker holds a live packet lease");
            SwingUtilities.invokeAndWait(()->{((JButton)find(switching,"cancelImport")).doClick();check(!switching.isBackgroundWorking()&&switching.isMediaPending()&&!switching.isBusy(),"stop keeps signaling open and marks media incomplete");switching.setSearch("INVITE");check(!switching.model.messages().isEmpty(),"SIP remains usable after stopping media");switching.load(new File(fixtures,"key-modes.pcap"));});
            waitFor(switching,()->!switching.isBusy()&&!switching.isBackgroundWorking());check(oldFile.isFile(),"switch waits for actual old worker termination before deleting its cache");
            Analysis[] current={null};SwingUtilities.invokeAndWait(()->{current[0]=switching.model.analysis;check(current[0].events.size()==37,"new capture gets its own complete key analysis");});
            blocked.release.countDown();long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);while(oldFile.exists()&&System.nanoTime()<until)Thread.sleep(20);
            SwingUtilities.invokeAndWait(()->check(switching.model.analysis==current[0]&&switching.model.analysis.events.size()==37,"cancelled worker never applies stale media or keys to the new capture"));check(!oldFile.exists(),"old cache removed when cancelled worker actually finishes");
        }finally{blocked.release.countDown();SwingUtilities.invokeAndWait(switching::shutdown);}

        DeferredCapture closing=read(fixtures);Gate closingGate=new Gate(closing.signaling.streams.get(0));File closingFile=closing.signaling.mediaStore.file();
        SwingUtilities.invokeAndWait(()->{holder[0]=new DesktopApp();start(holder[0],closing);});DesktopApp closingApp=holder[0];
        try{check(closingGate.entered.await(5,TimeUnit.SECONDS),"shutdown test starts media worker");SwingUtilities.invokeAndWait(closingApp::shutdown);check(closingFile.exists(),"shutdown defers cache deletion until active reader exits");}
        finally{closingGate.release.countDown();SwingUtilities.invokeAndWait(closingApp::shutdown);}
        long cleanupUntil=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);while(closingFile.exists()&&System.nanoTime()<cleanupUntil)Thread.sleep(20);check(!closingFile.exists(),"shutdown task eventually releases its cache");

        DeferredCapture failed=read(fixtures);RtpStream failing=failed.signaling.streams.get(0);List<RtpPacket> source=failing.packets;
        failing.packets=new AbstractList<RtpPacket>(){public int size(){return source.size();}public RtpPacket get(int n){if(!SwingUtilities.isEventDispatchThread())throw new IllegalStateException("synthetic media read failure");return source.get(n);}};
        SwingUtilities.invokeAndWait(()->{holder[0]=new DesktopApp();start(holder[0],failed);});DesktopApp failedApp=holder[0];
        try{waitFor(failedApp,()->!failedApp.isBackgroundWorking());SwingUtilities.invokeAndWait(()->{check(failedApp.isMediaPending()&&!failedApp.isBusy(),"media failure keeps an explicit incomplete state");failedApp.setSearch("INVITE");check(!failedApp.model.messages().isEmpty(),"media failure does not discard readable signaling");});}
        finally{SwingUtilities.invokeAndWait(failedApp::shutdown);}check(!failed.signaling.mediaStore.file().exists(),"media failure releases its task lease");

        // A queued, never-started SwingWorker must release its lease when cancelled.
        CountDownLatch workers=new CountDownLatch(10),releaseWorkers=new CountDownLatch(1);List<SwingWorker<Void,Void>> blockers=new ArrayList<>();
        for(int n=0;n<10;n++){SwingWorker<Void,Void> job=new SwingWorker<Void,Void>(){protected Void doInBackground()throws Exception{workers.countDown();releaseWorkers.await();return null;}};blockers.add(job);job.execute();}
        DeferredCapture queued=read(fixtures);File queuedFile=queued.signaling.mediaStore.file();DesktopApp[] queuedApp={null};
        try{
            check(workers.await(5,TimeUnit.SECONDS),"worker pool occupied before queue cancellation");
            SwingUtilities.invokeAndWait(()->{queuedApp[0]=new DesktopApp();start(queuedApp[0],queued);((JButton)find(queuedApp[0],"cancelImport")).doClick();queuedApp[0].shutdown();});
            check(!queuedFile.exists(),"cancelling a job before start releases its packet lease");
        }finally{releaseWorkers.countDown();if(queuedApp[0]!=null)SwingUtilities.invokeAndWait(queuedApp[0]::shutdown);for(SwingWorker<Void,Void> job:blockers)job.get(5,TimeUnit.SECONDS);}
        System.out.println("PASS: "+checks+" staged-desktop checks; early search, preserved selection, stopped tasks and stale-result isolation");return checks;
    }
}
