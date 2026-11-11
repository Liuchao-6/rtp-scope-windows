package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

/** Open real captures and use call actions without an initial click in the call list. */
public final class DefaultCallSelectionTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static Component find(Container parent,String name){for(Component c:parent.getComponents()){if(name.equals(c.getName()))return c;if(c instanceof Container){Component found=find((Container)c,name);if(found!=null)return found;}}return null;}
    private static JButton button(Container parent,String text){for(Component c:parent.getComponents()){if(c instanceof JButton&&text.equals(((JButton)c).getText()))return (JButton)c;if(c instanceof Container){JButton found=button((Container)c,text);if(found!=null)return found;}}return null;}
    private static Object field(Object object,String name)throws Exception{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}
    private static void ready(DesktopApp app)throws Exception{
        long until=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(15);
        while(System.nanoTime()<until){final boolean[] done={false};SwingUtilities.invokeAndWait(()->done[0]=!app.isBusy()&&!app.isBackgroundWorking());if(done[0])return;Thread.sleep(20);}
        throw new AssertionError("default call import timeout");
    }
    private static void selected(DesktopApp app){
        JList<?> list=(JList<?>)find(app,"calls");String first=app.model.analysis.calls.get(0).id;
        check(list.getSelectedIndex()==0&&first.equals(app.model.callId),"opening a capture selects its first call in both UI and model");
        check(app.model.streams().stream().allMatch(s->first.equals(s.callId)),"RTP list uses the default call");
        check(button(app,"播放当前通话双向").isEnabled()&&button(app,"转写当前通话").isEnabled(),"call audio actions are ready without clicking the call list");
        try{
            JTabbedPane tabs=(JTabbedPane)find(app,"analysisTabs");tabs.setSelectedIndex(4);
            CallHealth health=(CallHealth)field(field(app,"callTools"),"health");
            check(health!=null&&first.equals(health.call.id),"health tab inspects the default call without an initial list click");tabs.setSelectedIndex(0);
        }catch(Exception e){throw new RuntimeException(e);}
    }
    public static int run(File fixtures)throws Exception{
        DesktopApp[] holder={null};AtomicReference<AudioPreview> transcript=new AtomicReference<>();
        SwingUtilities.invokeAndWait(()->{DesktopApp app=new DesktopApp();holder[0]=app;app.setTranscriptHandler(transcript::set);app.loadFiles(Arrays.asList(new File(fixtures,"demo-analysis.pcap"),new File(fixtures,"key-modes.pcap")));});
        DesktopApp app=holder[0];
        try{
            ready(app);SwingUtilities.invokeAndWait(()->{
                selected(app);check(app.renderedFile()==null&&transcript.get()==null,"default selection does not automatically play or transcribe audio");
                button(app,"转写当前通话").doClick();
            });
            ready(app);SwingUtilities.invokeAndWait(()->{
                check(transcript.get()!=null&&transcript.get().tracks.size()==2,"real transcription action prepares both audio directions of the default call");
                app.setSearch("INVITE");((JTabbedPane)find(app,"analysisTabs")).setSelectedIndex(1);app.selectCapture(1);
            });
            ready(app);SwingUtilities.invokeAndWait(()->{selected(app);button(app,"全部").doClick();check(app.model.callId.isEmpty()&&((JList<?>)find(app,"calls")).isSelectionEmpty(),"explicit all-calls choice remains available");check(!button(app,"播放当前通话双向").isEnabled()&&!button(app,"转写当前通话").isEnabled(),"all-calls view does not offer ambiguous call audio actions");app.selectCapture(0);});
            ready(app);SwingUtilities.invokeAndWait(()->{
                check(app.model.callId.equals(app.model.analysis.calls.get(0).id)&&((JList<?>)find(app,"calls")).getSelectedIndex()==0,"returning to a file restores its selected call");
                check(app.model.query.equals("INVITE")&&((JTabbedPane)find(app,"analysisTabs")).getSelectedIndex()==1,"file switching retains its packet search and page");app.selectCapture(1);
            });
            ready(app);SwingUtilities.invokeAndWait(()->{check(app.model.callId.isEmpty()&&((JList<?>)find(app,"calls")).isSelectionEmpty(),"returning to an explicit all-calls view does not select the first call again");((JButton)find(app,"closeCapture")).doClick();});
            ready(app);SwingUtilities.invokeAndWait(()->app.loadFiles(Arrays.asList(new File(fixtures,"key-modes.pcap"))));
            ready(app);SwingUtilities.invokeAndWait(()->selected(app));
        }finally{SwingUtilities.invokeAndWait(app::shutdown);}
        SwingUtilities.invokeAndWait(()->{
            DesktopApp multi=new DesktopApp();try{
                Analysis analysis=new Analysis();Call first=new Call(),second=new Call();first.id="first-call";second.id="second-call";analysis.calls.add(first);analysis.calls.add(second);
                for(Call call:analysis.calls){SipMessage message=new SipMessage();message.callId=call.id;message.firstLine="INVITE sip:1002@example.test SIP/2.0";message.raw=message.firstLine+"\r\nCall-ID: "+call.id+"\r\n\r\n";message.src="10.0.0.1:5060";message.dst="10.0.0.2:5060";message.timeUs=analysis.sip.size();analysis.sip.add(message);}
                multi.acceptAnalysis(analysis,"多通话示例");check(multi.model.callId.equals(first.id)&&((JList<?>)find(multi,"calls")).getSelectedIndex()==0,"multiple calls default to the first list entry");
                check(multi.flow.data().entries.size()==1&&multi.model.messages().get(0).callId.equals(first.id),"initial flow only contains the selected first call");
                button(multi,"全部").doClick();check(multi.model.callId.isEmpty()&&multi.flow.data().entries.size()==2&&multi.model.messages().size()==2,"All restores the full multi-call flow and SIP list");
                ((JList<?>)find(multi,"calls")).setSelectedIndex(1);multi.refreshViews();multi.setCallSearch(new CallSearch.Filter());
                check(multi.model.callId.equals(second.id)&&((JList<?>)find(multi,"calls")).getSelectedIndex()==1,"later refreshes preserve the user's second-call selection");
                multi.acceptAnalysis(new Analysis(),"无通话示例");check(multi.model.callId.isEmpty()&&((JList<?>)find(multi,"calls")).isSelectionEmpty(),"a capture without calls does not retain a stale selection");
            }finally{multi.shutdown();}
        });
        System.out.println("PASS: "+checks+" default-call checks; initial call, audio preparation, health and restored per-file views");return checks;
    }
    public static void main(String[] args)throws Exception{run(new File(args.length==0?"tests/fixtures":args[0]));}
}
