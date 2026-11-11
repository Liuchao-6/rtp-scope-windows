package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.lang.management.ManagementFactory;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.*;
import java.util.prefs.Preferences;

/** Real Npcap tests are restricted to this test's own loopback UDP ports. */
public final class LocalCaptureTest {
    static int checks;
    static void check(boolean value,String text){checks++;if(!value)throw new AssertionError(text);}
    interface Checked {void run()throws Exception;}
    static void invalid(Checked action)throws Exception{try{action.run();throw new AssertionError("invalid filter accepted");}catch(IOException expected){checks++;}}
    static void layout(Container component){component.doLayout();for(Component c:component.getComponents())if(c instanceof Container)layout((Container)c);}
    static void screenshot(CapturePanel panel,File target,int width)throws Exception{panel.setSize(width,760);layout(panel);layout(panel);BufferedImage image=new BufferedImage(width,760,BufferedImage.TYPE_INT_RGB);Graphics2D g=image.createGraphics();panel.printAll(g);g.dispose();javax.imageio.ImageIO.write(image,"png",target);Rectangle button=SwingUtilities.convertRectangle(panel.start.getParent(),panel.start.getBounds(),panel);check(new Rectangle(0,0,width,760).contains(button),"start button stays inside workspace at width "+width);}
    static CaptureBackend.Snapshot waitState(CaptureBackend.Session s,boolean done)throws Exception{long end=System.currentTimeMillis()+15000;CaptureBackend.Snapshot last=null;while(System.currentTimeMillis()<end){try{last=s.poll();}catch(IOException transientState){}if(done?s.ended():last!=null&&(last.phase.equals("running")||last.terminal()))return last;Thread.sleep(35);}throw new AssertionError("capture state timeout: "+(last==null?"none":last.message));}
    static void send(DatagramSocket sender,int port,byte[] data,int n)throws Exception{for(int i=0;i<n;i++){sender.send(new DatagramPacket(data,data.length,InetAddress.getLoopbackAddress(),port));if(i%10==0)Thread.sleep(2);}}
    static final byte[] SIP=("OPTIONS sip:test@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-local\r\nFrom: <sip:1001@127.0.0.1>;tag=a\r\nTo: <sip:1002@127.0.0.1>\r\nCall-ID: local-capture-synthetic\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n").getBytes(StandardCharsets.UTF_8);
    public static void main(String[] args)throws Exception{
        if(args[0].equals("--parent")){Files.write(new File(args[1]).toPath(),ManagementFactory.getRuntimeMXBean().getName().split("@")[0].getBytes(StandardCharsets.UTF_8));Thread.sleep(30000);return;}
        File out=new File(args[0]);
        check(CaptureOptions.filter("",0,"",false,"").isEmpty(),"default is unrestricted");
        check(CaptureOptions.filter("192.0.2.1",1,"5060,10000-20000",false,"").equals("host 192.0.2.1 and (tcp or udp) and (port 5060 or portrange 10000-20000)"),"simple terms combine bidirectionally with AND and port OR");
        check(CaptureOptions.filter("2001:db8::/64",3,"",false,"").equals("net 2001:db8::/64 and udp"),"numeric IPv6 CIDR");
        check(CaptureOptions.filter("bad",0,"bad",true,"udp port 9999").equals("udp port 9999"),"advanced replaces simple inputs");
        for(String ip:Arrays.asList("example.com","1.2.3.999","01.2.3.4","1.2.3.4/33","::1/129","::z","1.2.3.4 or udp"))invalid(()->CaptureOptions.filter(ip,0,"",false,""));
        for(String port:Arrays.asList("0","65536","5000-1000","5060 or udp","1-2-3"))invalid(()->CaptureOptions.filter("",0,port,false,""));
        File directory=new File(out,"抓包测试 & 引号");directory.mkdirs();File one=CaptureOptions.output(directory,"a:b/网卡"),two=CaptureOptions.output(directory,"a:b/网卡");check(!one.equals(two)&&!one.getName().contains(":"),"unique Unicode filenames sanitized without overwrites");
        Map<String,String> values=new LinkedHashMap<>();values.put("version","1");values.put("message","中文 & 引号\"\n第二行");File ipc=new File(out,"capture-ipc");CaptureBackend.write(ipc,values);check(CaptureBackend.read(ipc).equals(values),"metadata round trip preserves Unicode and newlines");Files.write(ipc.toPath(),new byte[65537]);invalid(()->CaptureBackend.read(ipc));ipc.delete();
        AtomicReference<Throwable> failure=new AtomicReference<>();Preferences prefs=Preferences.userRoot().node("huatan-test-local-"+UUID.randomUUID());
        SwingUtilities.invokeAndWait(()->{CapturePanel panel=null;try{Ui.setup();panel=new CapturePanel(file->{},prefs);panel.adapters.addItem(new CaptureBackend.Adapter("synthetic","合成回环网卡","127.0.0.1","本机通信"));check(panel.start.isEnabled()&&!panel.stop.isVisible(),"idle controls");panel.advanced.doClick();check(!panel.address.isEnabled()&&panel.bpf.isEnabled(),"advanced disables overridden simple controls");panel.advanced.doClick();panel.saving.doClick();screenshot(panel,new File(out,"windows-local-capture-1040.png"),1040);screenshot(panel,new File(out,"windows-local-capture-1450.png"),1450);TrayPopup.MenuView menu=new TrayPopup.MenuView(()->{},()->{},()->{},()->values.put("stopped","yes"));menu.stop.doClick();check(values.containsKey("stopped"),"Swing tray stop callback");}catch(Throwable e){failure.set(e);}finally{if(panel!=null)panel.close();}});prefs.removeNode();if(failure.get()!=null)throw new AssertionError("local capture UI",failure.get());
        List<CaptureBackend.Adapter> found;try{found=CaptureBackend.probe();}catch(IOException e){System.out.println("SKIP: live Npcap unavailable: "+e.getMessage());System.out.println("PASS: "+checks+" local capture checks");return;}
        CaptureBackend.Adapter loop=null;for(CaptureBackend.Adapter a:found)if(a.id.toLowerCase(Locale.ROOT).contains("loopback"))loop=a;
        if(loop==null)throw new AssertionError("Npcap loopback interface missing");check(!loop.addresses.isEmpty(),"loopback metadata");
        try(DatagramSocket receiver=new DatagramSocket(new InetSocketAddress("127.0.0.1",0));DatagramSocket sender=new DatagramSocket(new InetSocketAddress("127.0.0.1",0))){
            int port=receiver.getLocalPort();String filter="host 127.0.0.1 and udp port "+port;
            File file=CaptureOptions.output(directory,"正常回环");CaptureBackend.Session s=CaptureBackend.start(loop,filter,file,128,false);
            try{check(waitState(s,false).phase.equals("running"),"native capture starts without Wireshark");try(FileInputStream held=new FileInputStream(new File(s.directory,"state"))){send(sender,port,SIP,20);Thread.sleep(750);check(s.process.isAlive(),"metadata reader does not interrupt packet capture");}s.stop();CaptureBackend.Snapshot finalState=waitState(s,true);check(finalState.phase.equals("done")&&finalState.packets>0&&file.length()>48,"stop closes nonempty PCAPNG");try(InputStream in=new FileInputStream(file);CaptureEngine.Analysis analysis=CaptureEngine.read(in)){check(!analysis.partial&&analysis.sip.size()>0&&analysis.sip.get(0).callId.equals("local-capture-synthetic"),"actual captured loopback parses as SIP");check(analysis.packets==finalState.packets,"saved packet count agrees with parser");}check(finalState.drops==null||finalState.drops>=0,"driver counters available or explicitly absent");}finally{s.stop();s.await(5000);s.cleanup();}
            File bad=CaptureOptions.output(directory,"无效过滤");s=CaptureBackend.start(loop,"udp and (((",bad,128,false);try{CaptureBackend.Snapshot failed=waitState(s,true);check(failed.phase.equals("error")&&"filter".equals(failed.values.get("kind"))&&!bad.exists(),"Npcap rejects bad BPF before creating output");}finally{s.cleanup();}
            File existing=CaptureOptions.output(directory,"已存在文件");byte[] sentinel="existing capture must survive".getBytes(StandardCharsets.UTF_8);Files.write(existing.toPath(),sentinel);s=CaptureBackend.start(loop,filter,existing,128,false);try{check(waitState(s,true).phase.equals("error")&&Arrays.equals(Files.readAllBytes(existing.toPath()),sentinel),"native writer never overwrites existing files");}finally{s.cleanup();}
            File empty=CaptureOptions.output(directory,"空文件");s=CaptureBackend.start(loop,filter,empty,128,false);try{check(waitState(s,false).phase.equals("running"),"empty capture starts");s.stop();CaptureBackend.Snapshot end=waitState(s,true);check(end.packets==0&&empty.length()==48,"no traffic stops promptly with a valid empty header");}finally{s.cleanup();}
            // A lowered helper-only limit makes the real auto-stop path economical to test.
            Path limitDir=Files.createTempDirectory(out.toPath(),"limit-session-");File limited=CaptureOptions.output(directory,"上限");Map<String,String> req=new LinkedHashMap<>();req.put("version","1");req.put("interface",loop.id);req.put("filter",filter);req.put("output",limited.getAbsolutePath());req.put("limit","1048576");req.put("parent",ManagementFactory.getRuntimeMXBean().getName().split("@")[0]);CaptureBackend.write(limitDir.resolve("request").toFile(),req);Process process=new ProcessBuilder(CaptureBackend.executable().getPath(),"--capture",limitDir.toString()).start();s=new CaptureBackend.Session(limitDir.toFile(),limited,process);
            try{check(waitState(s,false).phase.equals("running"),"limit test running");send(sender,port,new byte[16000],220);CaptureBackend.Snapshot end=waitState(s,true);check(end.phase.equals("done")&&"limit".equals(end.values.get("reason")),"size limit auto stop");check(limited.length()>=1048576&&limited.length()<1048576+SnapBound,"at most one packet beyond limit");try(InputStream in=new FileInputStream(limited);CaptureEngine.Analysis analysis=CaptureEngine.read(in)){check(!analysis.partial&&analysis.packets==end.packets,"size stop ends on complete packet block");}}finally{s.stop();s.await(5000);s.cleanup();}
            File parentPid=new File(out,"capture-parent.pid");parentPid.delete();Process parent=new ProcessBuilder(new File(System.getProperty("java.home"),"bin/java.exe").getPath(),"-cp",System.getProperty("java.class.path"),LocalCaptureTest.class.getName(),"--parent",parentPid.getAbsolutePath()).start();
            try{long deadline=System.currentTimeMillis()+10000;while(!parentPid.isFile()&&System.currentTimeMillis()<deadline)Thread.sleep(30);String pid=new String(Files.readAllBytes(parentPid.toPath()),StandardCharsets.UTF_8);Path orphanDir=Files.createTempDirectory(out.toPath(),"parent-session-");File saved=CaptureOptions.output(directory,"主程序中断");req.put("output",saved.getAbsolutePath());req.put("limit","134217728");req.put("parent",pid);CaptureBackend.write(orphanDir.resolve("request").toFile(),req);Process nativeProcess=new ProcessBuilder(CaptureBackend.executable().getPath(),"--capture",orphanDir.toString()).start();s=new CaptureBackend.Session(orphanDir.toFile(),saved,nativeProcess);
                try{check(waitState(s,false).phase.equals("running"),"parent lifecycle test running");send(sender,port,SIP,8);Thread.sleep(100);parent.destroy();check(parent.waitFor(5,java.util.concurrent.TimeUnit.SECONDS),"test parent exits");CaptureBackend.Snapshot end=waitState(s,true);check(end.phase.equals("done")&&"parent".equals(end.values.get("reason")),"parent exit stops capture without orphan process");try(InputStream in=new FileInputStream(saved);CaptureEngine.Analysis analysis=CaptureEngine.read(in)){check(!analysis.partial&&analysis.sip.size()>0,"parent exit flushes queued SIP to readable file");}}finally{s.stop();s.await(5000);s.cleanup();}
            }finally{parent.destroy();parentPid.delete();}
        }
        workspace(loop,directory,out);
        System.out.println("PASS: "+checks+" local capture checks; real Npcap loopback, SIP parsing, BPF errors, empty stop, bounded auto stop and Swing controls");
    }
    static final int SnapBound=262200;
    static Object field(Object target,String name)throws Exception{java.lang.reflect.Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(target);}
    static boolean onEdt(java.util.concurrent.Callable<Boolean> condition)throws Exception{AtomicReference<Boolean> value=new AtomicReference<>();AtomicReference<Throwable> error=new AtomicReference<>();SwingUtilities.invokeAndWait(()->{try{value.set(condition.call());}catch(Throwable e){error.set(e);}});if(error.get()!=null)throw new AssertionError(error.get());return value.get();}
    static void awaitEdt(java.util.concurrent.Callable<Boolean> condition)throws Exception{long deadline=System.currentTimeMillis()+20000;while(System.currentTimeMillis()<deadline){if(onEdt(condition))return;Thread.sleep(40);}throw new AssertionError("workspace condition timeout");}
    static void workspace(CaptureBackend.Adapter loop,File directory,File out)throws Exception{
        Preferences prefs=Preferences.userRoot().node("huatan-workspace-test-"+UUID.randomUUID());prefs.put("folder",directory.getAbsolutePath());
        AtomicReference<Workbench> w=new AtomicReference<>();AtomicReference<DesktopApp> app=new AtomicReference<>();AtomicReference<CapturePanel> panel=new AtomicReference<>();AtomicReference<JTabbedPane> tabs=new AtomicReference<>();
        try(DatagramSocket receiver=new DatagramSocket(new InetSocketAddress("127.0.0.1",0));DatagramSocket sender=new DatagramSocket(new InetSocketAddress("127.0.0.1",0))){
            onEdt(()->{DesktopApp a=new DesktopApp();app.set(a);Workbench bench=new Workbench(a,prefs);w.set(bench);panel.set((CapturePanel)field(bench,"localCapture"));tabs.set((JTabbedPane)field(bench,"workspaces"));a.load(new File("tests/fixtures/demo-analysis.pcap"));return true;});
            awaitEdt(()->app.get().acceptsCapture()&&app.get().model.analysis!=null);check(onEdt(()->app.get().captureCount()==1),"previous file loaded before local capture");
            onEdt(()->{CapturePanel p=panel.get();p.adapters.addItem(loop);p.address.setText("127.0.0.1");p.protocol.setSelectedIndex(3);p.ports.setText(Integer.toString(receiver.getLocalPort()));tabs.get().setSelectedIndex(1);p.start.doClick();check(!p.start.isEnabled()&&!p.address.isEnabled()&&!p.automatic.isEnabled(),"running configuration locked");return true;});
            awaitEdt(()->{Object snapshot=field(panel.get(),"latest");return snapshot!=null&&((CaptureBackend.Snapshot)snapshot).phase.equals("running");});
            onEdt(()->{screenshot(panel.get(),new File(out,"windows-local-capture-running.png"),1040);tabs.get().setSelectedIndex(2);return true;});send(sender,receiver.getLocalPort(),SIP,16);Thread.sleep(250);
            onEdt(()->{TrayPopup.MenuView tray=new TrayPopup.MenuView(()->{},()->{},()->{},w.get()::stopCapture);tray.stop.doClick();return true;});awaitEdt(()->!w.get().capturing()&&app.get().captureCount()==2&&app.get().acceptsCapture()&&app.get().model.analysis!=null);
            check(onEdt(()->tabs.get().getSelectedIndex()==0&&app.get().captureIndex()==1&&!app.get().model.callId.isEmpty()),"tray stop appends file, opens analysis and selects first call");
            check(onEdt(()->((JTextArea)field(panel.get(),"message")).getText().contains("已送入抓包分析")),"capture message changes from queued to opened when analysis starts");
            onEdt(()->{panel.get().automatic.setSelected(false);tabs.get().setSelectedIndex(1);panel.get().start.doClick();return true;});awaitEdt(()->{CaptureBackend.Snapshot snapshot=(CaptureBackend.Snapshot)field(panel.get(),"latest");return snapshot!=null&&snapshot.phase.equals("running");});send(sender,receiver.getLocalPort(),SIP,10);Thread.sleep(250);onEdt(()->{panel.get().stop.doClick();return true;});awaitEdt(()->!w.get().capturing());check(onEdt(()->app.get().captureCount()==2&&panel.get().analyze.isVisible()),"save-only keeps analysis list unchanged and offers manual analysis");onEdt(()->{panel.get().analyze.doClick();return true;});awaitEdt(()->app.get().captureCount()==3&&app.get().acceptsCapture());check(onEdt(()->app.get().captureIndex()==2),"manual analysis appends saved capture");
        }finally{onEdt(()->{if(w.get()!=null)w.get().close();if(app.get()!=null)app.get().shutdown();return true;});prefs.removeNode();}
    }
}
