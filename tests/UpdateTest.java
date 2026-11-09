package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.lang.reflect.Field;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import com.sun.net.httpserver.HttpServer;

/** Real HTTP, persisted preferences and Swing actions with no release publication or user files. */
public final class UpdateTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    private interface Action { void run()throws Exception; }
    private static void invalid(Action action,String label)throws Exception{boolean rejected=false;try{action.run();}catch(IOException|IllegalArgumentException expected){rejected=true;}check(rejected,label);}
    private static byte[] bytes(String value){return value.getBytes(StandardCharsets.UTF_8);}
    private static String release(String tag){return "{\"tag_name\":\""+tag+"\",\"draft\":false,\"prerelease\":false,\"name\":\"超哥话探 "+tag+"\",\"body\":\"### 更新说明\\n- 改进通话分析\\n- 修复使用问题\",\"html_url\":\"https://example.invalid/untrusted\",\"assets\":[{\"size\":200,\"optional\":null}]}";}
    private static Object field(Object target,String name)throws Exception{Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(target);}
    private static void edt(Action action)throws Exception{SwingUtilities.invokeAndWait(()->{try{action.run();}catch(Exception e){throw new RuntimeException(e);}});}
    private static void waitFor(UpdateManager manager)throws Exception{
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);
        while(System.nanoTime()<end){AtomicBoolean running=new AtomicBoolean();edt(()->running.set((Boolean)field(manager,"running")));if(!running.get())return;Thread.sleep(20);}
        throw new AssertionError("Update worker timeout");
    }
    private static UpdateManager.View view(UpdateManager manager)throws Exception{return (UpdateManager.View)field(manager,"view");}
    private static void layout(Container parent){parent.doLayout();for(Component child:parent.getComponents())if(child instanceof Container)layout((Container)child);}
    private static void image(UpdateManager.View view,Path output,int width)throws Exception{
        view.setSize(width,540);layout(view);layout(view);
        for(JButton button:new JButton[]{view.retry,view.download,view.ignore,view.later})if(button.isVisible())check(SwingUtilities.convertRectangle(button.getParent(),button.getBounds(),view).x+button.getWidth()<=view.getWidth(),"update button fits "+width+"px: "+button.getText());
        check(view.notes.getWidth()>300&&view.notes.getHeight()>100,"release notes retain readable area");
        BufferedImage image=new BufferedImage(view.getWidth(),view.getHeight(),BufferedImage.TYPE_INT_RGB);Graphics2D g=image.createGraphics();view.printAll(g);g.dispose();javax.imageio.ImageIO.write(image,"png",output.toFile());
    }

    public static int run(File output)throws Exception {
        checks=0;
        check(UpdateChecker.compareVersions("0.8.10","0.8.9")>0,"numeric ordering across two digit patch");
        check(UpdateChecker.compareVersions("v1.0.0","0.99.99")>0,"major version ordering");
        check(UpdateChecker.compareVersions("0.8.6.0","v0.8.6")==0,"equal versions and optional v prefix");
        check(UpdateChecker.compareVersions("0.8.5","0.8.6")<0,"never offer a downgrade");
        invalid(()->UpdateChecker.compareVersions("0.8.6-beta","0.8.5"),"exclude prerelease version syntax");
        UpdateChecker.Release newer=UpdateChecker.parse(bytes(release("v0.8.10")));
        check(newer.newerThan(DesktopApp.VERSION)&&newer.notes.contains("改进通话分析"),"Chinese release notes and newer release");
        check(newer.page.toString().equals(UpdateChecker.RELEASES+"/tag/v0.8.10"),"download stays at official repository despite remote URL");
        check(UpdateChecker.parse(bytes(release("v0.8.10").replace("### 更新说明","\\u66f4\\u65b0"))).notes.startsWith("更新"),"JSON unicode escapes");
        check(UpdateChecker.parse(bytes("{\"tag_name\":\"v1.0\",\"draft\":false,\"prerelease\":false}")).notes.contains("未填写"),"optional release notes fallback");
        for(String malformed:new String[]{"{}","[]",release("v1.0").replace("\"draft\":false","\"draft\":true"),release("v1.0").replace("\"prerelease\":false","\"prerelease\":true"),release("v1.0/../../evil"),release("v1.0")+" trailing",release("v1.0").replace("200","01"),release("v1.0").replace("200","1e9999999999"),release("v1.0").replace("200","[1,]"),release("v1.0").replace("200","\"\\q\""),release("v1.0").replace("200","{\"a\":1,\"a\":2}"),"["+new String(new char[40]).replace("\0","[")+"0"})invalid(()->UpdateChecker.parse(bytes(malformed)),"reject malformed or ineligible release metadata");
        invalid(()->UpdateChecker.readBounded(new ByteArrayInputStream(new byte[UpdateChecker.MAX_BYTES+1])),"cap response without content length");

        AtomicInteger requests=new AtomicInteger();AtomicBoolean publicOnly=new AtomicBoolean(true);
        HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/",exchange->{
            requests.incrementAndGet();publicOnly.compareAndSet(true,exchange.getRequestMethod().equals("GET")&&exchange.getRequestHeaders().getFirst("Authorization")==null&&exchange.getRequestHeaders().getFirst("Cookie")==null&&exchange.getRequestBody().read()==-1&&exchange.getRequestHeaders().getFirst("User-Agent").startsWith("ChaogeHuatan-Windows/"));
            String path=exchange.getRequestURI().getPath();int code=path.equals("/limited")?429:path.equals("/redirect")?302:path.equals("/missing")?404:200;
            byte[] data=bytes(path.equals("/bad")?"<html>not json</html>":release("v0.8.10"));
            if(code==302)exchange.getResponseHeaders().add("Location","/stable");
            exchange.sendResponseHeaders(code,data.length);try(OutputStream out=exchange.getResponseBody()){out.write(data);}
        });server.start();
        try{
            String base="http://127.0.0.1:"+server.getAddress().getPort();
            check(new UpdateChecker(()->(HttpURLConnection)new URL(base+"/stable").openConnection()).fetch().version.equals("0.8.10"),"real HTTP release query");
            for(String path:new String[]{"/limited","/missing","/redirect","/bad"})invalid(()->new UpdateChecker(()->(HttpURLConnection)new URL(base+path).openConnection()).fetch(),"HTTP error handled: "+path);
            check(requests.get()==5,"do not follow unexpected redirects");check(publicOnly.get(),"GET metadata without credentials or request body");
        }finally{server.stop(0);}

        Path dir=Files.createTempDirectory(output.toPath(),"update-test-");Path config=dir.resolve("preferences.properties");
        UpdateSettings settings=new UpdateSettings(config);long now=System.currentTimeMillis();
        check(settings.automatic()&&settings.due(now),"first startup checks by default");settings.attempted(now);
        check(!new UpdateSettings(config).due(now+UpdateSettings.DAY-1),"persist daily throttle across restart");
        check(new UpdateSettings(config).due(now+UpdateSettings.DAY),"check again after 24 hours");
        check(settings.due(now-1000),"recover after system clock moves backward");
        settings.ignore(newer);check(new UpdateSettings(config).ignored(newer),"ignored version persists");
        check(!settings.ignored(UpdateChecker.parse(bytes(release("v0.8.11")))),"ignoring one version still allows a subsequent version");
        settings.automatic(false);check(!new UpdateSettings(config).automatic()&&!settings.due(now+UpdateSettings.DAY*2),"automatic checks can be disabled");

        AtomicReference<UpdateManager> manager=new AtomicReference<>();AtomicInteger fetches=new AtomicInteger();AtomicReference<URI> opened=new AtomicReference<>();
        CountDownLatch entered=new CountDownLatch(1),unblock=new CountDownLatch(1);AtomicBoolean fetchedOnEdt=new AtomicBoolean();
        edt(()->{Ui.setup();manager.set(new UpdateManager(new JPanel(),settings,()->{fetches.incrementAndGet();fetchedOnEdt.set(SwingUtilities.isEventDispatchThread());entered.countDown();if(!unblock.await(5,TimeUnit.SECONDS))throw new IOException("test timeout");return newer;},opened::set));manager.get().check(false);});
        check(fetches.get()==0,"disabled startup does not contact network");
        try{
            edt(()->manager.get().check(true));check(entered.await(3,TimeUnit.SECONDS),"manual check bypasses disabled automatic setting");
            edt(()->{check(!view(manager.get()).retry.isEnabled(),"checking state disables duplicate query control");manager.get().check(true);check(true,"UI remains responsive while network is waiting");});
            check(fetches.get()==1&&!fetchedOnEdt.get(),"one independent background request for simultaneous checks");
            unblock.countDown();waitFor(manager.get());
            edt(()->{
                UpdateManager.View view=view(manager.get());check(view.heading.getText().equals("发现新版本")&&view.ignore.isVisible(),"manual check shows ignored release again");
                view.download.doClick();check(opened.get().equals(newer.page),"download action opens official release in browser");
                view.automatic.doClick();check(settings.automatic(),"real checkbox saves automatic setting");
                image(view,output.toPath().resolve("windows-update-available.png"),650);image(view,output.toPath().resolve("windows-update-compact.png"),600);
                view.ignore.doClick();check(new UpdateSettings(config).ignored(newer),"ignore control persists selected version");
                view.failed();image(view,output.toPath().resolve("windows-update-offline.png"),650);
            });
            edt(()->manager.get().check(false));check(fetches.get()==1,"manual check also throttles next startup attempt");
        }finally{unblock.countDown();edt(()->manager.get().close());}

        AtomicReference<UpdateManager> failed=new AtomicReference<>();UpdateSettings failedSettings=new UpdateSettings(dir.resolve("offline.properties"));
        edt(()->{failed.set(new UpdateManager(new JPanel(),failedSettings,()->{throw new SocketTimeoutException("test network unavailable");},opened::set));failed.get().check(true);});
        try{waitFor(failed.get());edt(()->check(view(failed.get()).heading.getText().contains("无法检查")&&view(failed.get()).retry.isEnabled(),"offline manual check offers retry"));}
        finally{edt(()->failed.get().close());}

        AtomicReference<UpdateManager> current=new AtomicReference<>();
        edt(()->{current.set(new UpdateManager(new JPanel(),new UpdateSettings(dir.resolve("current.properties")),()->UpdateChecker.parse(bytes(release("v"+DesktopApp.VERSION))),opened::set));current.get().check(true);});
        try{waitFor(current.get());edt(()->check(view(current.get()).heading.getText().equals("当前无需更新")&&!view(current.get()).ignore.isVisible(),"current version state has no ignore action"));}finally{edt(()->current.get().close());}

        CountDownLatch closing=new CountDownLatch(1),interrupted=new CountDownLatch(1);AtomicReference<UpdateManager> cancelled=new AtomicReference<>();
        edt(()->{cancelled.set(new UpdateManager(new JPanel(),new UpdateSettings(dir.resolve("cancel.properties")),()->{closing.countDown();try{new CountDownLatch(1).await();}catch(InterruptedException e){interrupted.countDown();throw e;}return newer;},opened::set));cancelled.get().check(true);});
        check(closing.await(3,TimeUnit.SECONDS),"background check started before close");edt(()->cancelled.get().close());check(interrupted.await(3,TimeUnit.SECONDS),"shutdown cancels pending check");
        try(java.util.stream.Stream<Path> files=Files.walk(dir)){files.sorted(java.util.Comparator.reverseOrder()).forEach(path->{try{Files.delete(path);}catch(IOException e){throw new UncheckedIOException(e);}});}
        System.out.println("PASS: "+checks+" update checks; HTTP, version ordering, offline behavior, persistence and Swing actions");return checks;
    }
    public static void main(String[] args)throws Exception{
        if(args.length>0&&args[0].equals("--live")){UpdateChecker.Release release=new UpdateChecker().fetch();System.out.println("PASS: anonymous HTTPS release query; tag="+release.tag+"; newer="+release.newerThan(DesktopApp.VERSION)+"; page="+release.page);return;}
        run(new File(args.length>0?args[0]:"build"));
    }
}
