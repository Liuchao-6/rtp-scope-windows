package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.*;

/** Close choices and lifecycle failures without terminating the test JVM. */
public final class TrayTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    private static final class Window implements TrayManager.Host {
        boolean visible=true,disposed;int restored;
        public void hide(){visible=false;}
        public void restore(){visible=true;restored++;}
        public void dispose(){disposed=true;visible=false;}
    }
    private static final class Tray implements TrayManager.Tray {
        boolean supported=true,installed,fail;int adds,removes;Runnable open,quit;
        public boolean supported(){return supported;}
        public void add(Runnable open,Runnable quit)throws AWTException{this.open=open;this.quit=quit;if(!installed){installed=true;adds++;}if(fail)throw new AWTException("simulated registration failure");}
        public void remove(){if(installed){installed=false;removes++;}}
    }
    private static final class Prompt implements TrayManager.Prompt {
        TrayManager.Choice choice=TrayManager.Choice.CANCEL;int asked,failures;boolean offeredHide;Runnable nested;
        public TrayManager.Choice choose(boolean canHide){asked++;offeredHide=canHide;if(nested!=null)nested.run();return choice;}
        public void unavailable(){failures++;}
    }
    private static final class Fixture {
        final Window window=new Window();final Tray tray=new Tray();final Prompt prompt=new Prompt();boolean allowExit=true;int confirmations,cleanups;Runnable onCleanup=()->{};
        final TrayManager manager=new TrayManager(window,tray,prompt,()->{confirmations++;return allowExit;},()->{cleanups++;onCleanup.run();});
    }
    private static void layout(Container container){container.doLayout();for(Component child:container.getComponents())if(child instanceof Container)layout((Container)child);}
    private static void image(TrayManager.CloseView panel,File file,int width)throws IOException{
        panel.setSize(width,220);layout(panel);layout(panel);
        for(JButton button:new JButton[]{panel.hide,panel.exit,panel.cancel})check(SwingUtilities.convertRectangle(button.getParent(),button.getBounds(),panel).getMaxX()<=width,"close choice fits "+width+"px: "+button.getText());
        BufferedImage image=new BufferedImage(width,panel.getHeight(),BufferedImage.TYPE_INT_RGB);Graphics2D g=image.createGraphics();panel.printAll(g);g.dispose();javax.imageio.ImageIO.write(image,"png",file);
    }
    public static int run(File output)throws Exception {
        checks=0;AtomicReference<Throwable> failure=new AtomicReference<>();
        SwingUtilities.invokeAndWait(()->{
            try{
                Fixture f=new Fixture();f.manager.requestClose();check(f.window.visible&&!f.tray.installed&&!f.window.disposed&&f.cleanups==0,"cancel keeps current session active");
                f.prompt.choice=TrayManager.Choice.HIDE;f.manager.windowClosing(null);
                check(!f.window.visible&&f.tray.installed,"main-window closing can hide to tray");
                check(f.cleanups==0&&f.confirmations==0&&!f.window.disposed,"hiding retains active tasks and skips exit confirmation");
                f.tray.open.run();check(f.window.visible&&!f.tray.installed&&f.window.restored==1,"tray open restores existing window and removes its icon");
                f.manager.requestClose();check(f.tray.adds==2&&f.tray.installed,"hide again installs a new accessible icon");
                f.allowExit=false;f.tray.quit.run();check(f.cleanups==0&&f.tray.installed&&!f.window.disposed,"cancel exit while capturing keeps tray and tasks");
                f.allowExit=true;f.tray.quit.run();check(f.cleanups==1&&f.window.disposed&&!f.tray.installed,"tray exit cleans up tasks, icon and window");
                f.manager.exit();f.manager.restore();f.manager.requestClose();check(f.cleanups==1&&!f.window.visible&&!f.tray.installed,"late tray or close events cannot restart an exited app");

                Fixture direct=new Fixture();direct.prompt.choice=TrayManager.Choice.EXIT;direct.manager.requestClose();check(direct.cleanups==1&&direct.confirmations==1&&direct.window.disposed,"exit choice follows the same cleanup path");
                Fixture unsupported=new Fixture();unsupported.tray.supported=false;unsupported.prompt.choice=TrayManager.Choice.HIDE;unsupported.manager.requestClose();check(!unsupported.prompt.offeredHide&&unsupported.window.visible&&unsupported.prompt.failures==1,"unsupported system tray never strands a hidden window");
                unsupported.prompt.choice=TrayManager.Choice.EXIT;unsupported.manager.requestClose();check(unsupported.window.disposed&&unsupported.cleanups==1,"exit remains available without a tray");

                Fixture registration=new Fixture();registration.tray.fail=true;registration.prompt.choice=TrayManager.Choice.HIDE;registration.manager.requestClose();check(registration.window.visible&&!registration.tray.installed&&registration.prompt.failures==1&&registration.cleanups==0,"failed registration removes partial icon and retains visible window");
                registration.tray.fail=false;registration.manager.requestClose();check(!registration.window.visible&&registration.tray.installed,"tray registration can be retried");registration.manager.exit();

                Fixture external=new Fixture();external.prompt.choice=TrayManager.Choice.HIDE;external.manager.requestClose();external.manager.windowClosed(null);external.manager.close();check(!external.tray.installed&&external.tray.removes==1,"external window disposal removes tray icon once");
                Fixture nested=new Fixture();nested.prompt.nested=nested.manager::requestClose;nested.manager.requestClose();check(nested.prompt.asked==1,"nested close event does not open duplicate prompts");nested.prompt.nested=null;nested.prompt.choice=TrayManager.Choice.EXIT;nested.onCleanup=nested.manager::exit;nested.manager.requestClose();check(nested.cleanups==1,"nested exit event does not run cleanup twice");
                Fixture throwing=new Fixture();throwing.prompt.choice=TrayManager.Choice.HIDE;throwing.manager.requestClose();throwing.onCleanup=()->{throw new IllegalStateException("simulated cleanup failure");};try{throwing.manager.exit();throw new AssertionError("Expected cleanup exception");}catch(IllegalStateException expected){}check(!throwing.tray.installed&&throwing.window.disposed,"tray and window still close if cleanup throws");

                Ui.setup();AtomicReference<TrayManager.Choice> selected=new AtomicReference<>();TrayManager.CloseView panel=new TrayManager.CloseView(true,selected::set);
                panel.hide.doClick();check(selected.get()==TrayManager.Choice.HIDE,"real hide button selects tray");panel.exit.doClick();check(selected.get()==TrayManager.Choice.EXIT,"real exit button selects exit");panel.cancel.doClick();check(selected.get()==TrayManager.Choice.CANCEL,"real cancel button keeps window");
                image(panel,new File(output,"windows-close-choice.png"),530);image(panel,new File(output,"windows-close-compact.png"),480);
                TrayManager.CloseView unavailable=new TrayManager.CloseView(false,selected::set);selected.set(null);unavailable.hide.doClick();check(!unavailable.hide.isEnabled()&&selected.get()==null,"unsupported tray choice is disabled");unavailable.exit.doClick();check(selected.get()==TrayManager.Choice.EXIT,"unsupported tray still exposes exit action");image(unavailable,new File(output,"windows-close-no-tray.png"),530);
            }catch(Throwable e){failure.set(e);}
        });
        if(failure.get()!=null)throw new AssertionError("Close/tray regression failed",failure.get());
        System.out.println("PASS: "+checks+" close/tray checks; hide, restore, exit, cancellation, registration failure and Swing choices");return checks;
    }

    /** Registers a real Windows tray icon briefly, invokes its native event callbacks, then removes it. */
    private static void nativeProbe()throws Exception {
        if(!SystemTray.isSupported())throw new AssertionError("System tray unavailable on this test host");
        TrayManager.NativeTray tray=new TrayManager.NativeTray();AtomicInteger opened=new AtomicInteger(),exited=new AtomicInteger();AtomicReference<TrayIcon> icon=new AtomicReference<>();
        Set<TrayIcon> existing=new HashSet<>(Arrays.asList(SystemTray.getSystemTray().getTrayIcons()));
        try{
            SwingUtilities.invokeAndWait(()->{try{
                Ui.setup();tray.add(opened::incrementAndGet,exited::incrementAndGet);for(TrayIcon item:SystemTray.getSystemTray().getTrayIcons())if(!existing.contains(item))icon.set(item);
                if(icon.get()==null||icon.get().getImage()==null||!icon.get().getToolTip().contains("超哥话探"))throw new AssertionError("Missing native tray icon");
                tray.add(opened::incrementAndGet,exited::incrementAndGet);
                for(ActionListener action:icon.get().getActionListeners())action.actionPerformed(new ActionEvent(icon.get(),ActionEvent.ACTION_PERFORMED,"open"));
            }catch(Exception e){throw new RuntimeException(e);}});
            SwingUtilities.invokeAndWait(()->{
                if(opened.get()!=1)throw new AssertionError("Tray double-click action did not reach Swing");
                PopupMenu menu=icon.get().getPopupMenu();MenuItem open=menu.getItem(0),quit=menu.getItem(2);
                if(!open.getLabel().equals("打开主界面")||!quit.getLabel().equals("退出程序"))throw new AssertionError("Native tray menu labels");
                for(ActionListener action:open.getActionListeners())action.actionPerformed(new ActionEvent(open,ActionEvent.ACTION_PERFORMED,"open"));
                for(ActionListener action:quit.getActionListeners())action.actionPerformed(new ActionEvent(quit,ActionEvent.ACTION_PERFORMED,"exit"));
            });
            SwingUtilities.invokeAndWait(()->{if(opened.get()!=2||exited.get()!=1)throw new AssertionError("Native tray menu callback dispatch");});
        }finally{SwingUtilities.invokeAndWait(tray::remove);}
        if(Arrays.asList(SystemTray.getSystemTray().getTrayIcons()).contains(icon.get()))throw new AssertionError("Tray icon leaked");
        System.out.println("PASS: real Windows tray registration, native menu/action callbacks and removal; os="+System.getProperty("os.name"));
    }
    public static void main(String[] args)throws Exception{if(args.length>0&&args[0].equals("--native"))nativeProbe();else run(new File(args.length>0?args[0]:"build"));}
}
