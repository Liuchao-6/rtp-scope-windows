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
                List<String> actions=new ArrayList<>();TrayPopup.MenuView menu=new TrayPopup.MenuView(()->actions.add("open"),()->actions.add("exit"),()->actions.add("dismiss"));
                check(menu.open.getFont().canDisplayUpTo(menu.open.getText())==-1&&menu.quit.getFont().canDisplayUpTo(menu.quit.getText())==-1,"Swing menu fonts cover all Chinese labels");
                menu.open.setSize(menu.open.getPreferredSize());menu.open.dispatchEvent(new MouseEvent(menu.open,MouseEvent.MOUSE_RELEASED,System.currentTimeMillis(),0,12,12,1,false,MouseEvent.BUTTON1));check(actions.equals(Arrays.asList("dismiss","open")),"mouse release dismisses the menu before restoring the main window");actions.clear();menu.quit.doClick();check(actions.equals(Arrays.asList("dismiss","exit")),"menu dismisses before requesting exit");actions.clear();
                menu.select(0);menu.getActionMap().get("next").actionPerformed(null);menu.getActionMap().get("activate").actionPerformed(null);check(actions.equals(Arrays.asList("dismiss","exit")),"Down and Enter activate exit");actions.clear();
                menu.getActionMap().get("previous").actionPerformed(null);menu.getActionMap().get("activate").actionPerformed(null);check(actions.equals(Arrays.asList("dismiss","open")),"Up and Enter activate open");actions.clear();menu.getActionMap().get("dismiss").actionPerformed(null);check(actions.equals(Collections.singletonList("dismiss")),"Escape dismisses without selecting an action");
                for(Rectangle area:Arrays.asList(new Rectangle(0,0,1920,1040),new Rectangle(-1920,0,1920,1040),new Rectangle(0,-1080,1920,1040)))for(Point point:Arrays.asList(new Point(area.x,area.y),new Point(area.x+area.width,area.y+area.height),new Point(area.x-20,area.y-20)))check(area.contains(TrayPopup.place(point,new Dimension(190,80),area)),"popup fits monitor work area, including negative screen coordinates");
                check(TrayPopup.place(new Point(100,100),new Dimension(300,200),new Rectangle(0,0,200,100)).equals(new Rectangle(0,0,200,100)),"oversized menu stays within small work area");
                TrayManager.CloseView unavailable=new TrayManager.CloseView(false,selected::set);selected.set(null);unavailable.hide.doClick();check(!unavailable.hide.isEnabled()&&selected.get()==null,"unsupported tray choice is disabled");unavailable.exit.doClick();check(selected.get()==TrayManager.Choice.EXIT,"unsupported tray still exposes exit action");image(unavailable,new File(output,"windows-close-no-tray.png"),530);
            }catch(Throwable e){failure.set(e);}
        });
        if(failure.get()!=null)throw new AssertionError("Close/tray regression failed",failure.get());
        System.out.println("PASS: "+checks+" close/tray checks; hide, restore, exit, cancellation, registration failure and Swing choices");return checks;
    }

    /** Exercise the actual registered tray icon mouse callback while no main window is visible. */
    static void rightClick(TrayIcon icon,Point point){
        MouseEvent event=new MouseEvent(new Canvas(),MouseEvent.MOUSE_RELEASED,System.currentTimeMillis(),0,point.x,point.y,1,true,MouseEvent.BUTTON3);event.setSource(icon);
        for(MouseListener listener:icon.getMouseListeners())listener.mouseReleased(event);
    }
    private static void nativeProbe()throws Exception {
        if(!SystemTray.isSupported())throw new AssertionError("System tray unavailable on this test host");
        TrayManager.NativeTray tray=new TrayManager.NativeTray();AtomicInteger opened=new AtomicInteger(),exited=new AtomicInteger();AtomicReference<TrayIcon> icon=new AtomicReference<>();AtomicReference<TrayPopup> popup=new AtomicReference<>();
        Set<TrayIcon> existing=new HashSet<>(Arrays.asList(SystemTray.getSystemTray().getTrayIcons()));Rectangle area=GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();Point edge=new Point(area.x+area.width-2,area.y+area.height-2);
        try{
            SwingUtilities.invokeAndWait(()->{try{
                Ui.setup();tray.add(opened::incrementAndGet,exited::incrementAndGet);for(TrayIcon item:SystemTray.getSystemTray().getTrayIcons())if(!existing.contains(item))icon.set(item);
                if(icon.get()==null||icon.get().getImage()==null||!icon.get().getToolTip().contains("超哥话探"))throw new AssertionError("Missing native tray icon");
                if(icon.get().getPopupMenu()!=null)throw new AssertionError("Native AWT tray menu must not render Chinese text");
                tray.add(opened::incrementAndGet,exited::incrementAndGet);
                for(ActionListener action:icon.get().getActionListeners())action.actionPerformed(new ActionEvent(icon.get(),ActionEvent.ACTION_PERFORMED,"open"));
                rightClick(icon.get(),edge);
            }catch(Exception e){throw new RuntimeException(e);}});
            SwingUtilities.invokeAndWait(()->{
                popup.set(tray.popup);if(opened.get()!=1||popup.get()==null||!popup.get().window.isVisible())throw new AssertionError("Tray right-click callback did not display the Swing menu");
                if(!area.contains(popup.get().window.getBounds()))throw new AssertionError("Tray popup outside work area");
                if(!popup.get().view.open.getText().equals("打开主界面")||!popup.get().view.quit.getText().equals("退出程序"))throw new AssertionError("Tray menu labels");
                for(JMenuItem item:new JMenuItem[]{popup.get().view.open,popup.get().view.quit})if(item.getFont().canDisplayUpTo(item.getText())!=-1)throw new AssertionError("Swing menu cannot display Chinese");
                popup.get().view.open.doClick();if(opened.get()!=2||popup.get().window.isVisible())throw new AssertionError("Open action must dismiss menu and restore the window");rightClick(icon.get(),edge);
            });
            SwingUtilities.invokeAndWait(()->{
                if(!popup.get().window.isVisible())throw new AssertionError("Repeated tray right-click did not reopen menu");popup.get().view.quit.doClick();
                if(exited.get()!=1||popup.get().window.isVisible())throw new AssertionError("Exit action did not dismiss menu and dispatch callback");rightClick(icon.get(),edge);
            });
            SwingUtilities.invokeAndWait(()->{
                for(WindowFocusListener listener:popup.get().window.getWindowFocusListeners())listener.windowLostFocus(new WindowEvent(popup.get().window,WindowEvent.WINDOW_LOST_FOCUS));
                if(popup.get().window.isVisible()||exited.get()!=1||opened.get()!=2)throw new AssertionError("Outside focus must dismiss without an action");
                rightClick(icon.get(),edge);tray.remove();
            });
            SwingUtilities.invokeAndWait(()->{if(tray.popup!=null||popup.get().window.isDisplayable())throw new AssertionError("Queued tray event recreated a removed menu");});
        }finally{SwingUtilities.invokeAndWait(tray::remove);}
        if(Arrays.asList(SystemTray.getSystemTray().getTrayIcons()).contains(icon.get()))throw new AssertionError("Tray icon leaked");
        System.out.println("PASS: registered Windows tray right-click callbacks, Swing menu without a visible main window, actions, focus dismissal, edge placement and resource cleanup; os="+System.getProperty("os.name"));
    }
    public static void main(String[] args)throws Exception{if(args.length>0&&args[0].equals("--native"))nativeProbe();else run(new File(args.length>0?args[0]:"build"));}
}
