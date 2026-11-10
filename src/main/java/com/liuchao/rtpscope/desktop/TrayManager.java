package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Main-window close policy. All controller actions run on the Swing event thread. */
final class TrayManager extends WindowAdapter implements AutoCloseable {
    enum Choice { HIDE, EXIT, CANCEL }
    interface Host { void hide();void restore();void dispose(); }
    interface Tray { boolean supported();void add(Runnable restore,Runnable exit)throws AWTException;void remove(); }
    interface Prompt { Choice choose(boolean canHide);void unavailable(); }
    private final Host host;
    private final Tray tray;
    private final Prompt prompt;
    private final BooleanSupplier confirmExit;
    private final Runnable cleanup;
    private boolean choosing,exiting,closed;

    TrayManager(JFrame frame,BooleanSupplier confirmExit,Runnable cleanup){
        this(new Host(){
            public void hide(){frame.setVisible(false);}
            public void restore(){frame.setExtendedState(frame.getExtendedState()&~Frame.ICONIFIED);frame.setVisible(true);frame.toFront();frame.requestFocus();}
            public void dispose(){frame.dispose();}
        },new NativeTray(),new Prompt(){
            public Choice choose(boolean canHide){return chooseClose(frame,canHide);}
            public void unavailable(){JOptionPane.showMessageDialog(frame,"暂时无法使用系统托盘，主窗口已保留。\n可以再次关闭并选择退出，或继续使用。","隐藏到托盘未完成",JOptionPane.INFORMATION_MESSAGE);}
        },confirmExit,cleanup);
        frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);frame.addWindowListener(this);
    }
    TrayManager(Host host,Tray tray,Prompt prompt,BooleanSupplier confirmExit,Runnable cleanup){this.host=host;this.tray=tray;this.prompt=prompt;this.confirmExit=confirmExit;this.cleanup=cleanup;}
    @Override public void windowClosing(WindowEvent event){requestClose();}
    @Override public void windowClosed(WindowEvent event){close();}
    void requestClose(){
        if(closed||choosing||exiting)return;choosing=true;
        try{Choice choice=prompt.choose(tray.supported());if(choice==Choice.HIDE)hide();else if(choice==Choice.EXIT)exit();}finally{choosing=false;}
    }
    private void hide(){
        if(!tray.supported()){prompt.unavailable();return;}
        try{tray.add(this::restore,this::exit);}catch(AWTException|RuntimeException e){tray.remove();prompt.unavailable();return;}
        // Register the icon first so there is always a way to restore the window.
        host.hide();
    }
    void restore(){if(closed||exiting)return;host.restore();tray.remove();}
    void exit(){
        if(closed||exiting)return;exiting=true;
        try{
            if(!confirmExit.getAsBoolean())return;
            try{cleanup.run();}finally{close();host.dispose();}
        }finally{exiting=false;}
    }
    public void close(){if(closed)return;closed=true;tray.remove();}

    private static Choice chooseClose(JFrame owner,boolean canHide){
        final Choice[] selected={Choice.CANCEL};JDialog dialog=new JDialog(owner,"关闭超哥话探",Dialog.ModalityType.DOCUMENT_MODAL);
        CloseView content=new CloseView(canHide,choice->{selected[0]=choice;dialog.dispose();});dialog.setContentPane(content);dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.setIconImages(Ui.icons());dialog.setResizable(false);dialog.getRootPane().setDefaultButton(canHide?content.hide:content.cancel);
        dialog.getRootPane().registerKeyboardAction(e->dialog.dispose(),KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE,0),JComponent.WHEN_IN_FOCUSED_WINDOW);
        Ui.fitWindow(dialog,530,255,480,230);dialog.setLocationRelativeTo(owner);dialog.setVisible(true);return selected[0];
    }

    static final class CloseView extends JPanel {
        final JButton hide=Ui.button("隐藏到托盘",true),exit=Ui.button("退出程序",false),cancel=Ui.button("取消",false);
        CloseView(boolean canHide,Consumer<Choice> choose){
            super(new BorderLayout(0,Ui.u(16)));setBackground(Ui.BG);setBorder(BorderFactory.createEmptyBorder(Ui.u(20),Ui.u(20),Ui.u(18),Ui.u(20)));
            JLabel title=Ui.label("关闭超哥话探",19,Ui.INK);title.setIcon(new ImageIcon(Ui.icon().getScaledInstance(Ui.u(32),Ui.u(32),Image.SCALE_SMOOTH)));title.setIconTextGap(Ui.u(10));add(title,BorderLayout.NORTH);
            JTextArea text=Ui.note(canHide?"隐藏到托盘：主窗口收起，当前任务继续运行。\n双击通知区域的图标，或在托盘菜单中打开主界面。\n\n退出程序：停止当前任务并关闭软件。":"当前环境无法使用系统托盘。\n可以退出程序，或取消关闭并继续使用。");text.setForeground(Ui.INK);text.setOpaque(false);add(text,BorderLayout.CENTER);
            JPanel buttons=new JPanel(new FlowLayout(FlowLayout.RIGHT,Ui.u(8),0));buttons.setOpaque(false);hide.setName("hideToTray");exit.setName("exitApplication");cancel.setName("cancelClose");hide.setEnabled(canHide);
            for(JButton button:new JButton[]{hide,exit,cancel})buttons.add(button);add(buttons,BorderLayout.SOUTH);
            hide.addActionListener(e->choose.accept(Choice.HIDE));exit.addActionListener(e->choose.accept(Choice.EXIT));cancel.addActionListener(e->choose.accept(Choice.CANCEL));
        }
    }

    static final class NativeTray implements Tray {
        private TrayIcon icon;
        TrayPopup popup;
        public boolean supported(){return SystemTray.isSupported();}
        public void add(Runnable restore,Runnable exit)throws AWTException {
            if(icon!=null)return;
            SystemTray system=SystemTray.getSystemTray();
            Dimension size=system.getTrayIconSize();final TrayIcon candidate=new TrayIcon(Ui.icon().getScaledInstance(size.width,size.height,Image.SCALE_SMOOTH),"超哥话探 · 双击打开主界面");candidate.setImageAutoSize(true);candidate.addActionListener(e->SwingUtilities.invokeLater(restore));
            candidate.addMouseListener(new MouseAdapter(){public void mouseReleased(MouseEvent event){
                if(!event.isPopupTrigger()&&event.getButton()!=MouseEvent.BUTTON3)return;final Point point=event.getPoint();
                SwingUtilities.invokeLater(()->{if(icon!=candidate)return;if(popup==null)popup=new TrayPopup(restore,exit);popup.show(point);});
            }});
            try{system.add(candidate);icon=candidate;}catch(AWTException|RuntimeException e){system.remove(candidate);throw e;}
        }
        public void remove(){if(icon!=null){SystemTray.getSystemTray().remove(icon);icon=null;}if(popup!=null){popup.close();popup=null;}}
    }
}
