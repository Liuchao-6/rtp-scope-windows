package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/** Swing owns the text rendering, including when no main window is visible. */
final class TrayPopup implements AutoCloseable {
    final JDialog window;
    final MenuView view;
    TrayPopup(Runnable restore,Runnable exit){
        window=new JDialog((Frame)null,"超哥话探 · 托盘菜单",false);window.setUndecorated(true);window.setType(Window.Type.POPUP);window.setAlwaysOnTop(true);window.setFocusableWindowState(true);
        window.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);view=new MenuView(restore,exit,()->window.setVisible(false));window.setContentPane(view);window.pack();
        window.addWindowFocusListener(new WindowAdapter(){public void windowLostFocus(WindowEvent event){window.setVisible(false);}});
    }
    void show(Point point){
        Rectangle area=workArea(point),bounds=place(point,window.getPreferredSize(),area);window.setBounds(bounds);view.select(0);window.setVisible(true);window.toFront();window.requestFocus();view.requestFocusInWindow();
    }
    private static Rectangle workArea(Point point){
        GraphicsConfiguration chosen=GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().getDefaultConfiguration();
        for(GraphicsDevice device:GraphicsEnvironment.getLocalGraphicsEnvironment().getScreenDevices())for(GraphicsConfiguration candidate:device.getConfigurations())if(candidate.getBounds().contains(point))chosen=candidate;
        Rectangle bounds=new Rectangle(chosen.getBounds());Insets insets=Toolkit.getDefaultToolkit().getScreenInsets(chosen);bounds.x+=insets.left;bounds.y+=insets.top;bounds.width-=insets.left+insets.right;bounds.height-=insets.top+insets.bottom;return bounds;
    }
    static Rectangle place(Point point,Dimension preferred,Rectangle area){
        int width=Math.min(preferred.width,area.width),height=Math.min(preferred.height,area.height);
        return new Rectangle(Math.max(area.x,Math.min(point.x,area.x+area.width-width)),Math.max(area.y,Math.min(point.y,area.y+area.height-height)),width,height);
    }
    public void close(){window.dispose();}

    static final class MenuView extends JPanel {
        final JMenuItem open=new JMenuItem("打开主界面"),quit=new JMenuItem("退出程序");
        private int selected;
        MenuView(Runnable restore,Runnable exit,Runnable dismiss){
            super(new BorderLayout());setFocusable(true);setBackground(Ui.PANEL);setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(Ui.LINE),BorderFactory.createEmptyBorder(Ui.u(4),Ui.u(4),Ui.u(4),Ui.u(4))));
            JPanel items=new JPanel();items.setOpaque(false);items.setLayout(new BoxLayout(items,BoxLayout.Y_AXIS));add(items,BorderLayout.CENTER);JMenuItem[] entries={open,quit};
            for(int i=0;i<entries.length;i++){
                final int index=i;JMenuItem item=entries[i];item.setFont(Ui.font(13));item.setForeground(Ui.INK);item.setBackground(Ui.PANEL);item.setFocusable(false);item.setPreferredSize(new Dimension(Ui.u(180),Ui.u(35)));item.setMaximumSize(new Dimension(Integer.MAX_VALUE,Ui.u(35)));item.setBorder(BorderFactory.createEmptyBorder(Ui.u(7),Ui.u(14),Ui.u(7),Ui.u(14)));
                item.addMouseListener(new MouseAdapter(){public void mouseEntered(MouseEvent e){select(index);}});item.addFocusListener(new FocusAdapter(){public void focusGained(FocusEvent event){select(index);}});items.add(item);if(i==0)items.add(new JSeparator());
            }
            open.setName("trayOpen");quit.setName("trayExit");open.addActionListener(e->{dismiss.run();restore.run();});quit.addActionListener(e->{dismiss.run();exit.run();});
            bind("ESCAPE","dismiss",dismiss);bind("UP","previous",()->select((selected+1)%2));bind("DOWN","next",()->select((selected+1)%2));bind("ENTER","activate",()->(selected==0?open:quit).doClick());select(0);
        }
        private void bind(String key,String name,Runnable action){getInputMap(WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(key),name);getActionMap().put(name,new AbstractAction(){public void actionPerformed(ActionEvent event){action.run();}});}
        void select(int index){selected=index;open.setArmed(index==0);quit.setArmed(index==1);}
    }
}
