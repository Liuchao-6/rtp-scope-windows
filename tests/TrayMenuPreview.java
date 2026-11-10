package com.liuchao.rtpscope.desktop;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;

/** Visual check enters the registered tray icon's mouse listener after hiding the frame. */
public final class TrayMenuPreview {
    public static void main(String[] args)throws Exception{
        SwingUtilities.invokeAndWait(()->{
            Ui.setup();JFrame frame=new JFrame("超哥话探 · 托盘回调检查");TrayManager.NativeTray tray=new TrayManager.NativeTray();
            JLabel state=Ui.label("通过真实注册的托盘图标回调弹出菜单",13,Ui.INK);JPanel pane=new JPanel(new BorderLayout(10,14));pane.setBorder(BorderFactory.createEmptyBorder(22,22,22,22));pane.add(state,BorderLayout.NORTH);
            JButton trigger=Ui.button("隐藏窗口并触发托盘右键事件",true);pane.add(trigger,BorderLayout.CENTER);frame.setContentPane(pane);
            Set<TrayIcon> old=new HashSet<>(Arrays.asList(SystemTray.getSystemTray().getTrayIcons()));Runnable exit=()->{tray.remove();frame.dispose();};
            try{tray.add(()->{frame.setVisible(true);frame.toFront();state.setText("已从托盘菜单恢复测试窗口");},exit);}catch(AWTException e){throw new RuntimeException(e);}
            final TrayIcon icon=Arrays.stream(SystemTray.getSystemTray().getTrayIcons()).filter(item->!old.contains(item)).findFirst().get();
            trigger.addActionListener(e->{Point point=MouseInfo.getPointerInfo().getLocation();frame.setVisible(false);TrayTest.rightClick(icon,point);});
            frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);frame.addWindowListener(new WindowAdapter(){public void windowClosing(WindowEvent event){exit.run();}});frame.setSize(480,200);frame.setLocationRelativeTo(null);frame.setVisible(true);
        });
    }
}
