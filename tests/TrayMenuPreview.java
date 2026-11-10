package com.liuchao.rtpscope.desktop;

import java.awt.*;
import java.awt.event.*;
import javax.swing.SwingUtilities;

/** Optional visual check using the exact native menu factory used by the tray icon. */
public final class TrayMenuPreview {
    public static void main(String[] args)throws Exception{
        SwingUtilities.invokeAndWait(()->{
            Ui.setup();Frame frame=new Frame("超哥话探 · 托盘菜单显示检查");frame.setFont(Ui.font(13));
            Label label=new Label("在这里右键，检查中文菜单；选退出关闭测试窗口",Label.CENTER);label.setFont(Ui.font(13));frame.add(label);
            PopupMenu menu=TrayManager.NativeTray.menu(()->label.setText("已执行打开主界面操作"),frame::dispose);frame.add(menu);
            MouseAdapter mouse=new MouseAdapter(){private void popup(MouseEvent event){if(event.isPopupTrigger())menu.show(event.getComponent(),event.getX(),event.getY());}public void mousePressed(MouseEvent e){popup(e);}public void mouseReleased(MouseEvent e){popup(e);}};label.addMouseListener(mouse);frame.addMouseListener(mouse);
            frame.addWindowListener(new WindowAdapter(){public void windowClosing(WindowEvent event){frame.dispose();}});frame.setSize(500,220);frame.setLocationRelativeTo(null);frame.setVisible(true);
        });
    }
}
