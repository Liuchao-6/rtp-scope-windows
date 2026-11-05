package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.text.SimpleDateFormat;
import java.util.*;
import com.formdev.flatlaf.FlatLightLaf;
import com.liuchao.rtpscope.core.SipSyntax;

final class Ui {
    static final Color BG=new Color(0xf5f6f8),PANEL=Color.WHITE,RAISED=new Color(0xf0f3f7),INK=new Color(0x202830),MUTED=new Color(0x66717d),ACCENT=new Color(0x0067c0),LINE=new Color(0xe0e5ec),SELECTED=new Color(0xe7f1fb),POSITIVE=new Color(0x087e60);
    static final double SCALE=GraphicsEnvironment.isHeadless()?1:Math.max(1,Toolkit.getDefaultToolkit().getScreenResolution()/96.0);
    static int u(int value){return (int)Math.round(value*SCALE);}
    private static final String FONT_FAMILY=fontFamily();
    private static String fontFamily(){for(String family:new String[]{"Microsoft YaHei UI","Microsoft YaHei",Font.DIALOG})if(new Font(family,Font.PLAIN,13).canDisplayUpTo("超哥话探 通话波形按键详情")==-1)return family;return Font.DIALOG;}
    static Font font(int size){return new Font(FONT_FAMILY,Font.PLAIN,u(size));}
    static void setup() {
        System.setProperty("flatlaf.uiScale","1x");FlatLightLaf.setup();
        String[] bases={"Panel","Label","Button","ToggleButton","TextField","TextArea","TextPane","Table","TableHeader","List","ComboBox","TabbedPane","CheckBox","Menu","MenuItem","OptionPane","ScrollPane","Viewport","ToolTip","FileChooser","Slider","SplitPane","ScrollBar"};
        for(String base:bases){UIManager.put(base+".font",font(13));UIManager.put(base+".foreground",INK);UIManager.put(base+".background",PANEL);}
        UIManager.put("TextField.caretForeground",INK);UIManager.put("TextPane.caretForeground",INK);UIManager.put("TextArea.caretForeground",INK);
        UIManager.put("Table.selectionBackground",SELECTED);UIManager.put("Table.selectionForeground",INK);UIManager.put("List.selectionBackground",SELECTED);UIManager.put("List.selectionForeground",INK);
        UIManager.put("Table.alternateRowColor",new Color(0xf9fafc));UIManager.put("Component.accentColor",ACCENT);UIManager.put("TabbedPane.underlineColor",ACCENT);UIManager.put("TabbedPane.selectedBackground",PANEL);UIManager.put("TabbedPane.contentAreaColor",PANEL);
        UIManager.put("OptionPane.messageForeground",INK);UIManager.put("OptionPane.buttonFont",font(13));
        UIManager.put("Button.arc",u(8));UIManager.put("Component.arc",u(8));UIManager.put("TextComponent.arc",u(8));UIManager.put("Component.focusWidth",1);UIManager.put("Button.minimumHeight",u(34));UIManager.put("TabbedPane.tabHeight",u(38));UIManager.put("SplitPane.dividerSize",u(10));UIManager.put("ScrollBar.width",u(12));
        System.setProperty("awt.useSystemAAFontSettings","on");System.setProperty("swing.aatext","true");
    }
    static JButton button(String label,boolean primary) {
        JButton b=new JButton(label);b.setFont(font(13));b.setForeground(primary?Color.WHITE:INK);b.setBackground(primary?ACCENT:PANEL);b.setMargin(new Insets(u(7),u(13),u(7),u(13)));
        b.putClientProperty("JButton.buttonType",primary?"roundRect":"roundRect");return b;
    }
    static JLabel label(String value,int size,Color color){JLabel l=new JLabel(value);l.putClientProperty("html.disable",Boolean.TRUE);l.setFont(font(size));l.setForeground(color);return l;}
    static JTextArea note(String value){JTextArea a=new JTextArea(value);a.setEditable(false);a.setLineWrap(true);a.setWrapStyleWord(true);a.setFont(font(12));a.setForeground(MUTED);a.setBackground(PANEL);return a;}
    static JScrollPane scroll(Component c){JScrollPane s=new JScrollPane(c);s.setBorder(new LineBorder(LINE));s.getViewport().setBackground(PANEL);s.getVerticalScrollBar().setUnitIncrement(u(24));return s;}
    static Color syntaxColor(SipSyntax.Kind kind){switch(kind){case HEADER:return new Color(0x005fb8);case METHOD:return new Color(0x7545b5);case URI:return new Color(0xa65312);case ID:case SUCCESS:return POSITIVE;case SDP:return new Color(0x4d6296);case PROVISIONAL:return new Color(0x936000);case ERROR:return new Color(0xc42b1c);default:return INK;}}
    static String stamp(long us){return new SimpleDateFormat("HH:mm:ss.SSS",Locale.ROOT).format(new Date(us/1000));}
    static String clock(long ms){return String.format(Locale.ROOT,"%02d:%02d.%03d",ms/60000,(ms/1000)%60,ms%1000);}
    static String shortText(String s,int size){return s.length()>size?s.substring(0,size-1)+"…":s;}
    static BufferedImage icon() {
        BufferedImage img=new BufferedImage(64,64,BufferedImage.TYPE_INT_ARGB);Graphics2D g=img.createGraphics();g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(ACCENT);g.fillRoundRect(0,0,64,64,16,16);g.setColor(Color.WHITE);int[] heights={14,26,42,30,18};
        for(int i=0;i<5;i++)g.fillRoundRect(11+i*9,32-heights[i]/2,5,heights[i],4,4);g.dispose();return img;
    }
    static void copy(String value){Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(value),null);}
    static void fitWindow(Window window,int width,int height,int minWidth,int minHeight){Rectangle area=GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();int w=Math.min(u(width),(int)(area.width*0.96)),h=Math.min(u(height),(int)(area.height*0.96));window.setMinimumSize(new Dimension(Math.min(u(minWidth),w),Math.min(u(minHeight),h)));window.setSize(w,h);}
    static String error(Throwable error){Throwable e=error;while(e.getCause()!=null)e=e.getCause();return e.getMessage()==null?e.getClass().getSimpleName():e.getMessage();}
}
