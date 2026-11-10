package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.function.Consumer;
import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;

/** Draws only visible rows; no component per packet and no raster as large as the capture. */
public final class FlowPanel extends JPanel implements Scrollable {
    private CallFlow flow=new CallFlow();
    private Consumer<Object> open;
    private final Map<String,Integer> nodes=new HashMap<>();
    private int selected=-1;
    private final JComponent header=new Header(),times=new Times();
    private final int row=Ui.u(82),spacing=Ui.u(230),pad=Ui.u(100);
    public FlowPanel() {
        setOpaque(true);setBackground(Ui.PANEL);setFocusable(true);setToolTipText("点击消息箭头查看详情；滚轮浏览，Shift＋滚轮横向滚动");
        addMouseListener(new MouseAdapter(){public void mousePressed(MouseEvent e){requestFocusInWindow();activate(entryAt(e.getPoint()));}});
        addKeyListener(new KeyAdapter(){public void keyPressed(KeyEvent e){if(flow.entries.isEmpty())return;if(e.getKeyCode()==KeyEvent.VK_DOWN)select(Math.min(flow.entries.size()-1,selected+1));else if(e.getKeyCode()==KeyEvent.VK_UP)select(Math.max(0,selected-1));else if(e.getKeyCode()==KeyEvent.VK_ENTER)activate(selected);}});
        getAccessibleContext().setAccessibleName("SIP RTP 通话流序图");
    }
    public JScrollPane scrollPane() {
        JScrollPane scroll=Ui.scroll(this);scroll.setColumnHeaderView(header);scroll.setRowHeaderView(times);
        JLabel corner=Ui.label(" 相对时间 / 秒",11,Ui.MUTED);corner.setOpaque(true);corner.setBackground(Ui.PANEL);scroll.setCorner(JScrollPane.UPPER_LEFT_CORNER,corner);
        scroll.getHorizontalScrollBar().setUnitIncrement(Ui.u(60));return scroll;
    }
    public void setOpenListener(Consumer<Object> callback){open=callback;}
    public CallFlow data(){return flow;}
    public void setData(CallFlow value) {
        setData(value,false);
    }
    public void setData(CallFlow value,boolean keepSelection) {
        Object source=keepSelection&&selected>=0&&selected<flow.entries.size()?flow.entries.get(selected).source:null;
        flow=value;nodes.clear();for(int i=0;i<flow.nodes.size();i++)nodes.put(flow.nodes.get(i),i);selected=-1;
        if(source!=null)for(int i=0;i<flow.entries.size();i++)if(flow.entries.get(i).source==source){selected=i;break;}
        revalidate();repaint();header.revalidate();header.repaint();times.revalidate();times.repaint();
    }
    public int entryAt(Point point){int n=point.y/row;return point.y>=0&&n<flow.entries.size()?n:-1;}
    private void select(int value){selected=value;scrollRectToVisible(new Rectangle(0,selected*row,1,row));repaint();times.repaint();}
    private void activate(int value){if(value>=0&&value<flow.entries.size()){select(value);if(open!=null)open.accept(flow.entries.get(value).source);}}
    private int x(String ip){return pad+spacing*nodes.get(ip);}
    public Dimension getPreferredSize(){return new Dimension(Math.max(Ui.u(480),2*pad+Math.max(0,flow.nodes.size()-1)*spacing),Math.max(Ui.u(220),flow.entries.size()*row));}
    public Dimension getPreferredScrollableViewportSize(){return new Dimension(Ui.u(680),Ui.u(480));}
    public int getScrollableUnitIncrement(Rectangle r,int orientation,int direction){return orientation==SwingConstants.VERTICAL?row/2:Ui.u(60);}
    public int getScrollableBlockIncrement(Rectangle r,int orientation,int direction){return orientation==SwingConstants.VERTICAL?Math.max(row,r.height-row):Math.max(spacing,r.width-spacing);}
    public boolean getScrollableTracksViewportWidth(){return getParent()!=null&&getParent().getWidth()>getPreferredSize().width;}
    public boolean getScrollableTracksViewportHeight(){return false;}
    public static Color color(CallFlow.Entry e) {
        if(e.source instanceof DtmfParser.Event)return Ui.POSITIVE;
        if(e.source instanceof RtpStream)return Ui.ACCENT;
        String first=((SipMessage)e.source).firstLine;
        return Ui.syntaxColor(first.startsWith("SIP/2.0 1")?SipSyntax.Kind.PROVISIONAL:first.startsWith("SIP/2.0 2")?SipSyntax.Kind.SUCCESS:first.startsWith("SIP/2.0")?SipSyntax.Kind.ERROR:SipSyntax.Kind.METHOD);
    }
    static void centered(Graphics2D g,String text,int center,int y,int width) {
        FontMetrics fm=g.getFontMetrics();String value=text;
        if(fm.stringWidth(value)>width){while(!value.isEmpty()&&fm.stringWidth(value+"…")>width)value=value.substring(0,value.length()-1);value+="…";}
        g.drawString(value,center-fm.stringWidth(value)/2,y);
    }
    protected void paintComponent(Graphics graphics) {
        super.paintComponent(graphics);Graphics2D g=(Graphics2D)graphics.create();g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,RenderingHints.VALUE_ANTIALIAS_ON);
        Rectangle clip=g.getClipBounds();int first=Math.max(0,clip.y/row),last=Math.min(flow.entries.size(),(clip.y+clip.height)/row+1);
        if(flow.entries.isEmpty()){g.setColor(Ui.MUTED);g.setFont(Ui.font(14));g.drawString("导入抓包或点击「体验演示」；无匹配时可清空搜索",Ui.u(25),Ui.u(65));}
        for(int i=first;i<last;i++) {
            CallFlow.Entry e=flow.entries.get(i);int top=i*row,from=x(e.src.ip),to=x(e.dst.ip),line=top+Ui.u(38);boolean loop=from==to;
            if(i==selected){g.setColor(Ui.SELECTED);g.fillRect(clip.x,top,clip.width,row);}
            g.setColor(Ui.LINE);g.setStroke(new BasicStroke(1,0,0,1,new float[]{Ui.u(3),Ui.u(5)},0));
            for(String ip:flow.nodes){int xx=x(ip);if(xx>=clip.x&&xx<=clip.x+clip.width)g.drawLine(xx,top,xx,top+row);}
            g.setColor(color(e));g.setStroke(new BasicStroke(Ui.u(2)));g.setFont(Ui.font(13));int center=loop?from+Ui.u(48):(from+to)/2;
            centered(g,e.title,center,top+Ui.u(22),loop?Ui.u(145):Math.abs(to-from)-Ui.u(12));
            if(loop){g.drawLine(from,line,from+Ui.u(78),line);g.drawLine(from+Ui.u(78),line,from+Ui.u(78),line+Ui.u(12));line+=Ui.u(12);g.drawLine(from+Ui.u(78),line,to,line);}else g.drawLine(from,line,to,line);
            int sign=loop?-1:to>from?1:-1;g.fillPolygon(new int[]{to,to-sign*Ui.u(8),to-sign*Ui.u(8)},new int[]{line,line-Ui.u(4),line+Ui.u(4)},3);
            g.setFont(Ui.font(10));g.setColor(Ui.MUTED);
            if(loop)centered(g,e.src.port+" → "+e.dst.port,center,top+Ui.u(65),Ui.u(145));else {centered(g,e.src.port,from,top+Ui.u(55),Ui.u(76));centered(g,e.dst.port,to,top+Ui.u(55),Ui.u(76));}
            centered(g,e.detail,center,top+Ui.u(76),loop?Ui.u(156):Math.abs(to-from)+Ui.u(120));
            g.setColor(Ui.RAISED);g.setStroke(new BasicStroke(1));g.drawLine(clip.x,top+row-1,clip.x+clip.width,top+row-1);
        }g.dispose();
    }
    private final class Header extends JPanel {
        Header(){setOpaque(true);setBackground(Ui.PANEL);}
        public Dimension getPreferredSize(){return new Dimension(FlowPanel.this.getPreferredSize().width,Ui.u(56));}
        protected void paintComponent(Graphics graphics){super.paintComponent(graphics);Graphics2D g=(Graphics2D)graphics.create();g.setColor(Ui.INK);g.setFont(Ui.font(11));for(String ip:flow.nodes){int center=x(ip);if(ip.length()>24){int half=(ip.length()+1)/2;centered(g,ip.substring(0,half),center,Ui.u(20),spacing-Ui.u(12));centered(g,ip.substring(half),center,Ui.u(37),spacing-Ui.u(12));}else centered(g,ip,center,Ui.u(29),spacing-Ui.u(12));g.setColor(Ui.LINE);g.drawLine(center,Ui.u(44),center,getHeight());g.setColor(Ui.INK);}g.dispose();}
    }
    private final class Times extends JPanel {
        Times(){setOpaque(true);setBackground(Ui.PANEL);}
        public Dimension getPreferredSize(){return new Dimension(Ui.u(102),FlowPanel.this.getPreferredSize().height);}
        protected void paintComponent(Graphics graphics){super.paintComponent(graphics);Graphics2D g=(Graphics2D)graphics.create();Rectangle r=g.getClipBounds();g.setFont(Ui.font(11));for(int i=Math.max(0,r.y/row);i<Math.min(flow.entries.size(),(r.y+r.height)/row+1);i++){if(i==selected){g.setColor(Ui.SELECTED);g.fillRect(0,i*row,getWidth(),row);}g.setColor(Ui.MUTED);centered(g,String.format(Locale.ROOT,"%.6f",(flow.entries.get(i).timeUs-flow.originUs)/1000000.0),getWidth()/2,i*row+Ui.u(38),getWidth()-Ui.u(8));}g.dispose();}
    }
}
