package com.liuchao.rtpscope.desktop;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.function.*;
import com.liuchao.rtpscope.core.WaveformData;
import com.liuchao.rtpscope.core.WaveformViewport;

public final class WaveformPanel extends JPanel {
    public static final class KeyBadge {
        public final AudioPreview.Key key;
        public final Rectangle bounds;
        KeyBadge(AudioPreview.Key key,Rectangle bounds){this.key=key;this.bounds=bounds;}
    }
    private static final Color[] COLORS={new Color(0x0067c0),new Color(0xc27715),new Color(0x8250b8),new Color(0x087e60)};
    private AudioPreview preview;
    private double position;
    private final WaveformViewport viewport=new WaveformViewport();
    private Runnable windowListener;
    private DoubleConsumer seek;
    private Consumer<AudioPreview.Key> keyListener;
    public WaveformPanel() {
        setBackground(Ui.PANEL);setToolTipText("点击波形定位，点击按键标签看详情");
        addMouseListener(new MouseAdapter(){public void mousePressed(MouseEvent e){if(preview==null)return;KeyBadge badge=badgeAt(e.getPoint());if(badge!=null){if(seek!=null)seek.accept(badge.key.startMs);if(keyListener!=null)keyListener.accept(badge.key);}else if(seek!=null)seek.accept(timeAt(e.getX()));}});
        addMouseWheelListener(e->{if(preview==null)return;if(e.isControlDown()){viewport.zoomAt(Math.pow(1.25,-e.getPreciseWheelRotation()),(e.getX()-Ui.u(14))/(double)Math.max(1,getWidth()-Ui.u(28)));windowChanged();e.consume();}else if(e.isShiftDown()){viewport.pan(e.getPreciseWheelRotation()*viewport.spanMs()/10);windowChanged();e.consume();}else{Container parent=SwingUtilities.getAncestorOfClass(JScrollPane.class,this);if(parent!=null)parent.dispatchEvent(SwingUtilities.convertMouseEvent(this,e,parent));}});
        addComponentListener(new ComponentAdapter(){public void componentResized(ComponentEvent e){revalidate();}});
        getAccessibleContext().setAccessibleName("分方向音频波形与可点击的 DTMF 按键标签");
    }
    public void setData(WaveformData value){setPreview(AudioPreview.fromWaveform(value));}
    public void setPreview(AudioPreview value){preview=value;position=0;viewport.reset(value==null?1:value.mixed.durationMs());windowChanged();getAccessibleContext().setAccessibleDescription(value==null?"尚未生成波形":value.keySummary());}
    public WaveformViewport viewport(){return viewport;}
    public void setWindowListener(Runnable value){windowListener=value;}
    public void zoomBy(double factor){viewport.zoomAt(factor,viewport.contains(position)?viewport.fractionAt(position):0.5);windowChanged();}
    public void fit(){viewport.fit();windowChanged();}
    public void panTo(double startMs){viewport.setStartMs(startMs);windowChanged();}
    public void revealPosition(double ms){viewport.reveal(ms);windowChanged();}
    private void windowChanged(){revalidate();repaint();if(windowListener!=null)windowListener.run();}
    public AudioPreview preview(){return preview;}
    public WaveformData data(){return preview==null?null:preview.mixed;}
    public void setPosition(double ms){position=ms;repaint();}
    public void setSeekListener(DoubleConsumer listener){seek=listener;}
    public void setKeyListener(Consumer<AudioPreview.Key> listener){keyListener=listener;}
    public static Color trackColor(int index){return COLORS[index%COLORS.length];}
    public double timeAt(int x){return preview==null?0:viewport.timeAt((x-Ui.u(14))/(double)Math.max(1,getWidth()-Ui.u(28)));}
    private int x(double ms){return Ui.u(14)+(int)(viewport.fractionAt(ms)*Math.max(1,getWidth()-Ui.u(28)));}
    private static final class Layout {
        final List<KeyBadge> badges=new ArrayList<>();
        int[] top,height,rows,hidden;
        int total;
    }
    private Layout geometry() {
        Layout result=new Layout();if(preview==null){result.total=Ui.u(94);return result;}
        int count=preview.tracks.size();result.top=new int[count];result.height=new int[count];result.rows=new int[count];result.hidden=new int[count];
        FontMetrics fm=getFontMetrics(Ui.font(12));int available=Math.max(Ui.u(100),getWidth()-Ui.u(28)),right=Ui.u(14)+available;
        for(int track=0;track<count;track++) {
            int[] ends={-1,-1,-1};List<KeyBadge> pending=new ArrayList<>();
            for(AudioPreview.Key key:preview.keys)if(key.track==track&&viewport.contains(key.startMs)) {
                int width=Math.min(available,fm.stringWidth(key.badgeText())+Ui.u(18)),left=Math.max(Ui.u(14),Math.min(right-width,x(key.startMs)-width/2)),lane=-1;
                for(int n=0;n<3;n++)if(ends[n]+Ui.u(5)<=left){lane=n;break;}
                if(lane<0){result.hidden[track]++;continue;}
                ends[lane]=left+width;result.rows[track]=Math.max(result.rows[track],lane+1);
                pending.add(new KeyBadge(key,new Rectangle(left,Ui.u(23)+lane*Ui.u(24),width,Ui.u(21))));
            }
            result.top[track]=result.total;result.height[track]=Ui.u(80)+result.rows[track]*Ui.u(24);result.total+=result.height[track];
            for(KeyBadge badge:pending){badge.bounds.translate(0,result.top[track]);result.badges.add(badge);}
        }
        result.total+=Ui.u(24);return result;
    }
    public List<KeyBadge> keyBadges(){return Collections.unmodifiableList(geometry().badges);}
    public KeyBadge badgeAt(Point point){for(KeyBadge b:geometry().badges)if(b.bounds.contains(point))return b;return null;}
    public Dimension getPreferredSize(){return new Dimension(Ui.u(500),geometry().total);}
    private String keyText(AudioPreview.Key key){return key.badgeText()+" · "+key.typeLabel()+" · "+Ui.clock((long)key.startMs)+" · "+(key.event==null?String.format(Locale.ROOT,"%.1f ms",key.durationMs):key.event.durationText())+" · 波形 "+(key.track+1);}
    public String getToolTipText(MouseEvent e){if(preview==null)return "选择 RTP 流生成波形";KeyBadge badge=badgeAt(e.getPoint());if(badge!=null)return keyText(badge.key);for(AudioPreview.Key key:preview.keys)if(viewport.contains(key.startMs)&&Math.abs(x(key.startMs)-e.getX())<=Ui.u(7))return keyText(key);return Ui.clock((long)timeAt(e.getX()))+" · 点击定位";}
    protected void paintComponent(Graphics graphics) {
        super.paintComponent(graphics);Graphics2D g=(Graphics2D)graphics.create();g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,RenderingHints.VALUE_ANTIALIAS_ON);g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        int left=Ui.u(14),width=Math.max(1,getWidth()-Ui.u(28));
        if(preview==null){g.setColor(Ui.MUTED);g.setFont(Ui.font(13));g.drawString("选择 RTP 媒体流播放或生成波形，双向音频会分成上下两路",left,Ui.u(45));g.dispose();return;}
        Layout layout=geometry();double duration=viewport.spanMs();
        for(int track=0;track<preview.tracks.size();track++) {
            AudioPreview.Track source=preview.tracks.get(track);int top=layout.top[track],plotTop=top+Ui.u(28)+layout.rows[track]*Ui.u(24),bottom=top+layout.height[track]-Ui.u(7),center=(plotTop+bottom)/2,amplitude=Math.max(4,(bottom-plotTop)/2);
            g.setColor(trackColor(track));g.fillRoundRect(left,top+Ui.u(8),Ui.u(4),Ui.u(12),Ui.u(3),Ui.u(3));g.setFont(Ui.font(12));g.drawString((track+1)+"  "+source.label,left+Ui.u(11),top+Ui.u(18));
            if(layout.hidden[track]>0){g.setColor(Ui.MUTED);String more="另有 "+layout.hidden[track]+" 次，见按键列表";g.drawString(more,Math.max(left,getWidth()-g.getFontMetrics().stringWidth(more)-left),top+Ui.u(18));}
            for(WaveformData.Marker m:source.waveform.markers)if(!m.kind.equals("DTMF")) {
                if(source.offsetMs+m.endMs<viewport.startMs()||source.offsetMs+m.startMs>viewport.endMs())continue;int start=x(Math.max(viewport.startMs(),source.offsetMs+m.startMs)),end=x(Math.min(viewport.endMs(),source.offsetMs+m.endMs));g.setColor(m.kind.equals("LOSS")?new Color(0x32d13438,true):new Color(0x88bc8100,true));g.fillRect(start,plotTop,Math.max(Ui.u(2),end-start),bottom-plotTop);
            }
            g.setColor(Ui.LINE);g.drawLine(left,center,left+width,center);g.setColor(trackColor(track));
            int bins=source.waveform.minimum.length;double ownDuration=Math.max(1,source.waveform.durationMs());
            for(int px=0;px<width;px++) {
                double local=viewport.startMs()+duration*px/width-source.offsetMs;if(local<0||local>=ownDuration)continue;
                int begin=(int)(local/ownDuration*bins),end=Math.min(bins,Math.max(begin+1,(int)((local+duration/width)/ownDuration*bins))),min=32767,max=-32768;
                for(int i=begin;i<end;i++){min=Math.min(min,source.waveform.minimum[i]);max=Math.max(max,source.waveform.maximum[i]);}
                g.drawLine(left+px,center-max*amplitude/32768,left+px,center-min*amplitude/32768);
            }
            for(AudioPreview.Key key:preview.keys)if(key.track==track&&viewport.contains(key.startMs)){int start=x(key.startMs);g.setColor(Ui.POSITIVE);g.drawLine(start,plotTop,start,bottom);}
            for(KeyBadge b:layout.badges)if(b.key.track==track) {
                Rectangle r=b.bounds;g.setColor(new Color(0xe1f4eb));g.fillRoundRect(r.x,r.y,r.width,r.height,Ui.u(6),Ui.u(6));g.setColor(Ui.POSITIVE);g.drawRoundRect(r.x,r.y,r.width,r.height,Ui.u(6),Ui.u(6));g.setFont(Ui.font(12));FlowPanel.centered(g,b.key.badgeText(),r.x+r.width/2,r.y+Ui.u(15),r.width-Ui.u(6));g.drawLine(x(b.key.startMs),r.y+r.height,x(b.key.startMs),plotTop);
            }
            g.setColor(Ui.LINE);g.drawLine(left,top+layout.height[track],left+width,top+layout.height[track]);
        }
        g.setColor(new Color(0x475569));int cursor=x(position);if(viewport.contains(position))g.drawLine(cursor,0,cursor,layout.total-Ui.u(22));g.setFont(Ui.font(11));g.setColor(Ui.MUTED);
        for(int n=0;n<=4;n++){String tick=String.format(Locale.ROOT,"%.2fs",(viewport.startMs()+duration*n/4)/1000);int xx=left+width*n/4;if(n==0)g.drawString(tick,xx,layout.total-Ui.u(5));else if(n==4)g.drawString(tick,xx-g.getFontMetrics().stringWidth(tick),layout.total-Ui.u(5));else FlowPanel.centered(g,tick,xx,layout.total-Ui.u(5),Ui.u(110));}g.dispose();
    }
}
