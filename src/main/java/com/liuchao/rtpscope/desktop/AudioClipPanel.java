package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.Locale;
import java.util.concurrent.CancellationException;

/** Shared excerpt editor for decoded RTP and imported recordings; source files are borrowed. */
final class AudioClipPanel extends JPanel implements AutoCloseable {
    final WaveformPanel waveform=new WaveformPanel();
    final JSpinner start,end;
    final JButton listen=Ui.button("试听片段",false),save=Ui.button("另存音频",true),stop=Ui.button("停止试听",false);
    private final JLabel range=Ui.label("",13,Ui.ACCENT),status=Ui.label("拖动波形选择范围，或输入起止秒数",12,Ui.MUTED);
    private final AudioPreview preview;
    private final File source;
    private File original;
    private final boolean recording;
    private final String sourceName;
    private final double durationMs;
    private final int channels;
    private final WavPlayer player=new WavPlayer();
    private final javax.swing.Timer timer;
    private SwingWorker<File,Void> job;
    private volatile boolean closed;
    private boolean updating,previewing;
    private File playing;
    private double playbackStart;

    AudioClipPanel(AudioPreview preview,File source,boolean recording,String name,double a,double b)throws IOException{
        super(new BorderLayout(Ui.u(10),Ui.u(12)));this.preview=preview;this.source=source;original=source;this.recording=recording;sourceName=name;
        if(recording){try(PcmFile pcm=new PcmFile(source)){durationMs=pcm.durationMs();}}else durationMs=preview.mixed.durationMs();
        if(durationMs<=0)throw new IOException("音频为空，无法截取");
        setBackground(Ui.BG);setBorder(BorderFactory.createEmptyBorder(Ui.u(16),Ui.u(16),Ui.u(14),Ui.u(16)));
        JPanel header=new JPanel(new GridLayout(0,1,0,Ui.u(6)));header.setOpaque(false);header.add(Ui.label("截取音频",21,Ui.INK));JLabel title=Ui.label(name,13,Ui.INK);title.setToolTipText(name);header.add(title);
        int count=preview.tracks.size();if(recording)try(PcmFile pcm=new PcmFile(source)){count=pcm.channels;}channels=count;
        header.add(Ui.label("总时长 "+Ui.clock(Math.round(durationMs))+" · "+channels+" 个独立声道 · 保存为一个 "+(channels<=2?"WAV / MP3":"WAV")+" 文件",12,Ui.MUTED));
        header.add(Ui.label(channels<=2?"MP3 为有损格式，部分播放器可能出现前后空白；需要精确起止时间时请选择 WAV":"MP3 最多支持双声道；当前使用 WAV 保留全部独立声道",12,Ui.MUTED));add(header,BorderLayout.NORTH);
        waveform.setName("clipWaveform");waveform.setPreview(preview);waveform.setToolTipText("拖动选择截取范围；Ctrl＋滚轮缩放，Shift＋滚轮平移；点击定位");
        JScrollPane wave=Ui.scroll(waveform);wave.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);JPanel graph=Ui.card(new BorderLayout(0,Ui.u(8)));graph.add(wave,BorderLayout.CENTER);
        JPanel zoom=new JPanel(new FlowLayout(FlowLayout.LEFT,Ui.u(6),0));zoom.setOpaque(false);JButton minus=Ui.button("−",false),plus=Ui.button("＋",false),fit=Ui.button("全览",false);zoom.add(minus);zoom.add(plus);zoom.add(fit);zoom.add(Ui.label("蓝色区域为待保存片段",12,Ui.MUTED));graph.add(zoom,BorderLayout.NORTH);
        JScrollBar pan=new JScrollBar(JScrollBar.HORIZONTAL);graph.add(pan,BorderLayout.SOUTH);final boolean[] panning={false};
        waveform.setWindowListener(()->{WaveformViewport v=waveform.viewport();panning[0]=true;int extent=Math.max(1,(int)Math.round(100000/v.zoom()));pan.setValues((int)Math.round(v.startMs()/v.durationMs()*100000),extent,0,100000);pan.setVisible(v.zoom()>1);panning[0]=false;});waveform.fit();
        pan.addAdjustmentListener(e->{if(!panning[0])waveform.panTo(pan.getValue()/100000.0*waveform.viewport().durationMs());});minus.addActionListener(e->waveform.zoomBy(.5));plus.addActionListener(e->waveform.zoomBy(2));fit.addActionListener(e->waveform.fit());add(graph,BorderLayout.CENTER);
        start=spinner(0);end=spinner(durationMs/1000);start.setName("clipStart");end.setName("clipEnd");
        JPanel footer=Ui.card(new BorderLayout(0,Ui.u(10))),times=new JPanel(new FlowLayout(FlowLayout.LEFT,Ui.u(8),0));times.setOpaque(false);times.add(Ui.label("起点（秒）",13,Ui.INK));times.add(start);times.add(Ui.label("终点（秒）",13,Ui.INK));times.add(end);times.add(range);footer.add(times,BorderLayout.NORTH);
        JPanel actions=new JPanel(new FlowLayout(FlowLayout.LEFT,Ui.u(6),0));actions.setOpaque(false);JButton markStart=Ui.button("当前点设为起点",false),markEnd=Ui.button("当前点设为终点",false);markStart.setName("clipMarkStart");markEnd.setName("clipMarkEnd");listen.setName("clipListen");save.setName("clipSave");stop.setEnabled(false);for(JButton button:new JButton[]{markStart,markEnd,listen,stop,save})actions.add(button);footer.add(actions,BorderLayout.CENTER);footer.add(status,BorderLayout.SOUTH);add(footer,BorderLayout.SOUTH);
        start.addChangeListener(e->{if(!updating)stopPlayback();selectionChanged();});end.addChangeListener(e->{if(!updating)stopPlayback();selectionChanged();});
        waveform.setSeekListener(ms->{if(!working()){stopPlayback();waveform.setPosition(ms);}});
        waveform.setSelectionListener((from,to)->{if(!working()){stopPlayback();setRange(from,to);}});
        markStart.addActionListener(e->{if(!working())start.setValue(Math.min(durationMs,waveform.position())/1000);});markEnd.addActionListener(e->{if(!working())end.setValue(Math.min(durationMs,waveform.position())/1000);});
        listen.addActionListener(e->listen());stop.addActionListener(e->stopPlayback());save.addActionListener(e->chooseSave());
        timer=new javax.swing.Timer(100,e->{if(previewing&&player.ready()){waveform.setPosition(playbackStart+player.position());if(!player.playing())stopPlayback();}});timer.start();
        setRange(Math.max(0,Math.min(a,durationMs)),b>a?Math.min(b,durationMs):durationMs);
    }
    private JSpinner spinner(double seconds){JSpinner result=new JSpinner(new SpinnerNumberModel(seconds,0.0,durationMs/1000,.1));result.setEditor(new JSpinner.NumberEditor(result,"0.000"));result.setPreferredSize(new Dimension(Ui.u(125),Ui.u(34)));result.setToolTipText("单位：秒，支持三位小数");return result;}
    void setRange(double a,double b){updating=true;try{start.setValue(a/1000);end.setValue(b/1000);}finally{updating=false;}selectionChanged();}
    private double[] selectionBounds()throws IOException{
        try{start.commitEdit();end.commitEdit();}catch(java.text.ParseException invalid){throw new IOException("请输入有效的起止秒数");}
        double a=((Number)start.getValue()).doubleValue()*1000,b=((Number)end.getValue()).doubleValue()*1000;
        // The displayed end may round up by less than half a millisecond.
        if(b>durationMs&&b-durationMs<=.500001)b=durationMs;
        AudioClip.validateRange(a,b,durationMs);return new double[]{a,b};
    }
    private void selectionChanged(){if(updating)return;double a=((Number)start.getValue()).doubleValue()*1000,b=Math.min(durationMs,((Number)end.getValue()).doubleValue()*1000);boolean valid=a>=0&&b>a;waveform.setSelection(valid?a:-1,valid?b:-1);range.setText(valid?Ui.clock(Math.round(a))+" → "+Ui.clock(Math.round(b))+" · "+String.format(Locale.ROOT,"%.3f 秒",(b-a)/1000):"终点须晚于起点");range.setForeground(valid?Ui.ACCENT:new Color(0xc42b1c));listen.setEnabled(valid&&!working());save.setEnabled(valid&&!working());}
    private boolean working(){return job!=null&&!job.isDone();}
    private void busy(boolean value){start.setEnabled(!value);end.setEnabled(!value);waveform.setEnabled(!value);listen.setEnabled(!value);save.setEnabled(!value);if(!value)selectionChanged();}
    private void showStatus(String message){status.setText(message);status.setToolTipText(message);}
    private void stopPlayback(){previewing=false;player.close();stop.setEnabled(false);if(playing!=null){if(!playing.delete())playing.deleteOnExit();playing=null;}}
    private void write(File target,double a,double b)throws IOException{AudioClip.different(source,target);AudioClip.different(original,target);for(AudioPreview.Track track:preview.tracks)AudioClip.different(track.audio,target);AudioExport.save(target,AudioExport.Format.of(target),wav->{if(recording)AudioClip.save(source,wav,a,b);else preview.exportClip(wav,a,b);},NativeMedia::encodeMp3);}
    private void listen(){
        if(working()||closed)return;final double[] selected;try{selected=selectionBounds();}catch(IOException e){showStatus(e.getMessage());return;}stopPlayback();busy(true);showStatus("正在准备片段试听…");
        job=new SwingWorker<File,Void>(){File temp;protected File doInBackground()throws Exception{
            temp=File.createTempFile("huatan-clip-listen-",".wav");boolean ready=false;
            try{AudioClip.save(source,temp,selected[0],selected[1]);int channels,rate;try(PcmFile pcm=new PcmFile(temp)){channels=pcm.channels;rate=pcm.rate;}if(channels>2){File mono=File.createTempFile("huatan-clip-mono-",".wav");try{PcmTracks.channel(temp,-1,mono,Math.min(48000,rate));if(!temp.delete())temp.deleteOnExit();temp=mono;}catch(Exception e){mono.delete();throw e;}}player.load(temp);if(closed||isCancelled())throw new InterruptedIOException("试听已取消");ready=true;return temp;}
            finally{if(!ready){player.close();if(temp!=null&&!temp.delete())temp.deleteOnExit();}}
        }protected void done(){if(closed||isCancelled()){player.close();if(temp!=null&&!temp.delete())temp.deleteOnExit();if(!closed){busy(false);showStatus("试听已取消");}return;}busy(false);try{playing=get();playbackStart=selected[0];waveform.setPosition(playbackStart);previewing=true;stop.setEnabled(true);player.play();showStatus("正在试听所选片段 · 多于两路时试听混合，保存仍保留全部声道");}catch(Exception e){showStatus("试听未完成："+Ui.error(e));}}};job.execute();
    }
    private void chooseSave(){
        if(working()||closed)return;double[] selected;try{selected=selectionBounds();}catch(IOException e){showStatus(e.getMessage());return;}
        String base=sourceName.replaceFirst("\\.[^.]+$","").replaceAll("[<>:\"/\\\\|?*\\p{Cntrl}]","_");
        File target=AudioSaveDialog.choose(this,"截取音频 · 另存音频",base+"-clip-"+Math.round(selected[0])+"-"+Math.round(selected[1])+"ms",channels);
        if(target!=null)saveSelection(target);
    }
    void saveSelection(File target){
        if(working()||closed)return;final double[] selected;try{selected=selectionBounds();}catch(IOException e){showStatus(e.getMessage());return;}stopPlayback();busy(true);showStatus("正在保存音频片段…");
        job=new SwingWorker<File,Void>(){protected File doInBackground()throws Exception{write(target,selected[0],selected[1]);return target;}protected void done(){if(closed)return;busy(false);try{File result=get();showStatus("片段已保存："+result.getAbsolutePath());}catch(CancellationException cancelled){showStatus("截取已取消");}catch(Exception e){showStatus("保存未完成："+Ui.error(e));}}};job.execute();
    }
    boolean finished(){return !working();}
    String statusText(){return status.getText();}
    public void close(){closed=true;if(job!=null)job.cancel(true);timer.stop();stopPlayback();}
    static void open(Component owner,AudioPreview preview,File source,File original,boolean recording,String name,double a,double b){
        try{AudioClipPanel content=new AudioClipPanel(preview,source,recording,name,a,b);content.original=original;JDialog dialog=new JDialog(SwingUtilities.getWindowAncestor(owner),"截取音频",Dialog.ModalityType.APPLICATION_MODAL);dialog.setContentPane(content);dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);dialog.addWindowListener(new WindowAdapter(){public void windowClosed(WindowEvent e){content.close();}});Ui.fitWindow(dialog,1000,620,860,500);dialog.setLocationRelativeTo(owner);try{dialog.setVisible(true);}finally{content.close();}}
        catch(IOException e){JOptionPane.showMessageDialog(owner,Ui.error(e),"截取音频",JOptionPane.ERROR_MESSAGE);}
    }
}
