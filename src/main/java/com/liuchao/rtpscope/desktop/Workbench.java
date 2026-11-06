package com.liuchao.rtpscope.desktop;
import com.liuchao.rtpscope.core.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.util.*;
import java.util.List;

/** Primary workspaces keep capture analysis and recording transcription navigable. */
final class Workbench extends JPanel {
    private final RecordingPanel recording=new RecordingPanel();private final JTabbedPane workspaces=new JTabbedPane();private SwingWorker<File,Void> job;private boolean closed;
    Workbench(DesktopApp capture){super(new BorderLayout());workspaces.addTab("抓包分析",capture);workspaces.addTab("录音转文字",recording);add(workspaces,BorderLayout.CENTER);capture.setTranscriptHandler(preview->{
        if(preview==null||job!=null&&!job.isDone())return;List<File> tracks=new ArrayList<>();List<Double> offsets=new ArrayList<>();List<String> labels=new ArrayList<>();for(AudioPreview.Track t:preview.tracks){tracks.add(t.audio);offsets.add(t.offsetMs);labels.add(t.label);}if(tracks.size()>2){JOptionPane.showMessageDialog(this,"请选取需要转写的两路媒体方向");return;}
        capture.preparingTranscript(true);
        job=new SwingWorker<File,Void>(){File target;protected File doInBackground()throws Exception{target=File.createTempFile("huatan-rtp-transcript-",".wav");try{boolean[] enabled=new boolean[tracks.size()];Arrays.fill(enabled,true);PcmTracks.mix(tracks,offsets,enabled,tracks.size()==2,target);if(isCancelled())throw new InterruptedIOException("转写准备已取消");return target;}catch(Exception e){target.delete();throw e;}}protected void done(){capture.preparingTranscript(false);if(closed){if(target!=null)target.delete();return;}try{recording.addPrepared(get(),"RTP 通话音频",labels.get(0),labels.size()>1?labels.get(1):"右声道");workspaces.setSelectedIndex(1);}catch(Exception e){JOptionPane.showMessageDialog(Workbench.this,Ui.error(e));}}};job.execute();
    });}
    void close(){closed=true;if(job!=null)job.cancel(true);recording.close();}
}
