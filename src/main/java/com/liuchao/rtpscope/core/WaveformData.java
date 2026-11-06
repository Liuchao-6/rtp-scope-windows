package com.liuchao.rtpscope.core;

import java.io.*;
import java.util.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;

/** Bounded-memory min/max waveform derived from decoded PCM, rather than packet sizes. */
public final class WaveformData {
    public short[] minimum,maximum;
    public long samples;
    public int rate;
    public final List<Marker> markers=new ArrayList<>();
    public static final class Marker {
        public double startMs,endMs;
        public String kind,label;
        public DtmfParser.Event event;
    }
    public double durationMs(){return samples*1000.0/rate;}
    public static WaveformData load(File wav,List<RtpStream> streams) throws IOException {
        WaveformData data=new WaveformData();
        try(RandomAccessFile in=new RandomAccessFile(wav,"r")) {
            byte[] h=new byte[44];in.readFully(h);
            if(h[0]!='R'||h[8]!='W'||h[20]!=1||h[22]!=1||h[34]!=16)throw new IOException("波形需要单声道 PCM16 WAV");
            data.rate=(h[24]&255)|((h[25]&255)<<8)|((h[26]&255)<<16)|((h[27]&255)<<24);
            if(data.rate<=0)throw new IOException("WAV 采样率无效");
            data.samples=(in.length()-44)/2;
            int bins=(int)Math.min(262144,Math.max(1,data.samples));
            data.minimum=new short[bins];data.maximum=new short[bins];
            Arrays.fill(data.minimum,Short.MAX_VALUE);Arrays.fill(data.maximum,Short.MIN_VALUE);
            byte[] buffer=new byte[32768];long sample=0;int count;
            while((count=in.read(buffer))!=-1) {
                for(int i=0;i+1<count;i+=2) {
                    short value=(short)((buffer[i]&255)|((buffer[i+1]&255)<<8));
                    int bin=(int)Math.min(bins-1,sample*bins/Math.max(1,data.samples));sample++;
                    data.minimum[bin]=(short)Math.min(data.minimum[bin],value);data.maximum[bin]=(short)Math.max(data.maximum[bin],value);
                }
            }
            for(int i=0;i<bins;i++)if(data.minimum[i]==Short.MAX_VALUE&&data.maximum[i]==Short.MIN_VALUE)data.minimum[i]=data.maximum[i]=0;
        }
        long origin=Long.MAX_VALUE;for(RtpStream s:streams)origin=Math.min(origin,s.firstUs());
        Set<QualityAnalyzer.Report> reports=Collections.newSetFromMap(new IdentityHashMap<QualityAnalyzer.Report,Boolean>());
        for(RtpStream stream:streams) {
            RtpTimeline timeline=RtpTimeline.of(stream);
            if(stream.quality!=null&&reports.add(stream.quality))for(QualityAnalyzer.Issue issue:stream.quality.issues) {
                Marker m=new Marker();m.kind=issue.kind;m.label=issue.description;
                if(issue.clock==stream.clock) {
                    m.startMs=(stream.firstUs()-origin)/1000.0+timeline.milliseconds(issue.startTimestamp,issue.timeUs);
                    m.endMs=(stream.firstUs()-origin)/1000.0+timeline.milliseconds(issue.endTimestamp,issue.endUs);
                } else {m.startMs=(issue.timeUs-origin)/1000.0;m.endMs=(issue.endUs-origin)/1000.0;}
                data.add(m);
            }
        }
        return data;
    }
    public void addEvents(List<DtmfParser.Event> events,List<RtpStream> streams) {
        if(streams.isEmpty())return;
        long origin=Long.MAX_VALUE;for(RtpStream s:streams)origin=Math.min(origin,s.firstUs());
        Map<RtpStream,RtpTimeline> bases=new IdentityHashMap<>();for(RtpStream s:streams)bases.put(s,RtpTimeline.of(s));
        for(DtmfParser.Event event:events)for(RtpStream s:streams) {
            if(!DtmfParser.matches(event,s))continue;
            Marker m=new Marker();m.kind="DTMF";m.label=event.key;m.event=event;
            m.startMs=DtmfParser.audioStartMs(event,s,origin,bases.get(s));
            m.endMs=m.startMs+event.durationMs();add(m);break;
        }
    }
    private void add(Marker marker){if(markers.size()<2048&&marker.endMs>=0&&marker.startMs<=durationMs()){marker.startMs=Math.max(0,marker.startMs);marker.endMs=Math.max(marker.startMs,Math.min(durationMs(),marker.endMs));markers.add(marker);}}
}
