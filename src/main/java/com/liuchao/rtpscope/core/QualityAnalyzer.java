package com.liuchao.rtpscope.core;

import java.util.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;

/** Capture-side RTP evidence. Sequence statistics include ALL payload types sharing an SSRC. */
public final class QualityAnalyzer {
    public static final double DELAY_THRESHOLD_MS=80;
    private static final int ISSUE_LIMIT=2000;
    public static final class Issue {
        public String kind,description;
        public long timeUs,endUs,firstMissing,lastMissing,count;
        public long startTimestamp,endTimestamp;
        public int clock;
        public double milliseconds;
    }
    public static final class Report {
        public long packets,unique,lost,duplicates,reordered,resets,firstUs,lastUs,delayCount;
        public double jitterMs,maxJitterMs,maxArrivalGapMs;
        public boolean reliableTimestamps,limited;
        public final Set<Integer> payloadTypes=new TreeSet<>();
        public final List<Issue> issues=new ArrayList<>();
        public double lossPercent(){return unique+lost==0?0:100.0*lost/(unique+lost);}
        public long delaySpikes(){return delayCount;}
    }
    private static final class Entry {
        RtpStream stream;RtpPacket packet;
        Entry(RtpStream s,RtpPacket p){stream=s;packet=p;}
    }
    public static void attach(List<RtpStream> visible,List<RtpStream> candidates,boolean reliable) {
        Map<String,List<RtpStream>> groups=new LinkedHashMap<>();
        for(RtpStream s:visible)groups.computeIfAbsent(s.transportKey(),k->new ArrayList<>());
        for(RtpStream s:candidates){List<RtpStream> group=groups.get(s.transportKey());if(group!=null)group.add(s);}
        Map<String,Report> reports=new HashMap<>();
        for(Map.Entry<String,List<RtpStream>> group:groups.entrySet())reports.put(group.getKey(),analyze(group.getValue(),reliable));
        for(RtpStream stream:visible){stream.quality=reports.get(stream.transportKey());stream.lost=stream.quality.lost;stream.duplicates=stream.quality.duplicates;}
    }
    public static Report analyze(List<RtpStream> streams,boolean reliable) {
        Report report=new Report();report.reliableTimestamps=reliable;
        List<Entry> entries=new ArrayList<>();
        for(RtpStream stream:streams){report.payloadTypes.add(stream.pt);for(RtpPacket p:stream.packets)entries.add(new Entry(stream,p));}
        entries.sort(Comparator.comparingLong(e->e.packet.timeUs));
        if(entries.isEmpty())return report;
        report.firstUs=entries.get(0).packet.timeUs;report.lastUs=entries.get(entries.size()-1).packet.timeUs;
        TreeMap<Long,Entry> sequence=new TreeMap<>();
        long high=entries.get(0).packet.sequence;Entry previousAudio=null;double jitter=0;
        for(Entry entry:entries) {
            RtpPacket p=entry.packet;RtpStream s=entry.stream;report.packets++;
            long extended=high+(short)(p.sequence-(int)high);
            if(Math.abs(extended-high)>3000) {
                collectGaps(sequence,report);sequence.clear();report.resets++;
                Issue issue=new Issue();issue.kind="RESET";issue.timeUs=p.timeUs;issue.endUs=p.timeUs;
                issue.description="序号大幅跳变，可能为发送端重启；未将此跳变计为丢包";add(report,issue);
                high=extended;previousAudio=null;jitter=0;
            }
            p.extendedSequence=extended;
            if(sequence.containsKey(extended)){report.duplicates++;continue;}
            if(extended<high)report.reordered++;
            sequence.put(extended,entry);high=Math.max(high,extended);report.unique++;
            if(s.encrypted || s.isDtmf() || s.codec.equals("CN") || !s.clockKnown)continue;
            if(previousAudio!=null && s.clock==previousAudio.stream.clock && s.codec.equals(previousAudio.stream.codec)) {
                double arrival=(p.timeUs-previousAudio.packet.timeUs)/1000.0;
                double media=(int)(p.timestamp-previousAudio.packet.timestamp)*1000.0/s.clock;
                report.maxArrivalGapMs=Math.max(report.maxArrivalGapMs,arrival);
                if(reliable && media<=arrival+5000) {
                    double deviation=arrival-media;
                    jitter+=(Math.abs(deviation)-jitter)/16.0;
                    report.jitterMs=jitter;report.maxJitterMs=Math.max(report.maxJitterMs,jitter);
                    boolean late=media<0&&extended<previousAudio.packet.extendedSequence;
                    if(deviation>=DELAY_THRESHOLD_MS && ((media>0&&extended>previousAudio.packet.extendedSequence)||late)) {
                        Issue issue=new Issue();issue.kind="DELAY";issue.timeUs=previousAudio.packet.timeUs;issue.endUs=p.timeUs;
                        issue.startTimestamp=p.timestamp;issue.endTimestamp=p.timestamp;issue.clock=s.clock;
                        issue.milliseconds=deviation;issue.description=String.format(Locale.ROOT,late?"乱序包晚到 %.1f ms（到包 %.1f ms / RTP 时间 %.1f ms）":"到达延迟增加 %.1f ms（到包 %.1f ms / RTP 时间 %.1f ms）",deviation,arrival,media);add(report,issue);
                    }
                }
            }
            previousAudio=entry;
        }
        collectGaps(sequence,report);
        report.issues.sort(Comparator.comparingLong(i->i.timeUs));
        return report;
    }
    private static void collectGaps(TreeMap<Long,Entry> sequence,Report report) {
        Map.Entry<Long,Entry> previous=null;
        for(Map.Entry<Long,Entry> current:sequence.entrySet()) {
            if(previous!=null && current.getKey()-previous.getKey()>1) {
                long missing=current.getKey()-previous.getKey()-1;report.lost+=missing;
                Issue issue=new Issue();issue.kind="LOSS";issue.count=missing;
                issue.firstMissing=(previous.getKey()+1)&65535;issue.lastMissing=(current.getKey()-1)&65535;
                issue.timeUs=previous.getValue().packet.timeUs;issue.endUs=current.getValue().packet.timeUs;
                Entry before=previous.getValue(),after=current.getValue();
                if(before.stream.clockKnown&&after.stream.clockKnown&&before.stream.clock==after.stream.clock) {
                    issue.clock=after.stream.clock;
                    issue.startTimestamp=(before.packet.timestamp+(before.stream.playable()?AudioRenderer.sampleCount(before.stream,before.packet.payload):0))&0xffffffffL;
                    issue.endTimestamp=after.packet.timestamp;
                }
                issue.description="缺少序号 "+issue.firstMissing+" — "+issue.lastMissing+"，共 "+missing+" 包";add(report,issue);
            }
            previous=current;
        }
    }
    private static void add(Report report,Issue issue){if(issue.kind.equals("DELAY"))report.delayCount++;if(report.issues.size()<ISSUE_LIMIT)report.issues.add(issue);else report.limited=true;}
}
