package com.liuchao.rtpscope.core;

import java.util.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;

/** Capture-side RTP evidence. Sequence statistics include ALL payload types sharing an SSRC. */
public final class QualityAnalyzer {
    public static final double DELAY_THRESHOLD_MS=80;
    private static final int ISSUE_LIMIT=2000;
    public static final class Issue implements java.io.Serializable {
        public String kind,description;
        public long timeUs,endUs,firstMissing,lastMissing,count;
        public long startTimestamp,endTimestamp;
        public int clock;
        public double milliseconds;
    }
    public static final class Report implements java.io.Serializable {
        public long packets,unique,lost,duplicates,reordered,resets,timestampResets,firstUs,lastUs,delayCount;
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
    private static final class Cursor {
        final RtpStream stream;final int order;int index;RtpPacket packet;
        Cursor(RtpStream stream,int order){this.stream=stream;this.order=order;packet=stream.packets.get(0);}
    }
    private static Iterator<Entry> entries(List<RtpStream> streams){
        boolean disk=false;for(RtpStream s:streams)disk|=s.packets instanceof PacketStore.Packets;
        if(!disk){List<Entry> all=new ArrayList<>();for(RtpStream s:streams)for(RtpPacket p:s.packets)all.add(new Entry(s,p));all.sort(Comparator.comparingLong(e->e.packet.timeUs));return all.iterator();}
        PriorityQueue<Cursor> queue=new PriorityQueue<>(Comparator.<Cursor>comparingLong(c->c.packet.timeUs).thenComparingInt(c->c.order));
        for(int n=0;n<streams.size();n++){RtpStream s=streams.get(n);if(!s.packets.isEmpty())queue.add(new Cursor(s,n));}
        return new Iterator<Entry>(){
            public boolean hasNext(){return !queue.isEmpty();}
            public Entry next(){Cursor c=queue.remove();Entry value=new Entry(c.stream,c.packet);if(++c.index<c.stream.packets.size()){c.packet=c.stream.packets.get(c.index);queue.add(c);}return value;}
        };
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
        for(RtpStream stream:streams)report.payloadTypes.add(stream.pt);
        TreeMap<Long,Entry> sequence=new TreeMap<>();
        long high=0;Entry previousAudio=null;double jitter=0;
        for(Iterator<Entry> iterator=entries(streams);iterator.hasNext();) {
            if(Thread.currentThread().isInterrupted())throw new java.util.concurrent.CancellationException("媒体分析已取消");
            Entry entry=iterator.next();
            if(report.packets==0){high=entry.packet.sequence;report.firstUs=entry.packet.timeUs;}report.lastUs=entry.packet.timeUs;
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
            if(sequence.size()>8192){NavigableMap<Long,Entry> old=sequence.headMap(high-4096,true);if(old.size()>1){Long boundary=old.lastKey();collectGaps(old,report);sequence.headMap(boundary,false).clear();}}
            if(s.encrypted || s.isDtmf() || s.codec.equals("CN") || !s.clockKnown)continue;
            if(previousAudio!=null && s.clock==previousAudio.stream.clock && s.codec.equals(previousAudio.stream.codec)) {
                double arrival=(p.timeUs-previousAudio.packet.timeUs)/1000.0;
                double media=(int)(p.timestamp-previousAudio.packet.timestamp)*1000.0/s.clock;
                report.maxArrivalGapMs=Math.max(report.maxArrivalGapMs,arrival);
                if(extended>previousAudio.packet.extendedSequence&&RtpTimeline.discontinuity((int)(p.timestamp-previousAudio.packet.timestamp),p.timeUs-previousAudio.packet.timeUs,s.clock)){
                    report.timestampResets++;jitter=0;
                    Issue issue=new Issue();issue.kind="TIMESTAMP";issue.timeUs=p.timeUs;issue.endUs=p.timeUs;
                    issue.description="RTP 时间戳基准跳变，播放按抓包时间衔接；未将跳变计为卡顿";add(report,issue);
                }else if(reliable && media<=arrival+5000) {
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
    private static void collectGaps(Map<Long,Entry> sequence,Report report) {
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
                    issue.startTimestamp=(before.packet.timestamp+(before.stream.playable()?AudioRenderer.sampleCount(before.stream,before.packet):0))&0xffffffffL;
                    issue.endTimestamp=after.packet.timestamp;
                }
                issue.description="缺少序号 "+issue.firstMissing+" — "+issue.lastMissing+"，共 "+missing+" 包";add(report,issue);
            }
            previous=current;
        }
    }
    private static void add(Report report,Issue issue){if(issue.kind.equals("DELAY"))report.delayCount++;if(report.issues.size()<ISSUE_LIMIT)report.issues.add(issue);else report.limited=true;}
}
