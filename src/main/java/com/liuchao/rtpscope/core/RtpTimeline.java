package com.liuchao.rtpscope.core;

import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.util.*;

/** RTP clock segments, with capture-time recovery for restarts and persistent clock lag. */
public final class RtpTimeline {
    private static final long LAG_TOLERANCE_US=80000, LAG_REPAIR_TOLERANCE_US=20000, LAG_CONFIRMATION_US=500000;
    private static final int LAG_LOOKAHEAD=512;
    public static boolean discontinuity(long timestampDelta,long arrivalUs,int clock){
        double mediaMs=timestampDelta*1000.0/clock,arrivalMs=arrivalUs/1000.0;
        return Math.abs(mediaMs-arrivalMs)>Math.max(5000,Math.abs(arrivalMs)*0.1)
            || mediaMs < -1000 && arrivalMs>=0;
    }
    private static final class Segment {
        long timestamp,ticks,timeUs,low,high;int id;
        Segment(RtpPacket p,long ticks,long sequence,int id){timestamp=p.timestamp;this.ticks=ticks;timeUs=p.timeUs;low=high=sequence;this.id=id;}
    }
    private static final class Clock {
        final RtpStream stream;final List<Segment> segments=new ArrayList<>();
        Segment segment;RtpPacket reference;long high,referenceTicks,referenceEnd,min,max,sequence,originUs;int segmentId,lagRepairs;
        Clock(RtpStream stream){this.stream=stream;}
        long captureTicks(RtpPacket p){return Math.round((p.timeUs-originUs)*stream.clock/1000000.0);}
        long sustainedLag(RtpPacket p,int index,long ticks){
            if(!stream.clockKnown||!stream.playable()||stream.quality!=null&&!stream.quality.reliableTimestamps)return 0;
            long toleranceUs=lagRepairs==0?LAG_TOLERANCE_US:LAG_REPAIR_TOLERANCE_US;
            long tolerance=Math.max(1,Math.round(toleranceUs*stream.clock/1000000.0));
            long minimum=captureTicks(p)-ticks;if(minimum<tolerance)return 0;
            int count=1,lastSequence=0;long span=0;
            int end=Math.min(stream.packets.size(),index+LAG_LOOKAHEAD);
            // A delay that is followed by a catch-up burst must keep its original RTP timing.
            // Use the lowest lag across subsequent unique packets, rather than one late arrival.
            for(int n=index+1;n<end;n++){
                if(Thread.currentThread().isInterrupted())throw new java.util.concurrent.CancellationException("媒体时间轴分析已取消");
                RtpPacket next=stream.packets.get(n);int sequenceDelta=(short)(next.sequence-p.sequence);
                if(sequenceDelta<=lastSequence)continue;
                long delta=(int)(next.timestamp-p.timestamp);
                if(sequenceDelta>3000||delta<0||discontinuity(delta,next.timeUs-p.timeUs,stream.clock))return 0;
                lastSequence=sequenceDelta;count++;span=delta;
                minimum=Math.min(minimum,captureTicks(next)-(ticks+delta));
                if(minimum<tolerance)return 0;
                if(count>=4&&span>=LAG_CONFIRMATION_US*stream.clock/1000000)return minimum;
            }
            // After confirmed repairs, a short stable tail may carry the last accumulated pause.
            // An isolated late last packet (or an entirely short capture) is not enough evidence.
            return end==stream.packets.size()&&lagRepairs>0&&count>=4&&span>=stream.clock/25?minimum:0;
        }
        long add(RtpPacket p,int index){
            if(Thread.currentThread().isInterrupted())throw new java.util.concurrent.CancellationException("媒体时间轴分析已取消");
            if(reference==null)originUs=p.timeUs;
            sequence=reference==null?p.sequence:high+(short)(p.sequence-(int)high);
            boolean restart=reference!=null&&(Math.abs(sequence-high)>3000 || sequence>high&&discontinuity((int)(p.timestamp-reference.timestamp),p.timeUs-reference.timeUs,stream.clock));
            int duration=duration(stream,p);long ticks;
            if(reference==null||restart){
                ticks=reference==null?0:Math.max(referenceEnd,referenceTicks+Math.round(Math.max(0,p.timeUs-reference.timeUs)*stream.clock/1000000.0));
                segment=new Segment(p,ticks,sequence,segments.size());segments.add(segment);high=sequence;
                lagRepairs=0;
            }else{
                Segment chosen=segment;
                // A late packet from the preceding clock segment must not start another restart.
                if(sequence<high)for(int n=segments.size()-2;n>=0;n--){Segment candidate=segments.get(n);if(sequence>=candidate.low&&sequence<=candidate.high){chosen=candidate;break;}}
                segmentId=chosen.id;ticks=sequence==high?referenceTicks:chosen.ticks+(int)(p.timestamp-chosen.timestamp);
                if(sequence>high){long lag=sustainedLag(p,index,ticks);if(lag>0){ticks+=lag;segment=new Segment(p,ticks,sequence,segments.size());segments.add(segment);lagRepairs++;}}
            }
            if(reference==null||restart||sequence>high){reference=p;referenceTicks=ticks;referenceEnd=ticks+duration;high=sequence;segment.high=Math.max(segment.high,sequence);segment.low=Math.min(segment.low,sequence);segmentId=segment.id;}
            min=Math.min(min,ticks);max=Math.max(max,ticks+duration);return ticks;
        }
    }
    public static final class Frame {
        public final int index,segment;public final long ticks,sequence;
        Frame(int index,long ticks,long sequence,int segment){this.index=index;this.ticks=ticks;this.sequence=sequence;this.segment=segment;}
        public String identity(){return segment+"/"+sequence;}
    }
    private final RtpStream stream;private final Clock clock;
    public final List<Frame> frames;
    public final long samples;
    public final int repairs;
    private RtpTimeline(RtpStream stream){
        this.stream=stream;clock=new Clock(stream);List<Frame> raw=new ArrayList<>();int index=0;
        for(RtpPacket p:stream.packets){long ticks=clock.add(p,index);raw.add(new Frame(index++,ticks,clock.sequence,clock.segmentId));}
        frames=raw;for(int n=0;n<frames.size();n++){Frame f=frames.get(n);frames.set(n,new Frame(f.index,f.ticks-clock.min,f.sequence,f.segment));}
        frames.sort(Comparator.comparingLong((Frame f)->f.ticks).thenComparingLong(f->f.sequence));
        samples=clock.max-clock.min;repairs=Math.max(0,clock.segments.size()-1);
    }
    public static RtpTimeline of(RtpStream stream){return new RtpTimeline(stream);}
    public static double seconds(RtpStream stream){Clock c=new Clock(stream);int index=0;for(RtpPacket p:stream.packets)c.add(p,index++);return (c.max-c.min)/(double)stream.clock;}
    private static int duration(RtpStream s,RtpPacket p){return s.playable()?AudioRenderer.sampleCount(s,p):0;}
    public double milliseconds(long timestamp,long timeUs){
        if(clock.segments.isEmpty())return 0;Segment chosen=clock.segments.get(0);
        for(Segment s:clock.segments)if(s.timeUs<=timeUs)chosen=s;else break;
        return (chosen.ticks+(int)(timestamp-chosen.timestamp)-clock.min)*1000.0/stream.clock;
    }
    public long firstTimestamp(){return stream.packets.isEmpty()?0:stream.packets.get(0).timestamp+clock.min;}
}
