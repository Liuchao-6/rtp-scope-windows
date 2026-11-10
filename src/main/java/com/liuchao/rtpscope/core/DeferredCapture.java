package com.liuchao.rtpscope.core;

import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.util.*;

/** Immutable signaling view plus an independent media analysis sharing sealed packet data. */
public final class DeferredCapture {
    public final Analysis signaling;
    private final List<RtpStream> candidates;
    private final Map<String,Integer> initialWarnings;
    private boolean applied;
    public DeferredCapture(Analysis signaling,List<RtpStream> candidates){this.signaling=signaling;this.candidates=candidates;initialWarnings=new LinkedHashMap<>(signaling.warnings);}
    public Analysis analyze(CaptureEngine.Progress progress)throws IOException{
        Analysis result=new Analysis();result.sip.addAll(signaling.sip);result.events.addAll(signaling.events);result.warnings.putAll(initialWarnings);
        result.packets=signaling.packets;result.bytes=signaling.bytes;result.firstUs=signaling.firstUs;result.lastUs=signaling.lastUs;result.format=signaling.format;result.reliableTimestamps=signaling.reliableTimestamps;result.partial=signaling.partial;
        Map<RtpStream,RtpStream> copies=new IdentityHashMap<>();List<RtpStream> all=new ArrayList<>();
        for(RtpStream stream:candidates){RtpStream copy=copy(stream);copies.put(stream,copy);all.add(copy);}
        for(RtpStream stream:signaling.streams)result.streams.add(copies.get(stream));
        for(Call call:signaling.calls){Call copy=new Call();copy.id=call.id;copy.from=call.from;copy.to=call.to;copy.status=call.status;copy.startUs=call.startUs;copy.endUs=call.endUs;copy.lastUs=call.lastUs;copy.requestTarget=call.requestTarget;copy.inviteIdentity=call.inviteIdentity;copy.sipCount=call.sipCount;copy.signalingIps.addAll(call.signalingIps);copy.mediaIps.addAll(call.mediaIps);for(RtpStream stream:call.streams)copy.streams.add(copies.get(stream));result.calls.add(copy);}
        if(progress!=null)progress.stage("RTP 质量分析");QualityAnalyzer.attach(result.streams,all,result.reliableTimestamps,progress);
        KeyAnalysis.attachAudio(result,progress);result.events.sort(Comparator.comparingLong(event->event.firstSeenUs));return result;
    }
    private static RtpStream copy(RtpStream source){
        RtpStream copy=new RtpStream();copy.src=source.src;copy.dst=source.dst;copy.srcIp=source.srcIp;copy.dstIp=source.dstIp;copy.codec=source.codec;copy.callId=source.callId;copy.note=source.note;copy.fmtp=source.fmtp;copy.srcPort=source.srcPort;copy.dstPort=source.dstPort;copy.pt=source.pt;copy.clock=source.clock;copy.ssrc=source.ssrc;copy.encrypted=source.encrypted;copy.clockKnown=source.clockKnown;copy.packets=source.packets;copy.events.addAll(source.events);return copy;
    }
    /** Apply only on the UI thread, while the original signaling view is still current. */
    public void apply(Analysis complete){
        if(applied)return;
        if(complete.streams.size()!=signaling.streams.size())throw new IllegalArgumentException("媒体结果与抓包不匹配");
        for(int n=0;n<signaling.streams.size();n++){RtpStream target=signaling.streams.get(n),source=complete.streams.get(n);target.quality=source.quality;target.lost=source.lost;target.duplicates=source.duplicates;target.events.clear();target.events.addAll(source.events);}
        signaling.events.clear();signaling.events.addAll(complete.events);
        for(Map.Entry<String,Integer> warning:complete.warnings.entrySet()){int extra=warning.getValue()-initialWarnings.getOrDefault(warning.getKey(),0);if(extra>0)signaling.warnings.put(warning.getKey(),signaling.warnings.getOrDefault(warning.getKey(),0)+extra);}
        applied=true;
    }
}
