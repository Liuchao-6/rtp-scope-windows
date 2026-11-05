package com.liuchao.rtpscope.core;

import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.IOException;
import java.util.*;

/** Keep independently observed key types; never merge INFO, RTP events and audio detections. */
public final class KeyAnalysis {
    public static void attach(Analysis analysis)throws IOException {
        List<DtmfParser.Event> added=SipInfoDtmf.parse(analysis);Map<String,List<RtpStream>> groups=new LinkedHashMap<>();
        for(RtpStream s:analysis.streams)if(s.playable())groups.computeIfAbsent(s.transportKey()+"/"+s.callId,k->new ArrayList<>()).add(s);
        long[] budget={AudioRenderer.MAX_SAMPLES*2};for(List<RtpStream> group:groups.values())added.addAll(InbandDtmf.detect(group,analysis,budget));
        if(analysis.events.size()+added.size()>30000)throw new IOException("电话事件超过 3 万条，请先拆分文件");
        for(DtmfParser.Event event:added){analysis.events.add(event);for(RtpStream s:analysis.streams)if(DtmfParser.matches(event,s))s.events.add(event);}
    }
    private KeyAnalysis(){}
}
