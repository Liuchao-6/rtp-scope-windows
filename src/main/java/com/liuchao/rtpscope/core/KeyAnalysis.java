package com.liuchao.rtpscope.core;

import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.IOException;
import java.util.*;

/** Keep independently observed key types; never merge INFO, RTP events and audio detections. */
public final class KeyAnalysis {
    public static void attach(Analysis analysis)throws IOException {
        attachSignaling(analysis);attachAudio(analysis,null);
    }
    public static void attachSignaling(Analysis analysis)throws IOException{append(analysis,SipInfoDtmf.parse(analysis));}
    public static void attachAudio(Analysis analysis,CaptureEngine.Progress progress)throws IOException{
        List<DtmfParser.Event> added=new ArrayList<>();Map<String,List<RtpStream>> groups=new LinkedHashMap<>();
        for(RtpStream s:analysis.streams)if(s.playable())groups.computeIfAbsent(s.transportKey()+"/"+s.callId+"/"+s.clock,k->new ArrayList<>()).add(s);
        long[] budget={AudioRenderer.MAX_SAMPLES*2};int index=0;for(List<RtpStream> group:groups.values()){if(progress!=null)progress.stage("音内按键分析 · "+(++index)+" / "+groups.size()+" 路");added.addAll(InbandDtmf.detect(group,analysis,budget));}
        append(analysis,added);
    }
    private static void append(Analysis analysis,List<DtmfParser.Event> added)throws IOException{
        if(analysis.events.size()+added.size()>30000)throw new IOException("电话事件超过 3 万条，请先拆分文件");
        for(DtmfParser.Event event:added){analysis.events.add(event);for(RtpStream s:analysis.streams)if(DtmfParser.matches(event,s))s.events.add(event);}
    }
    private KeyAnalysis(){}
}
