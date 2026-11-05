package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.util.*;

/** Desktop filtering and playback selection, independent of Swing and audio devices. */
public final class DesktopModel {
    public Analysis analysis;
    public String callId="",query="";
    public final Set<RtpStream> selected=new LinkedHashSet<>();
    public boolean matches(String text){return query.isEmpty()||text.toLowerCase(Locale.ROOT).contains(query.toLowerCase(Locale.ROOT));}
    private boolean call(String id){return callId.isEmpty()||callId.equals(id);}
    public List<SipMessage> messages(){List<SipMessage> out=new ArrayList<>();if(analysis!=null)for(SipMessage m:analysis.sip)if(call(m.callId)&&matches(m.searchable()))out.add(m);return out;}
    public List<RtpStream> streams(){List<RtpStream> out=new ArrayList<>();if(analysis!=null)for(RtpStream s:analysis.streams)if(call(s.callId)&&matches(s.searchable()))out.add(s);return out;}
    public List<DtmfParser.Event> events(){List<DtmfParser.Event> out=new ArrayList<>();if(analysis!=null)for(DtmfParser.Event e:analysis.events)if(call(e.callId)&&matches(e.searchable()))out.add(e);return out;}
    public CallFlow flow(){return CallFlow.build(analysis,callId,query);}
    public void load(Analysis value){analysis=value;callId="";query="";selected.clear();}
    public List<RtpStream> playbackSelection() {
        List<RtpStream> out=new ArrayList<>(selected);String id=null;
        for(RtpStream s:out){if(!s.playable())throw new IllegalArgumentException("选中的媒体流包含不支持的编码或加密媒体");if(id==null)id=s.callId;else if(!id.equals(s.callId))throw new IllegalArgumentException("请选择同一通话的媒体流分别播放");}
        if(out.size()>8)throw new IllegalArgumentException("一次最多混音 8 条媒体流");return out;
    }
}
