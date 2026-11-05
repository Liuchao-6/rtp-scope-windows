package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.util.*;

/** Actual decoded PCM per direction, aligned to the same capture origin as the mixed WAV. */
public final class AudioPreview {
    public static final class Track {
        public final String label;
        public final WaveformData waveform;
        public final double offsetMs;
        Track(String label,WaveformData waveform,double offsetMs){this.label=label;this.waveform=waveform;this.offsetMs=offsetMs;}
    }
    public static final class Key {
        public final String value;
        public String typeLabel(){return event==null?"RFC 2833 / 4733":event.typeLabel();}
        public String badgeText(){return "按键 "+value+" · "+(event==null?"2833":event.typeCode());}
        public final double startMs,durationMs;
        public final int track;
        public final DtmfParser.Event event;
        Key(String value,double startMs,double durationMs,int track,DtmfParser.Event event){this.value=value;this.startMs=startMs;this.durationMs=durationMs;this.track=track;this.event=event;}
    }
    public final WaveformData mixed;
    public final List<Track> tracks=new ArrayList<>();
    public final List<Key> keys=new ArrayList<>();
    private AudioPreview(WaveformData mixed){this.mixed=mixed;}
    public static AudioPreview render(List<RtpStream> streams,List<DtmfParser.Event> events,File output)throws IOException {
        AudioRenderer.render(streams,output);WaveformData mixed=WaveformData.load(output,streams);mixed.addEvents(events,streams);
        AudioPreview preview=new AudioPreview(mixed);Map<String,List<RtpStream>> directions=new LinkedHashMap<>();long origin=Long.MAX_VALUE;
        for(RtpStream s:streams){origin=Math.min(origin,s.firstUs());directions.computeIfAbsent(s.src+" → "+s.dst,k->new ArrayList<>()).add(s);}
        for(Map.Entry<String,List<RtpStream>> direction:directions.entrySet()) {
            List<RtpStream> group=direction.getValue();long groupOrigin=Long.MAX_VALUE;Set<String> codecs=new LinkedHashSet<>();
            for(RtpStream s:group){groupOrigin=Math.min(groupOrigin,s.firstUs());codecs.add(s.codec);}
            WaveformData wave;
            if(directions.size()==1)wave=mixed;
            else {File solo=File.createTempFile("chaoge-huatan-direction-",".wav",output.getAbsoluteFile().getParentFile());try{AudioRenderer.render(group,solo);wave=WaveformData.load(solo,group);wave.addEvents(events,group);}finally{if(!solo.delete())solo.deleteOnExit();}}
            Map<RtpStream,Long> bases=new IdentityHashMap<>();for(RtpStream s:group)bases.put(s,DtmfParser.mediaBase(s));
            int track=preview.tracks.size();preview.tracks.add(new Track(direction.getKey()+" · "+String.join(" / ",codecs),wave,(groupOrigin-origin)/1000.0));
            for(DtmfParser.Event event:events)for(RtpStream s:group) {
                if(!DtmfParser.matches(event,s))continue;
                double start=DtmfParser.audioStartMs(event,s,origin,bases.get(s));
                if(start+event.durationMs()>=0&&start<=mixed.durationMs())preview.keys.add(new Key(event.key,Math.max(0,start),event.durationMs(),track,event));break;
            }
        }
        preview.keys.sort(Comparator.comparingDouble(k->k.startMs));return preview;
    }
    public static AudioPreview fromWaveform(WaveformData wave) {
        if(wave==null)return null;AudioPreview preview=new AudioPreview(wave);preview.tracks.add(new Track("音频波形",wave,0));
        for(WaveformData.Marker m:wave.markers)if(m.kind.equals("DTMF"))preview.keys.add(new Key(m.label,m.startMs,m.endMs-m.startMs,0,m.event));return preview;
    }
    public String keySummary(){if(keys.isEmpty())return "当前音频无按键";StringBuilder s=new StringBuilder("按键：");for(int i=0;i<Math.min(20,keys.size());i++){if(i>0)s.append(' ');s.append(keys.get(i).value);}if(keys.size()>20)s.append(" …");return s.append("  ·  ").append(keys.size()).append(" 次").toString();}
}
