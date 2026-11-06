package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.util.*;

/** Actual decoded PCM per direction, aligned to the same capture origin as the mixed WAV. */
public final class AudioPreview implements Closeable {
    public static final class Track {
        public final String label;
        public final WaveformData waveform;
        public final double offsetMs;
        public File audio;
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
        try{for(Map.Entry<String,List<RtpStream>> direction:directions.entrySet()) {
            List<RtpStream> group=direction.getValue();long groupOrigin=Long.MAX_VALUE;Set<String> codecs=new LinkedHashSet<>();
            for(RtpStream s:group){groupOrigin=Math.min(groupOrigin,s.firstUs());codecs.add(s.codec);}
            WaveformData wave;File trackFile=output;
            if(directions.size()==1)wave=mixed;
            else {File solo=File.createTempFile("chaoge-huatan-direction-",".wav",output.getAbsoluteFile().getParentFile());try{AudioRenderer.render(group,solo);wave=WaveformData.load(solo,group);wave.addEvents(events,group);trackFile=solo;}catch(IOException|RuntimeException e){solo.delete();throw e;}}
            Map<RtpStream,RtpTimeline> bases=new IdentityHashMap<>();for(RtpStream s:group)bases.put(s,RtpTimeline.of(s));
            int track=preview.tracks.size();Track added=new Track(direction.getKey()+" · "+String.join(" / ",codecs),wave,(groupOrigin-origin)/1000.0);added.audio=trackFile;preview.tracks.add(added);
            for(DtmfParser.Event event:events)for(RtpStream s:group) {
                if(!DtmfParser.matches(event,s))continue;
                double start=DtmfParser.audioStartMs(event,s,origin,bases.get(s));
                if(start+event.durationMs()>=0&&start<=mixed.durationMs())preview.keys.add(new Key(event.key,Math.max(0,start),event.durationMs(),track,event));break;
            }
        }
        preview.keys.sort(Comparator.comparingDouble(k->k.startMs));return preview;}catch(IOException|RuntimeException e){preview.close();throw e;}
    }
    public static AudioPreview fromWaveform(WaveformData wave) {
        if(wave==null)return null;AudioPreview preview=new AudioPreview(wave);preview.tracks.add(new Track("音频波形",wave,0));
        for(WaveformData.Marker m:wave.markers)if(m.kind.equals("DTMF"))preview.keys.add(new Key(m.label,m.startMs,m.endMs-m.startMs,0,m.event));return preview;
    }
    public void exportWav(File target)throws IOException{List<File> files=new ArrayList<>();List<Double> offsets=new ArrayList<>();for(Track track:tracks){files.add(track.audio);offsets.add(track.offsetMs);}PcmTracks.separate(files,offsets,target);}
    public static AudioPreview recording(File input)throws IOException {
        File mixed=File.createTempFile("recording-mixed-",".wav",input.getParentFile());PcmTracks.channel(input,-1,mixed,16000);AudioPreview preview=new AudioPreview(WaveformData.load(mixed,Collections.emptyList()));
        try(PcmFile pcm=new PcmFile(input)){for(int c=0;c<pcm.channels;c++){File solo=File.createTempFile("recording-channel-",".wav",input.getParentFile());PcmTracks.channel(input,c,solo,16000);Track t=new Track(PcmFile.channelName(pcm.channels,c),WaveformData.load(solo,Collections.emptyList()),0);t.audio=solo;preview.tracks.add(t);}}finally{mixed.delete();}return preview;
    }
    public void close(){for(Track track:tracks)if(track.audio!=null&&track.audio.getName().startsWith("chaoge-huatan-direction-"))track.audio.delete();else if(track.audio!=null&&track.audio.getName().startsWith("recording-channel-"))track.audio.delete();}
    public String keySummary(){if(keys.isEmpty())return "当前音频无按键";StringBuilder s=new StringBuilder("按键：");for(int i=0;i<Math.min(20,keys.size());i++){if(i>0)s.append(' ');s.append(keys.get(i).value);}if(keys.size()>20)s.append(" …");return s.append("  ·  ").append(keys.size()).append(" 次").toString();}
}
