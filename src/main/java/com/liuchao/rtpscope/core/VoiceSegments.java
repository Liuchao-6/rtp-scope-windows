package com.liuchao.rtpscope.core;
import java.io.*;
import java.util.*;

/** Acoustic windows retain source time when silence is skipped; they are not word alignments. */
public final class VoiceSegments {
    public static final class Window {public final long startMs,endMs;Window(long a,long b){startMs=a;endMs=b;}}
    public static List<Window> find(PcmFile pcm,int channel)throws IOException{
        List<Window> windows=new ArrayList<>();long start=-1,lastVoice=-1;long duration=(long)Math.ceil(pcm.durationMs());
        for(long at=0;at<duration;at+=1000){if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("转写已取消");float[] samples=pcm.read(at,1000,channel,16000);
            for(int frame=0;frame<samples.length;frame+=320){int count=Math.min(320,samples.length-frame);double energy=0;for(int n=0;n<count;n++)energy+=samples[frame+n]*samples[frame+n];long time=at+frame/16;
                if(energy/Math.max(1,count)>=.000004){if(start<0)start=Math.max(0,time-120);lastVoice=Math.min(duration,time+20);}
                if(start>=0&&(time-lastVoice>=500||time+20-start>=20000)){long end=time-lastVoice>=500?Math.min(duration,lastVoice+120):Math.min(duration,start+20000);if(end-start>=200)windows.add(new Window(start,end));start=-1;}
            }
        }
        if(start>=0&&lastVoice+120-start>=200)windows.add(new Window(start,Math.min(duration,lastVoice+120)));return windows;
    }
}
