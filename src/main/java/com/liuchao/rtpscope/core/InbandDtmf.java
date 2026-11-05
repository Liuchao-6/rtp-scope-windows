package com.liuchao.rtpscope.core;

import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.util.*;
import org.jitsi.impl.neomedia.codec.audio.g729.G729Codec;

/** Conservative dual-tone detection on independently decoded 8 kHz audio. */
public final class InbandDtmf {
    private static final int N=160,HOP=80;
    private static final double[] FREQ={697,770,852,941,1209,1336,1477,1633};
    private static double power(double[] samples,double mean,double frequency){double coefficient=2*Math.cos(2*Math.PI*frequency/8000),a=0,b=0;for(double sample:samples){double next=sample-mean+coefficient*a-b;b=a;a=next;}return Math.max(0,2*(a*a+b*b-coefficient*a*b)/N);}
    private static int tone(double[] samples){double sum=0,total=0;for(double x:samples)sum+=x;double mean=sum/N;for(double x:samples)total+=(x-mean)*(x-mean);if(total/N<200*200)return -1;
        double[] p=new double[8];for(int i=0;i<8;i++)p[i]=power(samples,mean,FREQ[i]);int row=0,col=4;for(int i=1;i<4;i++)if(p[i]>p[row])row=i;for(int i=5;i<8;i++)if(p[i]>p[col])col=i;
        for(int i:new int[]{row,col}){double best=p[i];best=Math.max(best,power(samples,mean,FREQ[i]*0.985));best=Math.max(best,power(samples,mean,FREQ[i]*1.015));if(Math.max(power(samples,mean,FREQ[i]*0.965),power(samples,mean,FREQ[i]*1.035))>best*1.1)return -1;p[i]=best;}
        for(int i=0;i<4;i++)if(i!=row&&p[row]<p[i]*6.3)return -1;for(int i=4;i<8;i++)if(i!=col&&p[col]<p[i]*6.3)return -1;
        double twist=p[row]/Math.max(1,p[col]);if(twist<0.158||twist>2.512||(p[row]+p[col])/total<0.75)return -1;
        if(power(samples,mean,FREQ[row]*2)>p[row]*0.25||power(samples,mean,FREQ[col]*2)>p[col]*0.25)return -1;
        int[][] keys={{1,2,3,12},{4,5,6,13},{7,8,9,14},{10,0,11,15}};return keys[row][col-4];
    }
    private static final class Detector {
        final List<DtmfParser.Event> events=new ArrayList<>();final RtpStream stream;final long base,originUs;
        final double[] ring=new double[N];int fill,active=-1,frames;long start,lastEnd;double energy;
        Detector(RtpStream stream,long base,long originUs){this.stream=stream;this.base=base;this.originUs=originUs;}
        void add(short value,long at){ring[fill++]=value;if(fill<N)return;int key=tone(ring);if(key!=active){flush(true);active=key;start=at-N+1;}if(key>=0){frames++;lastEnd=at+1;double total=0;for(double x:ring)total+=x*x;energy+=total/N;}System.arraycopy(ring,HOP,ring,0,N-HOP);fill=N-HOP;}
        void flush(boolean ended){if(active>=0&&frames>=3&&events.size()<30000){DtmfParser.Event e=new DtmfParser.Event();e.type=DtmfParser.Type.IN_BAND;e.src=stream.src;e.dst=stream.dst;e.callId=stream.callId;e.ssrc=stream.ssrc;e.clock=8000;e.number=active;e.key=DtmfParser.key(active);e.timestamp=(base+start)&0xffffffffL;e.durationTicks=lastEnd-start;e.firstSeenUs=originUs+start*125;e.lastSeenUs=originUs+lastEnd*125;e.ended=ended;e.levelDbfs=10*Math.log10(Math.max(1,energy/frames)/(32768.0*32768));events.add(e);}active=-1;frames=0;energy=0;}
        void gap(){flush(false);fill=0;}
    }
    public static List<DtmfParser.Event> detect(List<RtpStream> streams,Analysis analysis,long[] budget){
        RtpStream first=streams.get(0);long base=DtmfParser.mediaBase(first);for(RtpStream s:streams)if((int)(DtmfParser.mediaBase(s)-base)<0)base=DtmfParser.mediaBase(s);
        final long origin=base;List<RtpPacket> ordered=new ArrayList<>();Map<RtpPacket,RtpStream> owners=new IdentityHashMap<>();for(RtpStream s:streams)for(RtpPacket p:s.packets){ordered.add(p);owners.put(p,s);}ordered.sort(Comparator.comparingLong(p->(int)(p.timestamp-origin)));
        long originUs=Long.MAX_VALUE;for(RtpStream s:streams)originUs=Math.min(originUs,s.firstUs()+(int)(base-DtmfParser.mediaBase(s))*125L);
        Detector detector=new Detector(first,base,originUs);long previous=-1;String codec="";G729Codec g729=null;Set<Long> seen=new HashSet<>();
        for(RtpPacket p:ordered){RtpStream s=owners.get(p);long position=(int)(p.timestamp-base);if(!seen.add(position))continue;int count=AudioRenderer.sampleCount(s,p.payload);if(position+count>AudioRenderer.MAX_SAMPLES||budget[0]<count){analysis.warn("音内按键分析达到时长上限，部分音频未扫描");break;}
            if(previous>=0&&position>previous){detector.gap();if(g729!=null)g729.advanceLoss((int)Math.min(101,(position-previous)/80));}if(position<previous)continue;
            if(!codec.equals(s.codec)){codec=s.codec;g729=codec.startsWith("G729")?new G729Codec():null;}
            try{short[] pcm;if(g729!=null)pcm=g729.decode(p.payload);else{pcm=new short[p.payload.length];for(int i=0;i<pcm.length;i++)pcm[i]=(short)AudioRenderer.decode(p.payload[i]&255,codec.equals("PCMA"));}budget[0]-=pcm.length;for(int i=0;i<pcm.length;i++)detector.add(pcm[i],position+i);previous=position+pcm.length;}
            catch(IOException e){analysis.warn("音内按键跳过编码包长异常的数据");detector.gap();g729=null;codec="";previous=-1;}
        }
        detector.flush(false);return detector.events;
    }
    private InbandDtmf(){}
}
