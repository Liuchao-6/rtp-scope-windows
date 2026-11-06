package com.liuchao.rtpscope.core;
import java.io.*;
import java.util.*;

/** Bounded PCM composition retaining fractional offsets and source audio rates. */
public final class PcmTracks {
    public static void pcm16(File source,File target)throws IOException{
        try(PcmFile pcm=new PcmFile(source);RandomAccessFile out=new RandomAccessFile(target,"rw")){if(pcm.frames*pcm.channels*2>512L*1024*1024)throw new IOException("解码后的录音超过 512 MiB");out.setLength(0);PcmFile.header(out,pcm.frames,pcm.rate,pcm.channels);
            for(long first=0;first<pcm.frames;first+=pcm.rate){cancel();int count=(int)Math.min(pcm.rate,pcm.frames-first);float[][] data=new float[pcm.channels][];for(int c=0;c<pcm.channels;c++)data[c]=pcm.readFrames(first,count,c,pcm.rate);byte[] bytes=new byte[count*pcm.channels*2];for(int n=0;n<count;n++)for(int c=0;c<pcm.channels;c++)sample(bytes,(n*pcm.channels+c)*2,data[c][n]);out.write(bytes);}
        }catch(IOException|RuntimeException e){target.delete();throw e;}
    }
    public static File channel(File source,int channel,File target,int rate)throws IOException{
        try(PcmFile pcm=new PcmFile(source);RandomAccessFile out=new RandomAccessFile(target,"rw")){
            long frames=(long)Math.floor(pcm.durationMs()*rate/1000);out.setLength(0);PcmFile.header(out,frames,rate,1);long written=0;
            for(long first=0;first<pcm.frames;first+=pcm.rate){cancel();float[] data=pcm.readFrames(first,(int)Math.min(pcm.rate,pcm.frames-first),channel,rate);int count=(int)Math.min(data.length,frames-written);byte[] bytes=new byte[count*2];for(int n=0;n<count;n++)sample(bytes,n*2,data[n]);out.write(bytes);written+=count;}
            out.setLength(44+frames*2);
        }return target;
    }
    public static void mix(List<File> files,List<? extends Number> offsetsMs,boolean[] enabled,boolean stereo,File target)throws IOException{
        if(files.isEmpty()||files.size()!=enabled.length||files.size()!=offsetsMs.size())throw new IOException("没有可混音的声道");List<PcmFile> sources=new ArrayList<>();int rate=8000,channels=stereo?2:1;
        try{
            for(File f:files){PcmFile p=new PcmFile(f);sources.add(p);rate=Math.max(rate,p.rate);}
            long[] starts=new long[files.size()];long frames=0;int[] active=new int[channels];
            for(int i=0;i<files.size();i++){starts[i]=Math.round(offsetsMs.get(i).doubleValue()*rate/1000);if(starts[i]<0)throw new IOException("声道偏移不能小于零");frames=Math.max(frames,starts[i]+(long)Math.ceil(sources.get(i).frames*(double)rate/sources.get(i).rate));if(enabled[i])active[stereo?i%2:0]++;}
            if(frames>rate*3600L)throw new IOException("音频最长 60 分钟");
            try(RandomAccessFile out=new RandomAccessFile(target,"rw")){out.setLength(0);PcmFile.header(out,frames,rate,channels);
                for(long at=0;at<frames;at+=rate){cancel();int count=(int)Math.min(rate,frames-at);float[][] mixed=new float[channels][count];
                    for(int n=0;n<sources.size();n++)if(enabled[n]){PcmFile p=sources.get(n);long sourceFrames=(long)Math.ceil(p.frames*(double)rate/p.rate);long first=Math.max(at,starts[n]),end=Math.min(at+count,starts[n]+sourceFrames);if(end<=first)continue;long sourceAt=Math.round((first-starts[n])*(double)p.rate/rate);int requested=(int)Math.min(p.frames-sourceAt,Math.ceil((end-first)*(double)p.rate/rate));float[] data=p.readFrames(sourceAt,requested,-1,rate);int offset=(int)(first-at),lane=stereo?n%2:0;for(int j=0;j<data.length&&offset+j<count;j++)mixed[lane][offset+j]+=data[j]/Math.max(1,active[lane]);}
                    byte[] bytes=new byte[count*channels*2];for(int i=0;i<count;i++)for(int c=0;c<channels;c++)sample(bytes,(i*channels+c)*2,mixed[c][i]);out.write(bytes);
                }
            }
        }catch(IOException|RuntimeException e){target.delete();throw e;}finally{for(PcmFile p:sources)p.close();}
    }
    /** One media direction per channel, without muting, gain averaging or parity folding. */
    public static void separate(List<File> files,List<? extends Number> offsetsMs,File target)throws IOException{
        if(files.isEmpty()||files.size()>64||files.size()!=offsetsMs.size())throw new IOException("导出需要 1～64 路媒体方向");
        List<PcmFile> sources=new ArrayList<>();int rate=8000,channels=files.size();
        try{
            for(File f:files){PcmFile p=new PcmFile(f);sources.add(p);rate=Math.max(rate,p.rate);}
            long[] starts=new long[channels];long frames=0;
            for(int c=0;c<channels;c++){double offset=offsetsMs.get(c).doubleValue();if(!Double.isFinite(offset)||offset<0)throw new IOException("声道偏移无效");starts[c]=Math.round(offset*rate/1000);long length=(long)Math.ceil(sources.get(c).frames*(double)rate/sources.get(c).rate);if(starts[c]>rate*3600L-length)throw new IOException("音频最长 60 分钟");frames=Math.max(frames,starts[c]+length);}
            if(frames*channels*2>0xffffffffL-60)throw new IOException("导出 WAV 超过 4 GiB，请减少所选媒体方向");
            try(RandomAccessFile out=new RandomAccessFile(target,"rw")){out.setLength(0);PcmFile.header(out,frames,rate,channels);
                int block=Math.min(rate,4096);
                for(long at=0;at<frames;at+=block){cancel();int count=(int)Math.min(block,frames-at);byte[] bytes=new byte[count*channels*2];
                    for(int c=0;c<channels;c++){PcmFile p=sources.get(c);long length=(long)Math.ceil(p.frames*(double)rate/p.rate),first=Math.max(at,starts[c]),end=Math.min(at+count,starts[c]+length);if(end<=first)continue;long sourceAt=Math.round((first-starts[c])*(double)p.rate/rate);int requested=(int)Math.min(p.frames-sourceAt,Math.ceil((end-first)*(double)p.rate/rate));float[] data=p.readFrames(sourceAt,requested,-1,rate);int offset=(int)(first-at);for(int j=0;j<data.length&&offset+j<count;j++)sample(bytes,((offset+j)*channels+c)*2,data[j]);}
                    out.write(bytes);
                }
            }
        }catch(IOException|RuntimeException e){target.delete();throw e;}finally{for(PcmFile p:sources)p.close();}
    }
    private static void sample(byte[] bytes,int at,float value){int n=Math.round(Math.max(-1,Math.min(1,value))*32767);bytes[at]=(byte)n;bytes[at+1]=(byte)(n>>8);}
    private static void cancel()throws InterruptedIOException{if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("音频处理已取消");}
}
