package com.liuchao.rtpscope.core;

import java.io.*;
import java.nio.file.*;

/** Frame-aligned WAV excerpts with bounded memory and safe replacement of existing output. */
public final class AudioClip {
    private AudioClip(){}
    public interface Writer {void write(File temporary)throws IOException;}
    public static void validateRange(double startMs,double endMs,double durationMs)throws IOException{
        if(!Double.isFinite(startMs)||!Double.isFinite(endMs)||!Double.isFinite(durationMs)||startMs<0||endMs<=startMs||endMs>durationMs)
            throw new IOException("截取范围无效：终点须晚于起点，且不能超出音频时长");
    }
    public static void different(File source,File target)throws IOException{
        if(source==null||source.getCanonicalFile().equals(target.getCanonicalFile())||target.exists()&&Files.isSameFile(source.toPath(),target.toPath()))
            throw new IOException("请另存为新文件，不能覆盖原音频");
    }
    public static void saveAtomically(File target,Writer writer)throws IOException{
        File destination=target.getAbsoluteFile();Path temp=Files.createTempFile(destination.getParentFile().toPath(),".huatan-clip-",".part");
        try{
            cancel();writer.write(temp.toFile());cancel();
            try{Files.move(temp,destination.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}
            catch(AtomicMoveNotSupportedException unsupported){Files.move(temp,destination.toPath(),StandardCopyOption.REPLACE_EXISTING);}
        }finally{Files.deleteIfExists(temp);}
    }
    public static void save(File source,File target,double startMs,double endMs)throws IOException{
        different(source,target);
        saveAtomically(target,temp->{
            try(PcmFile pcm=new PcmFile(source);RandomAccessFile in=new RandomAccessFile(source,"r");RandomAccessFile out=new RandomAccessFile(temp,"rw")){
                validateRange(startMs,endMs,pcm.durationMs());long first=Math.round(startMs*pcm.rate/1000),last=Math.min(pcm.frames,Math.round(endMs*pcm.rate/1000));
                if(last<=first)throw new IOException("截取范围不足一个音频采样帧");
                int frameBytes=pcm.channels*(pcm.bits/8);long remaining=(last-first)*frameBytes;
                out.setLength(0);PcmFile.header(out,last-first,pcm.rate,pcm.channels,pcm.bits,pcm.format);in.seek(pcm.offset+first*frameBytes);
                byte[] buffer=new byte[65536];while(remaining>0){cancel();int n=(int)Math.min(buffer.length,remaining);in.readFully(buffer,0,n);out.write(buffer,0,n);remaining-=n;}
                if(((last-first)*frameBytes&1)!=0)out.write(0);
            }
        });
    }
    private static void cancel()throws InterruptedIOException{if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("音频截取已取消");}
}
