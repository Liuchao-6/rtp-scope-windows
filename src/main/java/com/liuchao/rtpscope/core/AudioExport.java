package com.liuchao.rtpscope.core;

import java.io.*;
import java.util.Locale;

/** Shared safe audio export; the desktop supplies its bundled MP3 encoder. */
public final class AudioExport {
    private AudioExport(){}
    public enum Format {
        WAV("wav"), MP3("mp3");
        public final String extension;
        Format(String extension){this.extension=extension;}
        public static Format of(File file){return file.getName().toLowerCase(Locale.ROOT).endsWith(".mp3")?MP3:WAV;}
    }
    public interface Encoder {void encode(File wav,File target)throws IOException;}
    public static void save(File target,Format format,AudioClip.Writer writer,Encoder encoder)throws IOException{
        AudioClip.saveAtomically(target,temp->{
            if(format==Format.WAV){writer.write(temp);return;}
            if(encoder==null)throw new IOException("没有找到 MP3 编码组件，请使用完整 Windows 发布包");
            File wav=File.createTempFile(".huatan-mp3-",".wav",temp.getParentFile());
            try{
                writer.write(wav);
                try(PcmFile pcm=new PcmFile(wav)){
                    if(pcm.channels>2)throw new IOException("MP3 最多支持两个声道，请选择 WAV 保留全部独立声道");
                    if(pcm.frames==0)throw new IOException("音频为空，无法导出 MP3");
                }
                if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("音频导出已取消");
                encoder.encode(wav,temp);
                if(temp.length()==0)throw new IOException("MP3 编码没有生成音频");
            }finally{if(!wav.delete())wav.deleteOnExit();}
        });
    }
}
