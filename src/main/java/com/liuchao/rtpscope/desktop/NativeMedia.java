package com.liuchao.rtpscope.desktop;
import com.liuchao.rtpscope.core.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** FFmpeg process bridge for recording formats and AMR. Argument lists never pass through a shell. */
final class NativeMedia {
    static File executable(){
        String override=System.getProperty("huatan.ffmpeg","");if(!override.isEmpty()&&new File(override).isFile())return new File(override);
        File[] paths={new File("third_party/ffmpeg/ffmpeg.exe"),new File("app/lib/ffmpeg.exe"),new File(new File(System.getProperty("java.home")).getParentFile(),"app/lib/ffmpeg.exe")};
        for(File f:paths)if(f.isFile())return f.getAbsoluteFile();return null;
    }
    static void install(){CodecSupport.provider=new CodecSupport.Provider(){public boolean supports(String codec){return executable()!=null;}public File decode(File encoded,boolean wide,int rate)throws IOException{File raw=File.createTempFile("huatan-amr-pcm-",".pcm");try{run(Arrays.asList("-f","amr","-i",encoded.getAbsolutePath(),"-ac","1","-ar",String.valueOf(rate),"-f","s16le",raw.getAbsolutePath()));return raw;}catch(IOException e){raw.delete();throw e;}}};}
    static File recording(File source,File target)throws IOException{
        if(source.length()>1024L*1024*1024)throw new IOException("录音超过 1 GiB，请先拆分");
        try{run(Arrays.asList("-i",source.getAbsolutePath(),"-map","0:a:0","-vn","-c:a","pcm_s16le","-map_metadata","-1","-bitexact","-fs","1400000000",target.getAbsolutePath()));
        try(PcmFile pcm=new PcmFile(target)){if(pcm.durationMs()>3600000)throw new IOException("单个录音最长 60 分钟，请先拆分");if(target.length()>=1400000000)throw new IOException("录音解码大小超过限制，请先拆分");}return target;}catch(IOException e){target.delete();throw e;}
    }
    static void run(List<String> arguments)throws IOException{
        File exe=executable();if(exe==null)throw new IOException("没有找到音频解码组件，请使用完整 Windows 发布包");List<String> command=new ArrayList<>(Arrays.asList(exe.getAbsolutePath(),"-hide_banner","-loglevel","error","-nostdin","-y"));command.addAll(arguments);File log=File.createTempFile("huatan-media-",".log");Process process=null;
        try{process=new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log).start();while(!process.waitFor(200,TimeUnit.MILLISECONDS)){if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("音频处理已取消");}if(process.exitValue()!=0)throw new IOException("音频解码失败，文件可能损坏或编码不支持");}
        catch(InterruptedException e){Thread.currentThread().interrupt();throw new InterruptedIOException("音频处理已取消");}finally{if(process!=null&&process.isAlive())process.destroyForcibly();log.delete();}
    }
}
