package com.liuchao.rtpscope.desktop;
import com.liuchao.rtpscope.core.*;
import java.io.*;

/** Process boundary for native inference; the GUI can terminate cancellation promptly. */
public final class AsrWorker {
    public static void main(String[] args)throws Exception{
        if(args.length!=6)throw new IOException("识别任务参数不完整");
        try(SpeechTranscriber engine=new SpeechTranscriber(SpeechModels.inspect(new File(args[0])),args[2])){
            Transcript result=engine.transcribe(new File(args[1]),Boolean.parseBoolean(args[3]),(phase,value)->{System.out.println("PROGRESS\t"+value+"\t"+phase);System.out.flush();});
            result.save(new File(args[4]));
        }
    }
    public static Transcript run(File wav,SpeechModels.Model model,String language,boolean separate,SpeechTranscriber.Progress progress)throws Exception{
        File result=File.createTempFile("huatan-text-",".properties"),log=File.createTempFile("huatan-asr-",".log");Process process=null;
        try{
            File javaBinary=new File(System.getProperty("java.home"),"bin/java.exe");
            process=new ProcessBuilder(javaBinary.getAbsolutePath(),"-Xmx192m","-Dfile.encoding=UTF-8","-cp",System.getProperty("java.class.path"),AsrWorker.class.getName(),model.directory.getAbsolutePath(),wav.getAbsolutePath(),language,String.valueOf(separate),result.getAbsolutePath(),"v1").redirectError(log).start();final Process child=process;
            Thread output=new Thread(()->{try(BufferedReader reader=new BufferedReader(new InputStreamReader(child.getInputStream(),"UTF-8"))){String line;while((line=reader.readLine())!=null)if(line.startsWith("PROGRESS\t")){String[] parts=line.split("\t",3);progress.update(parts[2],Integer.parseInt(parts[1]));}}catch(Exception ignored){}},"transcript-progress");output.setDaemon(true);output.start();
            while(!process.waitFor(200,java.util.concurrent.TimeUnit.MILLISECONDS))if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("转写已取消");
            if(process.exitValue()!=0)throw new IOException("本地识别未完成，请检查模型是否完整、语言设置和可用内存");return Transcript.load(result);
        }catch(InterruptedException e){Thread.currentThread().interrupt();throw new InterruptedIOException("转写已取消");}finally{if(process!=null&&process.isAlive()){process.destroyForcibly();try{process.waitFor(5,java.util.concurrent.TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}}result.delete();log.delete();}
    }
}
