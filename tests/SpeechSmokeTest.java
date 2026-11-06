package com.liuchao.rtpscope.desktop;
import com.liuchao.rtpscope.core.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

/** Optional real model acceptance. Supply local model, public reference WAV and output folder. */
public final class SpeechSmokeTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    public static void main(String[] args)throws Exception{
        SpeechModels.Model model=SpeechModels.inspect(new File(args[0]));File wav=new File(args[1]),out=new File(args[2]);
        Transcript english=AsrWorker.run(wav,model,"en",false,(p,n)->{});check(english.segments.stream().anyMatch(s->s.text.toLowerCase(Locale.ROOT).contains("yellow lamps")),"public English recording recognized by real ONNX inference");
        File stereo=new File(out,"speech-stereo-offset.wav");PcmTracks.mix(Arrays.asList(wav,wav),Arrays.asList(5000,9000),new boolean[]{true,true},true,stereo);Transcript split=AsrWorker.run(stereo,model,"en",true,(p,n)->{});check(split.channels().size()==2,"actual stereo recording produces two channel transcripts");check(split.channel("左声道").segments.stream().allMatch(s->s.startMs>=4880)&&split.channel("右声道").segments.stream().allMatch(s->s.startMs>=8880),"real ASR keeps original timestamps after leading silence");split.save(new File(out,"speech-stereo-result.properties"));
        File chinese=new File(out,"asr-chinese.wav");if(chinese.isFile()){Transcript zh=AsrWorker.run(chinese,model,"zh",false,(p,n)->{});check(zh.segments.stream().anyMatch(s->s.text.contains("你好")),"Chinese synthesis is transcribed locally");zh.save(new File(out,"speech-chinese-result.properties"));}
        CountDownLatch stopped=new CountDownLatch(1);ExecutorService worker=Executors.newSingleThreadExecutor();Future<?> task=worker.submit(()->{try{AsrWorker.run(stereo,model,"en",true,(p,n)->{});}catch(Exception expected){}finally{stopped.countDown();}});Thread.sleep(250);long start=System.nanoTime();task.cancel(true);check(stopped.await(5,TimeUnit.SECONDS),"cancel terminates the native recognition process promptly");worker.shutdownNow();System.out.println("PASS: "+checks+" real speech checks; cancel="+(System.nanoTime()-start)/1000000+" ms");
    }
}
