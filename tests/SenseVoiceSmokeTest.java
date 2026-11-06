package com.liuchao.rtpscope.desktop;
import com.liuchao.rtpscope.core.*;
import java.io.*;

/** Real Chinese/automatic inference on upstream public recordings. */
public final class SenseVoiceSmokeTest {
    public static void main(String[] args)throws Exception{
        SpeechModels.Model model=SpeechModels.inspect(new File(args[0]));int checks=0;
        for(String lang:new String[]{"zh","auto"}){
            Transcript text=AsrWorker.run(new File(args[1]),model,lang,false,(p,n)->{});
            if(text.segments.isEmpty())throw new AssertionError("Public Chinese speech produced no text");checks++;
            boolean identified=false;
            for(Transcript.Segment s:text.segments){if(s.text.contains("<|"))throw new AssertionError("Model tags leaked into visible text");if(!SimplifiedChinese.convert(s.text).equals(s.text))throw new AssertionError("Chinese output is not simplified");if(s.language.equals("zh"))identified=true;}
            if(!identified)throw new AssertionError("Chinese language metadata is missing");checks++;
            text.save(new File(args[2],"sensevoice-public-"+lang+".properties"));
            System.out.println(lang+"="+text.segments.get(0).text);
        }
        System.out.println("PASS: "+checks+" public Chinese / auto language checks");
    }
}
