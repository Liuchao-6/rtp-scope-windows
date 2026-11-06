package com.liuchao.rtpscope.desktop;
import com.liuchao.rtpscope.core.*;
import java.io.*;

/** Acceptance through an installed model ZIP and the packaged app JAR/runtime. */
public final class SpeechPackageTest {
    public static void main(String[] args)throws Exception{
        SpeechModels.Model model;try(InputStream in=new FileInputStream(args[0])){model=SpeechModels.install(in,new File(args[2]),"Huatan-SenseVoice-int8.zip");}
        if(model.type!=SpeechModels.Type.SENSE_VOICE)throw new AssertionError("ZIP manifest not recognized");
        if(!SimplifiedChinese.convert("電話聯繫").equals("电话联系"))throw new AssertionError("Packaged conversion dictionary missing");
        Transcript text=AsrWorker.run(new File(args[1]),model,"zh",false,(p,n)->{});
        if(text.segments.isEmpty()||!text.segments.get(0).text.contains("开放时间"))throw new AssertionError("Packaged model cannot transcribe public Chinese reference");
        File file=new File(args[2],"package-transcript.properties");text.save(file);Transcript restored=Transcript.load(file);
        for(Transcript.Segment s:restored.segments)if(!s.language.equals("zh")||!SimplifiedChinese.convert(s.text).equals(s.text))throw new AssertionError("Packaged transcript normalization failed");
        System.out.println("PASS: installed model ZIP, packaged runtime/JAR and Chinese output");
    }
}
