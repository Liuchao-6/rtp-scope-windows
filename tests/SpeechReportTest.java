import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/** User-visible text consistency, old model compatibility and independent privacy controls. */
public final class SpeechReportTest {
    private static int checks;
    private static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
    private static byte[] zip(String... names)throws IOException{ByteArrayOutputStream out=new ByteArrayOutputStream();try(ZipOutputStream z=new ZipOutputStream(out)){for(String name:names){z.putNextEntry(new ZipEntry(name));z.write(name.endsWith("model.properties")?"type=sensevoice\nname=SenseVoice Small int8\n".getBytes("UTF-8"):new byte[2048]);z.closeEntry();}}return out.toByteArray();}
    public static int run(File output)throws Exception{
        check(SimplifiedChinese.convert("電話錄音，請聯繫客服，頭髮乾淨。臺灣通話。123 ABC!").equals("电话录音，请联系客服，头发干净。台湾通话。123 ABC!"),"Chinese characters and phrase exceptions simplify while ASCII stays intact");
        check(SimplifiedChinese.convert("😀 錄音 𠀀").equals("😀 录音 𠀀"),"supplementary characters survive conversion");
        Transcript t=new Transcript();Transcript.Segment zh=new Transcript.Segment(65000,68000,"左声道","電話錄音");zh.language="zh";Transcript.Segment ja=new Transcript.Segment(69000,70000,"右声道","電話の録音");ja.language="ja";t.segments.add(zh);t.segments.add(ja);t.simplifyChinese(true);
        check(zh.text.equals("电话录音")&&ja.text.equals("電話の録音"),"Chinese conversion does not rewrite detected Japanese");
        check(zh.startMs==65000&&zh.endMs==68000&&t.channels().size()==2,"normalization preserves source time and channels");
        File saved=new File(output,"speech-language.properties");t.save(saved);Transcript restored=Transcript.load(saved);check(restored.segments.get(0).language.equals("zh")&&restored.segments.get(1).language.equals("ja"),"language survives saving and reload");
        for(boolean srt:new boolean[]{false,true}){ByteArrayOutputStream out=new ByteArrayOutputStream();restored.export(out,srt);String text=out.toString("UTF-8");check(text.contains("电话录音")&&text.contains("電話の録音")&&!text.contains("電話錄音"),"TXT and SRT match displayed simplified Chinese");}
        Properties legacy=new Properties();legacy.setProperty("count","1");legacy.setProperty("0.start","12");legacy.setProperty("0.end","100");legacy.setProperty("0.channel","单声道");legacy.setProperty("0.text","請聯繫");try(OutputStream out=new FileOutputStream(saved)){legacy.store(out,"");}restored=Transcript.load(saved);restored.simplifyChinese(false);check(restored.segments.get(0).text.equals("請聯繫"),"unknown legacy language is preserved outside Chinese mode");restored.simplifyChinese(true);check(restored.segments.get(0).text.equals("请联系"),"old results normalize in Chinese mode without re-recognition");
        File root=Files.createTempDirectory(output.toPath(),"speech-model-test-").toFile();
        SpeechModels.Model old=SpeechModels.install(new ByteArrayInputStream(zip("old/encoder.int8.onnx","old/decoder.int8.onnx","old/tokens.txt")),root,"Whisper.zip");check(old.type==SpeechModels.Type.WHISPER,"existing Whisper packages remain compatible");
        SpeechModels.Model sense=SpeechModels.install(new ByteArrayInputStream(zip("sense/model.properties","sense/model.int8.onnx","sense/tokens.txt")),root,"Sense.zip");check(sense.type==SpeechModels.Type.SENSE_VOICE&&sense.network.length()==2048,"explicit SenseVoice manifest imports as correct architecture");check(SpeechModels.list(root).get(0).type==SpeechModels.Type.SENSE_VOICE,"Chinese recommended model sorts before tiny");
        int before=root.list().length;try{SpeechModels.install(new ByteArrayInputStream(zip("model.int8.onnx","tokens.txt")),root,"Unknown.zip");throw new AssertionError("unidentified architecture accepted");}catch(IOException expected){checks++;}check(root.list().length==before,"failed model import removes partial directory");
        Thread.currentThread().interrupt();try{SpeechModels.install(new ByteArrayInputStream(zip("model.properties","model.int8.onnx","tokens.txt")),root,"Cancel.zip");throw new AssertionError("cancel ignored");}catch(InterruptedIOException expected){checks++;}finally{Thread.interrupted();}check(root.list().length==before,"cancelled import removes partial files");
        Analysis a=new Analysis();Call c=new Call();c.id="privacy";c.from="<sip:13800138000@192.0.2.1>;tag=caller";c.to="<sip:02168908293@198.51.100.2>";a.calls.add(c);
        for(int n=0;n<3;n++){SipMessage m=new SipMessage();m.callId=c.id;m.timeUs=(n+1)*1000000;m.src="192.0.2.1:5060";m.dst="[2001:db8::2]:5060";m.from=c.from;m.to=c.to+(n==0?"":";tag=callee");m.cseq=(n==2?"2 BYE":"1 INVITE");m.firstLine=n==0?"INVITE sip:02168908293@198.51.100.2 SIP/2.0":n==1?"SIP/2.0 200 OK":"BYE sip:02168908293@198.51.100.2 SIP/2.0";m.raw=m.firstLine;a.sip.add(m);}
        for(boolean numbers:new boolean[]{false,true})for(boolean ips:new boolean[]{false,true}){
            ByteArrayOutputStream out=new ByteArrayOutputStream();CallExport.report(a,c.id,numbers,ips,out);String html=out.toString("UTF-8");
            check(html.contains("13800138000")==!numbers&&html.contains("02168908293")==!numbers,"number masking is independent of IP masking");check(html.contains("192.0.2.1")==!ips&&html.contains("2001:db8::2")==!ips,"IPv4 and IPv6 masking is independent of numbers");check(html.contains("00:01.000")&&html.contains("2 BYE"),"masking preserves duration and signaling evidence");
        }
        return checks;
    }
}
