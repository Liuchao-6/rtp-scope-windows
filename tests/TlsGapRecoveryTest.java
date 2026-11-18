package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.swing.*;

/** A handshake and a call captured hours later, without the intervening TLS records. */
public final class TlsGapRecoveryTest {
    private static int checks;
    private static final String TARGET="late-call@split.invalid";
    private static void check(boolean value,String text){checks++;if(!value)throw new AssertionError(text);}
    private static boolean warning(Analysis a,String text){return a.warnings.keySet().stream().anyMatch(w->w.contains(text));}
    private static Analysis read(File file,File directory,TlsKeyLog log,TlsRsaKeys rsa)throws IOException{try(InputStream in=new FileInputStream(file)){return CaptureEngine.readLarge(in,directory,null,log,rsa);}}
    private static TlsKeyLog log(File folder,String name)throws IOException{try(InputStream in=new FileInputStream(new File(folder,name+".keys"))){return TlsKeyLog.read(in);}}
    private static void inspect(Analysis a,String name){
        check(a.sip.size()==8,name+" must recover both captured segments, without joining incomplete bodies; got "+a.sip.size()+"; "+a.warnings);
        check(a.messagesFor("early@split.invalid").size()==2,"early request/response remain available");
        List<SipMessage> late=a.messagesFor(TARGET);check(late.size()==6,"late call retains INVITE, 200, ACK, INFO, BYE, 200");
        check(late.stream().allMatch(m->m.transport.equals("TLS")),"all recovered signaling remains labeled TLS");
        check(late.get(0).timeUs-a.firstUs>9000000000L,"late call keeps its original capture time");
        check(late.stream().anyMatch(m->m.firstLine.startsWith("ACK ")),"late SIP ACK is visible");
        check(a.events.stream().anyMatch(e->TARGET.equals(e.callId)&&e.type==DtmfParser.Type.SIP_INFO&&e.key.equals("7")),"late INFO digit is analyzed");
        check(a.streams.size()==2&&a.streams.stream().allMatch(s->TARGET.equals(s.callId)&&s.playable()),"both late media directions associate with the recovered SDP");
        check(a.messagesFor("incomplete@split.invalid").isEmpty(),"never fabricate a message across the missing bytes");
        check(warning(a,"已恢复")&&warning(a,"缺口"),"recovery and incomplete capture remain explicit");
    }
    private static void ready(DesktopApp app)throws Exception{
        long end=System.currentTimeMillis()+30000;boolean[] waiting={true};
        while(waiting[0]&&System.currentTimeMillis()<end){SwingUtilities.invokeAndWait(()->waiting[0]=app.isBusy()||app.isBackgroundWorking());if(waiting[0])Thread.sleep(35);}
        check(!waiting[0],"desktop background tasks finish");
    }
    public static void main(String[] args)throws Exception{
        File fixtures=new File(args[0]),output=new File(args[1]),inputs=new File(output,"tls-gaps");
        File directory=Files.createTempDirectory(output.toPath(),"tls-gap-cache-").toFile();
        TlsRsaKeys rsa,wrong;try(InputStream in=new FileInputStream(new File(fixtures,"rsa-synthetic-pkcs8.key"))){rsa=TlsRsaKeys.read(in);}try(InputStream in=new FileInputStream(new File(fixtures,"rsa-synthetic-wrong.key"))){wrong=TlsRsaKeys.read(in);}
        try{
            for(String name:new String[]{"gcm256","gcm128","gcm256-mid-record"})for(boolean useLog:new boolean[]{false,true}){
                try(Analysis a=read(new File(inputs,name+".pcap"),directory,useLog?log(inputs,name.startsWith("gcm256")?"gcm256":name):TlsKeyLog.empty(),useLog?TlsRsaKeys.empty():rsa)){inspect(a,name+(useLog?" keylog":" RSA"));}
            }
            for(boolean useLog:new boolean[]{false,true})try(Analysis a=read(new File(inputs,"gcm256-handshake-only.pcap"),directory,useLog?log(inputs,"gcm256"):TlsKeyLog.empty(),useLog?TlsRsaKeys.empty():rsa)){
                check(a.sip.size()==6&&a.messagesFor(TARGET).size()==6,"handshake-only first segment still recovers the full later call");
                check(a.messagesFor("early@split.invalid").isEmpty(),"omitted early application records are not fabricated");
                check(a.events.stream().anyMatch(e->e.key.equals("7")),"handshake-only capture recovers later INFO");
                check(a.streams.stream().filter(s->s.callId.equals(TARGET)).count()==2,"handshake-only capture associates both media directions");
                check(warning(a,"已恢复"),"handshake-only recovery is reported");
            }
            try(Analysis a=read(new File(inputs,"gcm256-tampered.pcap"),directory,TlsKeyLog.empty(),rsa)){
                check(a.messagesFor("early@split.invalid").size()==2,"tampered late record does not discard valid early signaling");
                check(a.messagesFor(TARGET).stream().noneMatch(m->m.firstLine.startsWith("INVITE ")||m.firstLine.startsWith("INFO ")),"failed authentication never delivers the affected direction's late SIP");
                check(warning(a,"认证失败"),"tampered resumed record warns explicitly");
            }
            try(Analysis a=read(new File(inputs,"gcm256.pcap"),directory,TlsKeyLog.empty(),wrong)){check(a.sip.isEmpty()&&warning(a,"不匹配"),"wrong RSA key cannot produce any recovered plaintext");}
            try(Analysis a=read(new File(inputs,"gcm256-no-handshake.pcap"),directory,TlsKeyLog.empty(),rsa)){check(a.sip.isEmpty()&&warning(a,"ClientHello"),"an RSA key alone cannot replace the absent handshake");}
            for(String name:new String[]{"cbc","tls13"})try(Analysis a=read(new File(inputs,name+".pcap"),directory,name.equals("tls13")?log(inputs,name):TlsKeyLog.empty(),name.equals("cbc")?rsa:TlsRsaKeys.empty())){
                check(a.messagesFor("early@split.invalid").size()==2,"unsupported gap recovery retains the valid initial segment: "+name);
                check(a.messagesFor(TARGET).isEmpty()&&warning(a,"无法安全恢复"),"unsupported cipher never guesses across gaps: "+name);
            }
            Thread.currentThread().interrupt();try(InputStream in=new FileInputStream(new File(inputs,"gcm256.pcap"))){try{CaptureEngine.readLarge(in,directory,null,TlsKeyLog.empty(),rsa);throw new AssertionError("cancelled gap import accepted");}catch(IOException expected){checks++;}}finally{Thread.interrupted();}
            check(directory.list().length==0,"gap success, rejection and cancellation clean temporary storage");
            final DesktopApp[] holder={null};SwingUtilities.invokeAndWait(()->{holder[0]=new DesktopApp();holder[0].load(new File(inputs,"gcm256.pcap"));});DesktopApp app=holder[0];
            try{
                ready(app);SwingUtilities.invokeAndWait(()->{check(app.model.analysis.sip.isEmpty(),"PCAP may be imported before a key");app.loadRsaKey(new File(fixtures,"rsa-synthetic-pkcs8.key"));});ready(app);
                SwingUtilities.invokeAndWait(()->{inspect(app.model.analysis,"desktop independent RSA import");app.model.callId=TARGET;app.refreshViews();check(app.model.messages().size()==6&&app.flow.data().entries.size()>6,"late call opens in desktop flow and SIP table");SipMessage info=app.model.messages().stream().filter(m->m.firstLine.startsWith("INFO ")).findFirst().get();app.openEntry(info);check(app.detail.original().contains("Signal=7"),"late decrypted SIP details are visible");});
            }finally{SwingUtilities.invokeAndWait(app::shutdown);}
            System.out.println("PASS: "+checks+" TLS gap recovery checks; RSA/keylog, AES-128/256-GCM, 55000/110000 omitted records, partial TLS/SIP, authentication rejection and desktop key import");
        }finally{for(File f:directory.listFiles())f.delete();directory.delete();}
    }
}
