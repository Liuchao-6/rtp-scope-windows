package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.swing.*;

/** Long sessions exceed both legacy limits, with the requested call at the end. */
public final class LongSignalingTest {
    private static int checks;
    private static final String TARGET="late-call@merged.invalid";
    private static void check(boolean value,String detail){checks++;if(!value)throw new AssertionError(detail);}
    private static TlsKeyLog keys(File folder,String kind)throws IOException{try(InputStream in=new FileInputStream(new File(folder,kind+".keys"))){return TlsKeyLog.read(in);}}
    private static void inspect(Analysis a,String transport){
        check(a.sip.size()==35010&&!a.partial,"all messages imported without truncation: "+transport);
        List<SipMessage> late=a.messagesFor(TARGET);check(late.size()==3,"target call retains INVITE, INFO and BYE");
        SipMessage invite=late.get(0),info=late.get(1),bye=late.get(2);
        check(invite.transport.equals(transport)&&info.transport.equals(transport),"transport survives disk backing");
        check(invite.raw==null&&invite.raw().contains("X-Regression-Index: 35007"),"late raw message read on demand from disk");
        check(info.headers.get("x-regression-index").equals("35008")&&info.body().contains("Signal=9"),"lazy headers and body preserve all fields");
        check(invite.timeUs<=info.timeUs&&info.timeUs<=bye.timeUs&&bye.timeUs-a.firstUs>6000000000L,"hours of signaling keep capture timestamps");
        check(a.streams.size()==1&&a.streams.get(0).callId.equals(TARGET)&&a.streams.get(0).playable(),"late SDP associates playable media");
        check(a.events.stream().anyMatch(e->e.type==DtmfParser.Type.SIP_INFO&&e.key.equals("9")&&TARGET.equals(e.callId)),"late INFO keypad event is parsed");
        CallFlow flow=CallFlow.build(a,TARGET,"");check(flow.entries.size()==5&&flow.entries.stream().anyMatch(e->e.title.equals("INVITE / SDP")),"selected-call flow includes signaling, media and key");
        DesktopModel model=new DesktopModel();model.load(a);model.callId=TARGET;
        check(model.messages().size()==3,"selected-call SIP index returns only requested messages");model.query="Signal=9";check(model.messages().size()==1,"full body search reads lazy original");
        check(CallHealth.inspect(a,TARGET).end!=null,"call health can read the late BYE");
    }
    public static void main(String[] args)throws Exception{
        File fixtures=new File(args[0]),output=new File(args[1]);
        if(args.length>2&&args[2].equals("--ordinary")){
            for(String kind:new String[]{"udp","tcp"})try(InputStream in=new FileInputStream(new File(output,"long-signaling/"+kind+".pcap"))){try(Analysis ignored=CaptureEngine.read(in)){throw new AssertionError("ordinary entry lost its limits");}}catch(IOException expected){check(expected.getMessage().contains(kind.equals("udp")?"3 万":"24 MB"),"ordinary limits remain: "+kind);}
            System.out.println("PASS: ordinary SIP and TCP limits preserved");return;
        }
        if(args.length>2){real(new File(args[2]),output);return;}
        File inputs=new File(output,"long-signaling"),directory=Files.createTempDirectory(output.toPath(),"long-index-").toFile();
        long started=System.nanoTime();
        try{
            TlsRsaKeys rsa;try(InputStream in=new FileInputStream(new File(fixtures,"rsa-synthetic-pkcs8.key"))){rsa=TlsRsaKeys.read(in);}
            for(String kind:new String[]{"udp","tcp","tls12-rsa","tls13-wss"}){
                String transport=kind.equals("udp")?"UDP":kind.equals("tcp")?"TCP":kind.equals("tls12-rsa")?"TLS":"WSS";
                List<String> stages=new ArrayList<>();DeferredCapture staged;
                try(InputStream in=new FileInputStream(new File(inputs,kind+".pcap"))){staged=CaptureEngine.readLargeSignaling(in,directory,new CaptureEngine.Progress(){public void update(long b,long p){}public void stage(String s){stages.add(s);}},kind.equals("tls13-wss")?keys(inputs,kind):TlsKeyLog.empty(),kind.equals("tls12-rsa")?rsa:TlsRsaKeys.empty());}
                Analysis a=staged.signaling;
                try{
                    inspect(a,transport);check(stages.contains("TLS 解密与 SIP 消息解析"),"reports signaling phase");
                    Analysis complete=staged.analyze(null);staged.apply(complete);check(a.streams.get(0).quality!=null,"media analysis completes for late call");
                    if(kind.equals("tcp")){
                        AnalysisCache cache=new AnalysisCache(directory);String key=cache.key(new ByteArrayInputStream(new byte[]{11,18}));cache.save(key,complete);
                        try(Analysis restored=cache.load(key)){check(restored!=null,"large SIP index restores");inspect(restored,transport);check(restored.streams.get(0).quality!=null,"cached media quality restores");}
                        cache.clear();
                        final DesktopApp[] holder={null};SwingUtilities.invokeAndWait(()->{holder[0]=new DesktopApp();holder[0].acceptAnalysis(a,"long synthetic capture");holder[0].model.callId=TARGET;holder[0].refreshViews();check(holder[0].flow.data().entries.size()==5,"actual desktop renders late call without selecting all background rows");holder[0].openEntry(a.messagesFor(TARGET).get(1));check(holder[0].detail.original().contains("Signal=9"),"SIP detail shows lazy body in Swing");});
                        SwingUtilities.invokeAndWait(()->{holder[0].model.analysis=null;holder[0].shutdown();});
                        File temporary=a.mediaStore.file();try(Closeable lease=a.mediaStore.retain()){a.close();check(temporary.isFile()&&a.messagesFor(TARGET).get(0).raw().contains("35007"),"task lease keeps lazy SIP readable after closing the owner");}
                        check(!temporary.exists(),"last lease deletes signaling storage");
                        try{a.messagesFor(TARGET).get(0).raw();throw new AssertionError("closed SIP store remained readable");}catch(UncheckedIOException expected){checks++;}
                    }
                }finally{a.close();}
                check(directory.list().length==0,"closing removes all temporary signaling and media: "+kind);
                System.out.println("PASS: long "+kind+" import, 35010 messages; elapsed="+String.format(Locale.ROOT,"%.1f",(System.nanoTime()-started)/1e9)+"s");
            }
            try(InputStream in=new FileInputStream(new File(inputs,"tls12-rsa.pcap"))){
                try{CaptureEngine.readLargeSignaling(in,directory,new CaptureEngine.Progress(){public void update(long b,long p){}public void stage(String name){if(name.startsWith("TLS 解密"))Thread.currentThread().interrupt();}},TlsKeyLog.empty(),rsa);throw new AssertionError("cancelled long decrypt accepted");}catch(InterruptedIOException expected){checks++;}finally{Thread.interrupted();}
            }
            check(directory.list().length==0,"cancelled long signaling import deletes all temporary data");
            System.out.println("PASS: "+checks+" long-signaling checks; bounded heap="+Runtime.getRuntime().maxMemory());
        }finally{for(File f:directory.listFiles())f.delete();directory.delete();}
    }
    private static void real(File file,File output)throws Exception{
        long start=System.nanoTime();DeferredCapture staged;try(InputStream in=new FileInputStream(file)){staged=CaptureEngine.readLargeSignaling(in,output,new CaptureEngine.Progress(){public void update(long b,long p){}public void stage(String name){System.out.println("stage="+name);}},TlsKeyLog.empty(),TlsRsaKeys.empty());}
        try(Analysis a=staged.signaling){
            check(a.sip.size()>30000,"provided merged capture exceeds old SIP limit");check(!a.calls.isEmpty(),"provided merged capture has selectable calls");
            SwingUtilities.invokeAndWait(()->{DesktopApp app=new DesktopApp();try{app.acceptAnalysis(a,"合并抓包复测");check(!app.model.callId.isEmpty()&&!app.model.messages().isEmpty(),"actual Swing opens first call");app.openEntry(app.model.messages().get(0));check(!app.detail.original().isEmpty(),"actual Swing opens SIP detail");CallSearch.Filter filter=new CallSearch.Filter();filter.keyword=a.calls.get(a.calls.size()-1).id;app.setCallSearch(filter);check(app.callCount()>0,"actual call filter finds last call");}finally{app.model.analysis=null;app.shutdown();}});
            System.out.println("REAL_CAPTURE_PASS packets="+a.packets+" sip="+a.sip.size()+" calls="+a.calls.size()+" streams="+a.streams.size()+" partial="+a.partial+" warning_types="+a.warnings.size()+" elapsed_seconds="+String.format(Locale.ROOT,"%.2f",(System.nanoTime()-start)/1e9));
        }
    }
}
