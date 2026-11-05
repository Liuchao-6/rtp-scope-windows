import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.desktop.AudioPreview;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.Files;
import java.util.*;

public final class SecureTransportTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static TlsKeyLog keys(File fixtures,String name)throws Exception{try(InputStream in=new FileInputStream(new File(fixtures,name))){return TlsKeyLog.read(in);}}
    private static Analysis read(File fixtures,String name,TlsKeyLog keys)throws Exception{try(InputStream in=new FileInputStream(new File(fixtures,name))){return CaptureEngine.read(in,keys);}}
    private static short pcm(byte[] bytes,int at){return (short)((bytes[at]&255)|((bytes[at+1]&255)<<8));}
    private static int le(byte[] bytes,int at){return (bytes[at]&255)|((bytes[at+1]&255)<<8)|((bytes[at+2]&255)<<16)|((bytes[at+3]&255)<<24);}
    public static int run(File fixtures,File out)throws Exception {
        for(String name:new String[]{"sip-websocket","sip-websocket-deflate","sip-websocket-context","sip-websocket-long","sip-websocket-no-upgrade","tls12-gcm128","tls12-gcm256","tls12-chacha","tls12-cbc","tls12-cbc-mte","tls13-sip","tls13-websocket","tls13-vector-1301","tls13-vector-1302","tls13-vector-1303","tls13-vector-1304","tls13-vector-1305"}){
            boolean tls=name.startsWith("tls"),ws=name.contains("websocket");TlsKeyLog log=tls?keys(fixtures,name+".keys"):TlsKeyLog.empty();
            if(tls){Analysis locked=read(fixtures,name+".pcap",TlsKeyLog.empty());check(locked.sip.isEmpty()&&!locked.warnings.isEmpty(),name+" has no invented SIP without session keys");}
            Analysis analysis=read(fixtures,name+".pcap",log);
            check(analysis.sip.size()==3,name+" decrypts/reassembles all SIP messages: "+analysis.sip.size()+"; warnings="+analysis.warnings);
            check(analysis.calls.size()==1&&analysis.calls.get(0).requestTarget.contains("1002"),name+" retains Call-ID and request target");
            check(analysis.sip.stream().allMatch(m->m.transport.equals(tls?(ws?"WSS":"TLS"):"WS")),name+" reports actual signaling transport");
            check(analysis.events.stream().anyMatch(e->e.type==DtmfParser.Type.SIP_INFO&&e.key.equals("5")),name+" retains SIP INFO digits");
            check(analysis.streams.stream().anyMatch(s->s.playable()&&s.codec.equals("PCMU")&&!s.callId.isEmpty()),name+" maps decrypted SDP to RTP");
        }
        TlsKeyLog one=keys(fixtures,"tls13-sip.keys"),two=keys(fixtures,"tls12-gcm128.keys");check(one.merge(one).size()==one.size(),"duplicate key imports are idempotent");check(one.merge(two).size()==one.size()+two.size(),"independent logs merge sessions");
        Analysis incomplete=read(fixtures,"sip-websocket-incomplete.pcap",TlsKeyLog.empty());check(incomplete.sip.isEmpty()&&!incomplete.warnings.isEmpty(),"unfinished WebSocket fragments are not presented as complete SIP");
        check(read(fixtures,"tls13-sip.pcap",two).sip.isEmpty(),"unrelated key log never produces plaintext SIP");
        byte[] raw=Files.readAllBytes(new File(fixtures,"tls12-gcm128.pcap").toPath());boolean changed=false;
        for(int at=24;at+16<raw.length;at+=16+le(raw,at+8)){int start=at+16+40;if(start+10<raw.length&&raw[start]==23&&raw[start+1]==3){raw[start+9]^=1;changed=true;break;}}
        check(changed,"test changes authenticated TLS ciphertext");Analysis corrupt=CaptureEngine.read(new ByteArrayInputStream(raw),two);
        check(corrupt.warnings.keySet().stream().anyMatch(w->w.contains("认证失败")),"tampered TLS record produces authentication warning");
        check(corrupt.sip.stream().noneMatch(m->m.firstLine.startsWith("INVITE ")),"tampered TLS plaintext is never delivered");
        for(String text:new String[]{"# comment only\n","CLIENT_RANDOM bad secret\n","CLIENT_TRAFFIC_SECRET_0 "+String.join("",Collections.nCopies(64,"0"))+" 010203\n"}){
            try{TlsKeyLog.read(new ByteArrayInputStream(text.getBytes("UTF-8")));throw new AssertionError("bad key file accepted");}catch(IOException expected){check(!expected.getMessage().contains("010203"),"key log validation does not disclose input secret");}
        }
        Analysis opus=read(fixtures,"opus-rtp.pcap",TlsKeyLog.empty());RtpStream stream=opus.streams.stream().filter(s->s.codec.equals("OPUS")).findFirst().get();check(stream.playable()&&stream.clock==48000,"SDP opus/48000/2 is playable");
        File wav=new File(out,"opus-actual.wav");AudioRenderer.render(Collections.singletonList(stream),wav);byte[] actual=Files.readAllBytes(wav.toPath()),reference=Files.readAllBytes(new File(fixtures,"opus-reference.pcm").toPath());check(le(actual,24)==48000,"Opus preserves 48 kHz playback and WAV");
        check(actual.length-44==reference.length,"Opus decoded duration matches independent FFmpeg output");double signal=0,error=0;for(int n=0;n<reference.length;n+=2){double a=pcm(reference,n),b=pcm(actual,n+44);signal+=a*a;error+=(a-b)*(a-b);}double snr=10*Math.log10(signal/Math.max(1,error));System.out.println("Opus independent reference SNR: "+snr+" dB");check(snr>23,"Opus PCM matches independent decoder");
        check(Math.abs(stream.seconds()-(actual.length-44)/96000.0)<.001,"Opus duration uses RTP timestamp clock");
        DtmfParser.Event event=opus.events.stream().filter(e->e.type==DtmfParser.Type.IN_BAND&&e.key.equals("5")).findFirst().orElse(null);check(event!=null&&event.clock==48000,"Opus in-band DTMF reports correct RTP clock");
        AudioPreview preview=AudioPreview.render(Collections.singletonList(stream),opus.events,wav);check(preview.keys.stream().anyMatch(k->k.event.type==DtmfParser.Type.IN_BAND&&k.startMs>250&&k.startMs<400),"Opus waveform digit is aligned in milliseconds");
        try(InputStream in=new FileInputStream(new File(fixtures,"opus-rtp.pcap"));Analysis disk=CaptureEngine.readLarge(in,out,null)){
            File copy=new File(out,"opus-disk.wav");AudioRenderer.render(Collections.singletonList(disk.streams.stream().filter(s->s.codec.equals("OPUS")).findFirst().get()),copy);check(Arrays.equals(actual,Files.readAllBytes(copy.toPath())),"disk-backed Opus decoding is byte-identical");
        }
        stream.encrypted=true;check(!stream.playable(),"SRTP ciphertext is not sent to Opus decoder");
        Analysis combined=read(fixtures,"tls13-websocket-opus.pcap",keys(fixtures,"tls13-websocket-opus.keys"));List<RtpStream> audio=new ArrayList<>();for(RtpStream s:combined.streams)if(s.playable())audio.add(s);
        check(combined.sip.size()==3&&audio.stream().filter(s->s.codec.equals("OPUS")).count()==2,"WSS signaling associates both Opus RTP directions after independent key import");
        AudioPreview duplex=AudioPreview.render(audio,combined.events,new File(out,"wss-opus-duplex.wav"));check(duplex.tracks.size()==2&&duplex.mixed.rate==48000,"mixed Opus/G711 preview preserves two direction tracks and 48 kHz");
        check(Math.abs(duplex.mixed.durationMs()-1025)<1&&duplex.tracks.get(1).offsetMs==5,"different RTP clock rates and direction offsets remain aligned");return checks;
    }
    public static void main(String[] args)throws Exception{System.out.println("PASS: "+run(new File(args[0]),new File(args[1]))+" secure/Opus assertions");}
}
