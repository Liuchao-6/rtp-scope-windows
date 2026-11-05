import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.file.Files;
import java.util.*;

public final class RsaTransportTest {
    private static int checks;
    private static void check(boolean condition,String message){checks++;if(!condition)throw new AssertionError(message);}
    private static TlsRsaKeys rsa(File folder,String file)throws IOException{try(InputStream in=new FileInputStream(new File(folder,file))){return TlsRsaKeys.read(in);}}
    private static TlsKeyLog log(File folder,String name)throws IOException{try(InputStream in=new FileInputStream(new File(folder,name+".keys"))){return TlsKeyLog.read(in);}}
    private static Analysis read(File folder,String name,TlsKeyLog keys,TlsRsaKeys rsa)throws IOException{try(InputStream in=new FileInputStream(new File(folder,name+".pcap"))){return CaptureEngine.read(in,keys,rsa);}}
    private static boolean warning(Analysis analysis,String text){return analysis.warnings.keySet().stream().anyMatch(value->value.contains(text));}
    private static int le(byte[] b,int at){return (b[at]&255)|(b[at+1]&255)<<8|(b[at+2]&255)<<16|(b[at+3]&255)<<24;}
    public static int run(File folder,File out)throws Exception {
        int start=checks;TlsRsaKeys keys=rsa(folder,"rsa-synthetic-pkcs1.key");
        for(String format:new String[]{"pkcs1.key","pkcs8.key","pkcs1.der","pkcs8.der"}){
            TlsRsaKeys imported=rsa(folder,"rsa-synthetic-"+format);check(imported.size()==1,"RSA PEM/DER PKCS#1/PKCS#8 imports "+format);check(keys.merge(imported).size()==1,"RSA imports deduplicate across formats "+format);
        }
        check(keys.size()==1&&TlsRsaKeys.empty().size()==0,"RSA key stores are immutable");
        String[] success={"rsa-tls12-gcm128","rsa-tls12-gcm256","rsa-tls12-cbc128","rsa-tls12-cbc256","rsa-tls12-cbc-sha1","rsa-tls10","rsa-tls11","rsa-wss","rsa-mutual","rsa-tls12-noems","rsa-tls12-vector-ems","rsa-tls12-vector-sha384","rsa-tls10-noems","rsa-tls11-noems","rsa-tls10-vector-ems","rsa-tls10-vector-etm","rsa-tls10-3des"};
        for(String name:success){
            try(Analysis analysis=read(folder,name,TlsKeyLog.empty(),keys);Analysis reference=read(folder,name,log(folder,name),TlsRsaKeys.empty())){
                check(analysis.sip.size()==3,name+" RSA decrypts three SIP messages; warnings="+analysis.warnings);
                check(reference.sip.size()==3,name+" independent OpenSSL/RFC session key decrypts");
                for(int n=0;n<3;n++)check(analysis.sip.get(n).raw.equals(reference.sip.get(n).raw)&&analysis.sip.get(n).timeUs==reference.sip.get(n).timeUs,name+" RSA plaintext and timestamps match independent key log");
                check(analysis.calls.size()==1&&analysis.calls.get(0).requestTarget.contains("1002"),name+" retains call discovery");
                check(analysis.sip.stream().allMatch(m->m.transport.equals(name.equals("rsa-wss")?"WSS":"TLS")),name+" retains transport");
                check(analysis.events.stream().anyMatch(e->e.type==DtmfParser.Type.SIP_INFO&&e.key.equals("5")),name+" retains SIP INFO digit");
                check(analysis.streams.stream().anyMatch(s->s.playable()&&!s.callId.isEmpty()),name+" decrypted SDP associates playable RTP");
            }
        }
        TlsRsaKeys wrong=rsa(folder,"rsa-synthetic-wrong.key");
        try(Analysis locked=read(folder,"rsa-tls12-gcm128",TlsKeyLog.empty(),wrong)){check(locked.sip.isEmpty()&&warning(locked,"证书不匹配"),"unrelated RSA key produces explicit certificate mismatch without plaintext");}
        try(Analysis combined=read(folder,"rsa-tls12-gcm128",TlsKeyLog.empty(),wrong.merge(keys))){check(combined.sip.size()==3,"multiple imported RSA keys select matching server certificate");}
        try(Analysis missing=read(folder,"rsa-missing-exchange",TlsKeyLog.empty(),keys)){check(missing.sip.isEmpty()&&warning(missing,"ClientKeyExchange"),"missing RSA handshake does not invent session key");}
        try(Analysis missing=read(folder,"rsa-missing-certificate",TlsKeyLog.empty(),keys)){check(missing.sip.size()==3,"matching RSA key can decrypt full key exchange when certificate packet is absent and EMS is not negotiated");}
        try(Analysis bad=read(folder,"rsa-bad-premaster",TlsKeyLog.empty(),keys)){check(bad.sip.isEmpty()&&warning(bad,"无法还原"),"premaster version mismatch is rejected");}
        for(String name:new String[]{"rsa-ecdhe","rsa-tls13","rsa-resumed"}){
            try(Analysis locked=read(folder,name,TlsKeyLog.empty(),keys);Analysis restored=read(folder,name,log(folder,name),keys)){
                check(locked.sip.isEmpty()&&warning(locked,name.equals("rsa-ecdhe")?"ECDHE":name.equals("rsa-tls13")?"TLS 1.3":"复用"),name+" explains RSA limitation");
                check(restored.sip.size()==3,name+" can still use independently imported key log");
            }
        }
        try(InputStream in=new FileInputStream(new File(folder,"rsa-wss.pcap"));Analysis disk=CaptureEngine.readLarge(in,out,null,TlsKeyLog.empty(),keys)){
            check(disk.sip.size()==3&&disk.streams.stream().anyMatch(s->s.playable()),"disk-backed Windows path accepts independent RSA keys");
        }
        byte[] capture=Files.readAllBytes(new File(folder,"rsa-tls12-gcm128.pcap").toPath());boolean changed=false;
        for(int at=24;at+56<capture.length;at+=16+le(capture,at+8)){int payload=at+56;if(capture[payload]==23&&capture[payload+1]==3){capture[payload+9]^=1;changed=true;break;}}
        check(changed,"tamper synthetic RSA TLS application ciphertext");
        try(Analysis bad=CaptureEngine.read(new ByteArrayInputStream(capture),TlsKeyLog.empty(),keys)){check(warning(bad,"认证失败")&&bad.sip.stream().noneMatch(m->m.firstLine.startsWith("INVITE ")),"RSA recovery never bypasses TLS record authentication");}
        byte[] cert=Files.readAllBytes(new File(folder,"rsa-synthetic-certificate.pem").toPath());
        for(byte[] invalid:new byte[][]{new byte[0],cert,"-----BEGIN ENCRYPTED PRIVATE KEY-----\nnot-real-secret\n-----END ENCRYPTED PRIVATE KEY-----".getBytes("UTF-8"),"-----BEGIN RSA PRIVATE KEY-----\nnot-real-secret\n-----END RSA PRIVATE KEY-----".getBytes("UTF-8"),"CLIENT_RANDOM not-real-secret\n".getBytes("UTF-8"),new byte[1024*1024+1]}){
            try{TlsRsaKeys.read(new ByteArrayInputStream(invalid));throw new AssertionError("invalid RSA file accepted");}catch(IOException expected){check(!expected.getMessage().contains("not-real-secret")&&expected.getCause()==null,"RSA import failures do not echo key material or provider details");}
        }
        try(InputStream in=new FileInputStream(new File(folder,"rsa-synthetic-pkcs1.key"))){try{TlsKeyLog.read(in);throw new AssertionError("PEM private key accepted as key log");}catch(IOException expected){check(expected.getMessage().contains("导入 RSA 私钥"),"mistaken key-log import points to RSA entry");}}
        check(keys.size()==1,"invalid imports leave original RSA key set intact");
        return checks-start;
    }
    public static void main(String[] args)throws Exception {System.out.println("PASS: "+run(new File(args[0]),new File(args[1]))+" RSA transport assertions");}
}
