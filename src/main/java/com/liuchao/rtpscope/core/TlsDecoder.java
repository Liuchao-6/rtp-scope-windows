package com.liuchao.rtpscope.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.*;
import static com.liuchao.rtpscope.core.SignalingTransport.Data;

/** Authenticated offline TLS records using NSS secrets or RSA key-exchange private keys. */
final class TlsDecoder {
    private static final class Record {int type,version;byte[] body,header;long time;}
    private static final class Handshake {int type;byte[] raw,body;}
    private static final class Hello {byte[] random;int suite,version;long time;boolean etm,ems;}
    private static final class Direction {int id;String src,dst;List<Record> records=new ArrayList<>();List<Handshake> handshakes=new ArrayList<>();Hello client,server;}
    private static final class Suite {
        int key,iv,tag=16,mode=1,mac,block=16;String hash="HmacSHA256",macHash="HmacSHA1",cipher="AES";boolean tls13;
        Suite(int key,int iv){this.key=key;this.iv=iv;}
    }
    private static final class Session {Direction client,server;Hello ch,sh;Suite suite;byte[] master;}
    private static boolean tls(byte[] b){return b.length>=3&&(b[0]&255)>=20&&(b[0]&255)<=24&&b[1]==3&&(b[2]&255)<=4;}
    static List<Data> decrypt(List<Data> inputs,TlsKeyLog keys,TlsRsaKeys rsa,CaptureEngine.Analysis analysis)throws IOException {
        List<Data> output=new ArrayList<>();Map<Integer,Direction> directions=new LinkedHashMap<>();Set<Integer> plain=new HashSet<>();
        for(Data input:inputs){
            Direction direction=directions.get(input.direction);
            if(direction==null){if(plain.contains(input.direction)||!tls(input.bytes)){plain.add(input.direction);output.add(input);continue;}direction=new Direction();direction.id=input.direction;direction.src=input.src;direction.dst=input.dst;directions.put(direction.id,direction);}
            if(input.gap){analysis.warn("TLS 所在 TCP 数据有缺口，已停止该方向解密");continue;}
            for(int at=0;at<input.bytes.length;){
                if(input.bytes.length-at<5){analysis.warn("TLS 记录尾不完整，已保留完整记录");break;}
                byte[] b=input.bytes;int type=b[at]&255,len=u16(b,at+3);
                if(type<20||type>24||b[at+1]!=3||len>18432){analysis.warn("TLS 记录边界无效，已停止该方向解密");break;}
                if(len>input.bytes.length-at-5){analysis.warn("TLS 记录不完整，已保留完整记录");break;}
                Record record=new Record();record.type=type;record.version=u16(b,at+1);record.header=Arrays.copyOfRange(b,at,at+5);record.body=Arrays.copyOfRange(b,at+5,at+5+len);record.time=input.time(at);direction.records.add(record);at+=5+len;
            }
        }
        for(Direction d:directions.values())readHellos(d,analysis);
        List<Session> sessions=new ArrayList<>();
        for(Direction client:directions.values())if(client.client!=null){
            Direction server=null;long distance=Long.MAX_VALUE;
            for(Direction candidate:directions.values())if(candidate.server!=null&&candidate.src.equals(client.dst)&&candidate.dst.equals(client.src)){
                long delta=Math.abs(candidate.server.time-client.client.time);if(delta<distance){distance=delta;server=candidate;}
            }
            if(server!=null){Session s=new Session();s.client=client;s.server=server;s.ch=client.client;s.sh=server.server;s.suite=suite(s.sh.suite);sessions.add(s);}
        }
        for(Session session:sessions)if(session.suite!=null&&!session.suite.tls13&&session.sh.version>=0x0301&&session.sh.version<=0x0303){
            session.master=keys.secret("CLIENT_RANDOM",session.ch.random);
            if(session.master==null&&rsa.size()>0)try{session.master=rsaMaster(session,rsa,analysis);}catch(GeneralSecurityException e){analysis.warn("RSA 私钥无法还原此会话：私钥不匹配或握手内容损坏；可尝试对应的 TLS key log");}
        }
        for(Direction direction:directions.values()){
            Session session=null;for(Session s:sessions)if(s.client==direction||s.server==direction){session=s;break;}
            if(session==null){analysis.warn("TLS 缺少配对的 ClientHello / ServerHello，无法匹配会话密钥");continue;}
            if(session.suite==null||session.sh.version<0x0301||session.sh.version>0x0303||session.sh.version<0x0303&&session.suite.mode!=3){analysis.warn("TLS 版本或密码套件暂不支持");continue;}
            if(keys.size()==0&&rsa.size()==0){analysis.warn("识别到 TLS；可从「解密密钥」单独导入 TLS key log 或 RSA 私钥后重新分析");continue;}
            if(session.suite.tls13&&keys.size()==0){analysis.warn("TLS 1.3 不能仅用 RSA 私钥解密；请导入匹配的 TLS key log");continue;}
            if(!session.suite.tls13&&session.master==null){if(rsa.size()==0)analysis.warn("TLS key log 没有匹配的 CLIENT_RANDOM 会话密钥");continue;}
            try{decode(direction,session,keys,analysis,output);}catch(GeneralSecurityException e){analysis.warn("TLS 加密组件无法处理此会话");}
        }
        return output;
    }
    private static void readHellos(Direction direction,CaptureEngine.Analysis analysis)throws IOException {
        ByteArrayOutputStream buffer=new ByteArrayOutputStream();int total=0;
        for(Record record:direction.records){
            if(record.type==20||record.type==23)break;if(record.type!=22)continue;
            if(total+record.body.length>2*1024*1024){analysis.warn("TLS 初始握手超过 2 MiB，RSA 解密可能缺少握手数据；可导入 key log");break;}total+=record.body.length;buffer.write(record.body);byte[] b=buffer.toByteArray();int at=0;
            while(b.length-at>=4){int type=b[at]&255,len=u24(b,at+1);if(len>b.length-at-4)break;
                if(direction.handshakes.size()>=4096){analysis.warn("TLS 初始握手消息超过解析限制");return;}
                if((type==1||type==2)&&len>=38){int base=at+4;Hello hello=new Hello();hello.version=u16(b,base);hello.random=Arrays.copyOfRange(b,base+2,base+34);hello.time=record.time;
                    int p=base+35+(b[base+34]&255),end=base+len;
                    if(type==1){if(p+2<=end){int suites=u16(b,p);p+=2+suites;if(p<end)p+=1+(b[p]&255);readExtensions(b,p,end,hello);}if(direction.client==null)direction.client=hello;}
                    else if(p+3<=end){hello.suite=u16(b,p);p+=3;readExtensions(b,p,end,hello);if(direction.server==null)direction.server=hello;}
                }
                Handshake message=new Handshake();message.type=type;message.raw=Arrays.copyOfRange(b,at,at+4+len);message.body=Arrays.copyOfRange(b,at+4,at+4+len);direction.handshakes.add(message);
                at+=4+len;
            }
            buffer.reset();buffer.write(b,at,b.length-at);
        }
    }
    private static void readExtensions(byte[] b,int at,int end,Hello hello){
        if(at+2>end)return;int limit=Math.min(end,at+2+u16(b,at));at+=2;
        while(at+4<=limit){int type=u16(b,at),size=u16(b,at+2);at+=4;if(size>limit-at)break;if(type==22&&size==0)hello.etm=true;if(type==23&&size==0)hello.ems=true;at+=size;}
    }
    private static boolean rsaExchange(int suite){return suite==0x000a||suite==0x002f||suite==0x0035||suite==0x003c||suite==0x003d||suite==0x009c||suite==0x009d;}
    private static byte[] rsaMaster(Session session,TlsRsaKeys keys,CaptureEngine.Analysis analysis)throws IOException,GeneralSecurityException {
        if(!rsaExchange(session.sh.suite)){analysis.warn("此 TLS 会话使用 ECDHE / DHE 等密钥交换，RSA 私钥不能解密；请导入匹配的 TLS key log");return null;}
        Handshake exchange=null;for(Handshake message:session.client.handshakes)if(message.type==16){exchange=message;break;}
        if(exchange==null){analysis.warn("RSA 解密缺少 ClientKeyExchange；会话可能为复用会话或握手未抓完整，请导入 TLS key log 或包含初始完整握手的抓包");return null;}
        RSAPublicKey serverKey=null;
        for(Handshake message:session.server.handshakes)if(message.type==11){
            byte[] body=message.body;if(body.length<6||u24(body,0)!=body.length-3||u24(body,3)>body.length-6)throw new GeneralSecurityException();
            PublicKey key=CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(body,6,u24(body,3))).getPublicKey();
            if(!(key instanceof RSAPublicKey))throw new GeneralSecurityException();serverKey=(RSAPublicKey)key;break;
        }
        if(serverKey!=null&&!keys.matches(serverKey)){analysis.warn("已加载的 RSA 私钥与此会话服务器证书不匹配");return null;}
        byte[] body=exchange.body;if(body.length<2||u16(body,0)!=body.length-2)throw new GeneralSecurityException();
        byte[] premaster=keys.premaster(Arrays.copyOfRange(body,2,body.length),serverKey,session.ch.version);
        try {
            if(session.sh.ems){
                if(!session.ch.ems)throw new GeneralSecurityException();
                ByteArrayOutputStream transcript=new ByteArrayOutputStream();boolean first=true;
                // Initial full-handshake flight order, independent of timestamp resolution.
                for(Handshake message:session.client.handshakes)if(message.type==1&&first){transcript.write(message.raw);first=false;}
                boolean serverDone=false;for(Handshake message:session.server.handshakes){transcript.write(message.raw);if(message.type==14){serverDone=true;break;}}
                if(first||!serverDone){analysis.warn("RSA 扩展主密钥解密需要完整初始握手；当前缺少 ClientHello / ServerHelloDone");return null;}
                for(Handshake message:session.client.handshakes){if(message.type==1)continue;transcript.write(message.raw);if(message==exchange)break;}
                byte[] hash=handshakeHash(session,transcript.toByteArray());return sessionPrf(session,premaster,"extended master secret",hash,48);
            }
            return sessionPrf(session,premaster,"master secret",join(session.ch.random,session.sh.random),48);
        }finally{Arrays.fill(premaster,(byte)0);}
    }
    private static byte[] handshakeHash(Session session,byte[] transcript)throws GeneralSecurityException {
        if(session.sh.version<0x0303)return join(MessageDigest.getInstance("MD5").digest(transcript),MessageDigest.getInstance("SHA-1").digest(transcript));
        return MessageDigest.getInstance(session.suite.hash.equals("HmacSHA384")?"SHA-384":"SHA-256").digest(transcript);
    }
    private static byte[] sessionPrf(Session session,byte[] secret,String label,byte[] seed,int length)throws GeneralSecurityException {
        if(session.sh.version>=0x0303)return prf(session.suite.hash,secret,label,seed,length);
        int half=(secret.length+1)/2;byte[] a=prf("HmacMD5",Arrays.copyOfRange(secret,0,half),label,seed,length),b=prf("HmacSHA1",Arrays.copyOfRange(secret,secret.length-half,secret.length),label,seed,length);
        for(int n=0;n<length;n++)a[n]^=b[n];return a;
    }
    private static Suite suite(int code){
        Suite s;
        switch(code){
            case 0x000a:s=new Suite(24,0);s.mode=3;s.mac=20;s.block=8;s.cipher="DESede";return s;
            case 0x1301:s=new Suite(16,12);s.tls13=true;return s;
            case 0x1302:s=new Suite(32,12);s.tls13=true;s.hash="HmacSHA384";return s;
            case 0x1303:s=new Suite(32,12);s.tls13=true;s.mode=2;return s;
            case 0x1304:case 0x1305:s=new Suite(16,12);s.tls13=true;s.mode=4;if(code==0x1305)s.tag=8;return s;
            case 0x009c:case 0x009e:case 0x00a2:case 0xc02b:case 0xc02f:return new Suite(16,4);
            case 0x009d:case 0x009f:case 0x00a3:case 0xc02c:case 0xc030:s=new Suite(32,4);s.hash="HmacSHA384";return s;
            case 0xcca8:case 0xcca9:case 0xccaa:s=new Suite(32,12);s.mode=2;return s;
            case 0x002f:case 0x0033:case 0xc009:case 0xc013:s=new Suite(16,0);s.mode=3;s.mac=20;return s;
            case 0x0035:case 0x0039:case 0xc00a:case 0xc014:s=new Suite(32,0);s.mode=3;s.mac=20;return s;
            case 0x003c:case 0x0067:case 0xc023:case 0xc027:s=new Suite(16,0);s.mode=3;s.mac=32;s.macHash="HmacSHA256";return s;
            case 0x003d:case 0x006b:s=new Suite(32,0);s.mode=3;s.mac=32;s.macHash="HmacSHA256";return s;
            case 0xc024:case 0xc028:s=new Suite(32,0);s.mode=3;s.mac=48;s.macHash=s.hash="HmacSHA384";return s;
            default:return null;
        }
    }
    private static final class State {
        final Suite suite;byte[] key,iv,macKey,traffic;long sequence;boolean application,started,finished,implicitIv;ByteArrayOutputStream handshake=new ByteArrayOutputStream();
        State(Suite suite){this.suite=suite;}
        void secret(byte[] value)throws GeneralSecurityException {
            if(value==null||value.length!=(suite.hash.equals("HmacSHA384")?48:32))throw new GeneralSecurityException();
            traffic=value;key=expandLabel(suite.hash,value,"key",suite.key);iv=expandLabel(suite.hash,value,"iv",suite.iv);sequence=0;
        }
    }
    private static void decode(Direction direction,Session session,TlsKeyLog keys,CaptureEngine.Analysis analysis,List<Data> output)throws IOException,GeneralSecurityException {
        Suite suite=session.suite;boolean client=direction==session.client;String side=client?"CLIENT":"SERVER";State state=new State(suite);
        byte[] app=keys.secret(side+"_TRAFFIC_SECRET_0",session.ch.random);
        if(suite.tls13){byte[] handshake=keys.secret(side+"_HANDSHAKE_TRAFFIC_SECRET",session.ch.random);if(handshake!=null)state.secret(handshake);else if(app!=null){state.secret(app);state.application=true;}else{analysis.warn("TLS key log 没有此方向的匹配会话密钥");return;}}
        else {
            state.implicitIv=session.sh.version==0x0301&&suite.mode==3;int ivSize=state.implicitIv?suite.block:suite.iv;
            byte[] block=sessionPrf(session,session.master,"key expansion",join(session.sh.random,session.ch.random),2*(suite.mac+suite.key+ivSize));int n=client?0:suite.mac;
            state.macKey=Arrays.copyOfRange(block,n,n+suite.mac);n=2*suite.mac+(client?0:suite.key);state.key=Arrays.copyOfRange(block,n,n+suite.key);n=2*(suite.mac+suite.key)+(client?0:ivSize);state.iv=Arrays.copyOfRange(block,n,n+ivSize);
        }
        ByteArrayOutputStream plain=new ByteArrayOutputStream();List<CaptureEngine.Span> stamps=new ArrayList<>();boolean failed=false;
        for(Record record:direction.records){
            if(!suite.tls13&&record.type==20){if(state.started){analysis.warn("TLS 再协商暂不支持，已保留此前解密的数据");break;}state.started=true;state.sequence=0;continue;}
            if(suite.tls13&&record.type!=23)continue;if(!suite.tls13&&!state.started)continue;
            byte[] decoded;int type=record.type;
            try{
                if(suite.tls13){decoded=aead(suite,state.key,nonce(state.iv,state.sequence),record.header,record.body);state.sequence++;
                    int last=decoded.length-1;while(last>=0&&decoded[last]==0)last--;if(last<0)throw new GeneralSecurityException();type=decoded[last]&255;decoded=Arrays.copyOf(decoded,last);if(type!=21&&type!=22&&type!=23)throw new GeneralSecurityException();state.started=true;
                }else{decoded=decrypt12(state,record,session.sh.etm);state.sequence++;}
            }catch(InvalidCipherTextException|GeneralSecurityException e){
                if(suite.tls13&&!state.started&&state.application)continue;
                analysis.warn("TLS 记录认证失败：会话密钥不匹配、记录缺失或内容损坏；已停止该方向解密");failed=true;break;
            }
            if(type==23){stamps.add(new CaptureEngine.Span(plain.size(),record.time));plain.write(decoded);}
            if(suite.tls13&&type==22){
                if(state.handshake.size()+decoded.length>2*1024*1024){analysis.warn("TLS 握手消息超过解析限制");failed=true;break;}
                state.handshake.write(decoded);byte[] b=state.handshake.toByteArray();int at=0;
                while(b.length-at>=4){int message=b[at]&255,len=u24(b,at+1);if(len>b.length-at-4)break;
                    if(message==20&&!state.application){state.finished=true;if(app==null){analysis.warn("TLS 缺少此方向的应用流量密钥");failed=true;break;}state.secret(app);state.application=true;}
                    else if(message==24&&state.application){if(len!=1){failed=true;break;}state.secret(expandLabel(suite.hash,state.traffic,"traffic upd",state.traffic.length));}
                    at+=4+len;
                }
                state.handshake.reset();state.handshake.write(b,at,b.length-at);if(failed)break;
            }
        }
        if(plain.size()>0){Data data=new Data(direction.src,direction.dst,plain.toByteArray(),stamps,direction.id,false);data.transport="TLS";output.add(data);}
        else if(!failed)analysis.warn("此 TLS 方向未还原出应用数据，请检查握手及会话密钥是否完整");
    }
    private static byte[] decrypt12(State state,Record record,boolean etm)throws GeneralSecurityException,InvalidCipherTextException {
        Suite s=state.suite;byte[] body=record.body;
        if(s.mode==3){
            if(etm){if(body.length<s.block+(state.implicitIv?0:s.block)+s.mac)throw new GeneralSecurityException();int end=body.length-s.mac;byte[] expected=hmac(s.macHash,state.macKey,join(aad(state.sequence,record,end),Arrays.copyOf(body,end)));if(!MessageDigest.isEqual(expected,Arrays.copyOfRange(body,end,body.length)))throw new GeneralSecurityException();body=Arrays.copyOf(body,end);}
            int explicit=state.implicitIv?0:s.block;if(body.length<explicit+s.block||(body.length-explicit)%s.block!=0)throw new GeneralSecurityException();
            byte[] iv=state.implicitIv?state.iv:Arrays.copyOf(body,s.block);Cipher cipher=Cipher.getInstance(s.cipher+"/CBC/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(state.key,s.cipher),new IvParameterSpec(iv));byte[] plain=cipher.doFinal(body,explicit,body.length-explicit);if(state.implicitIv)state.iv=Arrays.copyOfRange(body,body.length-s.block,body.length);
            int padding=(plain[plain.length-1]&255)+1;if(padding>plain.length)throw new GeneralSecurityException();for(int n=plain.length-padding;n<plain.length;n++)if((plain[n]&255)!=padding-1)throw new GeneralSecurityException();int length=plain.length-padding;
            if(etm)return Arrays.copyOf(plain,length);if(length<s.mac)throw new GeneralSecurityException();length-=s.mac;byte[] message=Arrays.copyOf(plain,length),expected=hmac(s.macHash,state.macKey,join(aad(state.sequence,record,length),message));if(!MessageDigest.isEqual(expected,Arrays.copyOfRange(plain,length,length+s.mac)))throw new GeneralSecurityException();return message;
        }
        if(s.mode==2)return aead(s,state.key,nonce(state.iv,state.sequence),aad(state.sequence,record,body.length-s.tag),body);
        if(body.length<8+s.tag)throw new GeneralSecurityException();return aead(s,state.key,join(state.iv,Arrays.copyOf(body,8)),aad(state.sequence,record,body.length-8-s.tag),Arrays.copyOfRange(body,8,body.length));
    }
    private static byte[] aad(long sequence,Record record,int length){byte[] out=new byte[13];for(int n=0;n<8;n++)out[7-n]=(byte)(sequence>>>(n*8));out[8]=(byte)record.type;out[9]=(byte)(record.version>>>8);out[10]=(byte)record.version;out[11]=(byte)(length>>>8);out[12]=(byte)length;return out;}
    private static byte[] nonce(byte[] iv,long sequence){byte[] out=iv.clone();for(int n=0;n<8;n++)out[out.length-1-n]^=(byte)(sequence>>>(n*8));return out;}
    private static byte[] aead(Suite s,byte[] key,byte[] nonce,byte[] aad,byte[] encrypted)throws InvalidCipherTextException {
        if(encrypted.length<s.tag)throw new InvalidCipherTextException("Truncated TLS record");
        AEADCipher cipher=s.mode==2?new ChaCha20Poly1305():s.mode==4?new CCMBlockCipher(new AESEngine()):new GCMBlockCipher(new AESEngine());
        cipher.init(false,new AEADParameters(new KeyParameter(key),s.tag*8,nonce,aad));byte[] output=new byte[cipher.getOutputSize(encrypted.length)];int n=cipher.processBytes(encrypted,0,encrypted.length,output,0);n+=cipher.doFinal(output,n);return Arrays.copyOf(output,n);
    }
    static byte[] prf(String algorithm,byte[] secret,String label,byte[] seed,int length)throws GeneralSecurityException {
        byte[] data=join(label.getBytes(StandardCharsets.US_ASCII),seed),a=data;ByteArrayOutputStream out=new ByteArrayOutputStream();while(out.size()<length){a=hmac(algorithm,secret,a);byte[] block=hmac(algorithm,secret,join(a,data));out.write(block,0,Math.min(block.length,length-out.size()));}return out.toByteArray();
    }
    private static byte[] expandLabel(String algorithm,byte[] secret,String label,int length)throws GeneralSecurityException {
        byte[] name=("tls13 "+label).getBytes(StandardCharsets.US_ASCII),info=new byte[name.length+4];info[0]=(byte)(length>>>8);info[1]=(byte)length;info[2]=(byte)name.length;System.arraycopy(name,0,info,3,name.length);byte[] previous=new byte[0];ByteArrayOutputStream out=new ByteArrayOutputStream();for(int n=1;out.size()<length;n++){previous=hmac(algorithm,secret,join(previous,info,new byte[]{(byte)n}));out.write(previous,0,Math.min(previous.length,length-out.size()));}return out.toByteArray();
    }
    private static byte[] hmac(String algorithm,byte[] key,byte[] data)throws GeneralSecurityException {Mac mac=Mac.getInstance(algorithm);mac.init(new SecretKeySpec(key,algorithm));return mac.doFinal(data);}
    private static byte[] join(byte[]...arrays){int size=0;for(byte[] a:arrays)size+=a.length;byte[] out=new byte[size];int at=0;for(byte[] a:arrays){System.arraycopy(a,0,out,at,a.length);at+=a.length;}return out;}
    private static int u16(byte[] b,int at){return ((b[at]&255)<<8)|(b[at+1]&255);}
    private static int u24(byte[] b,int at){return ((b[at]&255)<<16)|((b[at+1]&255)<<8)|(b[at+2]&255);}
    private TlsDecoder(){}
}
