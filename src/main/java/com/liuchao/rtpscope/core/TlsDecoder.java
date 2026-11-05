package com.liuchao.rtpscope.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.*;
import static com.liuchao.rtpscope.core.SignalingTransport.Data;

/** Authenticated offline TLS 1.2/1.3 record decryption using NSS session secrets. */
final class TlsDecoder {
    private static final class Record {int type,version;byte[] body,header;long time;}
    private static final class Hello {byte[] random;int suite,version;long time;boolean etm;}
    private static final class Direction {int id;String src,dst;List<Record> records=new ArrayList<>();Hello client,server;}
    private static final class Suite {
        int key,iv,tag=16,mode=1,mac;String hash="HmacSHA256",macHash="HmacSHA1";boolean tls13;
        Suite(int key,int iv){this.key=key;this.iv=iv;}
    }
    private static final class Session {Direction client,server;Hello ch,sh;Suite suite;}
    private static boolean tls(byte[] b){return b.length>=3&&(b[0]&255)>=20&&(b[0]&255)<=24&&b[1]==3&&(b[2]&255)<=4;}
    static List<Data> decrypt(List<Data> inputs,TlsKeyLog keys,CaptureEngine.Analysis analysis)throws IOException {
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
        for(Direction d:directions.values())readHellos(d);
        List<Session> sessions=new ArrayList<>();
        for(Direction client:directions.values())if(client.client!=null){
            Direction server=null;long distance=Long.MAX_VALUE;
            for(Direction candidate:directions.values())if(candidate.server!=null&&candidate.src.equals(client.dst)&&candidate.dst.equals(client.src)){
                long delta=Math.abs(candidate.server.time-client.client.time);if(delta<distance){distance=delta;server=candidate;}
            }
            if(server!=null){Session s=new Session();s.client=client;s.server=server;s.ch=client.client;s.sh=server.server;s.suite=suite(s.sh.suite);sessions.add(s);}
        }
        for(Direction direction:directions.values()){
            Session session=null;for(Session s:sessions)if(s.client==direction||s.server==direction){session=s;break;}
            if(session==null){analysis.warn("TLS 缺少配对的 ClientHello / ServerHello，无法匹配会话密钥");continue;}
            if(session.suite==null||session.sh.version!=0x0303){analysis.warn("TLS 版本或密码套件暂不支持");continue;}
            if(keys.size()==0){analysis.warn("识别到 TLS；可单独导入匹配的 TLS key log 后重新分析");continue;}
            try{decode(direction,session,keys,analysis,output);}catch(GeneralSecurityException e){analysis.warn("TLS 加密组件无法处理此会话");}
        }
        return output;
    }
    private static void readHellos(Direction direction)throws IOException {
        ByteArrayOutputStream buffer=new ByteArrayOutputStream();
        for(Record record:direction.records){
            if(record.type==20||record.type==23)break;if(record.type!=22)continue;
            if(buffer.size()+record.body.length>2*1024*1024)break;buffer.write(record.body);byte[] b=buffer.toByteArray();int at=0;
            while(b.length-at>=4){int type=b[at]&255,len=u24(b,at+1);if(len>b.length-at-4)break;
                if((type==1||type==2)&&len>=38){int base=at+4;Hello hello=new Hello();hello.version=u16(b,base);hello.random=Arrays.copyOfRange(b,base+2,base+34);hello.time=record.time;
                    int p=base+35+(b[base+34]&255),end=base+len;
                    if(type==1){if(direction.client==null)direction.client=hello;}
                    else if(p+3<=end){hello.suite=u16(b,p);p+=3;if(p+2<=end){int extEnd=Math.min(end,p+2+u16(b,p));p+=2;while(p+4<=extEnd){int ext=u16(b,p),size=u16(b,p+2);p+=4;if(size>extEnd-p)break;if(ext==22)hello.etm=true;p+=size;}}if(direction.server==null)direction.server=hello;}
                }
                at+=4+len;
            }
            buffer.reset();buffer.write(b,at,b.length-at);
        }
    }
    private static Suite suite(int code){
        Suite s;
        switch(code){
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
        final Suite suite;byte[] key,iv,macKey,traffic;long sequence;boolean application,started,finished;ByteArrayOutputStream handshake=new ByteArrayOutputStream();
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
            byte[] master=keys.secret("CLIENT_RANDOM",session.ch.random);if(master==null){analysis.warn("TLS key log 没有匹配的 CLIENT_RANDOM 会话密钥");return;}
            byte[] block=prf(suite.hash,master,"key expansion",join(session.sh.random,session.ch.random),2*(suite.mac+suite.key+suite.iv));int n=client?0:suite.mac;
            state.macKey=Arrays.copyOfRange(block,n,n+suite.mac);n=2*suite.mac+(client?0:suite.key);state.key=Arrays.copyOfRange(block,n,n+suite.key);n=2*(suite.mac+suite.key)+(client?0:suite.iv);state.iv=Arrays.copyOfRange(block,n,n+suite.iv);
        }
        ByteArrayOutputStream plain=new ByteArrayOutputStream();List<CaptureEngine.Span> stamps=new ArrayList<>();boolean failed=false;
        for(Record record:direction.records){
            if(!suite.tls13&&record.type==20){state.started=true;state.sequence=0;continue;}
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
            if(etm){if(body.length<16+s.mac)throw new GeneralSecurityException();int end=body.length-s.mac;byte[] expected=hmac(s.macHash,state.macKey,join(aad(state.sequence,record,end),Arrays.copyOf(body,end)));if(!MessageDigest.isEqual(expected,Arrays.copyOfRange(body,end,body.length)))throw new GeneralSecurityException();body=Arrays.copyOf(body,end);}
            if(body.length<32||(body.length-16)%16!=0)throw new GeneralSecurityException();Cipher cipher=Cipher.getInstance("AES/CBC/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(state.key,"AES"),new IvParameterSpec(Arrays.copyOf(body,16)));byte[] plain=cipher.doFinal(body,16,body.length-16);
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
