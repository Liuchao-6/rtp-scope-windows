package com.liuchao.rtpscope.core;

import java.io.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.util.zip.*;

/** Offline TCP/TLS and RFC 6455/RFC 7692 message boundaries. */
final class SignalingTransport {
    static final class Data {
        String src,dst,transport="TCP";byte[] bytes;PacketStore store;long offset;int storedLength;List<CaptureEngine.Span> spans;int direction;boolean gap,recoverSip;
        Data(String src,String dst,byte[] bytes,List<CaptureEngine.Span> spans,int direction,boolean gap){this.src=src;this.dst=dst;this.bytes=bytes;this.spans=new ArrayList<>(spans);this.direction=direction;this.gap=gap;}
        Data(String src,String dst,PacketStore store,long offset,int length,List<CaptureEngine.Span> spans,int direction,boolean gap){this(src,dst,null,spans,direction,gap);this.store=store;this.offset=offset;storedLength=length;}
        int length(){return bytes==null?storedLength:bytes.length;}
        byte[] bytes(int at,int length)throws IOException{return bytes==null?store.bytes(offset+at,length):Arrays.copyOfRange(bytes,at,at+length);}
        long time(int at){int low=0,high=spans.size();while(low<high){int mid=(low+high)>>>1;if(spans.get(mid).offset<=at)low=mid+1;else high=mid;}return low==0?0:spans.get(low-1).time;}
        Data message(byte[] payload,int at,String type){Data out=new Data(src,dst,payload,Collections.singletonList(new CaptureEngine.Span(0,time(at))),direction,gap);out.transport=type;return out;}
    }
    /** Appends one contiguous direction without holding the whole connection in heap. */
    static final class Buffer {
        final PacketStore store;final long offset;int size;final ByteArrayOutputStream memory;
        Buffer(PacketStore store){this.store=store;offset=store==null?0:store.position();memory=store==null?new ByteArrayOutputStream():null;}
        void write(byte[] bytes,int start,int length)throws IOException{if(store==null)memory.write(bytes,start,length);else store.appendBytes(bytes,start,length);size+=length;}
        Data data(String src,String dst,List<CaptureEngine.Span> spans,int direction,boolean gap){return store==null?new Data(src,dst,memory.toByteArray(),spans,direction,gap):new Data(src,dst,store,offset,size,spans,direction,gap);}
    }
    interface Receiver {void accept(Data data)throws IOException;}
    static void decode(List<Data> inputs,TlsKeyLog keys,TlsRsaKeys rsa,CaptureEngine.Analysis analysis,Receiver receiver)throws IOException {
        List<Data> decoded=TlsDecoder.decrypt(inputs,keys,rsa,analysis);
        for(Data data:decoded){
            if(!websocket(data,decoded,analysis,receiver))receiver.accept(data);
        }
    }
    private static boolean websocket(Data input,List<Data> all,CaptureEngine.Analysis analysis,Receiver receiver)throws IOException {
        int total=input.length();byte[] b=input.bytes(0,Math.min(total,65536));if(b.length==0)return false;int at=0;boolean upgraded=false,noContext=false;
        String prefix=new String(b,0,Math.min(b.length,16),StandardCharsets.US_ASCII);
        if(prefix.startsWith("GET ")||prefix.startsWith("HTTP/1.1 101")) {
            int end=-1;for(int n=0;n+3<b.length&&n<65536;n++)if(b[n]==13&&b[n+1]==10&&b[n+2]==13&&b[n+3]==10){end=n+4;break;}
            if(end<0)return false;
            String header=new String(b,0,end,StandardCharsets.US_ASCII).toLowerCase(Locale.ROOT);
            if(!header.matches("(?s).*\\r\\nupgrade\\s*:\\s*websocket\\s*\\r\\n.*"))return false;
            upgraded=true;at=end;
            String negotiated=header;boolean client=prefix.startsWith("GET ");
            if(client){long nearest=Long.MAX_VALUE;for(Data peer:all)if(peer.src.equals(input.dst)&&peer.dst.equals(input.src)){String candidate=new String(peer.bytes(0,Math.min(peer.length(),65536)),StandardCharsets.US_ASCII).toLowerCase(Locale.ROOT);if(candidate.startsWith("http/1.1 101")){long distance=Math.abs(peer.time(0)-input.time(0));if(distance<nearest){int boundary=candidate.indexOf("\r\n\r\n");negotiated=boundary<0?"":candidate.substring(0,boundary);nearest=distance;}}}}
            noContext=negotiated.contains(client?"client_no_context_takeover":"server_no_context_takeover");
        } else {
            int first=b[0]&255;
            if(input.gap||(first&0x30)!=0||((first&15)!=1&&(first&15)!=2))return false;
        }
        ByteArrayOutputStream fragmented=new ByteArrayOutputStream();int messageAt=at;boolean active=false,compressed=false;Inflater inflater=new Inflater(true);
        try {
            while(at<total){
                if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("导入已取消");
                int frame=at;if(total-at<2){analysis.warn("WebSocket 帧尾不完整，已保留完整消息");break;}
                b=input.bytes(at,Math.min(14,total-at));int h=0;
                int first=b[h++]&255,second=b[h++]&255,opcode=first&15;boolean fin=(first&128)!=0,zip=(first&64)!=0,mask=(second&128)!=0;long length=second&127;
                if((first&0x30)!=0){if(upgraded)analysis.warn("WebSocket 保留位无效");break;}
                int extra=length==126?2:length==127?8:0;
                if(b.length-h<extra){analysis.warn("WebSocket 帧头不完整");break;}
                if(extra>0){length=0;for(int n=0;n<extra;n++){if(n==0&&extra==8&&(b[h]&128)!=0){analysis.warn("WebSocket 长度无效");return true;}length=(length<<8)|(b[h++]&255L);}}
                if(length>4*1024*1024){analysis.warn("WebSocket 消息超过 4 MiB，已停止该方向解析");break;}
                if((long)total-at-h<(mask?4L:0)+length){analysis.warn("WebSocket 消息不完整，已保留完整消息");break;}
                byte[] masking=mask?Arrays.copyOfRange(b,h,h+4):null;if(mask)h+=4;at+=h;byte[] payload=input.bytes(at,(int)length);at+=length;
                if(mask)for(int n=0;n<payload.length;n++)payload[n]^=masking[n%4];
                if(opcode>=8){if(!fin||zip||length>125||(opcode!=8&&opcode!=9&&opcode!=10)){analysis.warn("WebSocket 控制帧无效");break;}if(opcode==8)break;continue;}
                if(opcode==1||opcode==2){if(active){analysis.warn("WebSocket 分片消息被中断");fragmented.reset();}active=true;compressed=zip;messageAt=frame;}
                else if(opcode!=0||!active||zip){analysis.warn("WebSocket 分片顺序无效");break;}
                if(fragmented.size()+payload.length>4*1024*1024){analysis.warn("WebSocket 分片消息超过 4 MiB");break;}
                fragmented.write(payload);
                if(fin){byte[] complete=fragmented.toByteArray();fragmented.reset();active=false;
                    if(compressed){try{complete=inflate(inflater,complete);}catch(DataFormatException|IOException e){analysis.warn("WebSocket 压缩消息无法还原或超过 4 MiB");break;}if(noContext)inflater.reset();}
                    receiver.accept(input.message(complete,messageAt,input.transport.equals("TLS")?"WSS":"WS"));
                }
            }
            if(active)analysis.warn("WebSocket 分片未完成，已保留此前完整消息");
        }finally{inflater.end();}
        return upgraded||at>0;
    }
    private static byte[] inflate(Inflater inflater,byte[] payload)throws DataFormatException,IOException {
        byte[] framed=Arrays.copyOf(payload,payload.length+4);framed[framed.length-2]=(byte)255;framed[framed.length-1]=(byte)255;
        inflater.setInput(framed);ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[8192];
        while(!inflater.needsInput()){int n=inflater.inflate(buffer);if(n==0){if(inflater.finished())break;throw new DataFormatException();}if(out.size()+n>4*1024*1024)throw new IOException("WebSocket 解压后超过 4 MiB");out.write(buffer,0,n);}
        return out.toByteArray();
    }
    private SignalingTransport(){}
}
