package com.liuchao.rtpscope.core;

import java.io.*;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Offline parser. Deliberately independent of Android so real captures can be tested on the JVM. */
public final class CaptureEngine {
    public static final long MAX_FILE = 128L * 1024 * 1024;
    public static final long MAX_DESKTOP_FILE = 1024L * 1024 * 1024;
    private static final int MAX_BLOCK = 16 * 1024 * 1024;
    private static final int MAX_MEDIA = 64 * 1024 * 1024;
    private static final int MAX_TCP = 24 * 1024 * 1024;
    public static final class Analysis implements Closeable,Serializable {
        public final List<SipMessage> sip = new ArrayList<>();
        public final List<Call> calls = new ArrayList<>();
        public final List<RtpStream> streams = new ArrayList<>();
        public final List<DtmfParser.Event> events = new ArrayList<>();
        public final Map<String,Integer> warnings = new LinkedHashMap<>();
        public long packets, bytes, firstUs = Long.MAX_VALUE, lastUs;
        public String format = "";
        public boolean reliableTimestamps = true, partial;
        public transient PacketStore mediaStore;
        public void close()throws IOException{if(mediaStore!=null)mediaStore.close();}
        public void warn(String message) { warnings.put(message, warnings.getOrDefault(message, 0) + 1); }
    }
    public static final class SipMessage implements Serializable {
        public long timeUs;
        public String src, dst, transport, firstLine, raw, callId, from, to, cseq, body;
        public final Map<String,String> headers = new LinkedHashMap<>();
        public String searchable() { return src + " " + dst + " " + raw; }
    }
    public static final class Call implements Serializable {
        public String id, from = "", to = "", status = "";
        public long startUs = Long.MAX_VALUE, endUs = Long.MAX_VALUE;
        public long lastUs;
        public String requestTarget="";
        public boolean inviteIdentity;
        public final Set<String> signalingIps=new LinkedHashSet<>(),mediaIps=new LinkedHashSet<>();
        public int sipCount;
        public final List<RtpStream> streams = new ArrayList<>();
    }
    public static final class RtpPacket {
        public long timeUs, timestamp;
        public int sequence;
        public boolean marker;
        public long extendedSequence;
        public byte[] payload;
        PacketStore store;long payloadOffset;int storedLength;
        public int payloadSize(){return payload==null?storedLength:payload.length;}
        public byte[] payload()throws IOException{return payload==null?store.bytes(payloadOffset,storedLength):payload;}
        byte[] prefix(int length)throws IOException{length=Math.min(length,payloadSize());return payload==null?store.bytes(payloadOffset,length):Arrays.copyOf(payload,length);}
    }
    public static final class RtpStream implements Serializable {
        public String src, dst, srcIp, dstIp, codec = "未知", callId = "", note = "",fmtp="";
        public int srcPort, dstPort, pt, clock = 8000;
        public long ssrc, lost, duplicates;
        public boolean encrypted, clockKnown;
        public transient List<RtpPacket> packets = new ArrayList<>();
        private void writeObject(ObjectOutputStream out)throws IOException{
            out.defaultWriteObject();out.writeInt(packets.size());for(RtpPacket p:packets){if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("导入已取消");out.writeLong(p.timeUs);out.writeLong(p.timestamp);out.writeInt(p.sequence);out.writeBoolean(p.marker);byte[] data=p.payload();out.writeInt(data.length);out.write(data);}
        }
        private void readObject(ObjectInputStream in)throws IOException,ClassNotFoundException{
            in.defaultReadObject();int count=in.readInt();if(count<0||count>20000000)throw new IOException("索引包数无效");PacketStore store=AnalysisCache.restoring.get();if(store==null)throw new IOException("缺少索引媒体存储");PacketStore.Packets restored=new PacketStore.Packets(store);packets=restored;
            for(int n=0;n<count;n++){if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("导入已取消");long time=in.readLong(),stamp=in.readLong();int seq=in.readInt();boolean marker=in.readBoolean();int len=in.readInt();if(len<0||len>16*1024*1024)throw new IOException("索引负载无效");byte[] b=new byte[len];in.readFully(b);restored.append(store.append(time,stamp,seq,marker,b,0,len),time);}
        }
        public final List<DtmfParser.Event> events = new ArrayList<>();
        public QualityAnalyzer.Report quality;
        public boolean playable() { return !encrypted && (CodecSupport.available(this)||(clock==48000&&codec.equals("OPUS"))||(clock == 8000 && (codec.equals("PCMA") || codec.equals("PCMU") || codec.equals("G729") || codec.equals("G729A") || codec.equals("G722")))); }
        public boolean isDtmf() { return codec.equals("TELEPHONE-EVENT") || codec.equals("RTPEVENT") || codec.equals("RTP-EVENT"); }
        public String transportKey() { return src+">"+dst+"/"+ssrc; }
        public long firstUs() { return packets.get(0).timeUs; }
        public double seconds() {
            if (!clockKnown) return -1;
            if (packets.isEmpty()) return 0;
            return RtpTimeline.seconds(this);
        }
        public String searchable() { return src + " " + dst + " " + codec + " " + callId + " " + ssrc; }
    }
    private static final class Media {
        String ip = "", profile, callId;
        int port;
        long timeUs;
        Map<Integer,String> codecs = new HashMap<>();
        Map<Integer,Integer> clocks = new HashMap<>();
        Map<Integer,String> formats = new HashMap<>();
        Set<Integer> pts = new HashSet<>();
    }
    private static final class Segment {
        long seq, time;
        byte[] data;
    }
    private static final class TcpFlow {
        String src, dst;
        long anchor;
        List<Segment> segments = new ArrayList<>();
    }
    static final class Span {
        int offset;
        long time;
        Span(int offset,long time) { this.offset=offset; this.time=time; }
    }
    private static final class Iface {
        int link, snap;
        double resolution = 0.000001;
        long offset;
    }
    private final Analysis result = new Analysis();
    private final Map<String,RtpStream> candidates = new LinkedHashMap<>();
    private final Map<String,TcpFlow> currentTcp = new HashMap<>();
    private final List<TcpFlow> tcp = new ArrayList<>();
    private final Map<String,Call> calls = new LinkedHashMap<>();
    private final List<Media> media = new ArrayList<>();
    private List<RtpStream> deferredCandidates;
    private int mediaBytes, tcpBytes;
    private long packetLimit=500000;
    private long inputLimit=MAX_FILE;
    private PacketSink packetSink;
    public interface PacketSink {
        void accept(byte[] packet,int link,long timeUs,String src,String dst,int protocol,byte[] payload)throws IOException;
        default void tcpHeader(long sequence,int flags){}
    }
    /** Single-packet inspection for a bounded live index; never stores media payloads. */
    public static final class PacketInspector {
        private final CaptureEngine engine=new CaptureEngine();
        public PacketInspector(PacketSink sink){engine.packetSink=Objects.requireNonNull(sink);engine.packetLimit=Long.MAX_VALUE;}
        public void accept(byte[] packet,int link,long timeUs)throws IOException{engine.packet(packet,link,timeUs);engine.result.warnings.clear();}
    }
    public static List<SipMessage> parseSignaling(byte[] data,String src,String dst,String transport,long timeUs)throws IOException {
        CaptureEngine engine=new CaptureEngine();engine.sip(data,src,dst,transport,timeUs);return engine.result.sip;
    }
    public static boolean looksLikeSip(byte[] data){return looksSip(data,0);}
    static List<SipMessage> parseSignaling(byte[] data,String src,String dst,String transport,long timeUs,List<Span> spans)throws IOException {
        CaptureEngine engine=new CaptureEngine();engine.sip(data,src,dst,transport,timeUs,spans);return engine.result.sip;
    }
    public static void visitPackets(InputStream input,PacketSink sink)throws IOException{
        CaptureEngine engine=new CaptureEngine();engine.inputLimit=MAX_DESKTOP_FILE;engine.packetLimit=20000000;engine.packetSink=sink;read(input,engine,null);
    }
    private TlsKeyLog keyLog=TlsKeyLog.empty();
    private TlsRsaKeys rsaKeys=TlsRsaKeys.empty();
    private boolean validHeader;
    private static final class FormatException extends IOException {
        FormatException(String message){super(message);}
    }
    private static final class TruncatedRead extends EOFException {
        final byte[] available;
        TruncatedRead(byte[] data,int count){super("文件提前结束，末尾数据未写完");available=Arrays.copyOf(data,count);}
    }
    private void recovered(long offset,String reason){result.partial=true;result.warn("文件不完整或局部损坏，字节 "+offset+"："+reason+"；已保留可解析的包");}

    public static Analysis read(InputStream input) throws IOException {
        return read(input,TlsKeyLog.empty());
    }
    public static Analysis read(InputStream input,TlsKeyLog keys)throws IOException {
        return read(input,keys,TlsRsaKeys.empty());
    }
    public static Analysis read(InputStream input,TlsKeyLog keys,TlsRsaKeys rsa)throws IOException {
        CaptureEngine engine=new CaptureEngine();engine.keyLog=Objects.requireNonNull(keys);engine.rsaKeys=Objects.requireNonNull(rsa);return read(input,engine,null);
    }
    public static Analysis read(InputStream input,TlsKeyLog keys,TlsRsaKeys rsa,Progress progress)throws IOException {
        CaptureEngine engine=new CaptureEngine();engine.keyLog=Objects.requireNonNull(keys);engine.rsaKeys=Objects.requireNonNull(rsa);return read(input,engine,progress);
    }
    public interface Progress {void update(long bytes,long packets);default void stage(String name){} }
    public static Analysis readLarge(InputStream input,File cacheDirectory,Progress progress)throws IOException{
        return readLarge(input,cacheDirectory,progress,TlsKeyLog.empty());
    }
    public static Analysis readLarge(InputStream input,File cacheDirectory,Progress progress,TlsKeyLog keys)throws IOException{
        return readLarge(input,cacheDirectory,progress,keys,TlsRsaKeys.empty());
    }
    public static Analysis readLarge(InputStream input,File cacheDirectory,Progress progress,TlsKeyLog keys,TlsRsaKeys rsa)throws IOException{
        CaptureEngine engine=new CaptureEngine();engine.keyLog=Objects.requireNonNull(keys);engine.rsaKeys=Objects.requireNonNull(rsa);engine.inputLimit=MAX_DESKTOP_FILE;engine.packetLimit=20000000;engine.result.mediaStore=new PacketStore(cacheDirectory);
        try{return read(input,engine,progress);}catch(IOException|RuntimeException e){try{engine.result.close();}catch(IOException ignored){}throw e;}
    }
    public static DeferredCapture readLargeSignaling(InputStream input,File directory,Progress progress,TlsKeyLog keys,TlsRsaKeys rsa)throws IOException{
        CaptureEngine engine=new CaptureEngine();engine.keyLog=Objects.requireNonNull(keys);engine.rsaKeys=Objects.requireNonNull(rsa);engine.inputLimit=MAX_DESKTOP_FILE;engine.packetLimit=20000000;engine.result.mediaStore=new PacketStore(directory);
        try{read(input,engine,progress,true);return new DeferredCapture(engine.result,engine.deferredCandidates);}catch(IOException|RuntimeException e){try{engine.result.close();}catch(IOException ignored){}throw e;}
    }
    private static Analysis read(InputStream input,CaptureEngine supplied,Progress progress)throws IOException{
        return read(input,supplied,progress,false);
    }
    private static Analysis read(InputStream input,CaptureEngine supplied,Progress progress,boolean deferMedia)throws IOException{
        CaptureEngine engine = supplied==null?new CaptureEngine():supplied;
        CountingInput in = new CountingInput(new BufferedInputStream(input,262144),engine.inputLimit,progress,engine);
        byte[] magic = exact(in, 4, false);
        try {
            if (u32(magic, 0, false) == 0x0a0d0d0aL) engine.readNg(in, magic);
            else engine.readPcap(in, magic);
        } catch(EOFException | FormatException e) {
            if(!engine.validHeader)throw e;
            engine.recovered(in.count,e.getMessage());
        }
        if(engine.result.mediaStore!=null)engine.result.mediaStore.seal();
        if(progress!=null)progress.stage("信令重组与通话索引");
        engine.finish(progress,deferMedia);
        engine.result.bytes = in.count;
        return engine.result;
    }
    private static final class CountingInput extends FilterInputStream {
        long count,nextProgress;final long limit;final Progress progress;final CaptureEngine engine;
        CountingInput(InputStream in,long limit,Progress progress,CaptureEngine engine) { super(in);this.limit=limit;this.progress=progress;this.engine=engine; }
        private void advanced(int n)throws IOException{
            if(n<=0)return;count+=n;
            if(count>limit)throw new IOException(limit==MAX_FILE?"抓包超过 128 MB，请先拆分文件":"抓包超过 1 GB，请先拆分文件");
            if(Thread.currentThread().isInterrupted())throw new IOException("导入已取消");
            if(progress!=null&&count>=nextProgress){progress.update(count,engine.result.packets);nextProgress=count+4*1024*1024;}
        }
        @Override public int read(byte[] b, int off, int len) throws IOException {
            int n = in.read(b,off,len);
            advanced(n);
            return n;
        }
        @Override public int read() throws IOException {
            int n = in.read();
            if(n>=0)advanced(1);
            return n;
        }
    }
    private void readPcap(InputStream in, byte[] magic) throws IOException {
        long m = u32(magic,0,false);
        boolean le = m == 0xd4c3b2a1L || m == 0x4d3cb2a1L;
        boolean nano = m == 0x4d3cb2a1L || m == 0xa1b23c4dL;
        if (!le && m != 0xa1b2c3d4L && m != 0xa1b23c4dL) throw new IOException("不是有效的 PCAP / PCAPNG 文件");
        byte[] header = exact(in,20,false);
        if (u16(header,0,le) != 2) throw new IOException("不支持的 PCAP 版本");
        int link = (int)u32(header,16,le) & 0xffff;
        result.format = nano ? "PCAP · ns" : "PCAP · μs";
        validHeader = true;
        while (true) {
            byte[] h = exact(in,16,true);
            if (h == null) break;
            int len = length(u32(h,8,le), "PCAP 包");
            long original = u32(h,12,le);
            byte[] packet = exact(in,len,false);
            if (original > len) result.warn("存在被截断的抓包数据");
            long time = u32(h,0,le)*1000000L + u32(h,4,le)/(nano ? 1000 : 1);
            packet(packet,link,time);
        }
    }
    private void readNg(InputStream in, byte[] first) throws IOException {
        result.format = "PCAPNG";
        byte[] prefix = first;
        boolean le = true;
        List<Iface> interfaces = new ArrayList<>();
        while (prefix != null) {
            byte[] size = exact(in,4,false);
            byte[] body;
            int block;
            long type = u32(prefix,0,true);
            boolean section = type == 0x0a0d0d0aL;
            if (section) {
                byte[] bom = exact(in,4,false);
                long order = u32(bom,0,false);
                if (order != 0x1a2b3c4dL && order != 0x4d3c2b1aL) throw new FormatException("PCAPNG 字节序无效");
                le = order == 0x4d3c2b1aL;
                block = length(u32(size,0,le),"PCAPNG 块");
                if (block < 28 || (block & 3) != 0) throw new FormatException("PCAPNG 节头损坏");
                body = new byte[block-8];
                System.arraycopy(bom,0,body,0,4);
                System.arraycopy(exact(in,block-12,false),0,body,4,block-12);
            } else {
                block = length(u32(size,0,le),"PCAPNG 块");
                if (block < 12 || (block & 3) != 0) throw new FormatException("PCAPNG 块长度无效");
                type = u32(prefix,0,le);
                try { body = exact(in,block-8,false); }
                catch(TruncatedRead e) {
                    // An interrupted writer can leave a complete packet without its block trailer.
                    if(type==6||type==2||type==3)try{ngPacket(e.available,type,interfaces,le,false);}catch(FormatException ignored){}
                    throw e;
                }
            }
            if (u32(body,body.length-4,le) != block) throw new FormatException("PCAPNG 首尾块长度不一致");
            if(section){interfaces.clear();validHeader=true;}
            try { if (type == 1) {
                if (body.length < 12) throw new FormatException("PCAPNG 接口头不完整");
                Iface f = new Iface(); f.link = u16(body,0,le); f.snap = (int)u32(body,4,le);
                int p = 8;
                while (p+4 <= body.length-4) {
                    int code = u16(body,p,le), len = u16(body,p+2,le); p += 4;
                    if (code == 0) break;
                    if (p+len > body.length-4) throw new FormatException("PCAPNG 接口选项损坏");
                    if (code == 9 && len == 1) {
                        int v = body[p]&255;
                        f.resolution = Math.pow((v&128)!=0 ? 2 : 10, -(v&127));
                    }
                    if (code == 14 && len == 8) f.offset = i64(body,p,le);
                    p += (len+3)&~3;
                }
                interfaces.add(f);
            } else if(type==6||type==2||type==3)ngPacket(body,type,interfaces,le,true);
            }catch(FormatException e){if(type==1)interfaces.add(null);recovered(((CountingInput)in).count-block,e.getMessage()+"，已跳过此块");}
            prefix = exact(in,4,true);
        }
    }
    private void ngPacket(byte[] body,long type,List<Iface> interfaces,boolean le,boolean trailer)throws IOException {
        int end=body.length-(trailer?4:0);
        if(type==6||type==2) {
            if(end<20)throw new FormatException("PCAPNG 包头不完整");
            int id=type==2?u16(body,0,le):(int)u32(body,0,le);
            if(id<0||id>=interfaces.size()||interfaces.get(id)==null)throw new FormatException("PCAPNG 引用了未知接口");
            Iface f=interfaces.get(id);int len=length(u32(body,12,le),"PCAPNG 包");
            if(len>end-20)throw new FormatException("PCAPNG 包长度超出已有数据");
            if(u32(body,16,le)>len)result.warn("存在被截断的抓包数据");
            double ticks=u32(body,4,le)*4294967296.0+u32(body,8,le);
            packet(Arrays.copyOfRange(body,20,20+len),f.link,Math.round(ticks*f.resolution*1000000.0)+f.offset*1000000L);
        }else {
            if(interfaces.isEmpty()||interfaces.get(0)==null||end<4)throw new FormatException("PCAPNG 简单包损坏");
            Iface f=interfaces.get(0);int len=length(u32(body,0,le),"PCAPNG 简单包");if(f.snap>0)len=Math.min(len,f.snap);
            if(len>end-4)throw new FormatException("PCAPNG 简单包长度无效");
            result.warn("简单包块没有时间戳，双向音频对齐仅供参考");result.reliableTimestamps=false;
            packet(Arrays.copyOfRange(body,4,4+len),f.link,result.lastUs+1);
        }
    }
    private void packet(byte[] data, int link, long time) throws IOException {
        if (++result.packets > packetLimit) throw new IOException("包数超过分析上限，请先拆分抓包文件");
        result.firstUs = Math.min(result.firstUs,time); result.lastUs = Math.max(result.lastUs,time);
        int p, proto;
        if (link == 1) {
            if (data.length < 14) return;
            p = 14; proto = u16(data,12,false);
            int tags = 0;
            while (proto == 0x8100 || proto == 0x88a8 || proto == 0x9100) {
                if (data.length < p+4 || ++tags > 4) return;
                proto = u16(data,p+2,false); p += 4;
            }
            if (proto != 0x800 && proto != 0x86dd) return;
        } else if (link == 113) { if (data.length < 16) return; p = 16; }
        else if (link == 276) { if (data.length < 20) return; p = 20; }
        else if (link == 0 || link == 108) p = 4;
        else if (link == 101 || link == 12 || link == 228 || link == 229) p = 0;
        else { result.warn("未支持链路类型 " + link); return; }
        if (p >= data.length) return;
        String src, dst;
        int end, version = (data[p]&255) >>> 4;
        if (version == 4) {
            if (data.length < p+20) return;
            int header = (data[p]&15)*4, total = u16(data,p+2,false);
            if (header < 20 || total < header || p+total > data.length) { result.warn("IP 包不完整"); return; }
            if ((u16(data,p+6,false)&0x3fff)!=0) { result.warn("IPv4 分片未重组"); return; }
            src = ip(data,p+12,4); dst = ip(data,p+16,4); proto = data[p+9]&255;
            end = p+total; p += header;
        } else if (version == 6) {
            if (data.length < p+40) return;
            int size = u16(data,p+4,false);
            if (size == 0 || p+40+size > data.length) { result.warn("IPv6 包不完整或为巨型包"); return; }
            src = ip(data,p+8,16); dst = ip(data,p+24,16); proto = data[p+6]&255;
            end = p+40+size; p += 40;
            int extensions = 0;
            while (proto == 0 || proto == 43 || proto == 60 || proto == 51 || proto == 44) {
                if (++extensions > 12 || p+2 > end) return;
                if (proto == 44) { result.warn("IPv6 分片未重组"); return; }
                int len = proto == 51 ? ((data[p+1]&255)+2)*4 : ((data[p+1]&255)+1)*8;
                proto = data[p]&255; p += len;
                if (p > end) return;
            }
        } else return;
        if (p+8 > end) return;
        int sp = u16(data,p,false), dp = u16(data,p+2,false);
        String source = endpoint(src,sp), destination = endpoint(dst,dp);
        if(packetSink!=null){
            int offset,stop=end;
            if(proto==17){int len=u16(data,p+4,false);if(len<8||p+len>end)return;offset=p+8;stop=p+len;}
            else if(proto==6&&p+20<=end){int h=((data[p+12]&255)>>>4)*4;if(h<20||p+h>end)return;offset=p+h;packetSink.tcpHeader(u32(data,p+4,false),data[p+13]&255);}
            else return;
            packetSink.accept(data,link,time,source,destination,proto,Arrays.copyOfRange(data,offset,stop));return;
        }
        if (proto == 17) {
            int len = u16(data,p+4,false);
            if (len < 8 || p+len > end) { result.warn("UDP 包不完整"); return; }
            byte[] payload = Arrays.copyOfRange(data,p+8,p+len);
            if (looksSip(payload,0)) sip(payload,source,destination,"UDP",time);
            else rtp(payload,src,sp,dst,dp,time);
        } else if (proto == 6 && p+20 <= end) {
            int h = ((data[p+12]&255) >>> 4)*4;
            if (h < 20 || p+h > end) return;
            long seq = u32(data,p+4,false);
            boolean syn = (data[p+13]&2)!=0;
            if (syn) seq = (seq+1)&0xffffffffL;
            String key = source + ">" + destination;
            TcpFlow f = currentTcp.get(key);
            if (f == null || (syn && f.anchor != seq)) {
                if (tcp.size()>=10000) throw new IOException("TCP 连接过多，请缩小抓包范围");
                f = new TcpFlow(); f.src = source; f.dst = destination; f.anchor = seq;
                currentTcp.put(key,f); tcp.add(f);
            }
            if (end > p+h) {
                tcpBytes += end-p-h;
                if (tcpBytes > MAX_TCP) throw new IOException("TCP 重组超过 24 MB，请缩小抓包范围");
                Segment s = new Segment(); s.seq = seq; s.time = time;
                s.data = Arrays.copyOfRange(data,p+h,end); f.segments.add(s);
            }
        }
    }
    private void rtp(byte[] b, String src, int sp, String dst, int dp, long time) throws IOException {
        if (b.length < 13 || (b[0]&0xc0)!=0x80 || ((b[1]&255)>=200 && (b[1]&255)<=211)) return;
        int off = 12+(b[0]&15)*4, end = b.length;
        if (off > end) return;
        if ((b[0]&16)!=0) {
            if (off+4 > end) return;
            off += 4 + 4*u16(b,off+2,false);
        }
        if ((b[0]&32)!=0) {
            int pad = b[end-1]&255;
            if (pad == 0 || pad > end-off) return;
            end -= pad;
        }
        if (off >= end) return;
        int pt = b[1]&127;
        long ssrc = u32(b,8,false);
        String source = endpoint(src,sp), destination = endpoint(dst,dp);
        String key = source+">"+destination+"/"+ssrc+"/"+pt;
        RtpStream stream = candidates.get(key);
        if (stream == null) {
            if (candidates.size() >= 10000) throw new IOException("候选媒体流过多，请过滤后再导入");
            stream = new RtpStream(); stream.src = source; stream.dst = destination;
            stream.srcIp = src; stream.dstIp = dst; stream.srcPort = sp; stream.dstPort = dp;
            stream.pt = pt; stream.ssrc = ssrc; candidates.put(key,stream);
            if(result.mediaStore!=null)stream.packets=new PacketStore.Packets(result.mediaStore);
        }
        mediaBytes += end-off;
        if (result.mediaStore==null&&mediaBytes > MAX_MEDIA) throw new IOException("媒体数据超过 64 MB，请先拆分通话");
        if(result.mediaStore!=null){((PacketStore.Packets)stream.packets).append(result.mediaStore.append(time,u32(b,4,false),u16(b,2,false),(b[1]&128)!=0,b,off,end),time);return;}
        RtpPacket packet = new RtpPacket(); packet.sequence = u16(b,2,false);
        packet.marker = (b[1]&128)!=0;
        packet.timestamp = u32(b,4,false); packet.timeUs = time;
        packet.payload = Arrays.copyOfRange(b,off,end); stream.packets.add(packet);
    }
    private void sip(byte[] data, String src, String dst, String transport, long time) throws IOException {
        sip(data,src,dst,transport,time,null);
    }
    private void sip(byte[] data, String src, String dst, String transport, long time,List<Span> spans) throws IOException {
        int cursor = 0;
        while (cursor<data.length && (data[cursor]==13 || data[cursor]==10)) cursor++;
        while (cursor < data.length && looksSip(data,cursor)) {
            int headEnd = -1, delimiter = 0;
            for (int i=cursor; i < data.length-1 && i-cursor <= 65536; i++) {
                if (i+3<data.length && data[i]==13 && data[i+1]==10 && data[i+2]==13 && data[i+3]==10) { headEnd=i; delimiter=4; break; }
                if (data[i]==10 && data[i+1]==10) { headEnd=i; delimiter=2; break; }
            }
            if (headEnd < 0) { result.warn("SIP 头不完整"); return; }
            String head = new String(data,cursor,headEnd-cursor,StandardCharsets.UTF_8);
            String[] lines = head.replaceAll("\r?\n[ \t]+"," ").split("\r?\n");
            SipMessage message = new SipMessage(); message.timeUs=time; message.src=src; message.dst=dst;
            if (spans!=null) for (Span span:spans) { if(span.offset>cursor)break; message.timeUs=span.time; }
            message.transport=transport; message.firstLine=lines[0];
            for (int i=1; i<lines.length; i++) {
                int colon=lines[i].indexOf(':');
                if (colon>0) {
                    String k=lines[i].substring(0,colon).trim().toLowerCase(Locale.ROOT);
                    if (k.equals("i")) k="call-id"; if (k.equals("f")) k="from";
                    if (k.equals("t")) k="to"; if (k.equals("l")) k="content-length";
                    if (k.equals("c")) k="content-type";
                    message.headers.put(k,lines[i].substring(colon+1).trim());
                }
            }
            int bodyStart=headEnd+delimiter, bodyLen=0;
            String declared=message.headers.get("content-length");
            if (declared!=null) {
                try { bodyLen=Integer.parseInt(declared); }
                catch (NumberFormatException e) { result.warn("SIP Content-Length 无效"); return; }
                if (bodyLen<0 || bodyLen>4*1024*1024) { result.warn("SIP 消息体长度超出限制"); return; }
            } else if (transport.equals("UDP")||transport.equals("WS")||transport.equals("WSS")) bodyLen=data.length-bodyStart;
            if (bodyLen>data.length-bodyStart) { result.warn("SIP 消息体不完整"); return; }
            message.raw=new String(data,cursor,bodyStart+bodyLen-cursor,StandardCharsets.UTF_8);
            message.body=new String(data,bodyStart,bodyLen,StandardCharsets.UTF_8);
            message.callId=message.headers.getOrDefault("call-id","");
            message.from=message.headers.getOrDefault("from",""); message.to=message.headers.getOrDefault("to","");
            message.cseq=message.headers.getOrDefault("cseq","");
            result.sip.add(message);
            if (result.sip.size()>30000) throw new IOException("SIP 消息超过 3 万条，请缩小抓包范围");
            cursor=bodyStart+bodyLen;
            while (cursor<data.length && (data[cursor]==13 || data[cursor]==10)) cursor++;
        }
    }
    private void finish(Progress progress,boolean deferMedia) throws IOException {
        List<SignalingTransport.Data> signals=new ArrayList<>();int direction=0;
        for (TcpFlow f : tcp) {
            final int id=direction++;boolean gap=false;
            f.segments.sort((a,b)->Long.compare((int)(a.seq-f.anchor),(int)(b.seq-f.anchor)));
            ByteArrayOutputStream buffer=new ByteArrayOutputStream();
            List<Span> spans=new ArrayList<>();
            long position=Long.MIN_VALUE, time=0;
            for (Segment s : f.segments) {
                long start=(int)(s.seq-f.anchor);
                if (position!=Long.MIN_VALUE && start>position) {
                    if (buffer.size()>0) signals.add(new SignalingTransport.Data(f.src,f.dst,buffer.toByteArray(),spans,id,gap));
                    buffer.reset(); spans.clear(); result.warn("TCP 数据有缺口，部分 SIP 可能缺失"); position=start;gap=true;
                }
                if (position==Long.MIN_VALUE) position=start;
                int skip=(int)Math.min(s.data.length,Math.max(0,position-start));
                if (skip<s.data.length) {
                    if (buffer.size()==0) time=s.time;
                    spans.add(new Span(buffer.size(),s.time));
                    buffer.write(s.data,skip,s.data.length-skip); position=start+s.data.length;
                }
            }
            if (buffer.size()>0) signals.add(new SignalingTransport.Data(f.src,f.dst,buffer.toByteArray(),spans,id,gap));
            f.segments.clear();
        }
        tcp.clear(); currentTcp.clear();
        SignalingTransport.decode(signals,keyLog,rsaKeys,result,data->sip(data.bytes,data.src,data.dst,data.transport,data.time(0),data.spans));
        result.sip.sort(Comparator.comparingLong(m->m.timeUs));
        for (SipMessage m : result.sip) {
            if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("导入已取消");
            if (m.callId.isEmpty()) continue;
            Call call=calls.get(m.callId);
            if (call==null) { call=new Call(); call.id=m.callId; calls.put(call.id,call); result.calls.add(call); }
            call.startUs=Math.min(call.startUs,m.timeUs); call.sipCount++;
            call.lastUs=Math.max(call.lastUs,m.timeUs);call.signalingIps.add(CallFlow.Endpoint.parse(m.src).ip);call.signalingIps.add(CallFlow.Endpoint.parse(m.dst).ip);
            if (call.from.isEmpty()) call.from=m.from; if (call.to.isEmpty()) call.to=m.to;
            if(!call.inviteIdentity&&m.firstLine.startsWith("INVITE ")){call.inviteIdentity=true;call.from=m.from;call.to=m.to;String[] words=m.firstLine.split(" +");if(words.length>1)call.requestTarget=words[1];}
            if (m.firstLine.startsWith("SIP/2.0") && m.cseq.toUpperCase(Locale.ROOT).endsWith("INVITE")) call.status=m.firstLine;
            if (m.firstLine.startsWith("BYE ") || m.firstLine.startsWith("CANCEL ")) call.endUs=Math.min(call.endUs,m.timeUs+2000000);
            if (m.headers.getOrDefault("content-type","").toLowerCase(Locale.ROOT).contains("application/sdp")) sdp(m);
        }
        for(Media endpoint:media)if(!endpoint.ip.isEmpty()&&calls.containsKey(endpoint.callId))calls.get(endpoint.callId).mediaIps.add(endpoint.ip);
        for (RtpStream stream : candidates.values()) {
            if(stream.packets instanceof PacketStore.Packets)((PacketStore.Packets)stream.packets).sortByTime();else stream.packets.sort(Comparator.comparingLong(p->p.timeUs));
            Media chosen=null; int best=0; boolean tied=false;
            for (Media m : media) {
                Call c=calls.get(m.callId); long t=stream.firstUs();
                if (!m.pts.contains(stream.pt) || t<c.startUs-2000000 || t>c.endUs) continue;
                int score=0;
                if (stream.srcPort==m.port) score=1+(stream.srcIp.equals(m.ip)?10:0);
                if (stream.dstPort==m.port) score=Math.max(score,1+(stream.dstIp.equals(m.ip)?10:0));
                if (score==0) continue;
                if (m.timeUs<=t+1000000) score+=2;
                if (score>best) { best=score; chosen=m; tied=false; }
                else if (score==best && chosen!=null) {
                    if (!chosen.callId.equals(m.callId)) tied=true;
                    else if (m.timeUs>chosen.timeUs && m.timeUs<=t+1000000) chosen=m;
                }
            }
            if (tied) chosen=null;
            if (chosen==null && !coherent(stream)) continue;
            stream.codec=stream.pt==0?"PCMU":stream.pt==8?"PCMA":stream.pt==18?"G729":stream.pt==9?"G722":stream.pt==13?"CN":"PT "+stream.pt;
            stream.clockKnown=stream.pt==0 || stream.pt==8 || stream.pt==18 || stream.pt==9 || stream.pt==13;
            if (chosen!=null) {
                stream.callId=chosen.callId;
                stream.codec=chosen.codecs.getOrDefault(stream.pt,stream.codec);
                stream.clock=chosen.clocks.getOrDefault(stream.pt,8000);
                stream.fmtp=chosen.formats.getOrDefault(stream.pt,"");
                stream.clockKnown=stream.clockKnown || chosen.clocks.containsKey(stream.pt);
                stream.encrypted=chosen.profile.toUpperCase(Locale.ROOT).contains("SAVP");
                if (stream.encrypted) stream.note="SDP 声明 SRTP，当前版本不解密";
                calls.get(chosen.callId).streams.add(stream);
                Call linked=calls.get(chosen.callId);linked.mediaIps.add(stream.srcIp);linked.mediaIps.add(stream.dstIp);linked.lastUs=Math.max(linked.lastUs,stream.packets.get(stream.packets.size()-1).timeUs);
            } else stream.note="未关联 SDP；静态 PT 仅推断编码，无法仅凭 RTP 首部排除 SRTP";
            if (!stream.playable() && !stream.encrypted) stream.note=stream.isDtmf()?"RFC 2833 / 4733 按键事件":"当前未提供此编码的解码器";
            if(stream.playable()&&stream.codec.startsWith("G729")) {
                boolean sid=false,invalid=false;
                for(RtpPacket p:stream.packets){int size=p.payloadSize();sid|=size%10==2;invalid|=size%10!=0&&size%10!=2;}
                if(sid)stream.note+=(stream.note.isEmpty()?"":"；")+"SID 区间保留静音，未合成舒适噪声";
                if(invalid)stream.note+=(stream.note.isEmpty()?"":"；")+"包含 G.729 包长异常，播放时会拒绝处理";
            }
            if (stream.isDtmf() && !stream.encrypted) {
                DtmfParser.Result events=DtmfParser.parse(stream);
                stream.events.addAll(events.events); result.events.addAll(events.events);
                if(result.events.size()>30000)throw new IOException("电话事件超过 3 万条，请先拆分文件");
                if (events.malformed>0) result.warn("存在不完整或保留位异常的电话事件");
            }
            result.streams.add(stream);
        }
        if(deferMedia){KeyAnalysis.attachSignaling(result);deferredCandidates=new ArrayList<>(candidates.values());}
        else{
            if(progress!=null)progress.stage("媒体质量与按键分析");
            QualityAnalyzer.attach(result.streams,new ArrayList<>(candidates.values()),result.reliableTimestamps);
            KeyAnalysis.attach(result);
        }
        if(progress!=null)progress.stage("准备通话列表");
        result.events.sort(Comparator.comparingLong(e->e.firstSeenUs));
        candidates.clear();
        if (result.firstUs==Long.MAX_VALUE) result.firstUs=0;
    }
    private boolean coherent(RtpStream s) {
        if (s.packets.size()<3) return false;
        int good=0, total=Math.min(s.packets.size()-1,30);
        for (int i=1;i<=total;i++) {
            int diff=(short)(s.packets.get(i).sequence-s.packets.get(i-1).sequence);
            if (Math.abs(diff)<=4096) good++;
        }
        return good*2>total;
    }
    private void sdp(SipMessage message) {
        String sessionIp=""; Media current=null; boolean mediaSection=false;
        for (String line : message.body.split("\r?\n")) {
            String value=line.length()>2?line.substring(2).trim():"";
            if (line.startsWith("m=")) {
                mediaSection=true;
                current=null; String[] parts=value.split("\\s+");
                if (parts.length<4 || !parts[0].equals("audio")) continue;
                try {
                    int port=Integer.parseInt(parts[1].split("/")[0]);
                    if (port<=0 || port>65535) continue;
                    current=new Media(); current.ip=sessionIp; current.port=port; current.profile=parts[2];
                    current.callId=message.callId; current.timeUs=message.timeUs;
                    for (int i=3;i<parts.length;i++) current.pts.add(Integer.parseInt(parts[i]));
                    current.codecs.put(0,"PCMU"); current.codecs.put(8,"PCMA");
                    media.add(current);
                } catch (NumberFormatException e) { current=null; }
            } else if (line.startsWith("c=")) {
                String[] parts=value.split("\\s+");
                if (parts.length>=3) {
                    String address=parts[2].split("/")[0];
                    if (!mediaSection) sessionIp=address; else if(current!=null) current.ip=address;
                }
            } else if (current!=null && line.startsWith("a=rtpmap:")) {
                try {
                    String[] parts=line.substring(9).trim().split("\\s+"); String[] format=parts[1].split("/");
                    int pt=Integer.parseInt(parts[0]), clock=Integer.parseInt(format[1]);
                    String codec=format[0].toUpperCase(Locale.ROOT);
                    // G.711 stereo or unusual clock rates must never be decoded as mono 8 kHz.
                    if (format.length>2 && !format[2].equals("1") && !(codec.equals("OPUS")&&format[2].equals("2"))) codec+="/"+format[2]+"ch";
                    current.codecs.put(pt,codec); if (clock>0) current.clocks.put(pt,clock);
                } catch (RuntimeException e) { result.warn("SDP rtpmap 格式无效"); }
            } else if(current!=null&&line.startsWith("a=fmtp:")){
                try{String[] parts=line.substring(7).trim().split("\\s+",2);current.formats.put(Integer.parseInt(parts[0]),parts.length>1?parts[1]:"");}catch(RuntimeException e){result.warn("SDP fmtp 格式无效");}
            }
        }
    }
    private static boolean looksSip(byte[] data,int off) {
        int end=off; while (end<data.length && end-off<256 && data[end]!=10 && data[end]!=13) end++;
        if (end==off) return false;
        String line=new String(data,off,end-off,StandardCharsets.US_ASCII);
        return line.startsWith("SIP/2.0 ") || line.matches("[A-Z][A-Z0-9_-]{1,30} [^ ]+ SIP/2\\.0");
    }
    private static String endpoint(String ip,int port) { return (ip.contains(":")?"["+ip+"]":ip)+":"+port; }
    private static String ip(byte[] data,int offset,int length) throws IOException {
        return InetAddress.getByAddress(Arrays.copyOfRange(data,offset,offset+length)).getHostAddress();
    }
    private static int length(long value,String label) throws IOException {
        if (value<0 || value>MAX_BLOCK) throw new FormatException(label+"长度超过安全限制");
        return (int)value;
    }
    private static byte[] exact(InputStream in,int size,boolean eof) throws IOException {
        byte[] out=new byte[size]; int pos=0;
        while (pos<size) {
            int n=in.read(out,pos,size-pos);
            if (n<0) { if (pos==0 && eof) return null; throw new TruncatedRead(out,pos); }
            if (n==0) continue; pos+=n;
        }
        return out;
    }
    private static int u16(byte[] b,int p,boolean le) { return le?(b[p]&255)|((b[p+1]&255)<<8):((b[p]&255)<<8)|(b[p+1]&255); }
    private static long u32(byte[] b,int p,boolean le) {
        long v=0; for (int i=0;i<4;i++) v=(v<<8)|(b[p+(le?3-i:i)]&255); return v;
    }
    private static long i64(byte[] b,int p,boolean le) {
        long v=0; for (int i=0;i<8;i++) v=(v<<8)|(b[p+(le?7-i:i)]&255); return v;
    }
}
