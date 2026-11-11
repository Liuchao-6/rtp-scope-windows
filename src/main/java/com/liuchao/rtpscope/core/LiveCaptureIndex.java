package com.liuchao.rtpscope.core;

import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Bounded capture-side metadata index. Audio and the authoritative analysis stay offline. */
public final class LiveCaptureIndex {
    public static final int MAX_CALLS=10000,MAX_STREAMS=20000;
    public static final class Stream {
        public String src,dst,codec="未知",callId="";public long ssrc,packets,gaps,duplicates,firstUs,lastUs;public int pt;
        private long base,highest,confirmed;private final Set<Long> sequence=new HashSet<>();
        private void sequence(int n){long ext=packets==0?n:highest+(short)(n-(int)highest);if(packets==0){base=ext;highest=ext;}if(ext<base){duplicates++;return;}if(ext>highest+10000){confirmed+=Math.max(0,highest-base+1-sequence.size());sequence.clear();base=ext;highest=ext;}
            highest=Math.max(highest,ext);long floor=Math.max(base,highest-2047);if(floor>base){long received=0;for(Iterator<Long> it=sequence.iterator();it.hasNext();)if(it.next()<floor){received++;it.remove();}confirmed+=floor-base-received;base=floor;}if(!sequence.add(ext))duplicates++;gaps=confirmed+highest-base+1-sequence.size();}
        private Stream copy(){Stream s=new Stream();s.src=src;s.dst=dst;s.codec=codec;s.callId=callId;s.ssrc=ssrc;s.packets=packets;s.gaps=gaps;s.duplicates=duplicates;s.firstUs=firstUs;s.lastUs=lastUs;s.pt=pt;return s;}
    }
    public static final class View {
        public final List<Call> calls=new ArrayList<>();public final List<Stream> streams=new ArrayList<>();public final List<SipMessage> messages=new ArrayList<>();public final List<DtmfParser.Event> events=new ArrayList<>();public final List<String> connections=new ArrayList<>();public final Map<String,Set<Integer>> sources=new HashMap<>(),volumes=new HashMap<>();
        public long packets,duplicateInterfaces,lastUs;public String notice="";
        public Call call(String id){for(Call c:calls)if(c.id.equals(id))return c;return null;}
    }
    public static final class Selection {
        public final String callId;public final long fromUs,toUs;public final Set<String> tcp=new HashSet<>(),rtp=new HashSet<>();
        private Selection(String id,long from,long to){callId=id;fromUs=from;toUs=to;}
        public boolean sharedTcp(){return !tcp.isEmpty();}
        public boolean matches(String src,String dst,int protocol,byte[] payload,long time)throws IOException {
            if(protocol==6)return tcp.contains(src+">"+dst)||tcp.contains(dst+">"+src);
            if(time<fromUs||time>toUs)return false;
            if(protocol==17){if(CaptureEngine.looksLikeSip(payload))for(SipMessage m:CaptureEngine.parseSignaling(payload,src,dst,"UDP",time))if(callId.equals(m.callId))return true;if(payload.length>=12&&(payload[0]&0xc0)==0x80)return rtp.contains(src+">"+dst+"/"+uint(payload,8));}return false;
        }
    }
    private static final class State {final Call call=new Call();final Set<String> tcp=new LinkedHashSet<>();final Set<Integer> sources=new LinkedHashSet<>(),volumes=new LinkedHashSet<>();long ended;boolean connected;}
    private static final class Offer {String endpoint,id,codec;int pt,clock;long time;boolean encrypted;}
    private static final class Tcp {
        String src,dst;long anchor,time,last,next;boolean initialized,dirty,tls,limited;int flags;byte[] contiguous=new byte[0];final TreeMap<Long,byte[]> pending=new TreeMap<>();int pendingBytes;
        final LinkedHashSet<String> emitted=new LinkedHashSet<>(),callIds=new LinkedHashSet<>();final List<CaptureEngine.Span> spans=new ArrayList<>();final Set<Integer> sources=new LinkedHashSet<>(),volumes=new LinkedHashSet<>();
    }
    private final LinkedHashMap<String,State> calls=new LinkedHashMap<>();private final LinkedHashMap<String,Stream> streams=new LinkedHashMap<>();private final Map<String,List<Offer>> offers=new HashMap<>();private int offerCount;
    private final LinkedHashMap<String,Tcp> tcp=new LinkedHashMap<>(16,.75f,true);
    private final ArrayDeque<SipMessage> recent=new ArrayDeque<>();private final LinkedHashMap<String,DtmfParser.Event> events=new LinkedHashMap<>();
    private final LinkedHashMap<String,long[]> duplicate=new LinkedHashMap<>();private final Set<String> notices=new LinkedHashSet<>();
    private final PacketInspector inspector;private long packets,duplicateInterfaces,lastUs,seq;private int flags,device,volume;
    public LiveCaptureIndex(){inspector=new PacketInspector(new PacketSink(){public void tcpHeader(long s,int f){seq=s;flags=f;}public void accept(byte[] p,int link,long t,String src,String dst,int protocol,byte[] payload)throws IOException{packet(src,dst,protocol,payload,t);}});}
    public void accept(byte[] raw,int link,long timeUs,int interfaceId)throws IOException {
        accept(raw,link,timeUs,interfaceId,0);
    }
    public void accept(byte[] raw,int link,long timeUs,int interfaceId,int volumeNumber)throws IOException {packets++;lastUs=Math.max(lastUs,timeUs);device=interfaceId;volume=volumeNumber;try{inspector.accept(raw,link,timeUs);}catch(IOException malformed){notice("部分报文无法生成实时摘要；原始报文仍已保存，请用快照检查");}}
    private void notice(String text){if(notices.size()<12)notices.add(text);}
    public void missingVolume(){notice("部分分卷已被循环覆盖，速览与快照可能缺少前段报文");}
    private void packet(String src,String dst,int protocol,byte[] b,long t)throws IOException {
        String fingerprint=src+">"+dst+"/"+protocol+"/"+b.length+"/"+Arrays.hashCode(b)+(protocol==6?"/"+seq+"/"+flags:"");
        long[] previous=duplicate.get(fingerprint);if(previous!=null&&previous[1]!=device&&Math.abs(t-previous[0])<=5000){duplicateInterfaces++;duplicateOrigin(src,dst,protocol,b,t);return;}duplicate.put(fingerprint,new long[]{t,device});if(duplicate.size()>4096)duplicate.remove(duplicate.keySet().iterator().next());
        if(protocol==17){if(CaptureEngine.looksLikeSip(b)){for(SipMessage m:CaptureEngine.parseSignaling(b,src,dst,"UDP",t))message(m,null);return;}rtp(src,dst,b,t);}
        else if(protocol==6)tcp(src,dst,b,t);
    }
    private void duplicateOrigin(String src,String dst,int protocol,byte[] b,long t)throws IOException {
        if(protocol==6){Tcp f=tcp.get(src+">"+dst);if(f!=null){if(f.sources.size()<256)f.sources.add(device);if(f.volumes.size()<256)f.volumes.add(volume);for(String id:f.callIds){State s=calls.get(id);if(s!=null)origin(s,device,volume);}}return;}
        if(protocol!=17)return;
        if(CaptureEngine.looksLikeSip(b)){for(SipMessage m:CaptureEngine.parseSignaling(b,src,dst,"UDP",t)){State s=calls.get(m.callId);if(s!=null)origin(s,device,volume);}return;}
        if(b.length<12||(b[0]&0xc0)!=0x80)return;Offer a=offer(src,b[1]&127,t),z=offer(dst,b[1]&127,t),o=a==null?z:z==null?a:a.id.equals(z.id)?a:a.time>z.time?a:z;if(o!=null){State s=calls.get(o.id);if(s!=null)origin(s,device,volume);}
    }
    private void message(SipMessage m,String connection){
        if(m.callId.isEmpty()||m.callId.length()>512)return;State state=calls.get(m.callId);
        if(state==null){if(calls.size()>=MAX_CALLS){notice("速览已达到 10000 通上限；原始报文仍继续保存，请用快照分析");return;}state=new State();state.call.id=m.callId;calls.put(m.callId,state);}
        Call c=state.call;c.startUs=Math.min(c.startUs,m.timeUs);c.lastUs=Math.max(c.lastUs,m.timeUs);c.sipCount++;if(c.signalingIps.size()<64){c.signalingIps.add(CallFlow.Endpoint.parse(m.src).ip);c.signalingIps.add(CallFlow.Endpoint.parse(m.dst).ip);}
        if(connection==null)origin(state,device,volume);else {Tcp f=null;for(Map.Entry<String,Tcp> entry:tcp.entrySet())if(entry.getKey().equals(connection)){f=entry.getValue();break;}if(f!=null){if(f.callIds.size()<MAX_CALLS)f.callIds.add(m.callId);state.sources.addAll(f.sources);for(int n:f.volumes)origin(state,-1,n);}}
        if(connection!=null&&state.tcp.size()<32)state.tcp.add(connection);
        if(!c.inviteIdentity||m.firstLine.startsWith("INVITE ")){c.from=shortHeader(m.from);c.to=shortHeader(m.to);if(m.firstLine.startsWith("INVITE ")){c.inviteIdentity=true;String[] line=m.firstLine.split(" ");c.requestTarget=line.length>1?shortHeader(line[1]):"";}}
        if(m.firstLine.startsWith("INVITE ")&&!state.connected&&state.ended==0)c.status="呼叫中";
        else if(state.ended==0&&!state.connected&&(m.firstLine.startsWith("SIP/2.0 180")||m.firstLine.startsWith("SIP/2.0 183")))c.status="振铃 / 早期媒体";
        else if(state.ended==0&&m.firstLine.startsWith("SIP/2.0 2")&&m.cseq.endsWith("INVITE")){c.status="通话中";state.connected=true;}
        else if(m.firstLine.startsWith("BYE ")||m.firstLine.startsWith("CANCEL ")||m.cseq.endsWith("INVITE")&&m.firstLine.matches("SIP/2.0 [4-6].*")&&!m.firstLine.startsWith("SIP/2.0 401")&&!m.firstLine.startsWith("SIP/2.0 407")){c.status=m.firstLine.startsWith("CANCEL ")||c.status.equals("已取消")?"已取消":m.firstLine.startsWith("BYE ")?"已结束":"呼叫失败";c.endUs=Math.min(c.endUs,m.timeUs);state.ended=Math.max(state.ended,m.timeUs);}
        if(c.status.isEmpty())c.status="仅见部分信令";
        sdp(m);
        if(m.firstLine.startsWith("INFO ")){Analysis a=new Analysis();a.sip.add(m);for(DtmfParser.Event e:SipInfoDtmf.parse(a)){String key="info/"+e.callId+"/"+e.src+"/"+m.cseq+"/"+e.key;DtmfParser.Event old=events.get(key);if(old==null)addEvent(key,e);else {old.packets++;old.lastSeenUs=Math.max(old.lastSeenUs,e.lastSeenUs);}}}
        // The raw file is authoritative; only recent message bodies are retained in memory.
        if(m.raw.length()>16384){m.raw=m.raw.substring(0,16384)+"\n[速览内容已截取，完整内容见快照]";m.body="";}
        recent.add(m);while(recent.size()>512)recent.remove();
    }
    private void addEvent(String key,DtmfParser.Event e){events.put(key,e);while(events.size()>2048)events.remove(events.keySet().iterator().next());}
    private void sdp(SipMessage m){
        if(m.body==null||!m.body.contains("m=audio"))return;
        String sessionIp="",ip="";int port=0;boolean audio=false,inMedia=false,encrypted=false;List<Integer> pts=new ArrayList<>();Map<Integer,String> codecs=new HashMap<>();Map<Integer,Integer> clocks=new HashMap<>();
        for(String raw:(m.body+"\nm=end").split("\\r?\\n")){String line=raw.trim();
            if(line.startsWith("m=")){
                if(audio&&port>0&&!ip.isEmpty())for(int pt:pts){String endpoint=(ip.contains(":")?"["+ip+"]":ip)+":"+port;List<Offer> list=offers.computeIfAbsent(endpoint,k->new ArrayList<>());Offer o=new Offer();o.endpoint=endpoint;o.id=m.callId;o.pt=pt;o.codec=codecs.getOrDefault(pt,staticCodec(pt));o.clock=clocks.getOrDefault(pt,8000);o.time=m.timeUs;o.encrypted=encrypted;list.add(o);offerCount++;while(list.size()>32){list.remove(0);offerCount--;}State state=calls.get(m.callId);if(state!=null&&state.call.mediaIps.size()<64)state.call.mediaIps.add(ip);}
                audio=line.startsWith("m=audio ");inMedia=true;port=0;ip=sessionIp;pts.clear();codecs.clear();clocks.clear();String[] p=line.split("\\s+");encrypted=p.length>2&&p[2].toUpperCase(Locale.ROOT).contains("SAVP");if(audio&&p.length>=4)try{port=Integer.parseInt(p[1].split("/")[0]);for(int n=3;n<p.length;n++){int pt=Integer.parseInt(p[n]);if(pt>=0&&pt<=127&&pts.size()<128)pts.add(pt);}}catch(NumberFormatException ignored){}
            }else if(line.startsWith("c=IN IP")){String[] p=line.split("\\s+");if(p.length>=3){ip=p[2].split("/")[0];if(ip.length()>128)ip="";if(!inMedia)sessionIp=ip;}}
            else if(line.startsWith("a=rtpmap:")){String[] p=line.substring(9).split("[ /]+");if(p.length>=3)try{int pt=Integer.parseInt(p[0]);codecs.put(pt,p[1].toUpperCase(Locale.ROOT));clocks.put(pt,Integer.parseInt(p[2]));}catch(NumberFormatException ignored){}}
        }
        if(offerCount>8192){offers.clear();offerCount=0;notice("速览媒体映射达到上限，后续完整关联请使用快照分析");}
    }
    private Offer offer(String endpoint,int pt,long t){List<Offer> list=offers.get(endpoint);if(list==null)return null;Offer best=null;for(Offer o:list)if(o.pt==pt&&o.time<=t+1000000&&(best==null||best.time<=o.time))best=o;return best;}
    private static String staticCodec(int pt){return pt==0?"PCMU":pt==8?"PCMA":pt==9?"G722":pt==18?"G729":"PT "+pt;}
    private void rtp(String src,String dst,byte[] b,long t){
        if(b.length<12||(b[0]&0xc0)!=0x80||(b[1]&255)>=192&&(b[1]&255)<=223)return;int offset=12+(b[0]&15)*4,end=b.length;if(offset>end)return;
        if((b[0]&16)!=0){if(offset+4>end)return;offset+=4+(((b[offset+2]&255)<<8)|(b[offset+3]&255))*4;}if((b[0]&32)!=0){int pad=b[end-1]&255;if(pad==0)return;end-=pad;}if(offset>=end)return;
        int pt=b[1]&127;long ssrc=uint(b,8);Offer a=offer(src,pt,t),z=offer(dst,pt,t),o=a==null?z:z==null?a:a.id.equals(z.id)?a:a.time>z.time?a:z;String id=o==null?"":o.id;
        String key=id+"/"+src+">"+dst+"/"+ssrc+"/"+pt;Stream s=streams.get(key);if(s==null){if(streams.size()>=MAX_STREAMS){notice("速览达到 20000 路媒体流上限；原始报文仍继续保存");return;}s=new Stream();s.src=src;s.dst=dst;s.ssrc=ssrc;s.pt=pt;s.codec=o==null?staticCodec(pt):o.codec+(o.encrypted?" · SRTP 未解密":"");s.callId=id;s.firstUs=t;streams.put(key,s);}s.sequence(((b[2]&255)<<8)|(b[3]&255));s.packets++;s.lastUs=Math.max(s.lastUs,t);
        State state=calls.get(id);if(state!=null){state.call.lastUs=Math.max(state.call.lastUs,t);origin(state,device,volume);}
        if(o!=null&&!o.encrypted&&(o.codec.equals("TELEPHONE-EVENT")||o.codec.equals("RTPEVENT")||o.codec.equals("RTP-EVENT"))&&o.clock>0&&(end-offset)%4==0){for(int p=offset;p+4<=end;p+=4){if((b[p+1]&64)!=0)continue;int number=b[p]&255;if(number>16)continue;String ekey=key+"/"+uint(b,4)+"/"+number;DtmfParser.Event e=events.get(ekey);if(e==null){e=new DtmfParser.Event();e.src=src;e.dst=dst;e.callId=id;e.number=number;e.key=DtmfParser.key(number);e.ssrc=ssrc;e.timestamp=uint(b,4);e.firstSeenUs=t;e.clock=o.clock;addEvent(ekey,e);}e.packets++;e.lastSeenUs=Math.max(e.lastSeenUs,t);e.ended|=(b[p+1]&128)!=0;e.volume=b[p+1]&63;e.durationTicks=Math.max(e.durationTicks,((b[p+2]&255)<<8)|(b[p+3]&255));}}
    }
    private void tcp(String src,String dst,byte[] b,long t){
        String key=src+">"+dst;Tcp f=tcp.get(key);long start=(seq+((flags&2)!=0?1:0))&0xffffffffL;
        if(f==null||(flags&2)!=0&&f.anchor!=start){f=new Tcp();f.src=src;f.dst=dst;f.anchor=start;f.next=start;f.initialized=true;f.time=t;tcp.put(key,f);if(tcp.size()>32){tcp.remove(tcp.keySet().iterator().next());notice("实时 TCP 速览仅保留最近 32 个方向，其余连接可在快照分析");}}
        if(f.sources.size()<256)f.sources.add(device);if(f.volumes.size()<256)f.volumes.add(volume);f.last=t;if(b.length==0)return;if(f.tls||f.limited)return;
        long ext=f.next+(int)(start-f.next);if(ext+b.length<=f.next)return;if(ext<f.next){b=Arrays.copyOfRange(b,(int)(f.next-ext),b.length);ext=f.next;}
        if(ext>f.next){if(f.pendingBytes+b.length<=262144&&f.pending.size()<128){byte[] old=f.pending.put(ext,b);f.pendingBytes+=b.length-(old==null?0:old.length);}else notice("TCP 乱序缓存达到上限，部分实时摘要可能缺失");return;}
        append(f,b);for(;;){Map.Entry<Long,byte[]> e=f.pending.firstEntry();if(e==null||e.getKey()>f.next)break;f.pending.pollFirstEntry();f.pendingBytes-=e.getValue().length;int skip=(int)Math.max(0,f.next-e.getKey());if(skip<e.getValue().length)append(f,Arrays.copyOfRange(e.getValue(),skip,e.getValue().length));}
    }
    private void append(Tcp f,byte[] b){
        if(f.contiguous.length+b.length>1048576){f.limited=true;f.contiguous=new byte[0];f.pending.clear();f.pendingBytes=0;notice("单方向 TCP 速览已到 1 MiB；后续信令请打开快照分析");return;}
        if(f.contiguous.length==0&&b.length>=3&&(b[0]&255)>=20&&(b[0]&255)<=23&&b[1]==3){f.tls=true;return;}
        if(f.spans.size()<8192)f.spans.add(new CaptureEngine.Span(f.contiguous.length,f.last));
        byte[] joined=Arrays.copyOf(f.contiguous,f.contiguous.length+b.length);System.arraycopy(b,0,joined,f.contiguous.length,b.length);f.contiguous=joined;f.next+=b.length;f.dirty=true;
    }
    /** Decode dirty bounded TCP buffers once per refresh, never per packet. */
    public void flush()throws IOException {
        for(Map.Entry<String,Tcp> entry:tcp.entrySet()){Tcp f=entry.getValue();if(!f.dirty||f.tls||f.limited)continue;f.dirty=false;
            try{
            int consumed=completeSipPrefix(f.contiguous);
            if(consumed>0){for(SipMessage m:CaptureEngine.parseSignaling(Arrays.copyOf(f.contiguous,consumed),f.src,f.dst,"TCP",f.time,f.spans))message(m,entry.getKey());consume(f,consumed);continue;}
            SignalingTransport.Data data=new SignalingTransport.Data(f.src,f.dst,f.contiguous,f.spans,0,false);
            Analysis scratch=new Analysis();SignalingTransport.decode(Collections.singletonList(data),TlsKeyLog.empty(),TlsRsaKeys.empty(),scratch,decoded->{for(SipMessage m:CaptureEngine.parseSignaling(decoded.bytes,decoded.src,decoded.dst,decoded.transport,decoded.time(0),decoded.spans)){String fingerprint=digest(m.raw);if(f.emitted.add(fingerprint)){message(m,entry.getKey());if(f.emitted.size()>4096){f.limited=true;notice("单方向 WebSocket 消息达到速览上限，后续请使用快照分析");break;}}}});
            }catch(IOException malformed){f.limited=true;f.contiguous=new byte[0];f.pending.clear();f.pendingBytes=0;f.spans.clear();notice("部分 TCP / WebSocket 实时摘要受限；原始报文仍已保存，请用快照检查");}
        }
    }
    private static int completeSipPrefix(byte[] b){int at=0,complete=0;while(at<b.length){while(at<b.length&&(b[at]==13||b[at]==10))at++;int end=-1;for(int i=at;i+3<b.length&&i-at<65536;i++)if(b[i]==13&&b[i+1]==10&&b[i+2]==13&&b[i+3]==10){end=i+4;break;}if(end<0)break;String head=new String(b,at,end-at,StandardCharsets.UTF_8);int line=head.indexOf('\n');if(line<0||!head.substring(0,line).trim().matches("(?:[A-Z]+ .+ SIP/2\\.0|SIP/2\\.0 [0-9]{3}.*)"))break;java.util.regex.Matcher m=java.util.regex.Pattern.compile("(?im)^(?:Content-Length|l)\\s*:\\s*([0-9]+)\\s*$").matcher(head);int length=0;try{if(m.find())length=Integer.parseInt(m.group(1));}catch(NumberFormatException e){break;}if(length<0||length>b.length-end)break;at=end+length;complete=at;}return complete;}
    private static void consume(Tcp f,int n){long first=f.time;List<CaptureEngine.Span> next=new ArrayList<>();for(CaptureEngine.Span span:f.spans){if(span.offset<=n)first=span.time;else next.add(new CaptureEngine.Span(span.offset-n,span.time));}f.spans.clear();f.spans.add(new CaptureEngine.Span(0,first));f.spans.addAll(next);f.contiguous=Arrays.copyOfRange(f.contiguous,n,f.contiguous.length);f.time=first;}
    public Selection selection(String id){State s=calls.get(id);if(s==null)return null;Selection out=new Selection(id,Math.max(0,s.call.startUs-2000000),s.ended>0?s.ended+2000000:Long.MAX_VALUE);out.tcp.addAll(s.tcp);for(Stream stream:streams.values())if(id.equals(stream.callId))out.rtp.add(stream.src+">"+stream.dst+"/"+stream.ssrc);return out;}
    public long pinEnd(String id,boolean caughtUp){State s=calls.get(id);return s!=null&&s.ended>0&&caughtUp?s.ended+2000000:Long.MAX_VALUE;}
    public long pinStart(String id){State s=calls.get(id);return s==null||!s.tcp.isEmpty()?0:Math.max(0,s.call.startUs-2000000);}
    public View view(){View v=new View();v.packets=packets;v.duplicateInterfaces=duplicateInterfaces;v.lastUs=lastUs;v.notice=String.join("；",notices);for(State state:calls.values()){Call c=state.call,z=new Call();z.id=c.id;z.from=c.from;z.to=c.to;z.status=c.status;z.startUs=c.startUs;z.lastUs=c.lastUs;z.endUs=c.endUs;z.requestTarget=c.requestTarget;z.sipCount=c.sipCount;z.signalingIps.addAll(c.signalingIps);z.mediaIps.addAll(c.mediaIps);v.calls.add(z);v.sources.put(c.id,new LinkedHashSet<>(state.sources));v.volumes.put(c.id,new LinkedHashSet<>(state.volumes));}for(Stream s:streams.values())v.streams.add(s.copy());v.messages.addAll(recent);for(DtmfParser.Event e:events.values()){DtmfParser.Event z=new DtmfParser.Event();z.src=e.src;z.dst=e.dst;z.callId=e.callId;z.key=e.key;z.type=e.type;z.firstSeenUs=e.firstSeenUs;z.lastSeenUs=e.lastSeenUs;z.durationTicks=e.durationTicks;z.durationKnown=e.durationKnown;z.clock=e.clock;z.packets=e.packets;z.ended=e.ended;v.events.add(z);}for(Tcp f:tcp.values())if(f.tls)v.connections.add(f.src+" → "+f.dst+" · TLS / WSS 未解密（快照后分别导入密钥）");return v;}
    private static void origin(State state,int device,int volume){if(device>=0&&state.sources.size()<256)state.sources.add(device);if(state.volumes.size()<256)state.volumes.add(volume);}
    private static String shortHeader(String value){return value.length()>512?value.substring(0,512):value;}
    private static String digest(String value){try{return Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}catch(java.security.NoSuchAlgorithmException e){throw new AssertionError(e);}}
    private static long uint(byte[] b,int p){return ((b[p]&255L)<<24)|((b[p+1]&255L)<<16)|((b[p+2]&255L)<<8)|(b[p+3]&255L);}
}
