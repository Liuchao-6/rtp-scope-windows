import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/** Packet import, independent tones, negative signals and media-time navigation. */
public final class KeyModesTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static Analysis read(File fixtures,String name)throws IOException{try(InputStream in=new FileInputStream(new File(fixtures,name))){return CaptureEngine.read(in);}}
    public static int run(File fixtures)throws Exception {
        Analysis a=read(fixtures,"key-modes.pcap");List<DtmfParser.Event> inband=new ArrayList<>(),info=new ArrayList<>(),rtp=new ArrayList<>();
        for(DtmfParser.Event e:a.events)(e.type==DtmfParser.Type.IN_BAND?inband:e.type==DtmfParser.Type.SIP_INFO?info:rtp).add(e);
        check(inband.size()==32,"16 independent G.711 keys in each direction: "+describe(inband));
        String keys="123A456B789C*0#D";
        for(int direction=0;direction<2;direction++){
            List<DtmfParser.Event> events=new ArrayList<>();for(DtmfParser.Event e:inband)if(e.ssrc==1234+direction)events.add(e);
            check(events.size()==16,"all keys retain independent SSRC direction");
            for(int i=0;i<16;i++){DtmfParser.Event e=events.get(i);check(e.key.equals(""+keys.charAt(direction==0?i:15-i)),"key value "+direction+"/"+i);check(e.durationMs()>=80&&e.durationMs()<=120,"100 ms tone duration tolerance");check(e.ended&&Double.isFinite(e.levelDbfs),"observed tone end and measured level");check(e.detailText().contains("dBFS")&&!e.detailText().contains("dBm0"),"inband uses PCM amplitude unit");}
        }
        check(info.size()==4,"INFO valid requests only, retransmissions merged");check(rtp.size()==1,"RFC event retained alongside INFO and inband");
        DtmfParser.Event five=info.get(0);check(five.key.equals("5")&&five.packets==2&&five.durationMs()==160,"INFO retransmission count and duration");
        check(five.audioSrc.equals("10.0.0.1:40000")&&five.audioDst.equals("10.0.0.2:50000"),"INFO SDP audio direction resolved");
        check(five.detailText().contains(five.signaling.raw)&&five.detailText().contains("2 INFO"),"INFO exact signaling body retained");
        check(info.get(1).key.equals("#")&&!info.get(1).durationKnown&&info.get(1).durationText().equals("未知"),"bare DTMF INFO unknown duration");
        check(info.get(1).audioSrc.equals("10.0.0.2:50000"),"reverse INFO maps to reverse waveform");check(info.get(2).key.equals("*")&&info.get(3).key.equals("D"),"numeric star and named D");
        check(a.warnings.containsKey("SIP INFO 按键内容或持续时间无效"),"invalid INFO input is explained");
        for(DtmfParser.Event e:a.events)check(e.searchable().contains(e.typeLabel()),"key type searchable");
        check(read(fixtures,"inband-negative.pcap").events.isEmpty(),"single tones, dialtone, noise, frequency error, short burst rejected");
        check(read(fixtures,"g729.pcap").events.isEmpty(),"independent G729 speech reference has no false key");
        RtpStream s=toneStream(false,100,160,100);Analysis direct=new Analysis();direct.streams.add(s);KeyAnalysis.attach(direct);
        check(direct.events.size()==1&&direct.events.get(0).key.equals("5"),"direct G711 tone detected");
        s=toneStream(true,100,240,120);direct=new Analysis();direct.streams.add(s);KeyAnalysis.attach(direct);
        check(direct.events.size()==1&&direct.events.get(0).key.equals("5"),"G729 encoded dual tone survives decode: "+describe(direct.events));
        s=toneStream(false,100,40,0);direct=new Analysis();direct.streams.add(s);KeyAnalysis.attach(direct);check(direct.events.size()==1&&!direct.events.get(0).ended,"40ms tone at EOF preserves incomplete observation");
        s=toneStream(false,0,60,0);s.packets.remove(1);direct=new Analysis();direct.streams.add(s);KeyAnalysis.attach(direct);check(direct.events.isEmpty(),"two 20ms fragments are not joined across packet loss");
        long[] exhausted={0};Analysis limited=new Analysis();check(InbandDtmf.detect(Collections.singletonList(toneStream(false,100,100,100)),limited,exhausted).isEmpty()&&!limited.warnings.isEmpty(),"scan budget reports partial coverage");
        // Two equally plausible transport paths must not paint INFO onto an arbitrary waveform.
        Analysis ambiguous=new Analysis();ambiguous.sip.add(five.signaling);RtpStream original=a.streams.stream().filter(v->v.playable()&&v.src.equals(five.audioSrc)).findFirst().get();ambiguous.streams.add(original);RtpStream other=new RtpStream();other.codec="PCMU";other.srcIp=original.srcIp;other.dstIp=original.dstIp;other.src=original.srcIp+":41000";other.dst=original.dst;other.callId=original.callId;ambiguous.streams.add(other);
        check(SipInfoDtmf.parse(ambiguous).get(0).audioSrc.isEmpty(),"ambiguous INFO direction remains unassigned");
        SipMessage relayed=new SipMessage();relayed.src="192.0.2.8:5060";relayed.dst="192.0.2.9:5060";relayed.firstLine=five.signaling.firstLine;relayed.headers.putAll(five.signaling.headers);relayed.callId=five.callId;relayed.cseq="10 INFO";relayed.body="Signal=5\r\nDuration=80\r\n";relayed.raw=relayed.firstLine;relayed.timeUs=five.firstSeenUs;
        SipMessage offer=new SipMessage();offer.src=relayed.src;offer.callId=five.callId;offer.headers.put("content-type","application/sdp");offer.body="v=0\r\nc=IN IP4 198.51.100.1\r\nm=video 30000 RTP/AVP 96\r\nc=IN IP4 198.51.100.2\r\nm=audio 40000 RTP/AVP 0\r\nc=IN IP4 10.0.0.1\r\n";offer.firstLine="INVITE sip:a SIP/2.0";offer.timeUs=relayed.timeUs-1000;
        Analysis mediaSdp=new Analysis();mediaSdp.sip.add(offer);mediaSdp.sip.add(relayed);mediaSdp.streams.add(original);mediaSdp.streams.add(other);check(SipInfoDtmf.parse(mediaSdp).get(0).audioSrc.equals(original.src),"media-level SDP connection overrides video/session address");
        RtpStream repeated=toneStream(false,100,100,100);int size=repeated.packets.size();List<RtpPacket> copy=new ArrayList<>(repeated.packets);for(RtpPacket p:copy){RtpPacket q=new RtpPacket();q.payload=p.payload;q.timestamp=p.timestamp+size*160;q.timeUs=p.timeUs+size*20000;q.sequence=p.sequence+size;repeated.packets.add(q);}direct=new Analysis();direct.streams.add(repeated);KeyAnalysis.attach(direct);check(direct.events.size()==2,"same digit separated by silence remains two presses");
        repeated.encrypted=true;direct=new Analysis();direct.streams.add(repeated);KeyAnalysis.attach(direct);check(direct.events.isEmpty(),"encrypted audio excluded from tone analysis");
        WaveformViewport window=new WaveformViewport();window.reset(137000);window.zoomAt(4,0.25);check(window.zoom()==4&&Math.abs(window.timeAt(0.25)-34250)<0.001,"zoom preserves anchor time");
        window.pan(1e9);check(window.endMs()==137000,"pan clamps at end");window.pan(-1e9);check(window.startMs()==0,"pan clamps at start");window.zoomAt(1000,0.5);check(window.zoom()==64,"zoom cap");window.reveal(100000);check(window.contains(100000),"event selection reveals offscreen time");check(window.timeAt(-1)==window.startMs()&&window.timeAt(2)==window.endMs(),"hit testing clamps to visible interval");window.fit();check(window.zoom()==1&&window.startMs()==0,"fit restores full call");
        return checks;
    }
    private static String describe(List<DtmfParser.Event> events){StringBuilder s=new StringBuilder();for(DtmfParser.Event e:events)s.append(e.key).append('@').append(e.ssrc).append('/').append(e.durationMs()).append(' ');return s.toString();}
    private static RtpStream toneStream(boolean g729,int beforeMs,int toneMs,int afterMs)throws Exception{
        RtpStream stream=new RtpStream();stream.codec=g729?"G729":"PCMU";stream.clockKnown=true;stream.src="a:1";stream.dst="b:2";stream.srcIp="a";stream.dstIp="b";stream.ssrc=77;int count=(beforeMs+toneMs+afterMs)*8;
        Object coder=null;Method process=null;if(g729){Class<?> cls=Class.forName("org.jitsi.impl.neomedia.codec.audio.g729.Coder");Constructor<?> c=cls.getDeclaredConstructor();c.setAccessible(true);coder=c.newInstance();process=cls.getDeclaredMethod("process",short[].class,short[].class);process.setAccessible(true);}
        for(int at=0;at<count;at+=160){RtpPacket p=new RtpPacket();p.timestamp=at;p.sequence=at/160;p.timeUs=1000000+at*125L;p.payload=new byte[g729?20:160];
            for(int frame=0;frame<2;frame++){short[] pcm=new short[80];for(int i=0;i<80;i++){int sample=at+frame*80+i;double t=sample/8000.0;pcm[i]=(short)(sample>=beforeMs*8&&sample<(beforeMs+toneMs)*8?5000*(Math.sin(2*Math.PI*770*t)+Math.sin(2*Math.PI*1336*t)):0);if(!g729)p.payload[frame*80+i]=ulaw(pcm[i]);}
                if(g729){short[] serial=new short[82];process.invoke(coder,pcm,serial);for(int i=0;i<80;i++)if(serial[i+2]==0x81)p.payload[frame*10+i/8]|=(byte)(1<<(7-i%8));}}
            stream.packets.add(p);
        }return stream;
    }
    private static byte ulaw(int value){int sign=value<0?0x80:0;if(value<0)value=-value;value=Math.min(32635,value)+0x84;int exponent=7;for(int mask=0x4000;exponent>0&&(value&mask)==0;exponent--,mask>>=1){}return (byte)~(sign|(exponent<<4)|((value>>(exponent+3))&15));}
}
