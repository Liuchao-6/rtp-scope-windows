import com.liuchao.rtpscope.core.*;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.text.*;
import java.util.*;

public final class CallSearchTest {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static long at(String value)throws Exception{return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS",Locale.ROOT).parse(value).getTime()*1000;}
    private static Call call(String id,String caller,String callee,String from,String to)throws Exception{Call c=new Call();c.id=id;c.from="<sip:"+caller+"@example.test>;tag=a";c.to="<tel:"+callee+">";c.startUs=at(from);c.lastUs=at(to);return c;}
    private static void le32(OutputStream out,long value)throws IOException{for(int n=0;n<4;n++)out.write((int)(value>>(n*8)));}
    private static void be16(byte[] b,int at,int value){b[at]=(byte)(value>>8);b[at+1]=(byte)value;}
    private static Analysis manyCalls()throws Exception{
        ByteArrayOutputStream out=new ByteArrayOutputStream();out.write(new byte[]{(byte)0xd4,(byte)0xc3,(byte)0xb2,(byte)0xa1,2,0,4,0});le32(out,0);le32(out,0);le32(out,65535);le32(out,101);
        for(int n=0;n<60;n++){
            String text="INVITE sip:"+(2000+n)+"@example.test SIP/2.0\r\nFrom: <sip:"+(1000+n)+"@example.test>;tag=a\r\nTo: <sip:"+(2000+n)+"@example.test>\r\nCall-ID: synthetic-call-"+n+"\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
            byte[] sip=text.getBytes("UTF-8"),packet=new byte[28+sip.length];packet[0]=0x45;be16(packet,2,packet.length);packet[8]=64;packet[9]=17;packet[12]=10;packet[15]=(byte)(n+1);packet[16]=10;packet[17]=10;packet[19]=1;be16(packet,20,5060);be16(packet,22,5060);be16(packet,24,8+sip.length);System.arraycopy(sip,0,packet,28,sip.length);
            le32(out,at("2026-11-05 14:00:00.000")/1000000+n*60);le32(out,0);le32(out,packet.length);le32(out,packet.length);out.write(packet);
        }
        return CaptureEngine.read(new ByteArrayInputStream(out.toByteArray()));
    }
    public static int run(File fixtures)throws Exception{
        TimeZone previous=TimeZone.getDefault();TimeZone.setDefault(TimeZone.getTimeZone("Asia/Shanghai"));
        try{
            Call one=call("first", "+8613800123456","10086","2026-11-05 14:00:00.100","2026-11-05 14:02:00.000");one.signalingIps.add("10.10.1.2");one.mediaIps.add("172.20.1.8");
            Call two=call("midnight","2001","2002","2026-11-05 23:59:40.000","2026-11-06 00:01:30.000");two.signalingIps.add("2001:db8:0:0:0:0:0:1");
            Call three=call("third","10086","3000","2026-11-06 14:00:00.000","2026-11-06 14:05:00.000");three.requestTarget="sip:95588@routing.test";
            List<Call> calls=Arrays.asList(one,two,three);CallSearch.Filter f=new CallSearch.Filter();
            check(CallSearch.find(calls,f).size()==3,"empty search returns all calls");
            f.caller="123456";f.callee="10086";f.ip="172.20";check(CallSearch.find(calls,f).equals(Collections.singletonList(one)),"caller, callee and media IP combine with AND");
            f.caller="10086";check(CallSearch.find(calls,f).isEmpty(),"caller and callee directions remain distinct");
            f=new CallSearch.Filter();f.callee="95588";check(CallSearch.find(calls,f).equals(Collections.singletonList(three)),"request URI destination is searchable");
            f=new CallSearch.Filter();f.ip="[2001:db8::1]";check(CallSearch.find(calls,f).equals(Collections.singletonList(two)),"compressed IPv6 filter matches expanded capture address");
            f=new CallSearch.Filter();f.keyword="138001";check(CallSearch.find(calls,f).size()==1,"quick number lookup");f.keyword="MIDNIGHT";check(CallSearch.find(calls,f).get(0)==two,"Call-ID lookup is case insensitive");
            f=new CallSearch.Filter();f.start="14:01:00";f.end="14:01:30";check(CallSearch.find(calls,f).size()==2,"time range matches calls already in progress on either day");
            f.start="2026-11-05 14:01:00";f.end="2026-11-05 14:01:30";check(CallSearch.find(calls,f).equals(Collections.singletonList(one)),"date restricts clock range to requested day");
            f.start="23:59:50";f.end="00:00:10";check(CallSearch.find(calls,f).equals(Collections.singletonList(two)),"clock range spans midnight");
            f.start="00:01:00";f.end="00:02:00";check(CallSearch.find(calls,f).equals(Collections.singletonList(two)),"call started previous day overlaps early-morning range");
            f.start="2026-11-05 14:00:00.100";f.end=f.start;check(CallSearch.find(calls,f).equals(Collections.singletonList(one)),"millisecond endpoints are inclusive");
            f.start="2026-11-05 14:00:00.099";f.end=f.start;check(CallSearch.find(calls,f).isEmpty(),"submillisecond ordering is not rounded to a full second");
            for(String bad:new String[]{"25:00","14:61:00","2026-02-30 10:00:00","wrong","14:00:00 junk"}){f.start=bad;f.end="";try{CallSearch.find(calls,f);throw new AssertionError("invalid time accepted");}catch(IllegalArgumentException expected){checks++;}}
            f.start="14:00";f.end="2026-11-05 14:01";try{CallSearch.find(calls,f);throw new AssertionError("mixed date/clock accepted");}catch(IllegalArgumentException expected){checks++;}
            f.start="2026-11-06 14:00";f.end="2026-11-05 14:00";try{CallSearch.find(calls,f);throw new AssertionError("reversed absolute dates accepted");}catch(IllegalArgumentException expected){checks++;}
            check(CallSearch.number("\"Example\" <sips:%2B86138@example.test>;tag=5").equals("+86138"),"escaped SIP number preserves plus sign");
            CallSearch.Filter copy=f.copy();copy.caller="changed";check(f.caller.isEmpty(),"filter copies are independent");
            CaptureWorkspace<String> workspace=new CaptureWorkspace<>();workspace.add("a","a",null);workspace.add("b","b",null);workspace.select(0);workspace.current().callSearch.caller="138";workspace.select(1);check(workspace.current().callSearch.empty(),"each capture starts with independent call search");workspace.select(0);check(workspace.current().callSearch.caller.equals("138"),"capture search restored after switching");
            Analysis demo;try(InputStream in=new FileInputStream(new File(fixtures,"demo-analysis.pcap"))){demo=CaptureEngine.read(in);}
            Call c=demo.calls.get(0);check(CallSearch.participants(c).equals("1001 → 1002"),"real parser populates caller and callee from INVITE");
            check(c.signalingIps.contains("10.0.0.1")&&c.mediaIps.contains("10.0.0.2"),"real parser indexes signal and media IPs");
            check(c.lastUs>c.startUs&&c.requestTarget.contains("1002"),"real parser retains observed interval and request destination");
            f=new CallSearch.Filter();f.ip="10.0.0.2";check(CallSearch.find(demo.calls,f).size()==1,"real capture can be located by IP");
            Analysis many=manyCalls();check(many.calls.size()==60,"one tcpdump-style capture retains 60 distinct Call-IDs");f=new CallSearch.Filter();f.caller="1037";f.callee="2037";f.ip="10.0.0.38";f.start="14:36:59";f.end="14:37:01";List<Call> found=CallSearch.find(many.calls,f);check(found.size()==1&&found.get(0).id.equals("synthetic-call-37"),"combined caller/callee/time/IP selects exact call among 60");
        }finally{TimeZone.setDefault(previous);}
        return checks;
    }
}
