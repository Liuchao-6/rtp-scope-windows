package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.swing.*;

/** Optional, local synthetic benchmark. Also runs against the previous packaged JAR. */
public final class LargeImportBenchmark {
    private static void le32(OutputStream out,long n)throws IOException{for(int i=0;i<4;i++)out.write((int)(n>>(i*8)));}
    private static void be16(byte[] b,int at,int n){b[at]=(byte)(n>>8);b[at+1]=(byte)n;}
    private static void be32(byte[] b,int at,long n){for(int i=0;i<4;i++)b[at+i]=(byte)(n>>(24-i*8));}
    private static byte[] udp(int src,int dst,boolean reverse,byte[] payload){byte[] b=new byte[28+payload.length];b[0]=0x45;be16(b,2,b.length);b[8]=64;b[9]=17;b[12]=(byte)(reverse?198:192);b[13]=(byte)(reverse?51:0);b[14]=(byte)(reverse?100:2);b[15]=(byte)(reverse?20:10);b[16]=(byte)(reverse?192:198);b[17]=(byte)(reverse?0:51);b[18]=(byte)(reverse?2:100);b[19]=(byte)(reverse?10:20);be16(b,20,src);be16(b,22,dst);be16(b,24,8+payload.length);System.arraycopy(payload,0,b,28,payload.length);return b;}
    private static void record(OutputStream out,byte[] b,long time)throws IOException{le32(out,1794272400L+time/1000000);le32(out,time%1000000);le32(out,b.length);le32(out,b.length);out.write(b);}
    private static byte[] sip(int index,boolean answer){int port=(answer?20000:10000)+index*4;String body="v=0\r\no=- 1 1 IN IP4 "+(answer?"198.51.100.20":"192.0.2.10")+"\r\ns=synthetic\r\nc=IN IP4 "+(answer?"198.51.100.20":"192.0.2.10")+"\r\nt=0 0\r\nm=audio "+port+" RTP/AVP 0\r\n";String message=(answer?"SIP/2.0 200 OK":"INVITE sip:"+(2000+index)+"@example.test SIP/2.0")+"\r\nVia: SIP/2.0/UDP 192.0.2.10;branch=z9hG4bK"+index+"\r\nFrom: <sip:"+(1000+index)+"@example.test>;tag=a"+index+"\r\nTo: <sip:"+(2000+index)+"@example.test>"+(answer?";tag=b"+index:"")+"\r\nCall-ID: benchmark-"+index+"@example.test\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: "+body.length()+"\r\n\r\n"+body;return udp(5060,5060,answer,message.getBytes(StandardCharsets.US_ASCII));}
    private static void create(File file)throws IOException{
        try(OutputStream out=new BufferedOutputStream(new FileOutputStream(file),262144)){
            le32(out,0xa1b2c3d4L);out.write(new byte[]{2,0,4,0});le32(out,0);le32(out,0);le32(out,65535);le32(out,101);
            for(int call=0;call<300;call++){record(out,sip(call,false),call*1000);record(out,sip(call,true),1000000+call*1000);}
            for(int call=0;call<300;call++)for(int direction=0;direction<2;direction++){
                byte[] rtp=new byte[172];rtp[0]=(byte)0x80;be32(rtp,8,1234+call*2+direction);Arrays.fill(rtp,12,rtp.length,(byte)0xff);
                byte[] packet=udp((direction==0?10000:20000)+call*4,(direction==0?20000:10000)+call*4,direction==1,rtp);
                for(int n=0;n<4860;n++){be16(packet,30,n);be32(packet,32,n*160L);record(out,packet,1020000+call*1000+n*20000L);}
            }
        }
        System.out.println("Created synthetic G.711 capture; bytes="+file.length()+"; calls=300; RTP=2916000");
    }
    public static void main(String[] args)throws Exception{
        File file=new File(args[1]);if(args[0].equals("create")){create(file);return;}
        DesktopApp[] holder={null};SwingUtilities.invokeAndWait(()->{Ui.setup();holder[0]=new DesktopApp();});DesktopApp app=holder[0];
        Method background;try{background=DesktopApp.class.getMethod("isBackgroundWorking");}catch(NoSuchMethodException old){background=null;}final Method backgroundMethod=background;
        long begin=System.nanoTime(),readyAt=0,mediaAt=0,filterMs=0;boolean measured=false;int calls=0;boolean[] running={true,true};
        try{
            SwingUtilities.invokeAndWait(()->app.load(file));
            while(System.nanoTime()-begin<300L*1000000000){
                SwingUtilities.invokeAndWait(()->{running[0]=app.isBusy();try{running[1]=backgroundMethod!=null&&(Boolean)backgroundMethod.invoke(app);}catch(Exception e){throw new RuntimeException(e);}});
                if(!running[0]&&!measured){readyAt=System.nanoTime();long before=System.nanoTime();final int[] count={0};SwingUtilities.invokeAndWait(()->{if(app.model.analysis==null)throw new AssertionError("import failed");CallSearch.Filter filter=new CallSearch.Filter();filter.caller="1001";app.setCallSearch(filter);count[0]=app.callCount();});filterMs=(System.nanoTime()-before)/1000000;calls=count[0];if(calls!=1)throw new AssertionError("target call not found");measured=true;}
                if(measured&&mediaAt==0&&backgroundMethod!=null){boolean[] pending={true};SwingUtilities.invokeAndWait(()->{try{pending[0]=(Boolean)DesktopApp.class.getMethod("isMediaPending").invoke(app);}catch(Exception e){throw new RuntimeException(e);}});if(!pending[0])mediaAt=System.nanoTime();}
                if(measured&&!running[0]&&!running[1])break;Thread.sleep(20);
            }
            if(!measured||running[0]||running[1])throw new AssertionError("benchmark timed out");
            String result=String.format(Locale.ROOT,"version=%s; bytes=%d; call_list=%.3fs; media_ready=%.3fs; all_done=%.3fs; call_filter=%dms; matches=%d%n",DesktopApp.class.getField("VERSION").get(null),file.length(),(readyAt-begin)/1e9,((mediaAt==0?readyAt:mediaAt)-begin)/1e9,(System.nanoTime()-begin)/1e9,filterMs,calls);System.out.print(result);
            if(args.length>2)java.nio.file.Files.write(new File(args[2]).toPath(),result.getBytes(StandardCharsets.UTF_8));
        }finally{SwingUtilities.invokeAndWait(app::shutdown);}
    }
}
