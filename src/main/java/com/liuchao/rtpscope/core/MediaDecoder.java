package com.liuchao.rtpscope.core;

import java.io.*;
import java.util.*;
import com.liuchao.rtpscope.core.CaptureEngine.RtpStream;
import org.concentus.*;
import org.jitsi.impl.neomedia.codec.audio.g729.G729Codec;

/** Per-direction codec state. Stereo Opus is downmixed to the app's mono direction track. */
final class MediaDecoder implements Closeable {
    private final RtpStream stream;private final int rate;private final G729Codec g729;private final OpusDecoder opus;
    private final G722Decoder g722;
    private File amrFile;private InputStream amrInput;
    MediaDecoder(RtpStream stream,int rate)throws IOException {
        this.stream=stream;this.rate=rate;g729=stream.codec.startsWith("G729")?new G729Codec():null;g722=stream.codec.equals("G722")?new G722Decoder():null;
        try{opus=stream.codec.equals("OPUS")?new OpusDecoder(rate,1):null;}catch(OpusException e){throw new IOException("无法初始化 Opus 解码器",e);}
        if(CodecSupport.amr(stream)){amrFile=CodecSupport.decode(stream,rate);amrInput=new BufferedInputStream(new FileInputStream(amrFile));}
    }
    short[] decode(byte[] payload)throws IOException {
        if(amrInput!=null){int count=AudioRenderer.sampleCount(stream,payload)*rate/stream.clock;short[] out=new short[count];for(int i=0;i<count;i++){int a=amrInput.read(),b=amrInput.read();if(a<0||b<0)throw new IOException("AMR 解码输出不完整");out[i]=(short)(a|(b<<8));}return out;}
        if(g722!=null){short[] source=g722.decode(payload);if(rate==16000)return source;short[] pcm=new short[source.length*rate/16000];for(int n=0;n<pcm.length;n++)pcm[n]=source[Math.min(source.length-1,(int)(n*16000L/rate))];return pcm;}
        if(opus!=null){
            try{int frames=OpusPacketInfo.getNumSamples(payload,0,payload.length,rate);if(frames<=0||frames>rate*120/1000)throw new IOException("Opus 包长度或帧时长无效");short[] pcm=new short[frames];int actual=opus.decode(payload,0,payload.length,pcm,0,frames,false);return actual==frames?pcm:Arrays.copyOf(pcm,actual);}
            catch(OpusException|IllegalArgumentException|IndexOutOfBoundsException e){throw new IOException("Opus 包无法解码",e);}
        }
        short[] pcm;if(g729!=null)pcm=g729.decode(payload);else{pcm=new short[payload.length];for(int n=0;n<pcm.length;n++)pcm[n]=(short)AudioRenderer.decode(payload[n]&255,stream.codec.equals("PCMA"));}
        if(rate==8000)return pcm;
        short[] expanded=new short[pcm.length*(rate/8000)];int factor=rate/8000;
        for(int n=0;n<expanded.length;n++){int index=n/factor,next=Math.min(pcm.length-1,index+1),fraction=n%factor;expanded[n]=(short)((pcm[index]*(factor-fraction)+pcm[next]*fraction)/factor);}return expanded;
    }
    void gap(long samples)throws IOException {
        if(g729!=null)g729.advanceLoss((int)Math.min(101,samples*8000/rate/80));
        if(opus!=null){if(samples>rate*2L){opus.resetState();return;}int frame=rate/50;short[] discard=new short[frame];try{while(samples>=frame){opus.decode(null,0,0,discard,0,frame,false);samples-=frame;}}catch(OpusException|RuntimeException e){opus.resetState();}}
    }
    public void close()throws IOException{if(amrInput!=null)amrInput.close();if(amrFile!=null)amrFile.delete();}
}
