package com.liuchao.rtpscope.core;
import java.io.*;
import java.util.Arrays;

/** Streaming PCM WAV reader and resampler; no recording-size arrays. */
public final class PcmFile implements Closeable {
    private final RandomAccessFile input;
    public final int rate,channels,bits,format;
    public final long offset,frames;
    public PcmFile(File file)throws IOException{
        input=new RandomAccessFile(file,"r");int r=0,c=0,b=0,f=0;long data=-1,size=0;
        try{
            if(!read4(input).equals("RIFF")){throw new IOException("需要 WAV 音频");}le(input,4);if(!read4(input).equals("WAVE"))throw new IOException("不是 WAV 音频");
            while(input.getFilePointer()+8<=input.length()){
                String kind=read4(input);long n=le(input,4),at=input.getFilePointer();if(n>input.length()-at)throw new IOException("录音文件不完整");
                if(kind.equals("fmt ")&&n>=16){f=(int)le(input,2);c=(int)le(input,2);r=(int)le(input,4);le(input,4);le(input,2);b=(int)le(input,2);
                    if(f==0xfffe){if(n<40||le(input,2)<22)throw new IOException("WAV 扩展格式不完整");int valid=(int)le(input,2);le(input,4);byte[] guid=new byte[16];input.readFully(guid);int sub=guid[0]&255;if((sub!=1&&sub!=3)||!Arrays.equals(guid,guid(sub))||valid!=0&&valid!=b)throw new IOException("不支持此 WAV 扩展编码");f=sub;}
                }
                else if(kind.equals("data")){data=at;size=n;}
                input.seek(at+n+(n&1));
            }
            if(data<0||r<1000||r>384000||c<1||c>64||!((f==1&&(b==8||b==16||b==24||b==32))||(f==3&&b==32))||size%(c*(b/8))!=0)throw new IOException("支持 1～64 声道 PCM 或浮点 WAV；其他录音请经音频解码器导入");
            rate=r;channels=c;bits=b;format=f;offset=data;frames=size/(c*(b/8));
        }catch(IOException|RuntimeException e){input.close();throw e;}
    }
    public double durationMs(){return frames*1000.0/rate;}
    public float[] read(long startMs,int lengthMs,int channel,int outputRate)throws IOException{
        return readFrames(Math.max(0,startMs*rate/1000),(int)Math.min(Integer.MAX_VALUE,(long)lengthMs*rate/1000),channel,outputRate);
    }
    public float[] readFrames(long first,int requested,int channel,int outputRate)throws IOException{
        if(channel>=channels)throw new IOException("声道不存在");
        if(first<0||requested<0||outputRate<1000||outputRate>384000)throw new IOException("音频读取参数无效");
        long count=Math.min(frames-first,requested);
        if(count<=0)return new float[0];int bytes=bits/8;
        if(count*channels*bytes>32*1024*1024)throw new IOException("音频读取片段过长");
        byte[] raw=new byte[(int)count*channels*bytes];input.seek(offset+first*channels*bytes);input.readFully(raw);
        float[] pcm=new float[(int)(count*outputRate/rate)];
        for(int i=0;i<pcm.length;i++){
            double source=i*(double)rate/outputRate;int a=(int)source,n=(int)Math.min(count-1,a+1);double blend=source-a;
            float x=value(raw,a,channel),y=value(raw,n,channel);pcm[i]=(float)(x*(1-blend)+y*blend);
        }return pcm;
    }
    private float value(byte[] raw,int frame,int channel){
        if(channel<0){float sum=0;for(int c=0;c<channels;c++)sum+=value(raw,frame,c);return sum/channels;}
        int bytes=bits/8,at=(frame*channels+channel)*bytes;long n=0;for(int i=0;i<bytes;i++)n|=(raw[at+i]&255L)<<(i*8);
        if(format==3){float x=Float.intBitsToFloat((int)n);return Float.isFinite(x)?Math.max(-1,Math.min(1,x)):0;}
        if(bits==8)return ((int)n-128)/128f;
        long signed=(n<<(64-bits))>>(64-bits);return (float)(signed/Math.pow(2,bits-1));
    }
    public void close()throws IOException{input.close();}
    static String read4(RandomAccessFile in)throws IOException{byte[] b=new byte[4];in.readFully(b);return new String(b,"US-ASCII");}
    static long le(RandomAccessFile in,int n)throws IOException{long v=0;for(int i=0;i<n;i++){int b=in.read();if(b<0)throw new EOFException();v|=(long)b<<(8*i);}return v;}
    public static void write(File file,float[] pcm,int rate)throws IOException{try(RandomAccessFile out=new RandomAccessFile(file,"rw")){out.setLength(0);header(out,pcm.length,rate,1);for(float f:pcm){int v=Math.round(Math.max(-1,Math.min(1,f))*32767);out.write(v);out.write(v>>8);}}}
    public static String channelName(int count,int channel){return count==1?"单声道":count==2?(channel==0?"左声道":"右声道"):"声道 "+(channel+1);}
    private static byte[] guid(int format){return new byte[]{(byte)format,0,0,0,0,0,0x10,0,(byte)0x80,0,0,(byte)0xaa,0,0x38,(byte)0x9b,0x71};}
    public static void header(RandomAccessFile out,long frames,int rate,int channels)throws IOException{
        boolean extended=channels>2;int extra=extended?24:0;
        if(channels<1||channels>64||frames<0||rate<1000||rate>384000||frames>(0xffffffffL-36-extra)/(channels*2))throw new IOException("WAV 声道数、采样率或大小超出支持范围");
        out.writeBytes("RIFF");writeLe(out,36+extra+frames*channels*2,4);out.writeBytes("WAVEfmt ");writeLe(out,16+extra,4);writeLe(out,extended?0xfffe:1,2);writeLe(out,channels,2);writeLe(out,rate,4);writeLe(out,rate*channels*2,4);writeLe(out,channels*2,2);writeLe(out,16,2);
        // These channels represent media directions, so no physical speaker layout is assigned.
        if(extended){writeLe(out,22,2);writeLe(out,16,2);writeLe(out,0,4);out.write(guid(1));}
        out.writeBytes("data");writeLe(out,frames*channels*2,4);
    }
    public static void writeLe(RandomAccessFile out,long n,int size)throws IOException{for(int i=0;i<size;i++)out.write((int)(n>>>(8*i)));}
}
