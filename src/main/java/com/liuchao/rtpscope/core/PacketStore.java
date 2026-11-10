package com.liuchao.rtpscope.core;

import com.liuchao.rtpscope.core.CaptureEngine.RtpPacket;
import java.io.*;
import java.util.*;

/** Disk-backed packet metadata and payloads; only per-stream offsets stay in memory. */
public final class PacketStore implements Closeable {
    private final File file;
    private DataOutputStream writer;
    private RandomAccessFile reader;
    private long position,cacheAt=-1;
    private final byte[] cache=new byte[262144];
    private int cached;
    private boolean closed;
    private boolean ownerClosed;
    private int leases;
    PacketStore(File directory)throws IOException{
        file=File.createTempFile("chaoge-huatan-media-",".cache",directory);file.deleteOnExit();
        try{writer=new DataOutputStream(new BufferedOutputStream(new FileOutputStream(file),262144));}catch(IOException e){file.delete();throw e;}
    }
    long append(long time,long timestamp,int sequence,boolean marker,byte[] payload,int from,int end)throws IOException{
        long at=position;writer.writeLong(time);writer.writeLong(timestamp);writer.writeInt(sequence);writer.writeBoolean(marker);writer.writeInt(end-from);writer.write(payload,from,end-from);position+=25L+end-from;return at;
    }
    void seal()throws IOException{writer.close();writer=null;reader=new RandomAccessFile(file,"r");}
    synchronized byte[] bytes(long offset,int length)throws IOException{
        if(closed||reader==null)throw new IOException("媒体缓存已关闭，请重新导入抓包");
        if(offset<cacheAt||offset+length>cacheAt+cached){reader.seek(offset);cacheAt=offset;cached=reader.read(cache);}
        if(length<=cached){return Arrays.copyOfRange(cache,(int)(offset-cacheAt),(int)(offset-cacheAt)+length);}
        byte[] out=new byte[length];reader.seek(offset);reader.readFully(out);return out;
    }
    private static long longAt(byte[] data,int at){long v=0;for(int i=0;i<8;i++)v=(v<<8)|(data[at+i]&255L);return v;}
    RtpPacket packet(long offset){
        try{byte[] h=bytes(offset,25);RtpPacket p=new RtpPacket();p.timeUs=longAt(h,0);p.timestamp=longAt(h,8);p.sequence=((h[16]&255)<<24)|((h[17]&255)<<16)|((h[18]&255)<<8)|(h[19]&255);p.marker=h[20]!=0;p.storedLength=((h[21]&255)<<24)|((h[22]&255)<<16)|((h[23]&255)<<8)|(h[24]&255);p.store=this;p.payloadOffset=offset+25;return p;}catch(IOException e){throw new UncheckedIOException(e);}
    }
    public File file(){return file;}
    public synchronized Closeable retain()throws IOException{
        if(ownerClosed||closed)throw new IOException("媒体缓存已关闭");leases++;
        return new Closeable(){private boolean released;public void close()throws IOException{synchronized(PacketStore.this){if(released)return;released=true;if(--leases==0&&ownerClosed)dispose();}}};
    }
    public synchronized void close()throws IOException{if(ownerClosed)return;ownerClosed=true;if(leases==0)dispose();}
    private void dispose()throws IOException{if(closed)return;closed=true;try{if(writer!=null)writer.close();if(reader!=null)reader.close();}finally{if(!file.delete())file.deleteOnExit();}}
    static final class Packets extends AbstractList<RtpPacket> implements RandomAccess {
        final PacketStore store;long[] offsets=new long[64];int count;long last=Long.MIN_VALUE;boolean sorted=true;
        Packets(PacketStore store){this.store=store;}
        void append(long offset,long time){if(count==offsets.length)offsets=Arrays.copyOf(offsets,count*2);offsets[count++]=offset;if(time<last)sorted=false;last=time;}
        public int size(){return count;}
        public RtpPacket get(int i){if(i<0||i>=count)throw new IndexOutOfBoundsException();return store.packet(offsets[i]);}
        void sortByTime(){if(sorted)return;long[] times=new long[count];for(int i=0;i<count;i++)times[i]=get(i).timeUs;sort(times,0,count-1);sorted=true;}
        private void sort(long[] times,int lo,int hi){
            int i=lo,j=hi;long pivot=times[(lo+hi)>>>1],tie=offsets[(lo+hi)>>>1];
            while(i<=j){while(times[i]<pivot||(times[i]==pivot&&offsets[i]<tie))i++;while(times[j]>pivot||(times[j]==pivot&&offsets[j]>tie))j--;if(i<=j){long t=times[i];times[i]=times[j];times[j]=t;t=offsets[i];offsets[i]=offsets[j];offsets[j]=t;i++;j--;}}
            if(lo<j)sort(times,lo,j);if(i<hi)sort(times,i,hi);
        }
    }
}
