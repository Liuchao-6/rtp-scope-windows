package com.liuchao.rtpscope.core;
import java.io.*;
import java.util.*;

/** RFC 4867 octet-aligned and bandwidth-efficient payloads, converted to AMR storage frames. */
public final class AmrPayload {
    private static final int[] NB={95,103,118,134,148,159,204,244,39,-1,-1,-1,-1,-1,-1,0};
    private static final int[] WB={132,177,253,285,317,365,397,461,477,40,-1,-1,-1,-1,0,0};
    private static final class Bits {final byte[] data;int at;Bits(byte[] p){data=p;}int get(int n)throws IOException{if(at+n>data.length*8)throw new IOException("AMR 负载不完整");int v=0;while(n-->0){v=(v<<1)|((data[at/8]>>(7-at%8))&1);at++;}return v;}void align(){at=(at+7)&~7;}}
    public static List<byte[]> frames(byte[] payload,boolean wide,boolean aligned)throws IOException{
        Bits bits=new Bits(payload);bits.get(4);if(aligned)bits.get(4);List<Integer> toc=new ArrayList<>();boolean more;
        do{more=bits.get(1)!=0;int ft=bits.get(4),quality=bits.get(1);if(aligned)bits.get(2);if((wide?WB:NB)[ft]<0)throw new IOException("AMR 帧类型不支持");toc.add((ft<<3)|(quality<<2));if(toc.size()>50)throw new IOException("AMR 聚合帧过多");}while(more);
        List<byte[]> out=new ArrayList<>();for(int header:toc){int count=(wide?WB:NB)[header>>3];byte[] frame=new byte[1+(count+7)/8];frame[0]=(byte)header;for(int n=0;n<count;n++)frame[1+n/8]|=bits.get(1)<<(7-n%8);if(aligned)bits.align();out.add(frame);}return out;
    }
    public static boolean aligned(String fmtp){return fmtp.toLowerCase(Locale.ROOT).matches("(?s).*(?:^|[; ])octet-align\\s*=\\s*1(?:[; ]|$).*");}
    public static boolean supported(String fmtp){String p=fmtp.toLowerCase(Locale.ROOT);return !p.matches("(?s).*(?:crc|robust-sorting)\\s*=\\s*1.*")&&!p.contains("interleaving=");}
}
