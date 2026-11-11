package com.liuchao.rtpscope.desktop;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** File validation for captures, including interrupted PCAPNG tails. */
public final class CaptureSession {
    /** Validate the new capture's signature without changing bytes; the parser recovers partial tails. */
    public static long finishFile(File file) throws IOException {
        if(!file.isFile())throw new IOException("没有生成抓包文件，请检查 Npcap 及权限");
        try(RandomAccessFile in=new RandomAccessFile(file,"r")) {
            if(in.length()<4)throw new IOException("抓包文件头未写完");
            byte[] magic=new byte[4];in.readFully(magic);
            if(u32(magic,0,true)!=0x0a0d0d0aL)throw new IOException("抓包文件不是 PCAPNG");
            return 0;
        }
    }
    private static long u32(byte[] b,int offset,boolean little){long value=0;for(int i=0;i<4;i++)value|=(b[offset+i]&255L)<<(8*(little?i:3-i));return value;}
}
