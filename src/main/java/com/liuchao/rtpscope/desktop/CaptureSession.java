package com.liuchao.rtpscope.desktop;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Optional integration with a user-installed tshark/Npcap, only manages the process it starts. */
public final class CaptureSession {
    private Process process;
    public static File findTshark() {
        for(String root:new String[]{System.getenv("ProgramFiles"),System.getenv("ProgramFiles(x86)")})if(root!=null){File p=new File(root,"Wireshark/tshark.exe");if(p.isFile())return p;}
        String path=System.getenv("PATH");if(path!=null)for(String dir:path.split(File.pathSeparator)){File p=new File(dir,"tshark.exe");if(p.isFile())return p;}return null;
    }
    public static List<String> listInterfaces(File tshark) throws Exception {
        File log=File.createTempFile("chaoge-huatan-interfaces-",".txt");
        try {
            Process p=new ProcessBuilder(tshark.getAbsolutePath(),"-D").redirectErrorStream(true).redirectOutput(log).start();
            if(!p.waitFor(15,TimeUnit.SECONDS)){p.destroyForcibly();p.waitFor(5,TimeUnit.SECONDS);throw new IOException("读取网卡超时，请检查 Npcap");}
            List<String> out=java.nio.file.Files.readAllLines(log.toPath(),StandardCharsets.UTF_8);if(p.exitValue()!=0)throw new IOException(String.join("\n",out));
            out.removeIf(s->!s.matches("^\\d+\\. .+"));if(out.isEmpty())throw new IOException("未发现可抓包网卡，请检查 Npcap 和权限");return out;
        }finally{if(!log.delete())log.deleteOnExit();}
    }
    public static List<String> command(File tshark,String iface,File output){return Arrays.asList(tshark.getAbsolutePath(),"-i",iface,"-s","0","-F","pcapng","-w",output.getAbsolutePath(),"-q");}
    public synchronized void start(File tshark,String iface,File output,File log) throws IOException {
        if(process!=null&&process.isAlive())throw new IOException("已有本程序启动的抓包正在运行");
        process=new ProcessBuilder(command(tshark,iface,output)).redirectErrorStream(true).redirectOutput(log).start();
    }
    public synchronized boolean running(){return process!=null&&process.isAlive();}
    public synchronized void stop() throws InterruptedException {if(process!=null){process.destroy();if(!process.waitFor(5,TimeUnit.SECONDS)){process.destroyForcibly();process.waitFor(5,TimeUnit.SECONDS);}process=null;}}
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
