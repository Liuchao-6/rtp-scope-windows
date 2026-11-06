package com.liuchao.rtpscope.core;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.security.*;
import java.util.*;

/** Private versioned index. Media is restored to a disk store, never materialised as a large byte array. */
public final class AnalysisCache {
    private static final String VERSION="huatan-index-3";
    static final ThreadLocal<PacketStore> restoring=new ThreadLocal<>();
    private final File directory;
    private final long capacity;
    public AnalysisCache(File dir)throws IOException{this(dir,2L*1024*1024*1024);}
    public AnalysisCache(File dir,long capacity)throws IOException{directory=dir;this.capacity=capacity;if(!dir.isDirectory()&&!dir.mkdirs())throw new IOException("无法建立索引目录");}
    public String key(InputStream source)throws IOException{
        return key(source,CaptureEngine.MAX_DESKTOP_FILE);
    }
    public String key(InputStream source,long limit)throws IOException{
        try{MessageDigest hash=MessageDigest.getInstance("SHA-256");hash.update(VERSION.getBytes("UTF-8"));byte[] b=new byte[262144];int n;long size=0;while((n=source.read(b))!=-1){if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("导入已取消");size+=n;if(size>limit)throw new IOException("抓包超过当前平台的文件大小限制");hash.update(b,0,n);}return TlsKeyLog.hex(hash.digest());}catch(NoSuchAlgorithmException e){throw new IOException(e);}
    }
    public Analysis load(String key)throws IOException{
        File f=file(key);if(!f.isFile())return null;PacketStore store=new PacketStore(directory);restoring.set(store);
        try(ObjectInputStream in=new ObjectInputStream(new BufferedInputStream(new FileInputStream(f),262144))){
            if(!VERSION.equals(in.readUTF()))throw new IOException("索引版本变化");
            Analysis a=(Analysis)in.readObject();store.seal();a.mediaStore=store;f.setLastModified(System.currentTimeMillis());return a;
        }catch(ClassNotFoundException|RuntimeException|IOException e){store.close();f.delete();return null;}finally{restoring.remove();}
    }
    public void save(String key,Analysis a)throws IOException{
        File target=file(key),temp=File.createTempFile("index-",".tmp",directory);
        try{try(ObjectOutputStream out=new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(temp),262144))){out.writeUTF(VERSION);out.writeObject(a);}if(target.exists()&&!target.delete())throw new IOException("无法更新索引");if(!temp.renameTo(target))throw new IOException("无法保存索引");trim(target);}finally{temp.delete();}
    }
    private File file(String key)throws IOException{if(!key.matches("[0-9a-f]{64}"))throw new IOException("索引标识无效");return new File(directory,key+".index");}
    private void trim(File keep){File[] files=directory.listFiles((d,n)->n.endsWith(".index"));if(files==null)return;Arrays.sort(files,Comparator.comparingLong(File::lastModified));long size=0;for(File f:files)size+=f.length();for(File f:files)if(size>capacity&&!f.equals(keep)){size-=f.length();f.delete();}}
    public void clear(){File[] fs=directory.listFiles((d,n)->n.endsWith(".index"));if(fs!=null)for(File f:fs)f.delete();}
}
