package com.liuchao.rtpscope.core;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.io.*;
import java.security.*;
import java.util.*;

/** Private versioned index. Media is restored to a disk store, never materialised as a large byte array. */
public final class AnalysisCache {
    private static final String VERSION="huatan-index-4";
    static final ThreadLocal<PacketStore> restoring=new ThreadLocal<>();
    private final File directory;
    private final long capacity;
    public AnalysisCache(File dir)throws IOException{this(dir,2L*1024*1024*1024);}
    public AnalysisCache(File dir,long capacity)throws IOException{directory=dir;this.capacity=capacity;if(!dir.isDirectory()&&!dir.mkdirs())throw new IOException("无法建立索引目录");}
    public String key(InputStream source)throws IOException{
        return key(source,CaptureEngine.MAX_DESKTOP_FILE);
    }
    public String key(InputStream source,long limit)throws IOException{
        return key(source,limit,null);
    }
    public String key(InputStream source,long limit,CaptureEngine.Progress progress)throws IOException{
        try{MessageDigest hash=MessageDigest.getInstance("SHA-256");hash.update(VERSION.getBytes("UTF-8"));byte[] b=new byte[262144];int n;long size=0,next=0;while((n=source.read(b))!=-1){checkCancelled();size+=n;if(size>limit)throw new IOException("抓包超过当前平台的文件大小限制");hash.update(b,0,n);if(progress!=null&&size>=next){progress.update(size,0);next=size+4*1024*1024;}}if(progress!=null)progress.update(size,0);return TlsKeyLog.hex(hash.digest());}catch(NoSuchAlgorithmException e){throw new IOException(e);}
    }
    public Analysis load(String key)throws IOException{
        return load(key,null);
    }
    public Analysis load(String key,CaptureEngine.Progress progress)throws IOException{
        File f=file(key);if(!f.isFile())return null;PacketStore store=new PacketStore(directory);restoring.set(store);
        try(InputStream source=new FileInputStream(f);ObjectInputStream in=new ObjectInputStream(new BufferedInputStream(new FilterInputStream(source){
            long count,next;public int read()throws IOException{checkCancelled();int n=super.read();if(n>=0)report(1);return n;}public int read(byte[] b,int off,int len)throws IOException{checkCancelled();int n=in.read(b,off,len);if(n>0)report(n);return n;}private void report(int n){count+=n;if(progress!=null&&count>=next){progress.update(count,0);next=count+4*1024*1024;}}
        },262144))){
            if(!VERSION.equals(in.readUTF()))throw new IOException("索引版本变化");
            Analysis a=(Analysis)in.readObject();store.seal();a.mediaStore=store;f.setLastModified(System.currentTimeMillis());return a;
        }catch(ClassNotFoundException|RuntimeException|IOException e){store.close();if(Thread.currentThread().isInterrupted()||e instanceof InterruptedIOException)throw new InterruptedIOException("导入已取消");f.delete();return null;}finally{restoring.remove();}
    }
    public void save(String key,Analysis a)throws IOException{
        save(key,a,null);
    }
    public void save(String key,Analysis a,CaptureEngine.Progress progress)throws IOException{
        File target=file(key),temp=File.createTempFile("index-",".tmp",directory);
        try{try(OutputStream sink=new FileOutputStream(temp);ObjectOutputStream out=new ObjectOutputStream(new BufferedOutputStream(new FilterOutputStream(sink){
            long count,next;public void write(int b)throws IOException{checkCancelled();out.write(b);report(1);}public void write(byte[] b,int off,int len)throws IOException{checkCancelled();out.write(b,off,len);report(len);}private void report(int n){count+=n;if(progress!=null&&count>=next){progress.update(count,0);next=count+4*1024*1024;}}
        },262144))){out.writeUTF(VERSION);out.writeObject(a);}checkCancelled();java.nio.file.Files.move(temp.toPath(),target.toPath(),java.nio.file.StandardCopyOption.REPLACE_EXISTING);trim(target);}finally{temp.delete();}
    }
    private static void checkCancelled()throws InterruptedIOException{if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("导入已取消");}
    private File file(String key)throws IOException{if(!key.matches("[0-9a-f]{64}"))throw new IOException("索引标识无效");return new File(directory,key+".index");}
    private void trim(File keep){File[] files=directory.listFiles((d,n)->n.endsWith(".index"));if(files==null)return;Arrays.sort(files,Comparator.comparingLong(File::lastModified));long size=0;for(File f:files)size+=f.length();for(File f:files)if(size>capacity&&!f.equals(keep)){size-=f.length();f.delete();}}
    public void clear(){File[] fs=directory.listFiles((d,n)->n.endsWith(".index"));if(fs!=null)for(File f:fs)f.delete();}
}
