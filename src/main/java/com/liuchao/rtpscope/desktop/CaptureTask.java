package com.liuchao.rtpscope.desktop;

import com.liuchao.rtpscope.core.*;
import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;

/** Persistent local task manifest and complete-block PCAPNG snapshots. Originals are read only. */
final class CaptureTask {
    static final long SNAPSHOT_LIMIT=768L*1048576;
    static final class Volume {
        final int number;final File file;final long bytes,packets,first,last;final boolean closed,pinned;
        Volume(int number,File file,long bytes,long packets,long first,long last,boolean closed,boolean pinned){this.number=number;this.file=file;this.bytes=bytes;this.packets=packets;this.first=first;this.last=last;this.closed=closed;this.pinned=pinned;}
        public String toString(){return file.getName();}
    }
    final File directory;final Map<String,String> values;final List<Volume> volumes=new ArrayList<>();final Set<String> pins=new LinkedHashSet<>();
    CaptureTask(File directory,Map<String,String> values)throws IOException {
        this.directory=directory.getCanonicalFile();this.values=Collections.unmodifiableMap(new LinkedHashMap<>(values));
        int count=(int)number(values,"volumes",0,256);for(int i=0;i<count;i++){String p="volume."+i+".";int n=(int)number(values,p+"number",1,999999);String name=values.getOrDefault(p+"file","");if(!name.equals(String.format(Locale.ROOT,"capture_%06d.pcapng",n)))throw new IOException("分卷文件名不正确");File file=new File(this.directory,name);if(!file.getCanonicalFile().getParentFile().equals(this.directory)||Files.isSymbolicLink(file.toPath()))throw new IOException("分卷路径不在任务目录内");long bytes=number(values,p+"bytes",28,1024L*1048576);volumes.add(new Volume(n,file,bytes,number(values,p+"packets",0,Long.MAX_VALUE),number(values,p+"first",0,Long.MAX_VALUE),number(values,p+"last",0,Long.MAX_VALUE),"1".equals(values.get(p+"closed")),"1".equals(values.get(p+"pinned"))));}
        int countPins=(int)number(values,"pins",0,256);for(int i=0;i<countPins;i++)pins.add(values.getOrDefault("pin."+i+".id",""));
    }
    static long number(Map<String,String> m,String key,long min,long max)throws IOException{try{long n=Long.parseLong(m.getOrDefault(key,Long.toString(min)));if(n<min||n>max)throw new NumberFormatException();return n;}catch(NumberFormatException e){throw new IOException("任务字段无效："+key);}}
    static CaptureTask read(File directory)throws IOException{return new CaptureTask(directory,CaptureBackend.readMetadata(new File(directory,"task")));}
    String name(){return values.getOrDefault("name",directory.getName());}
    String phase(){return values.getOrDefault("phase","recovered");}
    boolean incomplete(){return !phase().equals("done");}
    public String toString(){return name()+" · "+(phase().equals("running")?"未正常结束 / 正在运行":incomplete()?"可恢复":"已停止")+" · "+volumes.size()+" 卷";}
    static File historyRoot(){String override=System.getProperty("huatan.capture.history");String local=System.getenv("LOCALAPPDATA");return override==null?new File(local==null?System.getProperty("user.home"):local,"ChaogeHuatan/capture-tasks"):new File(override);}
    static void remember(File directory)throws IOException {File root=historyRoot();Files.createDirectories(root.toPath());File entry=new File(root,UUID.nameUUIDFromBytes(directory.getCanonicalPath().getBytes(java.nio.charset.StandardCharsets.UTF_8))+".task");Map<String,String> m=new LinkedHashMap<>();m.put("version","1");m.put("path",directory.getCanonicalPath());m.put("time",Long.toString(System.currentTimeMillis()));CaptureBackend.atomicWrite(entry,m);}
    static List<CaptureTask> history()throws IOException {List<CaptureTask> out=new ArrayList<>();File[] files=historyRoot().listFiles((dir,name)->name.endsWith(".task"));if(files==null)return out;Arrays.sort(files,Comparator.comparingLong(File::lastModified).reversed());for(int i=0;i<Math.min(files.length,200);i++)try{Map<String,String> m=CaptureBackend.read(files[i]);out.add(read(new File(m.get("path"))));}catch(Exception ignored){}return out;}
    static File newDirectory(File folder){String stamp=new SimpleDateFormat("yyyyMMdd-HHmmss",Locale.ROOT).format(new Date());return new File(folder,"抓包-"+stamp+"-"+UUID.randomUUID().toString().substring(0,8));}

    /** Native writer emits little endian microsecond PCAPNG, with a fresh section in each volume. */
    static final class Cursor implements Closeable {
        final RandomAccessFile input;long offset,limit;final List<Integer> links=new ArrayList<>();final List<byte[]> headers=new ArrayList<>();boolean partial;
        Cursor(File file,long limit)throws IOException {input=new RandomAccessFile(file,"r");this.limit=Math.min(limit,input.length());}
        byte[] next()throws IOException {
            if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("抓包读取已取消");
            if(offset+8>limit){if(offset<limit)partial=true;return null;}input.seek(offset);byte[] head=new byte[8];input.readFully(head);long length=u32(head,4);if(length<12||length%4!=0||length>16*1048576L)throw new IOException("分卷块长度无效，已读到字节 "+offset);if(offset+length>limit){partial=true;return null;}byte[] block=Arrays.copyOf(head,(int)length);input.readFully(block,8,block.length-8);if(u32(block,block.length-4)!=length)throw new IOException("分卷块边界无效，已读到字节 "+offset);
            int type=(int)u32(block,0);if(type==0x0a0d0d0a){if(length<28||u32(block,8)!=0x1a2b3c4dL)throw new IOException("任务分卷格式不受支持");links.clear();headers.clear();headers.add(block);}else if(type==1){if(length<20||links.size()>=256)throw new IOException("接口信息无效");links.add((block[8]&255)|((block[9]&255)<<8));headers.add(block);}else if(type==6){if(length<32||u32(block,8)>=links.size()||u32(block,20)>length-32)throw new IOException("分卷报文边界无效");}
            offset+=length;return block;
        }
        int link(byte[] b){return links.get((int)u32(b,8));}
        static long time(byte[] b){return (u32(b,12)<<32)|u32(b,16);}
        static byte[] packet(byte[] b){return Arrays.copyOfRange(b,28,28+(int)u32(b,20));}
        public void close()throws IOException{input.close();}
    }
    static long u32(byte[] b,int p){return (b[p]&255L)|((b[p+1]&255L)<<8)|((b[p+2]&255L)<<16)|((b[p+3]&255L)<<24);}
    /** Rebuild boundaries from existing bytes only. Never truncates or rewrites any original. */
    static CaptureTask recover(File directory)throws IOException {
        File canonical=directory.getCanonicalFile();File[] files=canonical.listFiles((d,n)->n.matches("capture_[0-9]{6}\\.pcapng"));if(files==null||files.length==0)throw new IOException("目录中没有本机抓包分卷");Arrays.sort(files,Comparator.comparing(File::getName));if(files.length>256)throw new IOException("任务分卷超过 256 个，请分目录恢复");
        Map<String,String> m=new LinkedHashMap<>();try{m.putAll(CaptureBackend.readMetadata(new File(directory,"task")));}catch(IOException ignored){}
        m.put("version","1");m.put("name",m.getOrDefault("name",directory.getName()));m.put("phase","recovered");m.put("message","异常中断恢复：仅分析完整报文，原始文件保留");m.put("volumes",Integer.toString(files.length));long total=0,count=0;int i=0;
        for(File file:files){if(!file.getCanonicalFile().getParentFile().equals(canonical)||Files.isSymbolicLink(file.toPath()))throw new IOException("恢复目录包含外部链接");long first=Long.MAX_VALUE,last=0,packets=0,safe=0;try(Cursor c=new Cursor(file,Long.MAX_VALUE)){try{byte[] b;while((b=c.next())!=null){safe=c.offset;if((int)u32(b,0)==6){long t=Cursor.time(b);first=Math.min(first,t);last=Math.max(last,t);packets++;}}}catch(IOException damaged){if(safe==0)throw damaged;}}
            if(safe<28)throw new IOException("分卷缺少完整头部："+file.getName());String p="volume."+i+++".";m.put(p+"number",Integer.toString(Integer.parseInt(file.getName().substring(8,14))));m.put(p+"file",file.getName());m.put(p+"bytes",Long.toString(safe));m.put(p+"packets",Long.toString(packets));m.put(p+"first",Long.toString(first));m.put(p+"last",Long.toString(last));m.put(p+"closed","1");m.put(p+"pinned","1");total+=safe;count+=packets;
        }
        m.put("packets",Long.toString(count));m.put("bytes",Long.toString(total));m.put("diskBytes",Long.toString(total));return new CaptureTask(directory,m);
    }
    static final class SnapshotResult {final List<File> files=new ArrayList<>();long packets,firstUs=Long.MAX_VALUE,lastUs;boolean shared,missing;}
    /** Copy at a frozen committed boundary; split output before the full analyzer's 1 GiB cap. */
    SnapshotResult snapshot(File target,Set<Integer> selected,long from,long to,LiveCaptureIndex.Selection call)throws IOException {
        return snapshot(target,selected,from,to,call,SNAPSHOT_LIMIT);
    }
    SnapshotResult snapshot(File target,Set<Integer> selected,long from,long to,LiveCaptureIndex.Selection call,long partLimit)throws IOException {
        if(from<0||to<from||partLimit<1048576||partLimit>SNAPSHOT_LIMIT)throw new IOException("快照范围不正确");Files.createDirectories(target.toPath());SnapshotResult result=new SnapshotResult();result.shared=call!=null&&call.sharedTcp();result.missing=!volumes.isEmpty()&&volumes.get(0).number>1;
        final boolean[] include={false};CaptureEngine.PacketInspector inspector=call==null?null:new CaptureEngine.PacketInspector((raw,link,t,src,dst,proto,payload)->include[0]=(proto==6||t>=from&&t<=to)&&call.matches(src,dst,proto,payload,t));
        OutputStream out=null;long bytes=0;try{
            for(Volume volume:volumes){if(selected!=null&&!selected.contains(volume.number)&&(call==null||!call.sharedTcp()))continue;
                // TCP contexts can precede the selected call's first SIP message.
                if(call==null&&(volume.last<from||volume.first>to))continue;if(!volume.file.isFile()){result.missing=true;continue;}
                try(Cursor cursor=new Cursor(volume.file,volume.bytes)){boolean sectionWritten=false;byte[] block;while((block=cursor.next())!=null){int type=(int)u32(block,0);if(type==0x0a0d0d0a){sectionWritten=false;continue;}if(type!=6)continue;long t=Cursor.time(block);
                        include[0]=t>=from&&t<=to;if(call!=null){include[0]=false;inspector.accept(Cursor.packet(block),cursor.link(block),t);}if(!include[0])continue;
                        long headers=0;for(byte[] h:cursor.headers)headers+=h.length;if(out==null||bytes+block.length+(sectionWritten?0:headers)>partLimit){if(out!=null)out.close();File file=new File(target,"分析快照-"+UUID.randomUUID().toString().substring(0,8)+"-"+(result.files.size()+1)+".pcapng");out=Files.newOutputStream(file.toPath(),StandardOpenOption.CREATE_NEW);result.files.add(file);bytes=0;sectionWritten=false;}
                        if(!sectionWritten){for(byte[] h:cursor.headers){out.write(h);bytes+=h.length;}sectionWritten=true;}out.write(block);bytes+=block.length;result.packets++;result.firstUs=Math.min(result.firstUs,t);result.lastUs=Math.max(result.lastUs,t);
                    }if(cursor.partial)result.missing=true;}
            }
            if(result.packets==0)throw new IOException("所选范围没有可分析的完整报文");return result;
        }catch(IOException|RuntimeException e){if(out!=null){try{out.close();}catch(IOException ignored){}out=null;}for(File f:result.files)Files.deleteIfExists(f.toPath());throw e;}finally{if(out!=null)out.close();}
    }
    /** Stateful tailer advances once through committed bytes, with a per-poll disk budget. */
    static final class Tailer implements Closeable {
        static final class Position {long offset;final List<Integer> links=new ArrayList<>();final List<byte[]> headers=new ArrayList<>();}
        final LiveCaptureIndex index=new LiveCaptureIndex();final Map<Integer,Position> positions=new HashMap<>();final Set<Integer> passed=new HashSet<>();long pending;boolean lost;
        void update(CaptureTask task,long maxBytes)throws IOException {
            Set<Integer> present=new HashSet<>();for(Volume v:task.volumes)present.add(v.number);for(Iterator<Map.Entry<Integer,Position>> it=positions.entrySet().iterator();it.hasNext();){Map.Entry<Integer,Position> e=it.next();if(!present.contains(e.getKey())){if(!passed.contains(e.getKey())){lost=true;index.missingVolume();}it.remove();}}
            passed.retainAll(present);long read=0;pending=0;
            for(Volume v:task.volumes){if(passed.contains(v.number))continue;if(!v.file.isFile()){lost=true;index.missingVolume();continue;}Position p=positions.computeIfAbsent(v.number,k->new Position());try(Cursor c=new Cursor(v.file,v.bytes)){c.offset=p.offset;c.links.addAll(p.links);c.headers.addAll(p.headers);
                while(read<maxBytes){long before=c.offset;byte[] b=c.next();if(b==null)break;read+=c.offset-before;if((int)u32(b,0)==6)index.accept(Cursor.packet(b),c.link(b),Cursor.time(b),(int)u32(b,8),v.number);}
                pending+=Math.max(0,v.bytes-c.offset);p.offset=c.offset;p.links.clear();p.links.addAll(c.links);p.headers.clear();p.headers.addAll(c.headers);if(v.closed&&c.offset==v.bytes){passed.add(v.number);positions.remove(v.number);}}
            }index.flush();
        }
        boolean caughtUp(){return pending==0&&!lost;}
        public void close(){positions.clear();}
    }
}
