package com.liuchao.rtpscope.desktop;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Versioned, bounded metadata IPC. Packet bytes never cross into the Java heap. */
final class CaptureBackend {
    static final class Adapter {
        final String id,label,addresses,status;
        Adapter(String id,String label,String addresses,String status){this.id=id;this.label=label;this.addresses=addresses;this.status=status;}
        public String toString(){return label+" · "+status;}
    }
    static final class Snapshot {
        final Map<String,String> values;final String phase,message;final long packets,bytes,elapsed,queueDrops;final Long drops;
        Snapshot(Map<String,String> values)throws IOException {this.values=values;phase=values.getOrDefault("phase","");message=values.getOrDefault("message","");packets=number("packets");bytes=number("bytes");elapsed=number("elapsed");queueDrops=number("queueDrops");drops=values.getOrDefault("drops","").isEmpty()?null:number("drops");}
        private long number(String key)throws IOException{try{return Long.parseLong(values.getOrDefault(key,"0"));}catch(NumberFormatException e){throw new IOException("抓包状态数据不正确",e);}}
        boolean terminal(){return phase.equals("done")||phase.equals("error");}
    }
    static final class Session {
        final File directory,output;final Process process;private boolean finished;private Snapshot last;
        Session(File directory,File output,Process process){this.directory=directory;this.output=output;this.process=process;}
        Snapshot poll()throws IOException {
            File state=new File(directory,"state");if(state.isFile())last=new Snapshot(readMetadata(state));
            if(!process.isAlive()){finished=true;if(last==null||!last.terminal()){Map<String,String> values=last==null?new HashMap<>():new HashMap<>(last.values);values.put("phase","error");values.put("message","抓包组件已中断；已写入的文件仍保留，可尝试分析。");last=new Snapshot(values);}}
            return last;
        }
        void stop()throws IOException {Files.write(new File(directory,"stop").toPath(),new byte[0]);}
        boolean ended(){return finished;}
        boolean await(long timeout)throws InterruptedException {return process.waitFor(timeout,TimeUnit.MILLISECONDS);}
        synchronized Map<String,String> command(String action,Map<String,String> arguments)throws Exception {
            if(!process.isAlive())throw new IOException("抓包已经停止，请从文件与任务打开分析");
            String id=UUID.randomUUID().toString();Map<String,String> request=new LinkedHashMap<>(arguments);request.put("version","1");request.put("id",id);request.put("action",action);atomicWrite(new File(directory,"command"),request);
            long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            while(System.nanoTime()<until){if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("操作已取消");File reply=new File(directory,"reply");Map<String,String> result=null;if(reply.isFile())try{result=readMetadata(reply);}catch(IOException changingFile){}if(result!=null&&id.equals(result.get("id"))){if(!"1".equals(result.get("ok")))throw new IOException(result.get("message"));return result;}if(!process.isAlive())throw new IOException("抓包已停止，已保存的文件仍可分析");Thread.sleep(25);}throw new IOException("抓包控制响应超时，请稍后重试");
        }
        void cleanup(){if(process.isAlive())return;for(String name:new String[]{"request","state","state.tmp","stop","command","command.tmp","reply","reply.tmp","lease"})new File(directory,name).delete();directory.delete();}
    }
    static File executable()throws IOException {
        String override=System.getProperty("huatan.capture.helper");if(override!=null)return require(new File(override));
        try{File location=new File(CaptureBackend.class.getProtectionDomain().getCodeSource().getLocation().toURI());File app=location.isDirectory()?location.getParentFile():location.getParentFile();File helper=new File(app,"HuatanCapture.exe");if(helper.isFile())return helper;}catch(Exception ignored){}
        return require(new File("build/HuatanCapture.exe"));
    }
    private static File require(File file)throws IOException {if(!file.isFile())throw new IOException("缺少本机抓包组件，请完整解压新版软件");return file.getAbsoluteFile();}
    static List<Adapter> probe()throws Exception {
        File dir=sessionDirectory();Process process=null;
        try{process=new ProcessBuilder(executable().getPath(),"--probe",dir.getPath()).start();if(!process.waitFor(15,TimeUnit.SECONDS)){process.destroyForcibly();throw new IOException("读取网卡超时，请检查 Npcap");}
            Snapshot result=new Snapshot(read(new File(dir,"state")));if(!result.phase.equals("ready"))throw new IOException(result.message);int count=Integer.parseInt(result.values.get("count"));if(count<0||count>256)throw new IOException("网卡列表过大");List<Adapter> out=new ArrayList<>();for(int i=0;i<count;i++)out.add(new Adapter(result.values.get("id."+i),result.values.get("label."+i),result.values.get("addresses."+i),result.values.get("status."+i)));return out;
        }finally{if(process!=null&&process.isAlive())process.destroyForcibly();for(String name:new String[]{"state","state.tmp"})new File(dir,name).delete();dir.delete();}
    }
    static Session start(Adapter adapter,String filter,File output,int mib,boolean elevated)throws Exception {
        if(!Arrays.asList(128,256,512,768).contains(mib))throw new IOException("不支持的抓包上限");
        File dir=sessionDirectory();Map<String,String> request=new LinkedHashMap<>();request.put("version","1");request.put("interface",adapter.id);request.put("filter",filter);request.put("output",output.getAbsolutePath());request.put("limit",Long.toString(mib*1048576L));request.put("parent",ManagementFactory.getRuntimeMXBean().getName().split("@")[0]);write(new File(dir,"request"),request);
        try{return new Session(dir,output,new ProcessBuilder(executable().getPath(),elevated?"--elevate":"--capture",dir.getPath()).start());}catch(Exception e){new File(dir,"request").delete();dir.delete();throw e;}
    }
    static Session startTask(List<Adapter> adapters,String filter,File task,String mode,long chunk,long budget,long duration,boolean elevated)throws Exception {
        Set<String> ids=new HashSet<>();for(Adapter a:adapters)ids.add(a.id);if(adapters.isEmpty()||adapters.size()>8||ids.size()!=adapters.size())throw new IOException("请选择 1～8 张不同网卡");
        if(!Arrays.asList("single","rotate","ring").contains(mode)||chunk<1048576||chunk>768L*1048576||budget<chunk||budget>64L*1024*1048576||duration<0||duration>86400)throw new IOException("抓包保存设置超出范围");
        if(task.exists())throw new IOException("任务目录已经存在");
        File dir=sessionDirectory();Map<String,String> request=new LinkedHashMap<>();request.put("version","1");request.put("interfaces",Integer.toString(adapters.size()));for(int i=0;i<adapters.size();i++){request.put("interface."+i,adapters.get(i).id);request.put("label."+i,adapters.get(i).label);}request.put("filter",filter);request.put("task",task.getAbsolutePath());request.put("name",task.getName());request.put("mode",mode);request.put("limit",Long.toString(chunk));request.put("budget",Long.toString(budget));request.put("duration",Long.toString(duration));request.put("parent",ManagementFactory.getRuntimeMXBean().getName().split("@")[0]);write(new File(dir,"request"),request);
        try{rememberTask(task);return new Session(dir,task,new ProcessBuilder(executable().getPath(),elevated?"--elevate":"--capture",dir.getPath()).start());}catch(Exception e){new File(dir,"request").delete();dir.delete();throw e;}
    }
    private static void rememberTask(File task)throws IOException {CaptureTask.remember(task);}
    private static File sessionDirectory()throws IOException {String local=System.getenv("LOCALAPPDATA");Path root=new File(local==null?System.getProperty("user.home"):local,"ChaogeHuatan/capture-sessions").toPath();Files.createDirectories(root);return Files.createTempDirectory(root,"session-").toFile();}
    static void write(File file,Map<String,String> values)throws IOException {StringBuilder text=new StringBuilder();for(Map.Entry<String,String> e:values.entrySet())text.append(e.getKey()).append('=').append(Base64.getEncoder().encodeToString(e.getValue().getBytes(StandardCharsets.UTF_8))).append('\n');Files.write(file.toPath(),text.toString().getBytes(StandardCharsets.UTF_8));}
    static void atomicWrite(File file,Map<String,String> values)throws IOException {File temp=new File(file.getParentFile(),file.getName()+".tmp");write(temp,values);for(int n=0;;n++)try{try{Files.move(temp.toPath(),file.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}catch(AtomicMoveNotSupportedException e){Files.move(temp.toPath(),file.toPath(),StandardCopyOption.REPLACE_EXISTING);}return;}catch(IOException e){if(n>=40)throw e;try{Thread.sleep(10);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new InterruptedIOException("任务写入已取消");}}}
    static Map<String,String> read(File file)throws IOException {
        return readBounded(file,65536);
    }
    static Map<String,String> readMetadata(File file)throws IOException {return readBounded(file,1048576);}
    private static Map<String,String> readBounded(File file,int max)throws IOException {
        if(!file.isFile()||file.length()>max)throw new IOException("抓包组件状态缺失或过大");byte[] data=new byte[(int)file.length()+1];int used=0;try(InputStream in=new FileInputStream(file)){int n;while(used<data.length&&(n=in.read(data,used,data.length-used))!=-1)used+=n;if(used==data.length)throw new IOException("抓包组件状态发生变化");}
        Map<String,String> values=new HashMap<>();try{for(String line:new String(data,0,used,StandardCharsets.UTF_8).split("\n")){int p=line.indexOf('=');if(p<=0)continue;String key=line.substring(0,p);if(values.put(key,new String(Base64.getDecoder().decode(line.substring(p+1)),StandardCharsets.UTF_8))!=null)throw new IOException("重复的状态字段");}}catch(IllegalArgumentException e){throw new IOException("抓包组件状态编码错误",e);}if(!"1".equals(values.get("version")))throw new IOException("抓包组件协议版本不匹配");return values;
    }
}
