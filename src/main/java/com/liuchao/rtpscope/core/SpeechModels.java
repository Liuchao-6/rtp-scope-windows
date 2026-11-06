package com.liuchao.rtpscope.core;
import java.io.*;
import java.util.*;
import java.util.zip.*;

/** Local Whisper or explicitly identified SenseVoice packages; source ZIPs are preserved. */
public final class SpeechModels {
    public enum Type {WHISPER,SENSE_VOICE}
    public static final class Model {
        public final File directory,encoder,decoder,tokens,network;public final Type type;public final String name;
        Model(File dir,File e,File d,File t,File network,Type type,String name){directory=dir;encoder=e;decoder=d;tokens=t;this.network=network;this.type=type;this.name=name;}
        public String toString(){return name;}
        @Override public boolean equals(Object other){return other instanceof Model&&directory.equals(((Model)other).directory);}
        @Override public int hashCode(){return directory.hashCode();}
    }
    public static Model inspect(File dir)throws IOException{
        Properties metadata=new Properties();File manifest=new File(dir,"model.properties");if(manifest.isFile())try(Reader reader=new InputStreamReader(new FileInputStream(manifest),"UTF-8")){metadata.load(reader);}
        String type=metadata.getProperty("type","whisper"),name=metadata.getProperty("name",dir.getName());
        if(type.equals("sensevoice")){File network=new File(dir,"model.int8.onnx");if(!network.isFile())network=new File(dir,"model.onnx");File tokens=new File(dir,"tokens.txt");if(!network.isFile()||network.length()<1024||!tokens.isFile()||tokens.length()<100)throw new IOException("SenseVoice 模型包需要 model.int8.onnx 与 tokens.txt");return new Model(dir,null,null,tokens,network,Type.SENSE_VOICE,name+" · 中文推荐");}
        if(!type.equals("whisper"))throw new IOException("不支持的语音模型类型");
        File e=null,d=null,t=null;File[] fs=dir.listFiles();if(fs!=null)for(File f:fs){String n=f.getName();if(n.contains("encoder")&&n.endsWith(".onnx")&&(e==null||n.contains("int8")))e=f;if(n.contains("decoder")&&n.endsWith(".onnx")&&(d==null||n.contains("int8")))d=f;if(n.endsWith("tokens.txt")||n.equals("tokens.txt"))t=f;}
        if(e==null||d==null||t==null||e.length()<1024||d.length()<1024||t.length()<100)throw new IOException("请导入配套 SenseVoice ZIP，或含 encoder、decoder、tokens 的 Whisper ZIP");return new Model(dir,e,d,t,null,Type.WHISPER,name);
    }
    public static List<Model> list(File root){List<Model> out=new ArrayList<>();File[] fs=root.listFiles(File::isDirectory);if(fs!=null)for(File f:fs)try{out.add(inspect(f));}catch(IOException ignored){}out.sort(Comparator.comparingInt((Model m)->m.type==Type.SENSE_VOICE?0:1).thenComparing(Model::toString));return out;}
    public static Model install(InputStream source,File root,String label)throws IOException{
        if(!root.isDirectory()&&!root.mkdirs())throw new IOException("无法建立模型目录");String name=label.replaceAll("[^\\p{L}\\p{N}._-]","_").replaceAll("(?i)\\.zip$","");if(name.isEmpty())name="Whisper";
        File dir=new File(root,name+"-"+System.currentTimeMillis());if(!dir.mkdir())throw new IOException("无法创建模型目录");boolean done=false;
        try(ZipInputStream zip=new ZipInputStream(new BufferedInputStream(source))){
            ZipEntry entry;long total=0;Set<String> names=new HashSet<>();int count=0;
            while((entry=zip.getNextEntry())!=null){if(++count>1000)throw new IOException("模型压缩包条目过多");if(entry.isDirectory())continue;String path=entry.getName().replace('\\','/');if(path.startsWith("/")||Arrays.asList(path.split("/")).contains(".."))throw new IOException("模型包路径无效");String base=path.substring(path.lastIndexOf('/')+1);
                if(!(base.endsWith(".onnx")||base.endsWith("tokens.txt")||base.equals("model.properties")||base.toLowerCase(Locale.ROOT).startsWith("license")))continue;
                if(base.contains(":")||base.equals(".")||!new File(dir,base).getCanonicalFile().getParentFile().equals(dir.getCanonicalFile()))throw new IOException("模型包路径无效");
                if(!names.add(base.toLowerCase(Locale.ROOT)))throw new IOException("模型包内文件重名");File target=new File(dir,base);
                try(OutputStream out=new FileOutputStream(target)){byte[] b=new byte[262144];int n;while((n=zip.read(b))!=-1){if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("模型导入已取消");total+=n;if(total>1024L*1024*1024)throw new IOException("模型解压大小超过 1 GiB");out.write(b,0,n);}}
            }
            Model model=inspect(dir);done=true;return model;
        }finally{if(!done){File[] files=dir.listFiles();if(files!=null)for(File f:files)f.delete();dir.delete();}}
    }
}
