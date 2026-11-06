package com.liuchao.rtpscope.core;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Source-time transcript. Channel labels are user-controlled and imply no speaker identity. */
public final class Transcript {
    public static final class Segment {
        public long startMs,endMs;public String channel,text,language="";
        public Segment(long a,long b,String c,String t){startMs=a;endMs=b;channel=c;text=t;}
        public boolean matches(String query){return text.toLowerCase(Locale.ROOT).contains(query.toLowerCase(Locale.ROOT));}
        public String toString(){return stamp(startMs,false)+"  ["+channel+"]  "+text;}
    }
    public final List<Segment> segments=new ArrayList<>();
    public Set<String> channels(){Set<String> out=new LinkedHashSet<>();for(Segment s:segments)out.add(s.channel);return out;}
    public Transcript channel(String name){Transcript out=new Transcript();for(Segment s:segments)if(name.equals(s.channel))out.segments.add(s);return out;}
    public void sort(){segments.sort(Comparator.comparingLong(s->s.startMs));}
    /** Legacy results have no language; only normalize those when the user selected Chinese. */
    public void simplifyChinese(boolean legacyChinese)throws IOException{for(Segment s:segments)if(s.language.equals("zh")||s.language.equals("yue")||s.language.isEmpty()&&legacyChinese){s.text=SimplifiedChinese.convert(s.text);if(s.language.isEmpty())s.language="zh";}}
    public void export(OutputStream output,boolean srt)throws IOException{
        StringBuilder text=new StringBuilder();int n=0;for(Segment s:segments){if(srt)text.append(++n).append('\n').append(stamp(s.startMs,true)).append(" --> ").append(stamp(s.endMs,true)).append('\n').append('[').append(s.channel).append("] ").append(s.text).append("\n\n");else text.append(s).append('\n');}output.write(text.toString().getBytes(StandardCharsets.UTF_8));
    }
    public static String stamp(long ms,boolean srt){return String.format(Locale.ROOT,"%02d:%02d:%02d%s%03d",ms/3600000,ms/60000%60,ms/1000%60,srt?",":".",ms%1000);}
    public void save(File file)throws IOException{Properties p=new Properties();p.setProperty("count",String.valueOf(segments.size()));for(int i=0;i<segments.size();i++){Segment s=segments.get(i);p.setProperty(i+".start",String.valueOf(s.startMs));p.setProperty(i+".end",String.valueOf(s.endMs));p.setProperty(i+".channel",s.channel);p.setProperty(i+".text",s.text);p.setProperty(i+".language",s.language);}File temp=File.createTempFile("transcript-",".tmp",file.getAbsoluteFile().getParentFile());try{try(OutputStream out=new FileOutputStream(temp)){p.store(out,"Transcript");}java.nio.file.Files.move(temp.toPath(),file.toPath(),java.nio.file.StandardCopyOption.REPLACE_EXISTING);}finally{temp.delete();}}
    public static Transcript load(File file)throws IOException{Transcript t=new Transcript();if(!file.isFile())return t;Properties p=new Properties();try(InputStream in=new FileInputStream(file)){p.load(in);}try{int count=Integer.parseInt(p.getProperty("count","0"));if(count<0||count>100000)throw new IOException("文字条数无效");for(int i=0;i<count;i++)t.segments.add(new Segment(Long.parseLong(p.getProperty(i+".start")),Long.parseLong(p.getProperty(i+".end")),p.getProperty(i+".channel"),p.getProperty(i+".text")));for(int i=0;i<t.segments.size();i++)t.segments.get(i).language=p.getProperty(i+".language","");return t;}catch(RuntimeException e){throw new IOException("文字结果文件无效",e);}}
}
