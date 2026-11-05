package com.liuchao.rtpscope.core;

import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.text.*;
import java.util.*;
import java.util.regex.*;

/** Call discovery is independent of packet filtering. Times use the device's local time zone. */
public final class CallSearch {
    public static final class Filter {
        public String keyword="",caller="",callee="",ip="",start="",end="";
        public Filter copy(){Filter f=new Filter();f.keyword=keyword;f.caller=caller;f.callee=callee;f.ip=ip;f.start=start;f.end=end;return f;}
        public boolean empty(){return (keyword+caller+callee+ip+start+end).trim().isEmpty();}
    }
    private static final class Bound {long value;boolean clock;}
    private static Bound time(String input){
        if(input.trim().isEmpty())return null;
        String value=input.trim().replace('T',' ');
        boolean clock=value.indexOf(' ')==-1;
        String[] patterns=clock?new String[]{"HH:mm:ss.SSS","HH:mm:ss","HH:mm"}:new String[]{"yyyy-MM-dd HH:mm:ss.SSS","yyyy-MM-dd HH:mm:ss","yyyy-MM-dd HH:mm"};
        if(!(clock?value.matches("\\d{2}:\\d{2}(:\\d{2}(\\.\\d{3})?)?"):value.matches("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}(:\\d{2}(\\.\\d{3})?)?")))throw new IllegalArgumentException("时间格式：HH:mm:ss 或 yyyy-MM-dd HH:mm:ss，可加三位毫秒");
        for(String pattern:patterns){SimpleDateFormat parser=new SimpleDateFormat(pattern,Locale.ROOT);parser.setLenient(false);if(clock)parser.setTimeZone(TimeZone.getTimeZone("UTC"));ParsePosition p=new ParsePosition(0);Date date=parser.parse(value,p);if(date!=null&&p.getIndex()==value.length()){Bound b=new Bound();b.value=date.getTime();b.clock=clock;return b;}}
        throw new IllegalArgumentException("时间无效，请检查日期、小时、分钟和秒");
    }
    public static List<Call> find(List<Call> calls,Filter f){
        Bound first=time(f.start),last=time(f.end);
        if(first!=null&&last!=null&&(first.clock!=last.clock))throw new IllegalArgumentException("起止时间请同时填写时分秒，或同时包含日期");
        if(first!=null&&last!=null&&!first.clock&&first.value>last.value)throw new IllegalArgumentException("开始时间不能晚于结束时间");
        List<Call> out=new ArrayList<>();
        for(Call c:calls){
            String peers=c.from+" "+c.to+" "+number(c.from)+" "+number(c.to)+" "+c.requestTarget;
            if(!contains(number(c.from),f.caller)||!contains(number(c.to)+" "+number(c.requestTarget),f.callee))continue;
            String ips=String.join(" ",c.signalingIps)+" "+String.join(" ",c.mediaIps);
            if(!ipMatches(c,f.ip)||(!contains(c.id+" "+peers+" "+ips,f.keyword)&&!ipMatches(c,f.keyword)))continue;
            if(!overlap(c,first,last))continue;
            out.add(c);
        }
        return out;
    }
    private static boolean contains(String value,String query){return query.trim().isEmpty()||value.toLowerCase(Locale.ROOT).contains(query.trim().toLowerCase(Locale.ROOT));}
    private static boolean ipMatches(Call call,String query){
        if(query.trim().isEmpty())return true;String q=query.trim().replace("[","").replace("]","");Set<String> ips=new LinkedHashSet<>(call.signalingIps);ips.addAll(call.mediaIps);
        for(String ip:ips)if(contains(ip,q))return true;
        if(q.contains(":")&&q.matches("[0-9a-fA-F:]+"))try{String canonical=java.net.InetAddress.getByName(q).getHostAddress();for(String ip:ips)if(java.net.InetAddress.getByName(ip).getHostAddress().equals(canonical))return true;}catch(Exception ignored){}
        return false;
    }
    private static boolean overlap(Call c,Bound first,Bound last){
        if(first==null&&last==null)return true;
        if(c.startUs==Long.MAX_VALUE)return false;
        long start=c.startUs/1000,end=Math.max(c.startUs,c.lastUs)/1000;
        Bound b=first==null?last:first;
        if(!b.clock)return (first==null||end>=first.value)&&(last==null||start<=last.value);
        long from=first==null?0:first.value,to=last==null?86399999:last.value;
        Calendar day=Calendar.getInstance();day.setTimeInMillis(start);day.set(Calendar.HOUR_OF_DAY,0);day.set(Calendar.MINUTE,0);day.set(Calendar.SECOND,0);day.set(Calendar.MILLISECOND,0);
        day.add(Calendar.DATE,-1);
        for(int i=0;i<4;i++){
            Calendar a=(Calendar)day.clone(),z=(Calendar)day.clone();a.add(Calendar.MILLISECOND,(int)from);if(to<from)z.add(Calendar.DATE,1);z.add(Calendar.MILLISECOND,(int)to);
            if(end>=a.getTimeInMillis()&&start<=z.getTimeInMillis())return true;
            day.add(Calendar.DATE,1);
        }
        return false;
    }
    public static String number(String header){
        Matcher m=Pattern.compile("(?i)(?:sips?|tel):([^@;>?\\s]+)").matcher(header==null?"":header);
        if(!m.find())return header==null?"":header;
        try{return java.net.URLDecoder.decode(m.group(1).replace("+","%2B"),"UTF-8");}catch(Exception e){return m.group(1);}
    }
    public static String participants(Call c){return number(c.from)+" → "+number(c.to);}
    public static String times(Call c){return new SimpleDateFormat("MM-dd HH:mm:ss",Locale.ROOT).format(new Date(c.startUs/1000))+" · "+String.format(Locale.ROOT,"%.1f 秒",Math.max(0,c.lastUs-c.startUs)/1000000.0);}
    private CallSearch(){}
}
