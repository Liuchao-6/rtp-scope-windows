package com.liuchao.rtpscope.desktop;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/** Reads public release metadata only. No account, capture or audio data is sent. */
final class UpdateChecker {
    static final String RELEASES="https://github.com/Liuchao-6/rtp-scope-windows/releases";
    static final String ENDPOINT="https://api.github.com/repos/Liuchao-6/rtp-scope-windows/releases/latest";
    static final int MAX_BYTES=1024*1024;
    interface Connection { HttpURLConnection open()throws IOException; }
    private final Connection connection;
    private static final Pattern VERSION=Pattern.compile("v?[0-9]{1,9}(?:\\.[0-9]{1,9}){1,3}");

    static final class Release {
        final String tag,version,title,notes;
        final URI page;
        Release(String tag,String title,String notes){
            this.tag=tag;version=tag.startsWith("v")?tag.substring(1):tag;
            this.title=title;this.notes=notes;page=URI.create(RELEASES+"/tag/"+tag);
        }
        boolean newerThan(String installed){return compareVersions(version,installed)>0;}
    }

    UpdateChecker(){this(()->(HttpURLConnection)new URL(ENDPOINT).openConnection());}
    UpdateChecker(Connection connection){this.connection=connection;}
    Release fetch()throws IOException {
        HttpURLConnection connection=this.connection.open();
        connection.setConnectTimeout(5000);connection.setReadTimeout(8000);connection.setInstanceFollowRedirects(false);
        connection.setRequestProperty("Accept","application/vnd.github+json");
        connection.setRequestProperty("X-GitHub-Api-Version","2022-11-28");
        connection.setRequestProperty("User-Agent","ChaogeHuatan-Windows/"+DesktopApp.VERSION);
        try {
            int code=connection.getResponseCode();
            if(code==403||code==429)throw new IOException("GitHub 暂时限制查询次数，请稍后重试。");
            if(code!=200)throw new IOException("暂时无法读取 GitHub 版本信息（HTTP "+code+"）。");
            if(connection.getContentLengthLong()>MAX_BYTES)throw new IOException("版本信息过大，请到发布页查看。");
            try(InputStream in=connection.getInputStream()){return parse(readBounded(in));}
        }finally{connection.disconnect();}
    }

    static byte[] readBounded(InputStream in)throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int count;
        while((count=in.read(buffer))!=-1){
            if(Thread.currentThread().isInterrupted())throw new InterruptedIOException("检查更新已取消");
            if(out.size()+count>MAX_BYTES)throw new IOException("版本信息过大，请到发布页查看。");
            out.write(buffer,0,count);
        }
        return out.toByteArray();
    }

    static Release parse(byte[] bytes)throws IOException {
        Object parsed=new Json(new String(bytes,StandardCharsets.UTF_8)).parse();
        if(!(parsed instanceof Map))throw invalid();Map<?,?> object=(Map<?,?>)parsed;
        String tag=string(object.get("tag_name"));
        if(!VERSION.matcher(tag).matches()||!Boolean.FALSE.equals(object.get("draft"))||!Boolean.FALSE.equals(object.get("prerelease")))throw invalid();
        // Derive the destination from our fixed repository and a validated version tag.
        // URLs and Markdown supplied by the response never become executable content.
        String title=string(object.get("name")),notes=string(object.get("body"));
        return new Release(tag,title.isEmpty()?"超哥话探 "+tag:title,notes.isEmpty()?"此版本未填写更新说明，可到 GitHub 发布页查看。":notes);
    }
    private static String string(Object value){return value instanceof String?(String)value:"";}
    private static IOException invalid(){return new IOException("版本信息格式不受支持，请到发布页查看。");}

    static int compareVersions(String left,String right) {
        if(!VERSION.matcher(left).matches()||!VERSION.matcher(right).matches())throw new IllegalArgumentException("Invalid release version");
        String[] a=left.replaceFirst("^v","").split("\\."),b=right.replaceFirst("^v","").split("\\.");
        for(int i=0;i<Math.max(a.length,b.length);i++){int x=i<a.length?Integer.parseInt(a[i]):0,y=i<b.length?Integer.parseInt(b[i]):0;if(x!=y)return Integer.compare(x,y);}
        return 0;
    }

    /** Small bounded JSON reader; no script engine or additional runtime dependency. */
    private static final class Json {
        private final String text;private int at;
        Json(String text)throws IOException{if(text.length()>MAX_BYTES)throw invalid();this.text=text;}
        Object parse()throws IOException{Object value=value(0);space();if(at!=text.length())throw invalid();return value;}
        private void space(){while(at<text.length()&&" \n\r\t".indexOf(text.charAt(at))>=0)at++;}
        private boolean take(char c){space();if(at<text.length()&&text.charAt(at)==c){at++;return true;}return false;}
        private void require(char c)throws IOException{if(!take(c))throw invalid();}
        private Object value(int depth)throws IOException {
            if(depth>32)throw invalid();space();if(at>=text.length())throw invalid();char c=text.charAt(at);
            if(c=='"')return quoted();
            if(c=='{'){
                at++;Map<String,Object> map=new HashMap<>();if(take('}'))return map;
                do{space();if(at>=text.length()||text.charAt(at)!='"')throw invalid();String key=quoted();require(':');Object item=value(depth+1);if(map.containsKey(key))throw invalid();map.put(key,item);}while(take(','));
                require('}');return map;
            }
            if(c=='['){at++;List<Object> list=new ArrayList<>();if(take(']'))return list;do{list.add(value(depth+1));}while(take(','));require(']');return list;}
            for(String literal:new String[]{"true","false","null"})if(text.startsWith(literal,at)){at+=literal.length();return literal.equals("null")?null:Boolean.valueOf(literal);}
            int start=at;while(at<text.length()&&"0123456789+-.eE".indexOf(text.charAt(at))>=0)at++;
            String number=text.substring(start,at);if(number.length()>128||!number.matches("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"))throw invalid();
            try{return new java.math.BigDecimal(number);}catch(NumberFormatException e){throw invalid();}
        }
        private String quoted()throws IOException {
            require('"');StringBuilder out=new StringBuilder();
            while(at<text.length()){
                char c=text.charAt(at++);if(c=='"')return out.toString();if(c<32)throw invalid();
                if(c!='\\'){out.append(c);continue;}if(at>=text.length())throw invalid();char escaped=text.charAt(at++);
                switch(escaped){
                    case '"':case '\\':case '/':out.append(escaped);break;
                    case 'b':out.append('\b');break;case 'f':out.append('\f');break;case 'n':out.append('\n');break;case 'r':out.append('\r');break;case 't':out.append('\t');break;
                    case 'u':
                        if(at+4>text.length())throw invalid();int code=0;for(int i=0;i<4;i++){int digit=Character.digit(text.charAt(at++),16);if(digit<0)throw invalid();code=code*16+digit;}out.append((char)code);break;
                    default:throw invalid();
                }
            }
            throw invalid();
        }
    }
}
