package com.liuchao.rtpscope.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** NSS key log, held only in memory. Errors never include input lines or secret values. */
public final class TlsKeyLog {
    private static final int MAX_BYTES=8*1024*1024,MAX_ENTRIES=50000;
    private final Map<String,byte[]> secrets;
    public final int ignored;
    private TlsKeyLog(Map<String,byte[]> values,int ignored){secrets=Collections.unmodifiableMap(values);this.ignored=ignored;}
    public static TlsKeyLog empty(){return new TlsKeyLog(new LinkedHashMap<>(),0);}
    public int size(){return secrets.size();}
    byte[] secret(String label,byte[] random){byte[] value=secrets.get(label+":"+hex(random));return value==null?null:value.clone();}
    public static TlsKeyLog read(InputStream input)throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int n;
        while((n=input.read(buffer))!=-1){if(bytes.size()+n>MAX_BYTES)throw new IOException("TLS 密钥日志超过 8 MiB");bytes.write(buffer,0,n);}
        String text=new String(bytes.toByteArray(),StandardCharsets.UTF_8);Map<String,byte[]> values=new LinkedHashMap<>();int line=0,ignored=0;
        if(text.contains("PRIVATE KEY-----"))throw new IOException("检测到私钥文件；请从「解密密钥 → 导入 RSA 私钥」入口导入 .key / .pem 文件");
        for(String raw:text.replace("\uFEFF","").split("\\r?\\n")) {
            line++;String value=raw.trim();if(value.isEmpty()||value.startsWith("#"))continue;
            String[] words=value.split("\\s+");String label=words[0];
            boolean accepted=label.equals("CLIENT_RANDOM")||label.matches("(?:CLIENT|SERVER)_(?:HANDSHAKE_TRAFFIC_SECRET|TRAFFIC_SECRET_0)");
            if(!accepted){ignored++;continue;}
            if(words.length!=3||!words[1].matches("[0-9a-fA-F]{64}")||!words[2].matches(label.equals("CLIENT_RANDOM")?"[0-9a-fA-F]{96}":"(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{96})"))throw new IOException("TLS 密钥日志第 "+line+" 行格式无效");
            String key=label+":"+words[1].toLowerCase(Locale.ROOT);byte[] secret=unhex(words[2]),previous=values.get(key);
            if(previous!=null&&!Arrays.equals(previous,secret))throw new IOException("TLS 密钥日志第 "+line+" 行与已有条目冲突");
            values.put(key,secret);if(values.size()>MAX_ENTRIES)throw new IOException("TLS 密钥条目超过 5 万条");
        }
        if(values.isEmpty())throw new IOException("没有找到可用的 NSS TLS 会话密钥；请导入 key log 文件");
        return new TlsKeyLog(values,ignored);
    }
    public TlsKeyLog merge(TlsKeyLog other)throws IOException {
        Map<String,byte[]> values=new LinkedHashMap<>(secrets);
        for(Map.Entry<String,byte[]> e:other.secrets.entrySet()){byte[] previous=values.get(e.getKey());if(previous!=null&&!Arrays.equals(previous,e.getValue()))throw new IOException("新日志与已加载的 TLS 密钥冲突；可先清除旧密钥再导入");values.put(e.getKey(),e.getValue());}
        if(values.size()>MAX_ENTRIES)throw new IOException("TLS 密钥条目超过 5 万条");return new TlsKeyLog(values,ignored+other.ignored);
    }
    static String hex(byte[] bytes){StringBuilder out=new StringBuilder();for(byte b:bytes)out.append(String.format(Locale.ROOT,"%02x",b&255));return out.toString();}
    private static byte[] unhex(String value){byte[] out=new byte[value.length()/2];for(int i=0;i<out.length;i++)out[i]=(byte)Integer.parseInt(value.substring(i*2,i*2+2),16);return out;}
}
