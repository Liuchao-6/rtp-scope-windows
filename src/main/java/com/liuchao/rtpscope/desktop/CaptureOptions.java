package com.liuchao.rtpscope.desktop;

import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.*;

/** Capture-time filters, deliberately separate from the analysis display filter. */
final class CaptureOptions {
    static final String[] PROTOCOLS={"全部协议","TCP + UDP","TCP","UDP"};
    static String filter(String address,int protocol,String ports,boolean advanced,String bpf)throws IOException {
        if(advanced){String value=bpf.trim();if(value.length()>4096||value.indexOf('\0')>=0)throw new IOException("高级过滤过长或含无效字符");return value;}
        List<String> terms=new ArrayList<>();String host=address.trim();
        if(!host.isEmpty()){
            String[] network=host.split("/",-1);if(network.length>2)throw new IOException("IP / CIDR 格式不正确");
            String ip=network[0];boolean v6=ip.indexOf(':')>=0;
            if(v6){if(!ip.matches("[0-9a-fA-F:]+"))throw new IOException("请输入数字 IPv4 或 IPv6 地址");try{if(!(InetAddress.getByName(ip) instanceof Inet6Address))throw new IOException("IPv6 地址不正确");}catch(UnknownHostException e){throw new IOException("IPv6 地址不正确");}}
            else {String[] octets=ip.split("\\.",-1);if(octets.length!=4)throw new IOException("请输入数字 IPv4 或 IPv6 地址");for(String octet:octets)if(!octet.matches("0|[1-9][0-9]{0,2}")||Integer.parseInt(octet)>255)throw new IOException("IPv4 地址不正确");}
            if(network.length==2){int prefix=number(network[1],0,v6?128:32,"CIDR 前缀");terms.add("net "+ip+"/"+prefix);}else terms.add("host "+ip);
        }
        if(protocol<0||protocol>3)throw new IOException("协议选择不正确");if(protocol>0)terms.add(protocol==1?"(tcp or udp)":protocol==2?"tcp":"udp");
        String values=ports.trim();if(!values.isEmpty()){
            String[] entries=values.split("[,，\\s]+",-1);if(entries.length>64)throw new IOException("端口条件最多 64 项");List<String> checks=new ArrayList<>();
            for(String entry:entries){String[] range=entry.split("-",-1);if(range.length>2)throw new IOException("端口格式示例：5060,5061,10000-20000");int first=number(range[0],1,65535,"端口");if(range.length==2){int last=number(range[1],1,65535,"端口");if(last<first)throw new IOException("端口范围应从小到大");checks.add("portrange "+first+"-"+last);}else checks.add("port "+first);}
            terms.add("("+String.join(" or ",checks)+")");
        }
        return String.join(" and ",terms);
    }
    private static int number(String text,int min,int max,String label)throws IOException {try{if(!text.matches("[0-9]{1,5}"))throw new NumberFormatException();int value=Integer.parseInt(text);if(value<min||value>max)throw new NumberFormatException();return value;}catch(NumberFormatException e){throw new IOException(label+"范围应为 "+min+"～"+max);}}
    static File output(File folder,String adapter)throws IOException {
        // Directory creation belongs to the background helper, including slow network paths.
        String safe=adapter.replaceAll("[\\\\/:*?\"<>|\\p{Cntrl}]","_").trim();if(safe.isEmpty())safe="网卡";if(safe.length()>45)safe=safe.substring(0,45);
        return new File(folder,new SimpleDateFormat("yyyyMMdd-HHmmss",Locale.ROOT).format(new Date())+"-"+safe+"-"+UUID.randomUUID().toString().substring(0,8)+".pcapng");
    }
}
