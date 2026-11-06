package com.liuchao.rtpscope.core;

import java.io.*;
import java.util.*;

/** Offline conversion with OpenCC's phrase exceptions taking precedence over characters. */
public final class SimplifiedChinese {
    private static final class Node {final Map<Integer,Node> children=new HashMap<>();String value;}
    private static volatile Node dictionary;
    private static Node dictionary()throws IOException{
        Node loaded=dictionary;if(loaded!=null)return loaded;
        synchronized(SimplifiedChinese.class){if(dictionary==null){Node root=new Node();read(root,"TSCharacters.txt");read(root,"TSPhrases.txt");dictionary=root;}return dictionary;}
    }
    private static void read(Node root,String name)throws IOException{
        InputStream source=SimplifiedChinese.class.getResourceAsStream("/opencc/"+name);if(source==null)throw new IOException("缺少中文转换词典，请重新安装完整应用");
        try(BufferedReader reader=new BufferedReader(new InputStreamReader(source,"UTF-8"))){String line;while((line=reader.readLine())!=null){if(line.isEmpty()||line.startsWith("#"))continue;int tab=line.indexOf('\t');if(tab<1)continue;String key=line.substring(0,tab),value=line.substring(tab+1).trim().split("\\s+",2)[0];Node node=root;for(int at=0;at<key.length();){int cp=key.codePointAt(at);node=node.children.computeIfAbsent(cp,k->new Node());at+=Character.charCount(cp);}node.value=value;}}
    }
    public static String convert(String value)throws IOException{
        if(value==null||value.isEmpty())return value;boolean han=false;for(int n=0;n<value.length();n++)if(value.charAt(n)>=0x3400){han=true;break;}if(!han)return value;
        Node root=dictionary();StringBuilder out=new StringBuilder();
        for(int at=0;at<value.length();){Node node=root;String replacement=null;int end=at;for(int next=at;next<value.length();){int cp=value.codePointAt(next);node=node.children.get(cp);if(node==null)break;next+=Character.charCount(cp);if(node.value!=null){replacement=node.value;end=next;}}if(replacement!=null){out.append(replacement);at=end;}else{int cp=value.codePointAt(at);out.appendCodePoint(cp);at+=Character.charCount(cp);}}
        return out.toString();
    }
    private SimplifiedChinese(){}
}
