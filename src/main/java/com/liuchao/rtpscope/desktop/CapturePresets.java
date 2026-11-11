package com.liuchao.rtpscope.desktop;

import java.io.*;
import java.util.*;
import java.util.prefs.*;

/** Local capture settings only; signaling payloads and decryption keys never enter presets. */
final class CapturePresets {
    private static final List<String> FIELDS=Arrays.asList("adapters","address","ports","protocol","advanced","bpf","mode","limit","budget","duration","folder","automatic","showFiles");
    static final class Preset {final String id,name;final Map<String,String> settings;Preset(String id,String name,Map<String,String> settings){this.id=id;this.name=name;this.settings=settings;}public String toString(){return name;}}
    private final Preferences root;CapturePresets(Preferences parent){root=parent.node("capture-plans");}
    List<Preset> list()throws IOException {try{List<Preset> list=new ArrayList<>();for(String id:root.childrenNames()){Preferences node=root.node(id);Map<String,String> values=new HashMap<>();for(String key:FIELDS)values.put(key,node.get(key,""));list.add(new Preset(id,node.get("name",id),values));if(list.size()>=30)break;}list.sort(Comparator.comparing(p->p.name));return list;}catch(BackingStoreException e){throw new IOException("读取本机抓包方案失败",e);}}
    Preset save(String name,Map<String,String> settings)throws IOException {name=name.trim();if(name.isEmpty()||name.length()>40)throw new IOException("方案名称请填写 1～40 个字符");List<Preset> current=list();String id=null;for(Preset p:current)if(p.name.equals(name))id=p.id;if(id==null&&current.size()>=30)throw new IOException("最多保存 30 个抓包方案");if(id==null)id=UUID.randomUUID().toString();Preferences node=root.node(id);node.put("name",name);Map<String,String> filtered=new HashMap<>();for(String key:FIELDS){String value=settings.getOrDefault(key,"");if(value.length()>4096)throw new IOException("方案设置过长");filtered.put(key,value);node.put(key,value);}try{node.flush();}catch(BackingStoreException e){throw new IOException("保存抓包方案失败",e);}return new Preset(id,name,filtered);}
}
