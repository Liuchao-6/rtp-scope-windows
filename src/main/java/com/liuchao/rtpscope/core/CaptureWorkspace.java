package com.liuchao.rtpscope.core;

import java.util.*;

/** UI-thread file registry. Only the active capture is decoded; entries retain lightweight view state. */
public final class CaptureWorkspace<T> {
    public static final class Entry<T> {
        public final String id, name;
        public final T source;
        public String query="", callId="", error="";
        public int tab;
        public boolean sipList;
        private Entry(String id,String name,T source){this.id=id;this.name=name;this.source=source;}
        @Override public String toString(){return name+(error.isEmpty()?"":" · 导入失败");}
    }
    private final List<Entry<T>> files=new ArrayList<>();
    private int active=-1;
    public int add(String id,String name,T source){
        if(id==null||id.isEmpty())throw new IllegalArgumentException("文件标识不能为空");
        for(int i=0;i<files.size();i++)if(files.get(i).id.equals(id))return i;
        files.add(new Entry<>(id,name==null||name.isEmpty()?"本地抓包":name,source));return files.size()-1;
    }
    public int size(){return files.size();}
    public int activeIndex(){return active;}
    public Entry<T> current(){return active<0?null:files.get(active);}
    public Entry<T> get(int index){return files.get(index);}
    public void select(int index){files.get(index);active=index;}
    public void removeCurrent(){if(active<0)return;files.remove(active);active=files.isEmpty()?-1:Math.min(active,files.size()-1);}
    public String label(int index){return (index+1)+" / "+files.size()+" · "+files.get(index);}
}
