package com.liuchao.rtpscope.core;
import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.util.*;
import java.net.URLDecoder;

/** Explicit SIP references and deliberately separate, unconfirmed heuristic candidates. */
public final class CallRelations {
    public static final class Link {
        public final String first,second,kind,evidence;public final boolean explicit;
        Link(String a,String b,String k,String e,boolean x){first=a;second=b;kind=k;evidence=e;explicit=x;}
    }
    private final List<Link> manual=new ArrayList<>();
    public List<Link> find(Analysis a,String current){
        List<Link> out=new ArrayList<>();Set<String> known=new HashSet<>();for(Call c:a.calls)known.add(c.id);
        for(SipMessage m:a.sip)for(String name:Arrays.asList("replaces","join","refer-to")){
            String v=m.headers.get(name);if(v==null)continue;
            try{v=URLDecoder.decode(v.replace("+","%2B"),"UTF-8");}catch(Exception ignored){}
            String id=v.split(";",2)[0].trim();if(name.equals("refer-to")){java.util.regex.Matcher match=java.util.regex.Pattern.compile("(?i)[?&]Replaces=([^;&>]+)").matcher(v);if(!match.find())continue;id=match.group(1);}
            if(known.contains(id)&&!id.equals(m.callId)&&(current.equals(id)||current.equals(m.callId)))out.add(new Link(m.callId,id,name,"报文字段 · "+CallHealth.time(m.timeUs)+" · CSeq "+m.cseq,true));
        }
        Call c=null;for(Call x:a.calls)if(x.id.equals(current))c=x;
        if(c!=null)for(Call other:a.calls)if(!other.id.equals(current)&&Math.abs(other.startUs-c.startUs)<10000000&&
            (same(c.from,other.from)||same(c.to,other.to)||same(c.from,other.to)||same(c.to,other.from)))out.add(new Link(current,other.id,"候选关联","号码相同且开始时间相近，待确认",false));
        for(Link l:manual)if(current.equals(l.first)||current.equals(l.second))out.add(l);return out;
    }
    private static boolean same(String a,String b){String x=CallSearch.number(a),y=CallSearch.number(b);return !x.isEmpty()&&x.equals(y);}
    public void confirm(String a,String b){if(a.equals(b))throw new IllegalArgumentException("请选择不同通话段");remove(a,b);manual.add(new Link(a,b,"手动确认","用户确认关联",true));}
    public void remove(String a,String b){manual.removeIf(l->(l.first.equals(a)&&l.second.equals(b))||(l.first.equals(b)&&l.second.equals(a)));}
}
