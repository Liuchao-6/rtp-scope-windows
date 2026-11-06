package com.liuchao.rtpscope.core;

import com.liuchao.rtpscope.core.CaptureEngine.*;
import java.text.SimpleDateFormat;
import java.util.*;

/** Evidence-based call summary. Missing termination is never inferred from the last RTP. */
public final class CallHealth {
    public static final class Finding {
        public final String state,title,detail;
        public final Object evidence;
        Finding(String s,String t,String d,Object e){state=s;title=t;detail=d;evidence=e;}
    }
    public static final class KeySummary {
        public final String callId;
        public final List<DtmfParser.Event> events;
        KeySummary(String id,List<DtmfParser.Event> values){callId=id;events=Collections.unmodifiableList(new ArrayList<>(values));}
        public String detailText(){
            StringBuilder text=new StringBuilder("按键总数：").append(events.size()).append(" 次\n");
            if(events.isEmpty())return text.append("当前通话未检测到按键。").toString();
            Set<String> types=new LinkedHashSet<>();for(DtmfParser.Event event:events)types.add(event.typeLabel());
            text.append("类型：").append(String.join(" / ",types)).append("\n");
            for(int i=0;i<Math.min(200,events.size());i++){
                DtmfParser.Event event=events.get(i);
                text.append("\n").append(i+1).append(". 按键 ").append(event.key).append(" · ").append(event.typeLabel())
                    .append("\n时间：").append(time(event.firstSeenUs)).append("\n方向：").append(event.src).append(" → ").append(event.dst)
                    .append("\n持续：").append(event.durationText()).append(" · ").append(event.stateText()).append("\n");
            }
            if(events.size()>200)text.append("\n此处显示前 200 次，完整明细请查看「DTMF 按键」列表。\n");
            return text.append("\n可在「按键」列表中选择具体事件查看详情。").toString();
        }
    }
    public final Call call;
    public SipMessage invite,answer,end;
    public String state="未知",endSide="未知",reason="未捕获";
    public long startUs=-1,answerUs=-1,endUs=-1,lastUs=-1;
    public final List<Finding> findings=new ArrayList<>();
    private CallHealth(Call c){call=c;}
    public static CallHealth inspect(Analysis a,String id){
        Call call=null;for(Call c:a.calls)if(c.id.equals(id)){call=c;break;}
        if(call==null)throw new IllegalArgumentException("请先选择一通电话");
        CallHealth h=new CallHealth(call);List<SipMessage> ms=new ArrayList<>();
        for(SipMessage m:a.sip)if(id.equals(m.callId))ms.add(m);
        ms.sort(Comparator.comparingLong(m->m.timeUs));
        for(SipMessage m:ms){
            h.lastUs=Math.max(h.lastUs,m.timeUs);
            if(h.invite==null&&method(m).equals("INVITE")&&!tag(m.to).isEmpty())continue;
            if(h.invite==null&&method(m).equals("INVITE")){h.invite=m;h.startUs=m.timeUs;}
        }
        // Mid-call captures may have only a re-INVITE; preserve that distinction.
        if(h.invite==null)h.startUs=-1;
        Map<String,SipMessage> transactions=new LinkedHashMap<>();for(SipMessage m:ms)if(method(m).equals("INVITE")&&tag(m.to).isEmpty()&&(h.invite==null||tag(h.invite.from).equals(tag(m.from))))transactions.putIfAbsent(m.cseq.trim().toUpperCase(Locale.ROOT),m);
        SipMessage failure=null,cancel=null;
        for(SipMessage m:ms){
            SipMessage request=transactions.get(m.cseq.trim().toUpperCase(Locale.ROOT));boolean initial=request!=null&&m.timeUs>=request.timeUs&&sameCaller(request,m);
            int code=status(m);
            if(initial&&code>=200&&code<300&&h.answer==null){h.answer=m;h.answerUs=m.timeUs;h.state="已接通";}
            if(method(m).equals("CANCEL"))cancel=m;
            if(initial&&code>=300&&code!=401&&code!=407)failure=m;
        }
        for(SipMessage m:ms)if(h.end==null&&method(m).equals("BYE")&&(h.answerUs<0||m.timeUs>=h.answerUs)&&dialog(h,m)){h.end=m;h.endUs=m.timeUs;h.state=h.answer==null?"结束已捕获 · 接通未知":"已接通";}
        if(h.answer==null&&h.end==null){if(cancel!=null){h.end=cancel;h.state="已取消";}else if(failure!=null){h.end=failure;int code=status(failure);h.state=code==486||code==603?"被拒接":code==408||code==504?"响应超时":"呼叫失败";}if(h.end!=null)h.endUs=h.end.timeUs;}
        if(h.state.equals("未知")&&h.invite!=null)h.state="接通未捕获";
        if(h.end!=null){
            h.reason=h.end.headers.getOrDefault("reason","未携带 Reason");
            if(h.invite!=null){String fromTag=tag(h.end.from),initialTag=tag(h.invite.from);
                if(!fromTag.isEmpty()&&!initialTag.isEmpty()){if(fromTag.equals(initialTag))h.endSide="主叫侧";else if(h.answer!=null&&fromTag.equals(tag(h.answer.to)))h.endSide="被叫侧";}
                else if(h.end.src.equals(h.invite.src))h.endSide="主叫侧";
                else if(h.end.src.equals(h.invite.dst))h.endSide="被叫侧";
            }
            if(method(h.end).isEmpty())h.endSide="响应端";
            h.reason+=reasonText(h.reason);
        }
        h.findings.add(new Finding(h.answer==null?"关注":"正常","接通状态",h.state,h.answer==null?h.invite:h.answer));
        h.findings.add(new Finding(h.end==null?"未知":"已捕获","结束信令",h.end==null?"结束未捕获，完整时长和挂断方未知":h.end.firstLine,h.end));
        boolean ack=false;Set<String> seen=new HashSet<>();int retries=0;
        for(SipMessage m:ms){
            if(method(m).equals("ACK")&&h.answerUs>=0&&m.timeUs>=h.answerUs&&number(m.cseq).equals(number(h.answer.cseq))&&dialog(h,m))ack=true;
            String key=m.src+"|"+m.dst+"|"+m.raw;if(!seen.add(key))retries++;
            int code=status(m);if(code>=400)h.findings.add(new Finding(code==401||code==407?"信息":"关注","SIP 响应",m.firstLine,m));
        }
        if(h.answer!=null&&!ack)h.findings.add(new Finding("关注","ACK 未捕获","需结合抓包范围确认",h.answer));
        if(retries>0)h.findings.add(new Finding("关注","重复信令",retries+" 条相同方向、相同内容消息；可能为重传",h.invite));
        if(h.answerUs>=0&&h.startUs>=0)h.findings.add(new Finding(h.answerUs-h.startUs>5000000?"关注":"信息","接通等待",duration(h.answerUs-h.startUs),h.answer));
        Set<QualityAnalyzer.Report> reports=Collections.newSetFromMap(new IdentityHashMap<QualityAnalyzer.Report,Boolean>());
        Set<String> directions=new HashSet<>();
        for(RtpStream s:call.streams){
            if(s.encrypted||!s.playable()&&!s.isDtmf())h.findings.add(new Finding("信息","媒体解码",s.codec+" · "+s.note,s));
            if(!s.isDtmf()){directions.add(s.src+">"+s.dst);if(!s.packets.isEmpty())h.lastUs=Math.max(h.lastUs,s.packets.get(s.packets.size()-1).timeUs);}
            if(s.quality!=null&&reports.add(s.quality)){
                QualityAnalyzer.Report r=s.quality;
                if(r.lost>0)h.findings.add(new Finding("关注","RTP 序号缺口",r.lost+" 包，缺包率 "+String.format(Locale.ROOT,"%.2f%%",r.lossPercent())+" · "+s.src+" → "+s.dst,s));
                if(r.delaySpikes()>0)h.findings.add(new Finding("关注","到达延迟突增",r.delaySpikes()+" 次 · 最大到达间隔 "+String.format(Locale.ROOT,"%.1f ms",r.maxArrivalGapMs),s));
                if(r.timestampResets>0)h.findings.add(new Finding("关注","RTP 时间戳跳变",r.timestampResets+" 处 · 播放按抓包时间衔接，原始报文不变",s));
                if(r.reordered>0||r.duplicates>0)h.findings.add(new Finding("关注","乱序 / 重复",r.reordered+" / "+r.duplicates,s));
            }
        }
        if(directions.size()<2)h.findings.add(new Finding("关注","媒体方向",directions.isEmpty()?"当前抓包未见媒体":"只观测到一路媒体方向，需确认抓包位置",null));
        List<DtmfParser.Event> keys=new ArrayList<>();Set<String> types=new LinkedHashSet<>();for(DtmfParser.Event e:a.events)if(id.equals(e.callId)){keys.add(e);types.add(e.typeLabel());}
        keys.sort(Comparator.comparingLong(e->e.firstSeenUs));
        h.findings.add(new Finding("信息","按键",keys.isEmpty()?"0 次 · 未检测到按键":keys.size()+" 次 · "+String.join(" / ",types),new KeySummary(id,keys)));
        return h;
    }
    public long durationUs(){return answerUs>=0&&endUs>=answerUs&&end!=null&&method(end).equals("BYE")?endUs-answerUs:-1;}
    public static String method(SipMessage m){if(m==null||m.firstLine.startsWith("SIP/"))return "";return m.firstLine.split(" ",2)[0].toUpperCase(Locale.ROOT);}
    public static int status(SipMessage m){try{return m.firstLine.startsWith("SIP/")?Integer.parseInt(m.firstLine.split(" ",3)[1]):0;}catch(RuntimeException e){return 0;}}
    static String tag(String s){java.util.regex.Matcher m=java.util.regex.Pattern.compile("(?i)(?:^|;)\\s*tag=([^;\\s>]+)").matcher(s==null?"":s);return m.find()?m.group(1):"";}
    public static String time(long us){return us<0||us==Long.MAX_VALUE?"未知":new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS Z",Locale.ROOT).format(new Date(us/1000));}
    public static String duration(long us){return us<0?"未知":String.format(Locale.ROOT,"%02d:%02d.%03d",us/60000000,us/1000000%60,us/1000%1000);}
    public static String escape(String s){return s==null?"":s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;");}
    private static boolean sameCaller(SipMessage a,SipMessage b){String x=tag(a.from),y=tag(b.from);return x.isEmpty()||y.isEmpty()||x.equals(y);}
    private static String number(String cseq){return cseq.trim().split("\\s+",2)[0];}
    private static boolean dialog(CallHealth h,SipMessage m){if(h.invite==null)return true;String caller=tag(h.invite.from),callee=h.answer==null?"":tag(h.answer.to),from=tag(m.from),to=tag(m.to);if(caller.isEmpty()||from.isEmpty()||to.isEmpty())return true;if(callee.isEmpty())return caller.equals(from)||caller.equals(to);return caller.equals(from)&&callee.equals(to)||callee.equals(from)&&caller.equals(to);}
    private static String reasonText(String reason){java.util.regex.Matcher m=java.util.regex.Pattern.compile("(?i)Q\\.850[^,]*?cause\\s*=\\s*(\\d+)").matcher(reason);if(!m.find())return "";int cause;try{cause=Integer.parseInt(m.group(1));}catch(NumberFormatException invalid){return "";}switch(cause){case 16:return " · 正常清除";case 17:return " · 用户忙";case 18:return " · 用户无响应";case 19:return " · 无应答";case 21:return " · 呼叫被拒绝";case 34:return " · 无可用电路";case 41:return " · 临时故障";default:return "";}}
    public String html(boolean redact){return html(redact,true);}
    public String html(boolean redact,boolean interactive){return html(redact,redact,interactive);}
    public String html(boolean maskNumbers,boolean maskIps,boolean interactive){
        StringBuilder s=new StringBuilder("<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><style>body{font-family:'Microsoft YaHei UI',sans-serif;font-size:13px;background:#f7f9fc;color:#18324e;margin:18px}h1{font-size:21px;margin:0 0 8px}h2{font-size:17px;margin:20px 0 8px}p{margin:6px 0 12px}table{width:100%;border-collapse:collapse}td,th{text-align:left;vertical-align:top}a{color:#0067c0;text-decoration:none}.card{background:#ffffff;border:1px solid #dce5f0;border-radius:8px;margin:12px 0}.card td{padding:14px}.metric{width:25%}.muted,small{color:#71849b;font-size:11px}.value{font-size:22px;font-weight:bold;color:#16314e;margin:8px 0 4px}.times td{width:33%}.checks th{padding:10px;background:#edf3fa;color:#71849b;font-size:12px;font-weight:normal}.checks td{padding:12px 10px;border-bottom:1px solid #e5edf5}.state{color:#087e60}.warn{color:#a35f00}.evidence{white-space:pre-wrap;word-break:break-word;font-family:inherit;font-size:12px}@media(max-width:600px){body{margin:12px}.metric{display:inline-block;box-sizing:border-box;width:50%}.times td{display:block;width:auto}.checks thead{display:none}.checks td{display:block;border:0;padding:5px 12px}.checks tr{display:block;border-bottom:1px solid #e5edf5;padding:8px 0}.value{font-size:20px}}</style></head><body bgcolor='#f7f9fc'><h1>通话概览</h1>");
        s.append("<p class='muted'>").append(escape(maskNumbers?"[号码] → [号码]":mask(CallSearch.participants(call),false,maskIps))).append("</p><table class='card' bgcolor='#ffffff' cellpadding='12'><tr>");
        metric(s,"通话时长",duration(durationUs()),"接通至首次 BYE");metric(s,"接通等待",duration(startUs>=0&&answerUs>=startUs?answerUs-startUs:-1),"首次 INVITE 至成功响应");metric(s,"结束方",endSide,"当前通话段所见");metric(s,"通话状态",state,"以 SIP 信令为依据");
        s.append("</tr></table><table class='card times' bgcolor='#ffffff' cellpadding='12'><tr>");
        moment(s,"呼叫开始",startUs);moment(s,"接通时间",answerUs);moment(s,"结束时间",endUs);s.append("</tr></table>");
        if(end!=null){s.append("<table class='card' bgcolor='#ffffff' cellpadding='12'><tr><td width='55%'><small>结束依据</small><p><b>").append(escape(endSide+" · "+(method(end).isEmpty()?end.firstLine:method(end)))).append("</b></p><small>").append(escape(mask(end.src+" → "+end.dst,false,maskIps))).append("</small><p class='muted'>CSeq ").append(escape(end.cseq)).append("</p></td><td><small>Reason / Q.850</small><p>").append(escape(mask(reason,maskNumbers,maskIps))).append("</p></td></tr></table>");}
        else s.append("<table class='card' bgcolor='#ffffff' cellpadding='12'><tr><td><b>结束未捕获</b><p>完整通话时长与挂断方未知</p><small>最后观测时间：").append(escape(time(lastUs))).append("</small></td></tr></table>");
        s.append("<h2>体检结论与证据</h2><p class='muted'>点击检查项目，查看对应信令、媒体或按键摘要。</p><table class='card checks' bgcolor='#ffffff'><thead><tr><th width='70'>状态</th><th width='145'>检查项目</th><th>观测结果</th><th width='95'>证据</th></tr></thead>");
        for(int i=0;i<findings.size();i++){
            Finding f=findings.get(i);String href=(interactive?"evidence:":"#evidence")+i;boolean linked=!interactive||f.evidence!=null;
            s.append("<tr><td class='").append(f.state.equals("关注")?"warn":"state").append("'>").append(escape(f.state)).append("</td><td>");
            if(linked)s.append("<a href='").append(href).append("'>");s.append(escape(f.title));if(linked)s.append("</a>");
            s.append("</td><td>").append(escape(mask(f.detail,maskNumbers,maskIps))).append("</td><td>");if(linked)s.append("<a href='").append(href).append("'>查看摘要 →</a>");else s.append("通话汇总");s.append("</td></tr>");
        }
        s.append("</table>");
        if(!interactive){s.append("<h2>证据索引</h2>");for(int i=0;i<findings.size();i++){Finding f=findings.get(i);String evidence=f.evidence instanceof SipMessage?time(((SipMessage)f.evidence).timeUs)+" · CSeq "+((SipMessage)f.evidence).cseq+" · "+((SipMessage)f.evidence).firstLine:f.evidence instanceof RtpStream?((RtpStream)f.evidence).src+" → "+((RtpStream)f.evidence).dst+" · SSRC "+((RtpStream)f.evidence).ssrc+" · PT "+((RtpStream)f.evidence).pt:f.evidence instanceof KeySummary?((KeySummary)f.evidence).detailText():"当前通话汇总";s.append("<div id='evidence").append(i).append("'><b>").append(escape(f.title)).append("</b><pre class='evidence'>").append(escape(mask(evidence,maskNumbers,maskIps))).append("</pre></div>");}}
        return s.append("<p class='muted'>结果来自当前抓包所见。结束方表示当前通话段的信令发起侧；序号缺口与到达延迟需结合抓包位置确认。</p></body></html>").toString();
    }
    private static void metric(StringBuilder s,String label,String value,String detail){s.append("<td class='metric' width='25%'><small>").append(escape(label)).append("</small><p class='value'>").append(escape(value)).append("</p><small>").append(escape(detail)).append("</small></td>");}
    private static void moment(StringBuilder s,String label,long us){String value=time(us);s.append("<td><small>").append(escape(label)).append("</small><p><b>").append(escape(value.equals("未知")?value:value.substring(11,23))).append("</b></p><small>").append(escape(value.equals("未知")?"未捕获":value.substring(0,10)+" · "+value.substring(24))).append("</small></td>");}
    static String redact(String s){return redact(s,true,true);}
    static String redact(String s,boolean numbers,boolean ips){
        if(numbers)s=s.replaceAll("(?i)(sips?:)[^\\s;@>]+@","$1[号码]@").replaceAll("(?i)(tel:)[^\\s;>]+","$1[号码]");
        if(ips)s=s.replaceAll("(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d+)?","[IP]").replaceAll("\\[[0-9a-fA-F:]+\\](?::\\d+)?","[IPv6]");
        return s;
    }
    private String mask(String value,boolean numbers,boolean ips){
        String text=redact(value,numbers,ips);
        if(numbers)for(String header:new String[]{call.from,call.to}){String number=CallSearch.number(header);if(!number.isEmpty())text=text.replaceAll("(?<![\\p{L}\\p{N}.:])"+java.util.regex.Pattern.quote(number)+"(?![\\p{L}\\p{N}.:])","[号码]");}
        return text;
    }
    private static void item(StringBuilder s,String k,String v){s.append("<tr><td width='116' nowrap valign='top'>").append(escape(k)).append("</td><td valign='top'>").append(escape(v)).append("</td></tr>");}
}
