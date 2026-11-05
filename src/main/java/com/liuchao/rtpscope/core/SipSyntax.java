package com.liuchao.rtpscope.core;

import java.util.*;
import java.util.regex.*;

/** Character offsets into the original message; coloring never rewrites SIP or line endings. */
public final class SipSyntax {
    public enum Kind { HEADER, METHOD, URI, ID, SDP, PROVISIONAL, SUCCESS, ERROR }
    public static final class Span {
        public final int start,end;
        public final Kind kind;
        Span(int start,int end,Kind kind){this.start=start;this.end=end;this.kind=kind;}
    }
    private static final Pattern URI=Pattern.compile("(?i)\\b(?:sips?|tel):[^\\s<>\",;]+");
    private static final Pattern METHOD=Pattern.compile("\\b(?:INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|PRACK|UPDATE|INFO|MESSAGE|REFER|NOTIFY|SUBSCRIBE|PUBLISH)\\b");
    private static final Pattern PARAM=Pattern.compile("(?i)(?:^|[; \\t])(?:branch|tag)=([^;\\s,>]+)");
    public static List<Span> spans(String raw) {
        List<Span> out=new ArrayList<>();boolean body=false,sdp=false,identifier=false;int offset=0,lineNumber=0;
        while(offset<raw.length()) {
            int next=raw.indexOf('\n',offset);if(next<0)next=raw.length();
            int end=next;if(end>offset&&raw.charAt(end-1)=='\r')end--;
            String line=raw.substring(offset,end);
            if(lineNumber++==0) {
                if(line.startsWith("SIP/2.0 ")) {
                    char code=line.length()>8?line.charAt(8):'0';
                    add(out,offset+8,end,code=='1'?Kind.PROVISIONAL:code=='2'?Kind.SUCCESS:code>='3'&&code<='6'?Kind.ERROR:Kind.HEADER);
                }else {int space=line.indexOf(' ');if(space>0)add(out,offset,offset+space,Kind.METHOD);}
                tokens(out,URI,line,offset,Kind.URI,0);
            }else if(line.isEmpty()){body=true;}
            else if(!body) {
                int colon=line.indexOf(':');boolean folded=Character.isWhitespace(line.charAt(0));int value=0;
                if(!folded) {
                    identifier=false;
                    if(colon>0) {
                        String header=line.substring(0,colon).trim().toLowerCase(Locale.ROOT);
                        add(out,offset,offset+colon+1,Kind.HEADER);value=colon+1;
                        identifier=Arrays.asList("from","to","call-id","f","t","i").contains(header);
                        if((header.equals("content-type")||header.equals("c"))&&line.substring(value).toLowerCase(Locale.ROOT).contains("application/sdp"))sdp=true;
                    }
                }
                if(identifier)add(out,offset+value,end,Kind.ID);
                if(!folded&&colon>0&&line.substring(0,colon).equalsIgnoreCase("CSeq"))tokens(out,METHOD,line.substring(value),offset+value,Kind.METHOD,0);
                if(!folded&&colon>0&&line.substring(0,colon).equalsIgnoreCase("Allow"))tokens(out,METHOD,line.substring(value),offset+value,Kind.METHOD,0);
                tokens(out,URI,line.substring(value),offset+value,Kind.URI,0);
                tokens(out,PARAM,line.substring(value),offset+value,Kind.ID,1);
            }else {
                if(line.startsWith("v="))sdp=true;
                if(sdp&&line.length()>=2&&line.charAt(1)=='=') {
                    int keyEnd=2;
                    if(line.startsWith("a=")){int colon=line.indexOf(':',2);if(colon>2)keyEnd=colon+1;}
                    add(out,offset,offset+keyEnd,Kind.SDP);
                    if(line.startsWith("m=")||line.startsWith("c="))add(out,offset+2,end,Kind.URI);
                }
            }
            offset=next<raw.length()?next+1:next;
        }
        return out;
    }
    private static void tokens(List<Span> out,Pattern pattern,String line,int base,Kind kind,int group) {
        Matcher m=pattern.matcher(line);while(m.find())add(out,base+m.start(group),base+m.end(group),kind);
    }
    private static void add(List<Span> out,int start,int end,Kind kind){if(end>start)out.add(new Span(start,end,kind));}
    public static int color(Kind kind) {
        switch(kind) {
            case HEADER:return 0xff6bd9ff;
            case METHOD:return 0xffcaabff;
            case URI:return 0xffffbd7a;
            case ID:case SUCCESS:return 0xff67e8c3;
            case SDP:return 0xffa9c3ff;
            case PROVISIONAL:return 0xffffdc83;
            case ERROR:return 0xffff9e9e;
            default:return 0xffeef4f8;
        }
    }
}
